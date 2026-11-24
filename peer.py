#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=14", "cryptography>=42"]
# ///
"""Peer for relay.py: two peers with the same ROOM_PSK get an end-to-end encrypted TCP tunnel.

    serve   : expose a local TCP service (e.g. --local-port 22) to the paired peer
    connect : open a local listening port; each connection to it goes to the serving peer

The relay authenticates you with RELAY_PSK, pairs you by HMAC(ROOM_PSK), and then just forwards
ciphertext. ROOM_PSK never leaves this machine. See relay.py for the protocol.
"""

import argparse
import asyncio
import hashlib
import hmac
import os
import struct
import sys
from contextlib import suppress

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, ConnectionClosedOK, InvalidHandshake

# ---------------------------------------------------------------- crypto (identical in relay.py)

HANDSHAKE_TIMEOUT = 10
HOP_LABEL = b"ham-relay-hop-v1"
E2E_LABEL = b"ham-relay-e2e-v1"
CONFIRM_INIT = b"initiator-confirm"
CONFIRM_RESP = b"responder-confirm"


class HandshakeError(Exception):
    pass


def as_bytes(msg) -> bytes:
    return msg.encode() if isinstance(msg, str) else msg


class Session:
    """ChaCha20-Poly1305 channel over any transport with async send(bytes) / recv() -> bytes.

    A Session is itself such a transport, so sessions stack (e2e runs inside hop).
    Nonce = direction byte || 64-bit counter || 3 zero bytes; one counter per direction.
    """

    def __init__(self, tx, key: bytes, send_dir: int):
        self.tx = tx
        self.aead = ChaCha20Poly1305(key)
        self.send_dir, self.recv_dir = send_dir, 1 - send_dir
        self.send_ctr = self.recv_ctr = 0
        self.lock = asyncio.Lock()

    @staticmethod
    def nonce(direction: int, ctr: int) -> bytes:
        return struct.pack("!BQ", direction, ctr) + b"\x00\x00\x00"

    def encrypt(self, pt: bytes) -> bytes:
        if self.send_ctr >= 2**64 - 1:
            raise RuntimeError("nonce space exhausted; reconnect to rekey")
        n = self.nonce(self.send_dir, self.send_ctr)
        self.send_ctr += 1
        return self.aead.encrypt(n, pt, None)

    def decrypt(self, ct: bytes) -> bytes:
        pt = self.aead.decrypt(self.nonce(self.recv_dir, self.recv_ctr), ct, None)
        self.recv_ctr += 1  # only advance on success
        return pt

    async def send(self, pt: bytes) -> None:
        async with self.lock:  # keep nonce order == wire order
            await self.tx.send(self.encrypt(pt))

    async def recv(self) -> bytes:
        return self.decrypt(as_bytes(await self.tx.recv()))

    async def messages(self):
        try:
            while True:
                yield await self.recv()
        except ConnectionClosedOK:
            return


async def handshake(tx, psk: bytes, label: bytes, initiator: bool) -> Session:
    async def recv() -> bytes:
        return as_bytes(await asyncio.wait_for(tx.recv(), HANDSHAKE_TIMEOUT))

    priv = X25519PrivateKey.generate()
    my_pub = priv.public_key().public_bytes_raw()
    if initiator:
        peer_pub = await recv()
        await tx.send(my_pub)
    else:
        await tx.send(my_pub)
        peer_pub = await recv()
    if len(peer_pub) != 32:
        raise HandshakeError("bad public key length")
    try:
        shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    except ValueError:
        raise HandshakeError("invalid public key") from None
    resp_pub, init_pub = (peer_pub, my_pub) if initiator else (my_pub, peer_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=psk,
               info=label + resp_pub + init_pub).derive(shared)
    sess = Session(tx, key, send_dir=1 if initiator else 0)

    mine, theirs = (CONFIRM_INIT, CONFIRM_RESP) if initiator else (CONFIRM_RESP, CONFIRM_INIT)
    if initiator:
        await sess.send(mine)
    try:
        got = sess.decrypt(await recv())
    except InvalidTag:
        raise HandshakeError("key confirmation failed (wrong PSK?)") from None
    if got != theirs:
        raise HandshakeError("unexpected key confirmation")
    if not initiator:
        await sess.send(mine)
    return sess


# ---------------------------------------------------------------- stream multiplexing (e2e)

OPEN, DATA, CLOSE = 1, 2, 3
CHUNK = 64 * 1024


class RelayError(Exception):
    pass


class Mux:
    """Many TCP streams over one e2e Session. Frame: [1B type][4B stream id][payload]."""

    def __init__(self, sess: Session):
        self.sess = sess
        self.streams: dict[int, asyncio.StreamWriter] = {}
        self.tasks: set[asyncio.Task] = set()
        self.next_sid = 1

    async def send_frame(self, t: int, sid: int, payload: bytes = b"") -> None:
        await self.sess.send(struct.pack("!BI", t, sid) + payload)

    def attach(self, sid: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.streams[sid] = writer
        task = asyncio.create_task(self._pump(sid, reader))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _pump(self, sid: int, reader: asyncio.StreamReader) -> None:
        try:
            while data := await reader.read(CHUNK):
                await self.send_frame(DATA, sid, data)
        except (ConnectionClosed, ConnectionError):
            pass
        finally:
            w = self.streams.pop(sid, None)
            if w is not None:  # local side closed first: tell the peer
                w.close()
                with suppress(ConnectionClosed):
                    await self.send_frame(CLOSE, sid)

    async def run(self, on_open=None) -> None:
        try:
            async for msg in self.sess.messages():
                t, sid = struct.unpack("!BI", msg[:5])
                payload = msg[5:]
                if t == OPEN and on_open is not None:
                    await on_open(self, sid)
                elif t == DATA:
                    w = self.streams.get(sid)
                    if w is not None:
                        w.write(payload)
                        await w.drain()
                elif t == CLOSE:
                    w = self.streams.pop(sid, None)
                    if w is not None:
                        w.close()
        finally:
            for w in self.streams.values():
                w.close()
            self.streams.clear()
            for task in self.tasks:
                task.cancel()


# ---------------------------------------------------------------- peer

def room_id(room_psk: bytes) -> bytes:
    return hmac.new(room_psk, b"ham-room-id-v1", hashlib.sha256).digest()


async def tunnel_once(args, role: bytes, on_tunnel) -> None:
    async with connect(args.relay, max_size=None) as ws:
        try:
            hop = await handshake(ws, args.relay_psk.encode(), HOP_LABEL, initiator=True)
        except (HandshakeError, ConnectionClosed) as e:
            raise HandshakeError(f"relay handshake failed ({e}) - wrong RELAY_PSK?") from None

        await hop.send(b"J" + role + room_id(args.room_psk.encode()))
        while (msg := await hop.recv()) != b"PAIR":
            if msg == b"WAIT":
                print("[peer] waiting for the other peer to join the room...")
            elif msg.startswith(b"ERR:"):
                raise RelayError(msg[4:].decode(errors="replace"))

        try:
            e2e = await handshake(hop, args.room_psk.encode(), E2E_LABEL, initiator=(role == b"C"))
        except (HandshakeError, ConnectionClosed) as e:
            raise HandshakeError(f"end-to-end handshake failed ({e})") from None
        print("[peer] paired, end-to-end session up")
        await on_tunnel(Mux(e2e))


async def main(args):
    role = b"S" if args.cmd == "serve" else b"C"
    current: dict[str, Mux | None] = {"mux": None}

    if args.cmd == "serve":
        async def on_open(mux: Mux, sid: int):
            try:
                r, w = await asyncio.open_connection(args.local_host, args.local_port)
            except OSError as e:
                print(f"[peer] stream {sid}: cannot reach {args.local_host}:{args.local_port}: {e}")
                await mux.send_frame(CLOSE, sid)
                return
            mux.attach(sid, r, w)

        async def on_tunnel(mux: Mux):
            print(f"[peer] serving {args.local_host}:{args.local_port} to the paired peer")
            await mux.run(on_open)
    else:
        async def on_local(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            mux = current["mux"]
            if mux is None:  # not paired right now
                writer.close()
                return
            sid = mux.next_sid
            mux.next_sid += 1
            try:
                await mux.send_frame(OPEN, sid)
            except ConnectionClosed:
                writer.close()
                return
            mux.attach(sid, reader, writer)

        async def on_tunnel(mux: Mux):
            current["mux"] = mux
            print(f"[peer] connect to {args.listen_host}:{args.listen_port} to reach the serving peer")
            try:
                await mux.run()
            finally:
                current["mux"] = None

        listener = await asyncio.start_server(on_local, args.listen_host, args.listen_port)
        print(f"[peer] listening on {args.listen_host}:{args.listen_port}")

    backoff = 1
    while True:
        try:
            await tunnel_once(args, role, on_tunnel)
            print("[peer] tunnel closed")
            backoff = 1
        except (HandshakeError, RelayError) as e:
            print(f"[peer] {type(e).__name__}: {e}")
        except (OSError, ConnectionClosed, InvalidHandshake, InvalidTag, asyncio.TimeoutError) as e:
            print(f"[peer] connection error: {type(e).__name__}: {e}")
        print(f"[peer] reconnecting in {backoff}s")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 30)


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # flush logs even when redirected
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--relay", default=os.environ.get("RELAY_URL", "ws://127.0.0.1:9000"),
                        help="relay WebSocket URL (or env RELAY_URL)")
    common.add_argument("--relay-psk", default=os.environ.get("RELAY_PSK"), help="relay access PSK (or env RELAY_PSK)")
    common.add_argument("--room-psk", default=os.environ.get("ROOM_PSK"), help="shared peer PSK (or env ROOM_PSK)")

    p = argparse.ArgumentParser(description="Peer for relay.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", parents=[common], help="expose a local TCP service to the other peer")
    s.add_argument("--local-host", default="127.0.0.1")
    s.add_argument("--local-port", type=int, required=True)
    c = sub.add_parser("connect", parents=[common], help="open a local port that reaches the other peer")
    c.add_argument("--listen-host", default="127.0.0.1")
    c.add_argument("--listen-port", type=int, required=True)
    a = p.parse_args()
    if not a.relay_psk or not a.room_psk:
        p.error("set --relay-psk/RELAY_PSK and --room-psk/ROOM_PSK")
    try:
        asyncio.run(main(a))
    except KeyboardInterrupt:
        pass
