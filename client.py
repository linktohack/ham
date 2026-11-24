#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=14", "cryptography>=42"]
# ///
"""Minimal ngrok-style agent.

Dials out to server.py over WebSocket, does the PSK handshake, then forwards every stream the
server opens to --local-host:--local-port. Reconnects with backoff if the link drops.
See server.py for the handshake and frame format.
"""

import argparse
import asyncio
import os
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake

# ---------------------------------------------------------------- protocol + crypto
# (kept identical in server.py so each script runs on its own)

OPEN, DATA, CLOSE = 1, 2, 3
CHUNK = 64 * 1024
HANDSHAKE_TIMEOUT = 10
LABEL = b"ham-tunnel-v1"
CLIENT_CONFIRM = b"client-confirm"
SERVER_CONFIRM = b"server-confirm"


class HandshakeError(Exception):
    pass


def frame(t: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack("!BI", t, sid) + payload


def unframe(msg: bytes) -> tuple[int, int, bytes]:
    t, sid = struct.unpack("!BI", msg[:5])
    return t, sid, msg[5:]


def as_bytes(msg) -> bytes:
    return msg.encode() if isinstance(msg, str) else msg


class Session:
    """ChaCha20-Poly1305 channel with one nonce counter per direction.

    Nonce = direction byte || 64-bit counter || 3 zero bytes, so the two directions never share
    a nonce. Both ends must use the counters in the same order, so `send` holds a lock across
    encrypt + send.
    """

    def __init__(self, ws, key: bytes, send_dir: int):
        self.ws = ws
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

    async def send_raw(self, pt: bytes) -> None:
        async with self.lock:
            await self.ws.send(self.encrypt(pt))

    async def send(self, t: int, sid: int, payload: bytes = b"") -> None:
        await self.send_raw(frame(t, sid, payload))

    async def frames(self):
        async for msg in self.ws:
            yield unframe(self.decrypt(as_bytes(msg)))


def derive_key(shared: bytes, psk: bytes, eph_server: bytes, eph_client: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=psk,
                info=LABEL + eph_server + eph_client).derive(shared)


async def recv_pubkey(ws) -> bytes:
    pub = as_bytes(await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT))
    if len(pub) != 32:
        raise HandshakeError("bad public key length")
    return pub


# ---------------------------------------------------------------- agent side

async def handshake_client(ws, psk: bytes) -> Session:
    server_pub = await recv_pubkey(ws)
    priv = X25519PrivateKey.generate()
    my_pub = priv.public_key().public_bytes_raw()
    await ws.send(my_pub)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(server_pub))
    sess = Session(ws, derive_key(shared, psk, server_pub, my_pub), send_dir=1)
    await sess.send_raw(CLIENT_CONFIRM)
    try:
        confirm = sess.decrypt(as_bytes(await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT)))
    except InvalidTag:
        raise HandshakeError("server key confirmation failed (wrong PSK or MITM)") from None
    except ConnectionClosed as e:
        raise HandshakeError(f"server closed during handshake ({e.rcvd.reason if e.rcvd else 'no reason'}) - wrong PSK?") from None
    if confirm != SERVER_CONFIRM:
        raise HandshakeError("unexpected server confirmation")
    return sess


async def run_session(url: str, psk: bytes, local_host: str, local_port: int) -> None:
    async with connect(url, max_size=None) as ws:
        sess = await handshake_client(ws, psk)
        print(f"[agent] tunnel up: {url} -> {local_host}:{local_port}")
        streams: dict[int, asyncio.StreamWriter] = {}
        tasks: set[asyncio.Task] = set()

        async def pump_local(sid: int, reader: asyncio.StreamReader):
            try:
                while data := await reader.read(CHUNK):
                    await sess.send(DATA, sid, data)
            except (ConnectionClosed, ConnectionError):
                pass
            finally:
                w = streams.pop(sid, None)
                if w is not None:  # local side closed first: tell the server
                    w.close()
                    try:
                        await sess.send(CLOSE, sid)
                    except ConnectionClosed:
                        pass

        try:
            async for t, sid, payload in sess.frames():
                if t == OPEN:
                    try:
                        r, w = await asyncio.open_connection(local_host, local_port)
                    except OSError as e:
                        print(f"[agent] stream {sid}: cannot reach local service: {e}")
                        await sess.send(CLOSE, sid)
                        continue
                    streams[sid] = w
                    task = asyncio.create_task(pump_local(sid, r))
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                elif t == DATA:
                    w = streams.get(sid)
                    if w is not None:
                        w.write(payload)
                        await w.drain()
                elif t == CLOSE:
                    w = streams.pop(sid, None)
                    if w is not None:
                        w.close()
        finally:
            for w in streams.values():
                w.close()
            for task in tasks:
                task.cancel()


async def main(args):
    psk = args.psk.encode()
    backoff = 1
    while True:
        try:
            await run_session(args.url, psk, args.local_host, args.local_port)
            print("[agent] tunnel closed by server")
            backoff = 1
        except HandshakeError as e:
            print(f"[agent] handshake failed: {e}")
        except (OSError, ConnectionClosed, InvalidHandshake, InvalidTag, asyncio.TimeoutError) as e:
            print(f"[agent] connection error: {type(e).__name__}: {e}")
        print(f"[agent] reconnecting in {backoff}s")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 30)


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # flush logs even when redirected
    p = argparse.ArgumentParser(description="Reverse tunnel agent")
    p.add_argument("--url", default="ws://127.0.0.1:9000", help="server WebSocket URL (ws:// or wss://)")
    p.add_argument("--local-host", default="127.0.0.1")
    p.add_argument("--local-port", type=int, required=True, help="local service port to expose")
    p.add_argument("--psk", default=os.environ.get("TUNNEL_PSK"), help="pre-shared key (or env TUNNEL_PSK)")
    a = p.parse_args()
    if not a.psk:
        p.error("set --psk or TUNNEL_PSK")
    try:
        asyncio.run(main(a))
    except KeyboardInterrupt:
        pass
