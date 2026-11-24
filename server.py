#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=14", "cryptography>=42"]
# ///
"""Minimal ngrok-style relay server.

An agent (client.py) dials in over WebSocket and authenticates with a pre-shared key (PSK).
Every TCP connection to --public-port is then forwarded through the encrypted WebSocket
to the agent, which connects to its local service.

Handshake (mini-Noise, "NNpsk"-style; the PSK never goes on the wire):
    server -> client : server ephemeral X25519 public key
    client -> server : client ephemeral X25519 public key
    both             : key = HKDF(ECDH, salt=PSK, info=label || eph_s || eph_c)
    client -> server : AEAD("client-confirm")
    server -> client : AEAD("server-confirm")

Frames (encrypted with ChaCha20-Poly1305): [1B type][4B stream id][payload]
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
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

# ---------------------------------------------------------------- protocol + crypto
# (kept identical in client.py so each script runs on its own)

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


# ---------------------------------------------------------------- server side

async def handshake_server(ws, psk: bytes) -> Session:
    priv = X25519PrivateKey.generate()
    my_pub = priv.public_key().public_bytes_raw()
    await ws.send(my_pub)
    client_pub = await recv_pubkey(ws)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(client_pub))
    sess = Session(ws, derive_key(shared, psk, my_pub, client_pub), send_dir=0)
    try:
        confirm = sess.decrypt(as_bytes(await asyncio.wait_for(ws.recv(), HANDSHAKE_TIMEOUT)))
    except InvalidTag:
        raise HandshakeError("client key confirmation failed (wrong PSK?)") from None
    if confirm != CLIENT_CONFIRM:
        raise HandshakeError("unexpected client confirmation")
    await sess.send_raw(SERVER_CONFIRM)
    return sess


class Relay:
    def __init__(self, psk: bytes):
        self.psk = psk
        self.sess: Session | None = None
        self.streams: dict[int, asyncio.StreamWriter] = {}
        self.next_sid = 1

    async def agent_handler(self, ws):
        peer = ws.remote_address
        try:
            sess = await handshake_server(ws, self.psk)
        except (HandshakeError, asyncio.TimeoutError, ConnectionClosed, ValueError) as e:
            print(f"[server] handshake from {peer} failed: {e}")
            await ws.close(code=4001, reason="handshake failed")
            return
        if self.sess is not None:
            print(f"[server] rejecting {peer}: an agent is already connected")
            await ws.close(code=4002, reason="agent already connected")
            return

        self.sess = sess
        print(f"[server] agent {peer} connected")
        try:
            async for t, sid, payload in sess.frames():
                w = self.streams.get(sid)
                if w is None:
                    continue
                if t == DATA:
                    w.write(payload)
                    await w.drain()
                elif t == CLOSE:
                    self.streams.pop(sid, None)
                    w.close()
        except (ConnectionClosed, InvalidTag, ConnectionError) as e:
            print(f"[server] agent session ended: {type(e).__name__}")
        finally:
            self.sess = None
            for w in self.streams.values():
                w.close()
            self.streams.clear()
            print(f"[server] agent {peer} disconnected")

    async def public_handler(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sess = self.sess
        if sess is None:
            writer.close()
            return
        sid = self.next_sid
        self.next_sid += 1
        self.streams[sid] = writer
        print(f"[server] stream {sid} opened from {writer.get_extra_info('peername')}")
        try:
            await sess.send(OPEN, sid)
            while data := await reader.read(CHUNK):
                await sess.send(DATA, sid, data)
        except (ConnectionClosed, ConnectionError):
            pass
        finally:
            if self.streams.pop(sid, None) is not None:  # we closed first: tell the agent
                try:
                    await sess.send(CLOSE, sid)
                except ConnectionClosed:
                    pass
            writer.close()
            print(f"[server] stream {sid} closed")


async def main(args):
    relay = Relay(args.psk.encode())
    async with serve(relay.agent_handler, args.host, args.ws_port, max_size=None):
        public = await asyncio.start_server(relay.public_handler, args.host, args.public_port)
        print(f"[server] agents -> ws://{args.host}:{args.ws_port}   public -> tcp://{args.host}:{args.public_port}")
        async with public:
            await public.serve_forever()


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # flush logs even when redirected
    p = argparse.ArgumentParser(description="Reverse tunnel relay server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--ws-port", type=int, default=9000, help="port agents connect to")
    p.add_argument("--public-port", type=int, default=8080, help="public TCP port to expose")
    p.add_argument("--psk", default=os.environ.get("TUNNEL_PSK"), help="pre-shared key (or env TUNNEL_PSK)")
    a = p.parse_args()
    if not a.psk:
        p.error("set --psk or TUNNEL_PSK (e.g. export TUNNEL_PSK=$(openssl rand -hex 32))")
    try:
        asyncio.run(main(a))
    except KeyboardInterrupt:
        pass
