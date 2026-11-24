#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=14", "cryptography>=42"]
# ///
"""Rendezvous relay: pairs two peers (peer.py) that share a room PSK.

Two layers of encryption:
  hop  : peer <-> relay, keyed with RELAY_PSK. Gates who may use the relay and hides metadata.
  e2e  : peer <-> peer, keyed with ROOM_PSK, which the relay never learns. The relay only
         forwards opaque ciphertext between the paired peers.

Pairing: a peer joins with ("J", role, room_id), role "S" (serve) or "C" (connect), and
room_id = HMAC-SHA256(ROOM_PSK, "ham-room-id-v1"). One S plus one C in the same room = a pair.
The relay replies "WAIT", then "PAIR" once the other side arrives, or "ERR:<reason>".

Handshake (both layers, mini-Noise "NNpsk"-style, the PSK never goes on the wire):
    responder -> initiator : ephemeral X25519 public key
    initiator -> responder : ephemeral X25519 public key
    both                   : key = HKDF(ECDH, salt=PSK, info=label || eph_resp || eph_init)
    initiator -> responder : AEAD("initiator-confirm")
    responder -> initiator : AEAD("responder-confirm")
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
from websockets.exceptions import ConnectionClosed, ConnectionClosedOK

# ---------------------------------------------------------------- crypto (identical in peer.py)

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


# ---------------------------------------------------------------- relay

class Member:
    def __init__(self, ws, hop: Session):
        self.ws = ws
        self.hop = hop
        self.partner: asyncio.Future[Member] = asyncio.get_running_loop().create_future()


class Relay:
    def __init__(self, psk: bytes):
        self.psk = psk
        self.rooms: dict[bytes, dict[bytes, Member]] = {}  # room_id -> {role: waiting member}

    async def handler(self, ws):
        addr = ws.remote_address
        try:
            hop = await handshake(ws, self.psk, HOP_LABEL, initiator=False)
            join = await asyncio.wait_for(hop.recv(), HANDSHAKE_TIMEOUT)
        except (HandshakeError, InvalidTag, asyncio.TimeoutError, ConnectionClosed) as e:
            print(f"[relay] {addr}: handshake failed: {type(e).__name__}: {e}")
            await ws.close(code=4001, reason="handshake failed")
            return

        if len(join) != 34 or join[:1] != b"J" or join[1:2] not in (b"S", b"C"):
            await hop.send(b"ERR:bad join message")
            await ws.close(code=4003, reason="bad join")
            return
        role, room = join[1:2], join[2:]
        other = b"C" if role == b"S" else b"S"
        tag = f"room {room.hex()[:8]} {role.decode()}"
        slots = self.rooms.setdefault(room, {})
        if role in slots:
            print(f"[relay] {addr}: {tag} rejected, role already taken")
            await hop.send(b"ERR:role already taken in this room")
            await ws.close(code=4004, reason="role taken")
            return

        me = Member(ws, hop)
        waiting = slots.pop(other, None)
        if waiting is not None:
            try:
                # Send PAIR to both before either side starts forwarding, so PAIR is always the
                # first thing each peer gets after WAIT.
                await waiting.hop.send(b"PAIR")
            except ConnectionClosed:
                waiting.partner.cancel()
                waiting = None
        if waiting is not None:
            if not slots:
                self.rooms.pop(room, None)
            await hop.send(b"PAIR")
            waiting.partner.set_result(me)
            partner = waiting
            print(f"[relay] {addr}: {tag} paired with {partner.ws.remote_address}")
        else:
            slots[role] = me
            print(f"[relay] {addr}: {tag} waiting for partner")
            await hop.send(b"WAIT")
            closed = asyncio.ensure_future(ws.wait_closed())
            await asyncio.wait({me.partner, closed}, return_when=asyncio.FIRST_COMPLETED)
            closed.cancel()
            if not me.partner.done() or me.partner.cancelled():
                if self.rooms.get(room, {}).get(role) is me:
                    del self.rooms[room][role]
                    if not self.rooms[room]:
                        del self.rooms[room]
                print(f"[relay] {addr}: {tag} left while waiting")
                return
            partner = me.partner.result()

        # Forward opaque e2e ciphertext: decrypt our hop layer, re-encrypt on the partner's hop.
        try:
            async for blob in hop.messages():
                await partner.hop.send(blob)
        except (ConnectionClosed, InvalidTag):
            pass
        finally:
            await partner.ws.close()
            print(f"[relay] {addr}: {tag} disconnected")


async def main(args):
    relay = Relay(args.psk.encode())
    async with serve(relay.handler, args.host, args.port, max_size=None) as server:
        print(f"[relay] listening on ws://{args.host}:{args.port}")
        await server.serve_forever()


if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)  # flush logs even when redirected
    p = argparse.ArgumentParser(description="Rendezvous relay for peer.py")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--psk", default=os.environ.get("RELAY_PSK"), help="relay access PSK (or env RELAY_PSK)")
    a = p.parse_args()
    if not a.psk:
        p.error("set --psk or RELAY_PSK (e.g. export RELAY_PSK=$(openssl rand -hex 32))")
    try:
        asyncio.run(main(a))
    except KeyboardInterrupt:
        pass
