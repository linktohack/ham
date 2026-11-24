# ham — minimal encrypted TCP tunnels over WebSocket

Single-file Python scripts, run with [uv](https://docs.astral.sh/uv/) (no install step; dependencies are declared inline).

| Mode | Scripts | Use it for |
|---|---|---|
| **Reverse tunnel** (like `ngrok tcp`) | `server.py` + `client.py` | Expose a local service on a public server's port |
| **Relay** (rendezvous) | `relay.py` + `peer.py` | Two peers behind NAT reach each other through a relay that can't read their traffic |

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Python 3.10+ (uv can fetch it)

Run scripts directly (`./server.py`) or with `uv run server.py`.

## Reverse tunnel

```bash
export TUNNEL_PSK=$(openssl rand -hex 32)       # same value on both machines

./server.py --ws-port 9000 --public-port 8080   # public machine
./client.py --url ws://SERVER:9000 --local-port 22   # machine behind NAT

ssh -p 8080 user@SERVER                         # from anywhere
```

The server accepts one agent at a time.

## Relay

```bash
export RELAY_PSK=$(openssl rand -hex 32)
./relay.py --port 9000                          # public relay

# on both peers: same RELAY_PSK, plus a ROOM_PSK shared only between them
export RELAY_URL=ws://RELAY:9000 RELAY_PSK=... ROOM_PSK=...

./peer.py serve   --local-port 22               # peer A: share a local service
./peer.py connect --listen-port 2222            # peer B: opens 127.0.0.1:2222
ssh -p 2222 user@127.0.0.1                      # on B, reaches A
```

- `RELAY_PSK` controls who may use the relay and encrypts the peer-to-relay hop.
- `ROOM_PSK` never leaves the peers. Peers are paired by `HMAC(ROOM_PSK)`, and their traffic is end-to-end encrypted, so the relay forwards only ciphertext.
- Only the `connect` side can open connections; data then flows both ways. For the other direction, run a second pair with a different `ROOM_PSK` and the roles swapped.

## Deploy the relay (Kubernetes, `link/stack` chart)

`relay.py` is mounted from a ConfigMap into the stock `astral/uv` image, so there's nothing to build. This example serves it on `/secure` of a host that already has a site, without touching the existing ingress on `/`.

`relay-stack.yaml`:

```yaml
configs:
  relay_py:
    file: ./relay.py
services:
  relay:
    image: astral/uv:python3.12-bookworm-slim
    entrypoint: ["uv", "run", "--script", "/app/relay.py"]
    command: ["--host", "0.0.0.0", "--port", "9000"]
    environment:
      - RELAY_PSK=change-me              # openssl rand -hex 32; keep it out of git
    configs:
      - source: relay_py
        target: /app/relay.py
    deploy:
      labels:
        - traefik.frontend.rule=Host:example.com;PathPrefix:/secure
        - traefik.port=9000
    Ingress:
      default:
        metadata:
          annotations:
            nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
            nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
```

There's no `ports:` (it would add a LoadBalancer Service that bypasses the ingress) and no cert-issuer label (the path reuses the host's existing certificate).

```bash
helm upgrade --install relay link/stack -n ham-relay --create-namespace \
  -f relay-stack.yaml --set-file configs.relay_py.data=relay.py
kubectl -n ham-relay rollout restart deploy/relay   # needed after changing relay.py
```

Peers then use `RELAY_URL=wss://example.com/secure`.

## Security

- **Handshake:** ephemeral X25519, with the PSK mixed into HKDF. Then ChaCha20-Poly1305 with per-direction nonce counters.
- **The PSK is never sent.** You get forward secrecy, and a man in the middle without the PSK fails the handshake.
- **Use long random PSKs** (`openssl rand -hex 32`). A weak `ROOM_PSK` can be guessed by the relay operator from the room ID.
- **The handshake is a custom design, not a reviewed protocol.** For anything important, also run it over `wss://` (put the server or relay behind a TLS proxy).
- **The relay still sees metadata:** IP addresses, room IDs, timing and traffic sizes.

## Limitations

- TCP only; no UDP.
- All connections share one WebSocket, so a slow connection can stall the others.
- In the reverse tunnel, the public port has no access control: anyone who reaches it gets through to your service.
