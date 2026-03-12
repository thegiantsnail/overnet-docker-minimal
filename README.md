# Overnet — Probabilistic P2P overlay network using Markov distance chaining

> ⚠️ **Security notice**
>
> UDP ports 9000–9006 are published to `0.0.0.0` on the host by the default
> `docker-compose.yml`. **Do not run this compose file on an internet-connected
> machine without firewall rules.** The included compose file is a
> **local testnet only** and is not hardened for public exposure.

## Overview

Overnet is a decentralised, anonymous-capable peer-to-peer overlay network
implemented in Python. Nodes use Markov/XOR-band routing (SSEP-inspired
heuristics) to locate and deliver content across the network. Each node holds a
**dual Ed25519 + X25519 identity** — the Ed25519 keypair is used for signing and
the X25519 keypair for key exchange.

All wire traffic is **onion-encrypted** with ChaCha20-Poly1305 AEAD and sent in
**fixed-size 900-byte frames** to resist traffic analysis through packet-size
fingerprinting. Multi-hop forward and reply circuits provide layered encryption
so no single relay learns both the sender and the destination.

This repository contains a minimal Dockerized deployment suitable for local
testnet experiments and research. It is **not** a production-ready anonymity
network.

## Security design

The following defensive layers are implemented in `overnet.py`:

| Layer | Description |
|---|---|
| BLUE-5 | Trust inactivity decay — idle peers lose trust over time |
| BLUE-6 | Per-destination reply token cap (`MAX_TOKENS_PER_DEST = 100`) |
| BLUE-7 | Exit timing jitter — Poisson-distributed delay on reply emission |
| BLUE-8 | Exception class specificity — narrow except clauses throughout |
| BLUE-9 | Route selection diversity penalty — prevents routing concentration |
| Token-bucket rate limiter | Per-IP rate limiting, burst = 40 tokens |
| Replay cache | Nonce + 300-second timestamp window, 65 536-entry LRU |
| Sybil resistance | Max 3 peers per /24 subnet in the routing table |
| Disk guard | 512 MB content quota, 256 MB minimum free space enforced |
| Fixed-size frames | 900-byte wire frames for traffic analysis resistance |

## Architecture

| Class | Role |
|---|---|
| `Identity` | Loads or generates the dual Ed25519/X25519 keypair; restricts key file permissions to `0o600` |
| `OnionRouter` | Builds, wraps, and unwraps layered AEAD onion packets; manages forward and reply circuits |
| `RoutingTable` | Stores peers with XOR-distance scoring, Sybil /24 subnet cap, and trust-decay eviction |
| `TrustLedger` | Tracks per-peer trust scores with velocity capping and inactivity decay (BLUE-5) |
| `ContentStore` | SQLite-backed immutable content addressed by hash; enforces disk quota via `DiskGuard` |
| `TokenBucket` | Per-IP token-bucket rate limiter with configurable rate and burst ceiling |
| `ReplayCache` | Fixed-capacity LRU nonce cache with timestamp window to block message replay |
| `DiskGuard` | Enforces maximum stored content size and minimum host free space |
| `Node` | Async UDP event loop; ties all components together; handles all wire message types |

## Quick start (Docker)

```bash
docker compose up -d --build
```

Watch logs for a single node:

```bash
docker compose logs -f node-a
```

Tear down (keeps named volumes / node identity):

```bash
docker compose down
```

Tear down and wipe all node state (removes volumes, deletes keys and DB):

```bash
docker compose down -v
```

See [`README_VALIDATION.md`](README_VALIDATION.md) for additional operational
notes including the routing experiment override compose file.

## Requirements

- Python 3.12+
- `cryptography >= 42`
- `aiosqlite >= 0.19`

(Docker handles all dependencies automatically.)

## Vulnerability reporting

Please **do not** open a public GitHub issue for security vulnerabilities.
See [`SECURITY.md`](SECURITY.md) for the responsible disclosure process.

## License

GPL-3.0. See [`LICENSE`](LICENSE).
