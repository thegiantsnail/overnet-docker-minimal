# overnet-docker-minimal

A minimal Dockerized deployment of **Overnet**, an experimental peer-to-peer overlay node focused on authenticated messaging, onion-routed relay paths, and defensive controls against replay/abuse.

## Status

This repository is designed as a **local testnet and research sandbox**, not a production-ready anonymity network.

## What this project includes

- A single Python node implementation (`overnet.py`)
- Docker image and multi-node `docker-compose.yml` testnet
- Persistent node state and key material in `/data`

## Security-oriented design highlights

- Ed25519 + X25519 key material via `cryptography`
- ChaCha20-Poly1305 AEAD for authenticated encryption
- HKDF-based key derivation
- Fixed-size wire frames to reduce packet size leakage
- Replay window + nonce cache
- Per-IP token-bucket rate limiting
- Trust decay/velocity controls and anti-centralization route weighting

## Quick start (local)

```bash
docker compose up --build -d
```

```bash
docker compose logs -f node-a
```

Stop:

```bash
docker compose down
```

## Important network safety notes

1. **Local testnet topology:** In `docker-compose.yml`, nodes `b`–`g` bootstrap from `node-a`. This is intentional for deterministic local startup and should not be treated as a production topology pattern.
2. **Published UDP ports:** The compose file publishes UDP `9000-9006` on the host. On shared/internet-connected hosts, restrict exposure with host firewalling or localhost-only bindings.
3. **Experimental software:** Treat this project as a security-focused prototype; audit and harden further before any untrusted deployment.

## Documentation

- Validation/run notes: [`README_VALIDATION.md`](README_VALIDATION.md)
- Vulnerability reporting policy: [`SECURITY.md`](SECURITY.md)

## License

GPL-3.0. See [`LICENSE`](LICENSE).
