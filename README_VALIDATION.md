# Overnet — Minimal Docker Desktop Module (External Validation)

This folder is a **self-contained Docker module** for validating Overnet’s Docker build + multi-node UDP testnet using Docker Desktop.

## Prereqs

- Docker Desktop (Compose v2)

## Quick start (7-node testnet)

From this folder:

```bash
docker compose up -d --build
```

Watch logs for one node:

```bash
docker logs -f overnet-node-a
```

Stop and remove containers (keeps named volumes unless you add `-v`):

```bash
docker compose down
```

To wipe all node state (removes volumes):

```bash
docker compose down -v
```

## Optional: routing experiment override

```bash
docker compose -f docker-compose.yml -f docker-compose.avoid-node.yml up -d --build
```

## What’s included

- `Dockerfile` — multi-stage Python image build
- `requirements.txt` — runtime deps
- `overnet.py` — Overnet node implementation
- `docker-compose.yml` — 7-node UDP testnet on a fixed bridge subnet
- `docker-compose.avoid-node.yml` — optional override for routing experiments

## Notes

- UDP ports `9000-9006` are published to the host.
- State persists per node in a named volume at `/data` (SQLite DB + identity keys by default).
