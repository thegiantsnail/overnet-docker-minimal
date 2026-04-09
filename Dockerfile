# ─────────────────────────────────────────────
# Overnet — Dockerfile
# Multi-stage build: keeps final image minimal
# ─────────────────────────────────────────────

# Stage 1: build dependencies
FROM python:3.15.0a8-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# Stage 2: runtime
FROM python:3.15.0a8-slim

LABEL org.opencontainers.image.title="Overnet"
LABEL org.opencontainers.image.description="Probabilistic P2P overlay network"

# Non-root user for security
RUN useradd -m -u 1000 overnet
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application
COPY overnet.py .

# Data volume — SQLite DB persists here; identity keys default next to the DB
RUN mkdir /data && chown overnet:overnet /data
VOLUME ["/data"]

USER overnet

# Default UDP port
EXPOSE 9000/udp

# Entrypoint: runs node with DB in persistent volume
# Override CMD in docker-compose to set port / peer
ENTRYPOINT ["python", "overnet.py", "--db", "/data/overnet.db"]
CMD ["--port", "9000", "--no-cli"]
