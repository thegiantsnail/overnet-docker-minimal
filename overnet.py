"""overnet.py - Hardened Overnet Implementation v9

Notes
-----
This repository is intended for GitHub distribution; it does not rely on any
external paper reference. Any routing bias described as "SSEP" is treated as an
SSEP-inspired heuristic (XOR-band density weighting), not a formal citation.

v9 adds:
    BLUE-9 Route selection diversity penalty
        RoutingTable tracks per-peer selection counts between hot-table rebuilds.
        During rebuild_hot_table, peers that are selected more than their
        equilibrium share get softly downweighted for the next rebuild period.

v8 adds:
    BLUE-5 Trust inactivity decay
    BLUE-6 Per-destination reply token cap
    BLUE-7 Exit timing jitter
    BLUE-8 Exception class specificity
"""

import asyncio
import hashlib
import json
import math
import time
import random
import argparse
import os
import signal
import struct
import sys
import collections
import logging
import shutil

import aiosqlite

from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.exceptions import InvalidSignature, InvalidTag

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("overnet")


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


def _restrict_private_key_permissions(path: str):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _parse_avoid_peers(values: list[str]) -> tuple[list[str], set[tuple[str, int]]]:
    """Parse avoid-peer selectors.

    Accepts either:
      - node_id prefix (hex)
      - host:port (e.g. 172.30.0.13:9003)

    Returns (node_id_prefixes, hostports).
    """
    node_prefixes: list[str] = []
    hostports: set[tuple[str, int]] = set()

    for raw in values or []:
        s = (raw or "").strip()
        if not s:
            continue
        if ":" in s:
            host, _, port_s = s.rpartition(":")
            host = host.strip()
            port_s = port_s.strip()
            if host and port_s.isdigit():
                hostports.add((host, int(port_s)))
                continue
        node_prefixes.append(s.lower())

    return node_prefixes, hostports


# ---------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------

ALLJUNK_CHANNEL   = "a" * 64
PROTOCOL_VERSION  = 10
MARKOV_LAMBDA     = 0.01
TRUST_FLOOR       = 0.1
MAX_HOPS          = 12
PING_INTERVAL     = 30
LATENCY_DECAY     = 0.25

# Trust inactivity decay (v8)
TRUST_DECAY_RATE  = 0.1
TRUST_DECAY_FLOOR = 0.01

# SSEP-inspired routing bias (v7)
SSEP_BAND_COUNT = 64
SSEP_BAND_FLOOR = 0.02

# Reply token limits (v8)
MAX_TOKENS_PER_DEST = 100

# Restricted-channel authorization (v10)
CHANNEL_DESCRIPTOR_CONTEXT = b"overnet-channel-descriptor-v1"
CHANNEL_MEMBER_CONTEXT     = b"overnet-channel-member-v1"

# Plain find reverse-route cache (v10)
FIND_ROUTE_TTL  = 60
MAX_FIND_ROUTES = 4096
MAX_FIND_ROUTES_PER_KEY = 32

# Hot table / routing (v3)
HOT_TABLE_SIZE    = 64
HOT_BUCKET_COUNT  = 16
HOT_BUCKET_SLOTS  = HOT_TABLE_SIZE // HOT_BUCKET_COUNT
HOT_TABLE_REFRESH = 15
SYBIL_PER_SUBNET  = 3

# Trust velocity (v3)
TRUST_VELOCITY_WINDOW = 3600
TRUST_VELOCITY_MAX    = 1.5
TRUST_VELOCITY_DAMP   = 0.2

# Rate-limiting / replay (v2)
RATE_LIMIT_BUCKET  = 20
RATE_LIMIT_BURST   = 40
TIMESTAMP_WINDOW   = 300
NONCE_CACHE_SIZE   = 65_536
PING_NONCE_TTL     = 60

# Content limits (v3)
MAX_UDP_PAYLOAD     = 65_507
MAX_CONTENT_SIZE    = 512 * 1024
DISK_QUOTA_BYTES    = 512 * 1024 * 1024
DISK_MIN_FREE_BYTES = 256 * 1024 * 1024

# Onion cell geometry (v5)
CIRCUIT_HOPS      = 3
EXIT_PLAIN        = 450
ROUTING_RESERVE   = 85
CELL_OVERHEAD     = 60
PLAIN_HEADER      = 5
ONION_INFO        = b"overnet-onion-v6"
ONION_AAD_CONTEXT = b"overnet-onion-aad-v1"
TRANSPORT_INFO    = b"overnet-transport-v1"
TRANSPORT_AAD_CONTEXT = b"overnet-transport-aad-v1"
REPLY_AAD_CONTEXT = b"overnet-reply-aad-v1"
WIRE_FRAME_SIZE   = 900

# Reply circuits (v5)
REPLY_CONTENT_MAX  = 30_000
REPLY_ROUTE_TTL    = 120

# Cover traffic (v5)
COVER_RATE         = 1.0
COVER_MIN_INTERVAL = 0.2

# Relay delay mixing (v6) / exit jitter (v8/BLUE-7)
RELAY_DELAY_MEAN   = 0.5


# ---------------------------------------------------------------------
# UTILITY: per-depth plaintext size
# ---------------------------------------------------------------------

def _cell_plain_at_depth(depth: int) -> int:
    p = EXIT_PLAIN
    for _ in range(depth):
        p = PLAIN_HEADER + ROUTING_RESERVE + p + CELL_OVERHEAD
    return p


_PLAIN_SIZES = [_cell_plain_at_depth(d) for d in range(CIRCUIT_HOPS)]


# ---------------------------------------------------------------------
# WIRE FRAME HELPERS
# ---------------------------------------------------------------------

def make_wire_frame(cell_bytes: bytes) -> bytes:
    assert len(cell_bytes) <= WIRE_FRAME_SIZE - 2, \
        f"cell too large for wire frame: {len(cell_bytes)}"
    hdr     = struct.pack(">H", len(cell_bytes))
    padding = os.urandom(WIRE_FRAME_SIZE - 2 - len(cell_bytes))
    return hdr + cell_bytes + padding


def extract_cell_from_frame(frame: bytes) -> Optional[bytes]:
    if len(frame) < 2:
        return None
    cell_len = struct.unpack(">H", frame[:2])[0]
    if 2 + cell_len > len(frame):
        return None
    return frame[2:2 + cell_len]


# ---------------------------------------------------------------------
# SECURITY: TOKEN BUCKET
# ---------------------------------------------------------------------

class TokenBucket:
    def __init__(self):
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(ip, (RATE_LIMIT_BURST, now))
        tokens = min(RATE_LIMIT_BURST, tokens + (now - last) * RATE_LIMIT_BUCKET)
        if tokens < 1.0:
            return False
        self._buckets[ip] = (tokens - 1.0, now)
        return True

    def evict_old(self):
        cutoff = time.monotonic() - 300
        self._buckets = {
            ip: (t, ts) for ip, (t, ts) in self._buckets.items()
            if ts > cutoff
        }


# ---------------------------------------------------------------------
# SECURITY: REPLAY CACHE
# ---------------------------------------------------------------------

class ReplayCache:
    def __init__(self, maxsize: int = NONCE_CACHE_SIZE):
        self._seen: collections.OrderedDict[tuple[str, str], float] = collections.OrderedDict()
        self._maxsize = maxsize

    def _evict_expired(self, now: float):
        cutoff = now - TIMESTAMP_WINDOW
        expired = [key for key, ts in self._seen.items() if ts < cutoff]
        for key in expired:
            self._seen.pop(key, None)

    def check(self, node_id: str, nonce: str, timestamp: float) -> bool:
        now = time.time()
        if abs(now - timestamp) > TIMESTAMP_WINDOW:
            return False
        self._evict_expired(now)
        cache_key = (node_id, nonce)
        if cache_key in self._seen:
            return False
        if len(self._seen) >= self._maxsize:
            return False
        self._seen[cache_key] = timestamp
        self._seen.move_to_end(cache_key)
        return True


# ---------------------------------------------------------------------
# IDENTITY  (dual keypair: Ed25519 + X25519)
# ---------------------------------------------------------------------

class Identity:
    def __init__(self, keyfile: str = "node.key"):
        if os.path.exists(keyfile):
            _restrict_private_key_permissions(keyfile)
            with open(keyfile, "rb") as f:
                self._ed_priv = Ed25519PrivateKey.from_private_bytes(f.read())
        else:
            self._ed_priv = Ed25519PrivateKey.generate()
            with open(keyfile, "wb") as f:
                f.write(self._ed_priv.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
            _restrict_private_key_permissions(keyfile)
        ed_pub = self._ed_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.node_id    = hashlib.sha256(ed_pub).hexdigest()
        self.pub_bytes  = ed_pub
        self.pub_hex    = ed_pub.hex()

        xfile = keyfile + ".x25519"
        if os.path.exists(xfile):
            _restrict_private_key_permissions(xfile)
            with open(xfile, "rb") as f:
                self._x_priv = X25519PrivateKey.from_private_bytes(f.read())
        else:
            self._x_priv = X25519PrivateKey.generate()
            with open(xfile, "wb") as f:
                f.write(self._x_priv.private_bytes(
                    Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
            _restrict_private_key_permissions(xfile)
        x_pub = self._x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.x25519_pub     = x_pub
        self.x25519_pub_hex = x_pub.hex()

    @staticmethod
    def _canonical(node_id: str, nonce: str, ts: float,
                   msg_type: str, channel_id: str, ttl0: int,
                   payload_bytes: bytes) -> bytes:
        """Canonical bytes for message signing.

        End-to-end authenticates routing/policy-critical outer fields:
          - type
          - channel
          - ttl0 (cap)

        `ttl` (remaining hops) is intentionally NOT signed so relays can
        decrement it without re-signing. Receivers enforce `ttl <= ttl0`.
        """
        nid = bytes.fromhex(node_id)
        nonc = bytes.fromhex((nonce or "").ljust(32, "0")[:32])

        mt = (msg_type or "").encode()
        ch = (channel_id or "").encode()
        if len(mt) > 255 or len(ch) > 255:
            raise ValueError("msg_type/channel too long")

        ttl_i = int(ttl0)
        if ttl_i < 0:
            ttl_i = 0
        if ttl_i > 65535:
            ttl_i = 65535

        header = struct.pack(">B32s16sdBH", PROTOCOL_VERSION, nid, nonc, float(ts),
                             len(mt), ttl_i)
        return hashlib.sha256(
            header + mt + struct.pack(">B", len(ch)) + ch + payload_bytes
        ).digest()

    def sign_msg(self, nonce: str, ts: float,
                 msg_type: str, channel_id: str, ttl0: int,
                 payload_bytes: bytes) -> str:
        return self._ed_priv.sign(
            self._canonical(self.node_id, nonce, ts, msg_type, channel_id, ttl0, payload_bytes)
        ).hex()

    @staticmethod
    def verify_msg(pub_hex: str, node_id: str, nonce: str, ts: float,
                   msg_type: str, channel_id: str, ttl0: int,
                   payload_bytes: bytes, sig_hex: str) -> bool:
        try:
            pub_bytes = bytes.fromhex(pub_hex)
        except ValueError:
            return False
        if hashlib.sha256(pub_bytes).hexdigest() != node_id:
            return False
        try:
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(bytes.fromhex(sig_hex),
                       Identity._canonical(node_id, nonce, ts, msg_type, channel_id, ttl0, payload_bytes))
            return True
        except (InvalidSignature, ValueError):
            return False

    def sign(self, data: bytes) -> str:
        return self._ed_priv.sign(data).hex()

    @staticmethod
    def verify_signature(pub_hex: str, data: bytes, sig_hex: str) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            pub.verify(bytes.fromhex(sig_hex), data)
            return True
        except (InvalidSignature, ValueError):
            return False

    def verify(self, pub_hex: str, data: bytes, sig_hex: str) -> bool:
        return self.verify_signature(pub_hex, data, sig_hex)

    def x25519_exchange(self, their_pub_bytes: bytes) -> bytes:
        return self._x_priv.exchange(X25519PublicKey.from_public_bytes(their_pub_bytes))


# ---------------------------------------------------------------------
# ONION ROUTER
# ---------------------------------------------------------------------

class OnionRouter:
    """
    Wire frame (WIRE_FRAME_SIZE = 900 bytes, always identical on every link):
      [2B cell_len] [cell_len B encrypted cell] [padding to 900B]

    Per-depth plaintext sizes (CIRCUIT_HOPS=3):
            exit  depth 0: plain=450 -> cell=510 -> frame=900
            relay depth 1: plain=600 -> cell=660 -> frame=900
            entry depth 2: plain=750 -> cell=810 -> frame=900

    Cell layout:
      32B ephemeral X25519 pubkey | 12B nonce | ciphertext | 16B Poly1305 tag

    Plaintext layout:
      4B body_len | 1B flags (0x00=relay, 0x01=exit, 0x02=drop) | body | padding
    """

    @staticmethod
    def _derive_key(shared: bytes, salt: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=salt, info=ONION_INFO).derive(shared)

    @staticmethod
    def _aad(plain_size: int) -> bytes:
        return ONION_AAD_CONTEXT + struct.pack(">H", plain_size)

    @staticmethod
    def _seal(x25519_pub_bytes: bytes, body: bytes,
              flags: int, plain_size: int) -> bytes:
        ephem_priv = X25519PrivateKey.generate()
        ephem_pub  = ephem_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        shared = ephem_priv.exchange(
            X25519PublicKey.from_public_bytes(x25519_pub_bytes))
        raw   = struct.pack(">IB", len(body), flags) + body
        if len(raw) > plain_size:
            raise ValueError(f"onion body too large: {len(raw)} > {plain_size}")
        plain = raw + os.urandom(plain_size - len(raw))
        nonce = os.urandom(12)
        key   = OnionRouter._derive_key(shared, nonce)
        ct    = ChaCha20Poly1305(key).encrypt(nonce, plain, OnionRouter._aad(plain_size))
        return ephem_pub + nonce + ct

    @staticmethod
    def _unseal(identity: "Identity", cell_bytes: bytes) -> Optional[dict]:
        if len(cell_bytes) < CELL_OVERHEAD + PLAIN_HEADER:
            return None
        ephem_pub = cell_bytes[:32]
        nonce     = cell_bytes[32:44]
        ct        = cell_bytes[44:]
        plain_size = len(ct) - 16
        if plain_size < PLAIN_HEADER:
            return None
        try:
            shared = identity.x25519_exchange(ephem_pub)
            key    = OnionRouter._derive_key(shared, nonce)
            plain  = ChaCha20Poly1305(key).decrypt(
                nonce, ct, OnionRouter._aad(plain_size))
        except InvalidTag:
            return None
        except ValueError as e:
            log.debug("onion unseal key error: %s", e)
            return None
        body_len = struct.unpack(">I", plain[:4])[0]
        flags    = plain[4]
        if 5 + body_len > len(plain):
            return None
        return {"flags": flags, "body": plain[5:5 + body_len]}

    @staticmethod
    def build_circuit(hops: list, payload: bytes) -> bytes:
        """Build complete N-hop circuit. Returns wire frame for hops[0]."""
        if not hops:
            raise ValueError("build_circuit requires at least one hop")

        cell = OnionRouter._seal(
            bytes.fromhex(hops[-1].x25519_pub),
            payload,
            flags=0x01,
            plain_size=_PLAIN_SIZES[0],
        )

        relay_hops = hops[:-1]
        for idx, hop in enumerate(reversed(relay_hops)):
            depth        = len(relay_hops) - idx
            next_hop     = hops[len(relay_hops) - idx]
            routing_json = json.dumps(
                {"nh": next_hop.host, "np": next_hop.port},
                separators=(",", ":")).encode()
            body = struct.pack(">H", len(routing_json)) + routing_json + cell
            cell = OnionRouter._seal(
                bytes.fromhex(hop.x25519_pub),
                body,
                flags=0x00,
                plain_size=_PLAIN_SIZES[min(depth, len(_PLAIN_SIZES) - 1)],
            )

        return make_wire_frame(cell)

    @staticmethod
    def build_drop_cell(x25519_pub_bytes: bytes) -> bytes:
        """1-hop drop cell for cover traffic. Returns wire frame."""
        cell = OnionRouter._seal(
            x25519_pub_bytes, b"", flags=0x02,
            plain_size=_PLAIN_SIZES[0])
        return make_wire_frame(cell)

    @staticmethod
    def peel_frame(identity: "Identity", wire_frame: bytes) -> Optional[dict]:
        cell_bytes = extract_cell_from_frame(wire_frame)
        if cell_bytes is None:
            return None
        result = OnionRouter._unseal(identity, cell_bytes)
        if result is None:
            return None
        flags = result["flags"]
        if flags == 0x02:
            return {"role": "drop"}
        if flags == 0x01:
            return {"role": "exit", "payload": result["body"]}
        body = result["body"]
        if len(body) < 2:
            return None
        rlen = struct.unpack(">H", body[:2])[0]
        if len(body) < 2 + rlen:
            return None
        try:
            routing = json.loads(body[2:2 + rlen])
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        inner_cell = body[2 + rlen:]
        return {
            "role":        "relay",
            "next_host":   routing["nh"],
            "next_port":   routing["np"],
            "inner_frame": make_wire_frame(inner_cell),
        }


# ---------------------------------------------------------------------
# REPLY ROUTER
# ---------------------------------------------------------------------

@dataclass
class ReplyRoute:
    next_host:  str
    next_port:  int
    next_token: str
    expires:    float = field(default_factory=lambda: time.time() + REPLY_ROUTE_TTL)

    @property
    def expired(self) -> bool:
        return time.time() > self.expires


class ReplyRouter:
    """
    In-memory LRU table of pre-registered reply routes.
    RED-10: global LRU cap (MAX_ROUTES).
    BLUE-6: per-destination cap (MAX_TOKENS_PER_DEST).
    """

    MAX_ROUTES = 10_000

    def __init__(self):
        self._routes: collections.OrderedDict[str, ReplyRoute] = \
            collections.OrderedDict()
        self._dest_counts: dict[tuple, int] = {}

    def register(self, token: str, next_host: str,
                 next_port: int, next_token: str):
        dest = (next_host, next_port)
        if self._dest_counts.get(dest, 0) >= MAX_TOKENS_PER_DEST:
            log.warning("reply router: dest cap %s:%d (max=%d) -- token dropped",
                        next_host, next_port, MAX_TOKENS_PER_DEST)
            return
        if len(self._routes) >= self.MAX_ROUTES:
            evicted_tok, evicted_r = self._routes.popitem(last=False)
            self._decrement_dest(evicted_r)
            log.debug("reply router: LRU evict token=%s (cap=%d)",
                      evicted_tok[:8], self.MAX_ROUTES)
        self._routes[token] = ReplyRoute(next_host, next_port, next_token)
        self._routes.move_to_end(token)
        self._dest_counts[dest] = self._dest_counts.get(dest, 0) + 1
        log.debug("reply route registered token=%s -> %s:%d (dest_n=%d)",
                  token[:8], next_host, next_port, self._dest_counts[dest])

    def lookup(self, token: str) -> Optional[ReplyRoute]:
        route = self._routes.get(token)
        if route is None or route.expired:
            if token in self._routes:
                self._decrement_dest(self._routes.pop(token))
            return None
        self._routes.move_to_end(token)
        return route

    def evict_expired(self):
        expired = [t for t, r in self._routes.items() if r.expired]
        for t in expired:
            self._decrement_dest(self._routes.pop(t))
        if expired:
            log.debug("reply router: evicted %d expired routes", len(expired))

    def _decrement_dest(self, route: ReplyRoute):
        dest = (route.next_host, route.next_port)
        n = self._dest_counts.get(dest, 0) - 1
        if n <= 0:
            self._dest_counts.pop(dest, None)
        else:
            self._dest_counts[dest] = n


@dataclass
class FindRoute:
    prev_addr: tuple
    expires:   float = field(default_factory=lambda: time.time() + FIND_ROUTE_TTL)

    @property
    def expired(self) -> bool:
        return time.time() > self.expires


class FindRouteCache:
    MAX_ROUTES = MAX_FIND_ROUTES
    MAX_ROUTES_PER_KEY = MAX_FIND_ROUTES_PER_KEY

    def __init__(self):
        self._routes: collections.OrderedDict[str, list[FindRoute]] = \
            collections.OrderedDict()

    @staticmethod
    def _route_key(channel_id: str, key: str) -> str:
        return f"{channel_id}:{key}"

    def register(self, channel_id: str, key: str, prev_addr: tuple):
        if not (channel_id and key):
            return
        route_key = self._route_key(channel_id, key)
        active_routes = [
            route for route in self._routes.get(route_key, [])
            if not route.expired
        ]
        duplicate = any(route.prev_addr == prev_addr for route in active_routes)
        routes = [
            route for route in active_routes
            if route.prev_addr != prev_addr
        ]
        if duplicate or len(routes) < self.MAX_ROUTES_PER_KEY:
            routes.append(FindRoute(prev_addr))
        self._routes[route_key] = routes
        self._routes.move_to_end(route_key)
        while len(self._routes) > self.MAX_ROUTES:
            self._routes.popitem(last=False)

    def pop(self, channel_id: str, key: str) -> list[tuple]:
        routes = self._routes.pop(self._route_key(channel_id, key), [])
        return [route.prev_addr for route in routes if not route.expired]

    def evict_expired(self):
        expired_keys = []
        for route_key, routes in self._routes.items():
            active = [route for route in routes if not route.expired]
            if active:
                self._routes[route_key] = active
            else:
                expired_keys.append(route_key)
        for route_key in expired_keys:
            self._routes.pop(route_key, None)


# ---------------------------------------------------------------------
# TRUST LEDGER
# ---------------------------------------------------------------------

class TrustLedger:
    def __init__(self, db: aiosqlite.Connection):
        self.db = db

    async def init_tables(self):
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS trust (
                node_id    TEXT PRIMARY KEY,
                uploaded   INTEGER DEFAULT 0,
                downloaded INTEGER DEFAULT 0,
                seen_at    REAL    DEFAULT 0,
                first_seen REAL    DEFAULT 0,
                score_snap REAL    DEFAULT 0,
                snap_at    REAL    DEFAULT 0
            )""")
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS content_quota (
                node_id     TEXT PRIMARY KEY,
                total_bytes INTEGER DEFAULT 0
            )""")
        await self.db.commit()

    async def record_upload(self, node_id: str, nbytes: int):
        await self._upsert(node_id)
        await self.db.execute(
            "UPDATE trust SET uploaded=uploaded+?, seen_at=? WHERE node_id=?",
            (nbytes, time.time(), node_id))
        await self.db.commit()

    async def record_download(self, node_id: str, nbytes: int):
        await self._upsert(node_id)
        await self.db.execute(
            "UPDATE trust SET downloaded=downloaded+?, seen_at=? WHERE node_id=?",
            (nbytes, time.time(), node_id))
        await self.db.commit()

    async def score(self, node_id: str) -> float:
        """
        Effective trust score with inactivity decay (BLUE-5).
        T_eff = T_raw * max(exp(-gamma * idle_hours), TRUST_DECAY_FLOOR)
        """
        async with self.db.execute(
            "SELECT uploaded, downloaded, seen_at FROM trust WHERE node_id=?",
            (node_id,)) as cur:
            row = await cur.fetchone()
        if not row or (row[0] == 0 and row[1] == 0):
            return TRUST_FLOOR
        raw        = min(row[0] / (row[1] + 1), 4.0)
        idle_hours = (time.time() - (row[2] or 0)) / 3600.0
        decay      = max(math.exp(-TRUST_DECAY_RATE * idle_hours), TRUST_DECAY_FLOOR)
        return max(raw * decay, TRUST_FLOOR)

    async def velocity_weight(self, node_id: str) -> float:
        now = time.time()
        async with self.db.execute(
            "SELECT score_snap, snap_at, first_seen FROM trust WHERE node_id=?",
            (node_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            return 1.0
        snap_score, snap_at, first_seen = row
        if now - first_seen < TRUST_VELOCITY_WINDOW:
            return 1.0
        elapsed = max(now - snap_at, 1.0)
        if elapsed > TRUST_VELOCITY_WINDOW:
            await self.db.execute(
                "UPDATE trust SET score_snap=?, snap_at=? WHERE node_id=?",
                (await self.score(node_id), now, node_id))
            await self.db.commit()
            return 1.0
        velocity = (await self.score(node_id) - snap_score) / (elapsed / 3600.0)
        if velocity > TRUST_VELOCITY_MAX:
            log.warning("trust velocity high: %s %.2f/hr", node_id[:12], velocity)
            return TRUST_VELOCITY_DAMP
        return 1.0

    async def add_content_bytes(self, node_id: str, nbytes: int):
        await self.db.execute(
            "INSERT INTO content_quota (node_id, total_bytes) VALUES(?,?) "
            "ON CONFLICT(node_id) DO UPDATE SET total_bytes=total_bytes+?",
            (node_id, nbytes, nbytes))
        await self.db.commit()

    async def _upsert(self, node_id: str):
        now = time.time()
        await self.db.execute(
            "INSERT OR IGNORE INTO trust (node_id, seen_at, first_seen, snap_at) "
            "VALUES(?,?,?,?)", (node_id, now, now, now))


# ---------------------------------------------------------------------
# DISK GUARD
# ---------------------------------------------------------------------

class DiskGuard:
    @staticmethod
    def raw_packet_ok(data: bytes) -> bool:
        return len(data) <= MAX_UDP_PAYLOAD

    @staticmethod
    def item_size_ok(data: bytes) -> bool:
        if len(data) > MAX_CONTENT_SIZE:
            log.warning("content rejected: size=%d", len(data))
            return False
        return True

    @staticmethod
    def disk_has_space(dbfile: str = ".") -> bool:
        try:
            d = shutil.disk_usage(os.path.dirname(os.path.abspath(dbfile)) or ".")
            if d.free < DISK_MIN_FREE_BYTES:
                log.error("disk guard: %d MB free", d.free // (1024 * 1024))
                return False
            return True
        except OSError:
            return True


# ---------------------------------------------------------------------
# CHANNELS
# ---------------------------------------------------------------------

@dataclass
class Channel:
    channel_id:    str
    name:          str
    trust_min:     float = 0.0
    description:   str   = ""
    members:       set   = field(default_factory=set)
    owner_id:      str   = ""
    owner_pub:     str   = ""
    owner_sig:     str   = ""
    member_proofs: dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def all_junk(cls) -> "Channel":
        return cls(ALLJUNK_CHANNEL, "all-junk", 0.0, "Base channel. No filters.")

    def _descriptor_payload(self) -> dict:
        return {
            "channel_id": self.channel_id,
            "name": self.name,
            "trust_min": f"{float(self.trust_min):.6f}",
            "description": self.description,
            "owner_id": self.owner_id,
        }

    def descriptor_bytes(self) -> bytes:
        return CHANNEL_DESCRIPTOR_CONTEXT + b"|" + _canonical_json_bytes(
            self._descriptor_payload())

    def descriptor(self) -> dict:
        if self.channel_id == ALLJUNK_CHANNEL:
            return self._descriptor_payload()
        return {
            **self._descriptor_payload(),
            "owner_pub": self.owner_pub,
            "owner_sig": self.owner_sig,
        }

    @classmethod
    def from_descriptor(cls, descriptor: dict) -> Optional["Channel"]:
        if not isinstance(descriptor, dict):
            return None
        try:
            channel_id  = str(descriptor["channel_id"])
            name        = str(descriptor["name"])
            trust_min   = float(descriptor.get("trust_min", 0.0))
            description = str(descriptor.get("description", ""))
            owner_id    = str(descriptor["owner_id"])
            owner_pub   = str(descriptor["owner_pub"])
            owner_sig   = str(descriptor["owner_sig"])
            owner_bytes = bytes.fromhex(owner_pub)
        except (KeyError, TypeError, ValueError):
            return None
        if hashlib.sha256(owner_bytes).hexdigest() != owner_id:
            return None
        if hashlib.sha256(f"{name}{owner_id}".encode()).hexdigest() != channel_id:
            return None
        ch = cls(channel_id, name, trust_min, description, {owner_id},
                 owner_id, owner_pub, owner_sig)
        if not Identity.verify_signature(owner_pub, ch.descriptor_bytes(), owner_sig):
            return None
        return ch

    def membership_bytes(self, member_id: str) -> bytes:
        payload = {
            "channel_id": self.channel_id,
            "member_id": member_id,
            "owner_id": self.owner_id,
        }
        return CHANNEL_MEMBER_CONTEXT + b"|" + _canonical_json_bytes(payload)

    def issue_membership(self, identity: Identity, member_id: str) -> str:
        if self.channel_id == ALLJUNK_CHANNEL:
            return ""
        if identity.node_id != self.owner_id or identity.pub_hex != self.owner_pub:
            return ""
        return identity.sign(self.membership_bytes(member_id))

    def membership_proof(self, identity: Identity) -> str:
        if self.channel_id == ALLJUNK_CHANNEL:
            return ""
        proof = self.member_proofs.get(identity.node_id, "")
        if proof and self.verify_member(identity.node_id, identity.pub_hex, proof):
            return proof
        if identity.node_id == self.owner_id and identity.pub_hex == self.owner_pub:
            proof = self.issue_membership(identity, identity.node_id)
            if proof:
                self.member_proofs[identity.node_id] = proof
                self.members.add(identity.node_id)
            return proof
        return ""

    def verify_member_id(self, node_id: str, proof: str) -> bool:
        if self.channel_id == ALLJUNK_CHANNEL:
            return True
        if not (self.owner_id and self.owner_pub and node_id and proof):
            return False
        return Identity.verify_signature(
            self.owner_pub, self.membership_bytes(node_id), proof)

    def verify_member(self, node_id: str, pub_hex: str, proof: str) -> bool:
        try:
            pub_bytes = bytes.fromhex(pub_hex)
        except ValueError:
            return False
        if hashlib.sha256(pub_bytes).hexdigest() != (node_id or ""):
            return False
        return self.verify_member_id(node_id, proof)

    def admits(self, node_id: str, trust_score: float) -> bool:
        if self.channel_id == ALLJUNK_CHANNEL:
            return True
        if trust_score < self.trust_min:
            return False
        return (not self.members) or (node_id in self.members)


# ---------------------------------------------------------------------
# PEER
# ---------------------------------------------------------------------

@dataclass
class Peer:
    node_id:    str
    host:       str
    port:       int
    pub_hex:    str
    x25519_pub: str   = ""
    latency:    float = 500.0
    last_seen:  float = field(default_factory=time.time)

    @property
    def addr(self) -> tuple:
        return (self.host, self.port)

    @property
    def subnet(self) -> str:
        parts = self.host.split(".")
        return ".".join(parts[:3]) if len(parts) == 4 else self.host

    @property
    def onion_capable(self) -> bool:
        return bool(self.x25519_pub)


# ---------------------------------------------------------------------
# ROUTING TABLE
# ---------------------------------------------------------------------

class RoutingTable:
    def __init__(
        self,
        trust: TrustLedger,
        self_id: str,
        *,
        avoid_node_prefixes: Optional[list[str]] = None,
        avoid_hostports: Optional[set[tuple[str, int]]] = None,
        avoid_extra_latency_ms: float = 0.0,
        avoid_latency_noise_ms: float = 0.0,
    ):
        self.trust         = trust
        self.self_id       = self_id
        self.peers:        dict[str, Peer] = {}
        self._hot_nids:    list[str]       = []
        self._hot_weights: list[float]     = []
        # BLUE-9: per-peer selection counts (reset each hot-table rebuild)
        self._selection_counts: dict[str, int] = {}

        self._avoid_node_prefixes = [p.lower() for p in (avoid_node_prefixes or []) if p]
        self._avoid_hostports = set(avoid_hostports or set())
        self._avoid_extra_latency_ms = max(0.0, float(avoid_extra_latency_ms or 0.0))
        self._avoid_latency_noise_ms = max(0.0, float(avoid_latency_noise_ms or 0.0))

    def _should_avoid_peer(self, peer: Peer) -> bool:
        if self._avoid_hostports and (peer.host, peer.port) in self._avoid_hostports:
            return True
        if self._avoid_node_prefixes:
            nid = (peer.node_id or "").lower()
            return any(nid.startswith(pfx) for pfx in self._avoid_node_prefixes)
        return False

    def _effective_latency_ms(self, peer: Peer) -> float:
        latency = float(peer.latency)
        if self._should_avoid_peer(peer):
            jitter = random.uniform(0.0, self._avoid_latency_noise_ms) if self._avoid_latency_noise_ms else 0.0
            latency += self._avoid_extra_latency_ms + jitter
        return max(0.0, latency)

    def add_peer(self, peer: Peer):
        self.peers[peer.node_id] = peer

    def remove_peer(self, node_id: str):
        self.peers.pop(node_id, None)

    def update_latency(self, node_id: str, rtt_ms: float):
        if node_id in self.peers:
            p           = self.peers[node_id]
            p.latency   = (1 - LATENCY_DECAY) * p.latency + LATENCY_DECAY * rtt_ms
            p.last_seen = time.time()

    def _xor_band(self, node_id: str) -> int:
        xor = int(self.self_id[:8], 16) ^ int(node_id[:8], 16)
        if xor == 0:
            return HOT_BUCKET_COUNT - 1
        return HOT_BUCKET_COUNT - 1 - min(xor.bit_length() - 1,
                                          HOT_BUCKET_COUNT - 1)

    def _xor_band_to_key(self, node_id: str, key_hex: str) -> int:
        xor = int(node_id[:16], 16) ^ int(key_hex[:16], 16)
        if xor == 0:
            return 0
        return min(xor.bit_length() - 1, SSEP_BAND_COUNT - 1)

    async def rebuild_hot_table(self, channel: Channel):
        """
        Rebuild hot table with equilibrium Gibbs weights + BLUE-9 diversity correction.
        w_eq(v) = exp(-lambda * latency) * T_eff(v) * velocity_weight(v)
        w_final(v) = w_eq(v) * diversity(v)  [BLUE-9]
        """
        candidates = []
        for nid, peer in list(self.peers.items()):
            ts  = await self.trust.score(nid)
            vel = await self.trust.velocity_weight(nid)
            if not channel.admits(nid, ts):
                continue
            latency_ms = self._effective_latency_ms(peer)
            w = math.exp(-MARKOV_LAMBDA * latency_ms) * max(ts, TRUST_FLOOR) * vel
            candidates.append((nid, w, self._xor_band(nid)))

        buckets: dict[int, list] = {b: [] for b in range(HOT_BUCKET_COUNT)}
        for nid, w, band in candidates:
            buckets[band].append((nid, w))
        for b in buckets:
            buckets[b].sort(key=lambda x: -x[1])

        selected: list[tuple[str, float]] = []
        subnet_counts: dict[str, int] = {}
        for band in range(HOT_BUCKET_COUNT):
            taken = 0
            for nid, w in buckets[band]:
                if taken >= HOT_BUCKET_SLOTS:
                    break
                p      = self.peers.get(nid)
                subnet = p.subnet if p else nid
                if subnet_counts.get(subnet, 0) >= SYBIL_PER_SUBNET:
                    continue
                selected.append((nid, w))
                subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
                taken += 1

        # BLUE-9: diversity penalty
        total_sel   = sum(self._selection_counts.values()) or 1
        w_raw_total = sum(w for _, w in selected) or 1.0
        adjusted: list[tuple[str, float]] = []
        for nid, w in selected:
            expected_share = w / w_raw_total
            actual_share   = self._selection_counts.get(nid, 0) / total_sel
            if actual_share > expected_share and expected_share > 0:
                diversity = expected_share / actual_share
                log.debug("diversity penalty %s expected=%.3f actual=%.3f -> x%.2f",
                          nid[:12], expected_share, actual_share, diversity)
            else:
                diversity = 1.0
            adjusted.append((nid, w * diversity))
        self._selection_counts.clear()

        total             = sum(w for _, w in adjusted) or 1.0
        self._hot_nids    = [n for n, _ in adjusted]
        self._hot_weights = [w / total for _, w in adjusted]

    def probabilistic_next_hop(self, _ch: Channel) -> Optional[Peer]:
        if not self._hot_nids:
            return None
        chosen = random.choices(self._hot_nids, weights=self._hot_weights, k=1)[0]
        self._selection_counts[chosen] = self._selection_counts.get(chosen, 0) + 1
        return self.peers.get(chosen)

    def ssep_next_hop(self, key: str, _ch: Channel) -> Optional[Peer]:
        """SSEP-inspired routing bias by XOR band."""
        if not self._hot_nids:
            return None
        key_hex = hashlib.sha256(key.encode()).hexdigest()
        scored: dict[str, float] = {}
        for i, nid in enumerate(self._hot_nids):
            if nid not in self.peers:
                continue
            band  = self._xor_band_to_key(nid, key_hex)
            rho   = max(1.0 - band / SSEP_BAND_COUNT, SSEP_BAND_FLOOR)
            scored[nid] = self._hot_weights[i] * rho
        if not scored:
            return None
        nids    = list(scored.keys())
        weights = list(scored.values())
        chosen  = random.choices(nids, weights=weights, k=1)[0]
        self._selection_counts[chosen] = self._selection_counts.get(chosen, 0) + 1
        return self.peers[chosen]

    def greedy_next_hop(self, dest_id: str, _ch: Channel) -> Optional[Peer]:
        return self.ssep_next_hop(dest_id, _ch)

    def onion_capable_peers(self, n: int = CIRCUIT_HOPS,
                            exclude: Optional[set] = None) -> list:
        exclude = exclude or set()
        capable = [
            (self._hot_nids[i], self._hot_weights[i])
            for i in range(len(self._hot_nids))
            if self._hot_nids[i] not in exclude and
               self.peers.get(self._hot_nids[i], Peer("", "", 0, "")).onion_capable
        ]
        if len(capable) < n:
            return []
        nids    = [c[0] for c in capable]
        weights = [c[1] for c in capable]
        chosen, result, attempts = set(), [], 0
        while len(result) < n and attempts < n * 10:
            attempts += 1
            pick = random.choices(nids, weights=weights, k=1)[0]
            if pick not in chosen:
                chosen.add(pick)
                result.append(self.peers[pick])
                self._selection_counts[pick] = \
                    self._selection_counts.get(pick, 0) + 1
        return result if len(result) == n else []


# ---------------------------------------------------------------------
# MESSAGE FORMAT
# ---------------------------------------------------------------------

def make_message(identity: Identity, msg_type: str, payload: dict,
                 channel_id: str = ALLJUNK_CHANNEL,
                 ttl: int = MAX_HOPS) -> bytes:
    nonce = os.urandom(8).hex()
    ts    = time.time()
    pb    = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ttl0  = int(ttl)
    sig   = identity.sign_msg(nonce, ts, msg_type, channel_id, ttl0, pb)
    return json.dumps({
        "v": PROTOCOL_VERSION, "type": msg_type, "channel": channel_id,
        "from": identity.node_id, "pub": identity.pub_hex,
        "ts": ts, "nonce": nonce, "ttl": ttl, "ttl0": ttl0,
        "payload": payload, "sig": sig,
    }, separators=(",", ":")).encode()


def parse_message(data: bytes, replay_cache: ReplayCache) -> Optional[dict]:
    try:
        msg = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not all(k in msg for k in
               ("v", "type", "channel", "from", "pub", "ts",
                "nonce", "ttl", "ttl0", "payload", "sig")):
        return None

    if msg.get("v") != PROTOCOL_VERSION:
        return None

    try:
        ttl = int(msg.get("ttl", 0))
        ttl0 = int(msg.get("ttl0", 0))
        ts = float(msg.get("ts", 0.0))
    except (TypeError, ValueError):
        return None
    if ttl < 0 or ttl0 < 0 or ttl > ttl0:
        return None
    pb = json.dumps(msg["payload"], separators=(",", ":"), sort_keys=True).encode()
    if not Identity.verify_msg(
        msg["pub"], msg["from"], msg["nonce"], ts,
        msg.get("type", ""), msg.get("channel", ""), ttl0,
        pb, msg["sig"],
    ):
        return None
    if not replay_cache.check(msg["from"], msg["nonce"], ts):
        return None
    return msg


# ---------------------------------------------------------------------
# CONTENT STORE
# ---------------------------------------------------------------------

class ContentStore:
    def __init__(self, db: aiosqlite.Connection, dbfile: str = "."):
        self.db     = db
        self.dbfile = dbfile

    async def init_tables(self):
        # v2 schema: composite primary key (key, channel_id)
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS content (
                key TEXT,
                channel_id TEXT,
                data BLOB,
                stored_at REAL,
                size INTEGER,
                from_node TEXT,
                PRIMARY KEY (key, channel_id)
            )""")
        await self.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_content_key ON content(key)"
        )

        # Best-effort migration from older schema where key was PRIMARY KEY.
        try:
            async with self.db.execute("PRAGMA table_info(content)") as cur:
                cols = await cur.fetchall()
            # Old schema had key as pk=1 and no composite pk.
            key_pk = any((r[1] == "key" and int(r[5] or 0) == 1) for r in cols)
            chan_pk = any((r[1] == "channel_id" and int(r[5] or 0) >= 1) for r in cols)
            if key_pk and not chan_pk:
                await self.db.execute("""
                    CREATE TABLE IF NOT EXISTS content_v2 (
                        key TEXT,
                        channel_id TEXT,
                        data BLOB,
                        stored_at REAL,
                        size INTEGER,
                        from_node TEXT,
                        PRIMARY KEY (key, channel_id)
                    )""")
                await self.db.execute(
                    "INSERT OR REPLACE INTO content_v2 SELECT key, channel_id, data, stored_at, size, from_node FROM content"
                )
                await self.db.execute("DROP TABLE content")
                await self.db.execute("ALTER TABLE content_v2 RENAME TO content")
                await self.db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_content_key ON content(key)"
                )
        except Exception as e:
            log.debug("content schema migration skipped: %s", e)

        await self.db.commit()

    async def total_stored(self) -> int:
        async with self.db.execute(
            "SELECT COALESCE(SUM(size), 0) FROM content") as cur:
            return (await cur.fetchone())[0]

    async def put(self, data: bytes, channel_id: str = ALLJUNK_CHANNEL,
                  from_node: str = "") -> Optional[str]:
        if not DiskGuard.item_size_ok(data):
            return None
        if await self.total_stored() + len(data) > DISK_QUOTA_BYTES:
            return None
        if not DiskGuard.disk_has_space(self.dbfile):
            return None
        key = hashlib.sha256(data).hexdigest()
        await self.db.execute(
            "INSERT OR REPLACE INTO content VALUES(?,?,?,?,?,?)",
            (key, channel_id, data, time.time(), len(data), from_node))
        await self.db.commit()
        return key

    async def get(self, key: str, channel_id: str = ALLJUNK_CHANNEL) -> Optional[bytes]:
        async with self.db.execute(
            "SELECT data FROM content WHERE key=? AND channel_id=?",
            (key, channel_id)) as cur:
            row = await cur.fetchone()
        return row[0] if row else None

    async def has(self, key: str, channel_id: str = ALLJUNK_CHANNEL) -> bool:
        async with self.db.execute(
            "SELECT 1 FROM content WHERE key=? AND channel_id=?",
            (key, channel_id)) as cur:
            return (await cur.fetchone()) is not None

    async def has_any_channel(self, key: str) -> bool:
        async with self.db.execute(
            "SELECT 1 FROM content WHERE key=? LIMIT 1", (key,)) as cur:
            return (await cur.fetchone()) is not None

    async def list_channel(self, channel_id: str) -> list:
        async with self.db.execute(
            "SELECT key, size, stored_at FROM content WHERE channel_id=?",
            (channel_id,)) as cur:
            return [{"key": r[0], "size": r[1], "stored_at": r[2]}
                    for r in await cur.fetchall()]


# ---------------------------------------------------------------------
# UDP PROTOCOL
# ---------------------------------------------------------------------

class OvernetProtocol(asyncio.DatagramProtocol):
    def __init__(self, node: "Node"):
        self.node      = node
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        if not DiskGuard.raw_packet_ok(data):
            return
        if not self.node.rate_limiter.allow(addr[0]):
            return
        asyncio.ensure_future(self.node.handle_raw(data, addr))

    def send(self, data: bytes, addr: tuple):
        if self.transport:
            try:
                self.transport.sendto(data, addr)
            except OSError as e:
                log.debug("udp send error %s: %s", addr, e)

    def error_received(self, exc):
        pass


# ---------------------------------------------------------------------
# NODE
# ---------------------------------------------------------------------

class Node:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9000,
        dbfile: str = "overnet.db",
        public_host: str = "127.0.0.1",
        *,
        avoid_node_prefixes: Optional[list[str]] = None,
        avoid_hostports: Optional[set[tuple[str, int]]] = None,
        avoid_extra_latency_ms: float = 0.0,
        avoid_latency_noise_ms: float = 0.0,
    ):
        self.host        = host
        self.port        = port
        self.dbfile      = dbfile
        self.public_host = public_host
        _keydir          = os.path.dirname(os.path.abspath(dbfile))
        self.identity    = Identity(os.path.join(_keydir, "node.key"))
        self.db: Optional[aiosqlite.Connection] = None
        self.trust:    Optional[TrustLedger]  = None
        self.routing:  Optional[RoutingTable] = None
        self.content:  Optional[ContentStore] = None
        self.channels: dict[str, Channel]    = {
            ALLJUNK_CHANNEL: Channel.all_junk()
        }
        self.protocol: Optional[OvernetProtocol] = None
        self.rate_limiter = TokenBucket()
        self.replay_cache = ReplayCache()
        self.reply_router = ReplyRouter()
        self.find_routes  = FindRouteCache()
        self._avoid_node_prefixes = list(avoid_node_prefixes or [])
        self._avoid_hostports = set(avoid_hostports or set())
        self._avoid_extra_latency_ms = float(avoid_extra_latency_ms or 0.0)
        self._avoid_latency_noise_ms = float(avoid_latency_noise_ms or 0.0)
        self._ping_nonces:        dict[str, float]          = {}
        self._registered:         set[str]                  = set()
        self._pending_replies:    dict[str, asyncio.Future] = {}
        self._pending_reply_keys: dict[str, bytes]          = {}
        log.info("node_id=%s port=%d x25519=%s",
                 self.identity.node_id[:16], port,
                 self.identity.x25519_pub_hex[:16])

    async def start(self):
        preloaded_channels = [
            ch for cid, ch in self.channels.items() if cid != ALLJUNK_CHANNEL
        ]
        self.db      = await aiosqlite.connect(self.dbfile)
        self.trust   = TrustLedger(self.db)
        self.content = ContentStore(self.db, self.dbfile)
        await self.trust.init_tables()
        await self.content.init_tables()
        await self._init_channel_tables()
        await self._load_persisted_channels()
        for ch in preloaded_channels:
            self.channels[ch.channel_id] = ch
            await self._persist_channel(ch)
            for node_id, proof in ch.member_proofs.items():
                await self._persist_member_proof(ch.channel_id, node_id, proof)
        self.routing = RoutingTable(
            self.trust,
            self.identity.node_id,
            avoid_node_prefixes=self._avoid_node_prefixes,
            avoid_hostports=self._avoid_hostports,
            avoid_extra_latency_ms=self._avoid_extra_latency_ms,
            avoid_latency_noise_ms=self._avoid_latency_noise_ms,
        )

        loop = asyncio.get_event_loop()
        _, proto = await loop.create_datagram_endpoint(
            lambda: OvernetProtocol(self),
            local_addr=(self.host, self.port))
        self.protocol = proto

        asyncio.ensure_future(self._ping_loop())
        asyncio.ensure_future(self._hot_table_loop())
        asyncio.ensure_future(self._cleanup_loop())
        asyncio.ensure_future(self._cover_loop())
        log.info("listening %s:%d [onion+reply+cover+mixing+SSEP-routing ENABLED]",
                 self.host, self.port)

    async def handle_raw(self, data: bytes, addr: tuple):
        peer = self._lookup_peer(addr)
        if peer and peer.x25519_pub and not self._is_transport_wrapper(data):
            log.debug("transport downgrade rejected from %s:%d", addr[0], addr[1])
            return
        inner = self._unwrap_transport(data)
        if inner is None:
            return
        msg = parse_message(inner, self.replay_cache)
        if msg is None:
            return

        # Trust ledger is keyed by node_id, and should track *neighbor* traffic.
        peer_id = None
        if self.routing:
            for nid, p in self.routing.peers.items():
                if p.host == addr[0] and p.port == addr[1]:
                    peer_id = nid
                    break
        if peer_id and self.trust:
            await self.trust.record_download(peer_id, len(data))
        else:
            await self.trust.record_download(msg["from"], len(data))
        await self.handle_message(msg, addr)

    async def handle_message(self, msg: dict, addr: tuple):
        handlers = {
            "hello":               self._on_hello,
            "hello_ack":           self._on_hello_ack,
            "ping":                self._on_ping,
            "pong":                self._on_pong,
            "peers":               self._on_peers,
            "store":               self._on_store,
            "find":                self._on_find,
            "found":               self._on_found,
            "route":               self._on_route,
            "channel_join":        self._on_channel_join,
            "onion":               self._on_onion,
            "onion_reply_deliver": self._on_onion_reply_deliver,
        }
        h = handlers.get(msg["type"])
        if h:
            await h(msg, addr)

    def _lookup_peer(self, addr: tuple) -> Optional[Peer]:
        if not self.routing:
            return None
        for peer in self.routing.peers.values():
            if peer.host == addr[0] and peer.port == addr[1]:
                return peer
        return None

    def _lookup_peer_id(self, addr: tuple) -> Optional[str]:
        peer = self._lookup_peer(addr)
        return peer.node_id if peer else None

    def _is_transport_wrapper(self, data: bytes) -> bool:
        try:
            wrapper = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return isinstance(wrapper, dict) and wrapper.get("tv") == 1

    def _transport_aad(self, peer_x25519_hex: str) -> bytes:
        return TRANSPORT_AAD_CONTEXT + b"|" + bytes.fromhex(peer_x25519_hex)

    def _seal_transport(self, data: bytes, peer: Optional[Peer]) -> bytes:
        if peer is None or not peer.x25519_pub:
            return data
        nonce = os.urandom(12)
        ephem_priv = X25519PrivateKey.generate()
        ephem_pub = ephem_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        shared = ephem_priv.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(peer.x25519_pub)))
        key = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=nonce, info=TRANSPORT_INFO).derive(shared)
        aad = self._transport_aad(peer.x25519_pub)
        ct = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
        return json.dumps({
            "tv": 1,
            "epk": ephem_pub.hex(),
            "nonce": nonce.hex(),
            "ct": ct.hex(),
        }, separators=(",", ":")).encode()

    def _unwrap_transport(self, data: bytes) -> Optional[bytes]:
        try:
            wrapper = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return data
        if not isinstance(wrapper, dict) or wrapper.get("tv") != 1:
            return data
        if not all(k in wrapper for k in ("tv", "epk", "nonce", "ct")):
            return None
        try:
            epk = bytes.fromhex(wrapper["epk"])
            nonce = bytes.fromhex(wrapper["nonce"])
            ct = bytes.fromhex(wrapper["ct"])
        except (TypeError, ValueError):
            return None
        try:
            shared = self.identity.x25519_exchange(epk)
            key = HKDF(algorithm=hashes.SHA256(), length=32,
                       salt=nonce, info=TRANSPORT_INFO).derive(shared)
            aad = self._transport_aad(self.identity.x25519_pub_hex)
            plain = ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
        except (InvalidTag, ValueError):
            return None
        if not DiskGuard.raw_packet_ok(plain):
            return None
        return plain

    def _send_bytes(self, data: bytes, addr: tuple):
        peer = self._lookup_peer(addr)
        wire = self._seal_transport(data, peer)
        self.protocol.send(wire, addr)
        if peer and self.trust:
            asyncio.ensure_future(self.trust.record_upload(peer.node_id, len(wire)))

    def _send_raw(self, msg: dict, addr: tuple):
        data = json.dumps(msg, separators=(",", ":")).encode()
        self._send_bytes(data, addr)

    async def _init_channel_tables(self):
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                channel_id  TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                trust_min   REAL NOT NULL,
                description TEXT NOT NULL,
                owner_id    TEXT NOT NULL,
                owner_pub   TEXT NOT NULL,
                owner_sig   TEXT NOT NULL
            )""")
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id TEXT NOT NULL,
                node_id    TEXT NOT NULL,
                proof      TEXT NOT NULL,
                PRIMARY KEY (channel_id, node_id)
            )""")
        await self.db.commit()

    async def _load_persisted_channels(self):
        async with self.db.execute(
            "SELECT channel_id, name, trust_min, description, owner_id, owner_pub, owner_sig FROM channels"
        ) as cur:
            rows = await cur.fetchall()
        for row in rows:
            descriptor = {
                "channel_id": row[0],
                "name": row[1],
                "trust_min": row[2],
                "description": row[3],
                "owner_id": row[4],
                "owner_pub": row[5],
                "owner_sig": row[6],
            }
            ch = Channel.from_descriptor(descriptor)
            if ch is None:
                continue
            existing = self.channels.get(ch.channel_id)
            if existing is None or existing.channel_id == ALLJUNK_CHANNEL:
                self.channels[ch.channel_id] = ch
                continue
            if existing.owner_id and existing.owner_id != ch.owner_id:
                continue
            existing.name = ch.name
            existing.trust_min = ch.trust_min
            existing.description = ch.description
            existing.owner_id = ch.owner_id
            existing.owner_pub = ch.owner_pub
            existing.owner_sig = ch.owner_sig
            existing.members.add(ch.owner_id)

        async with self.db.execute(
            "SELECT channel_id, node_id, proof FROM channel_members"
        ) as cur:
            rows = await cur.fetchall()
        for channel_id, node_id, proof in rows:
            ch = self.channels.get(channel_id)
            if ch and ch.verify_member_id(node_id, proof):
                ch.member_proofs[node_id] = proof
                ch.members.add(node_id)

    async def _persist_channel(self, ch: Channel):
        if not self.db or ch.channel_id == ALLJUNK_CHANNEL or not ch.owner_id:
            return
        await self.db.execute(
            "INSERT OR REPLACE INTO channels VALUES(?,?,?,?,?,?,?)",
            (ch.channel_id, ch.name, float(ch.trust_min), ch.description,
             ch.owner_id, ch.owner_pub, ch.owner_sig))
        await self.db.commit()

    async def _persist_member_proof(self, channel_id: str, node_id: str, proof: str):
        if not self.db or channel_id == ALLJUNK_CHANNEL or not (node_id and proof):
            return
        await self.db.execute(
            "INSERT OR REPLACE INTO channel_members VALUES(?,?,?)",
            (channel_id, node_id, proof))
        await self.db.commit()

    def _queue_channel_persist(self, ch: Optional[Channel]):
        if not self.db or ch is None:
            return
        asyncio.ensure_future(self._persist_channel(ch))

    def _queue_member_persist(self, ch: Optional[Channel], node_id: str, proof: str):
        if not self.db or ch is None:
            return
        asyncio.ensure_future(self._persist_member_proof(ch.channel_id, node_id, proof))

    def _merge_channel(self, descriptor: dict) -> Optional[Channel]:
        ch = Channel.from_descriptor(descriptor)
        if ch is None:
            return None
        existing = self.channels.get(ch.channel_id)
        if existing is None:
            self.channels[ch.channel_id] = ch
            self._queue_channel_persist(ch)
            return ch
        if existing.channel_id == ALLJUNK_CHANNEL:
            return existing
        if existing.owner_id and existing.owner_id != ch.owner_id:
            return None
        existing.name = ch.name
        existing.trust_min = ch.trust_min
        existing.description = ch.description
        existing.owner_id = ch.owner_id
        existing.owner_pub = ch.owner_pub
        existing.owner_sig = ch.owner_sig
        existing.members.add(ch.owner_id)
        self._queue_channel_persist(existing)
        return existing

    async def _on_hello(self, msg: dict, addr: tuple):
        real_addr = (addr[0], msg["payload"].get("port", addr[1]))
        self._register_peer(msg, real_addr)
        self._send("hello_ack", {
            "port": self.port, "peers": self._peer_list(),
            "x25519_pub": self.identity.x25519_pub_hex,
        }, real_addr)

    async def _on_hello_ack(self, msg: dict, addr: tuple):
        self._register_peer(
            msg, (addr[0], msg["payload"].get("port", addr[1])),
            x25519_pub=msg["payload"].get("x25519_pub", ""))
        for p in msg["payload"].get("peers", [])[:5]:
            if p["node_id"] != self.identity.node_id:
                asyncio.ensure_future(self.connect_peer(p["host"], p["port"]))

    async def _on_ping(self, msg: dict, addr: tuple):
        if msg["from"] not in self._registered:
            return
        self._send("pong", {"nonce": msg["payload"]["nonce"]}, addr)

    async def _on_pong(self, msg: dict, addr: tuple):
        nonce = msg["payload"].get("nonce", "")
        if nonce in self._ping_nonces:
            rtt = (time.time() - self._ping_nonces.pop(nonce)) * 1000
            self.routing.update_latency(msg["from"], rtt)

    async def _on_peers(self, msg: dict, addr: tuple):
        for p in msg["payload"].get("peers", []):
            if p["node_id"] != self.identity.node_id:
                asyncio.ensure_future(self.connect_peer(p["host"], p["port"]))

    async def _on_store(self, msg: dict, addr: tuple):
        if msg["from"] not in self._registered:
            return
        ch = self.channels.get(msg["channel"])
        if not ch:
            return
        ts = await self.trust.score(msg["from"])
        if not ch.admits(msg["from"], ts):
            return
        try:
            data = bytes.fromhex(msg["payload"]["data"])
        except (ValueError, KeyError):
            return
        key = await self.content.put(data, msg["channel"], msg["from"])
        if key:
            await self.trust.add_content_bytes(msg["from"], len(data))
            log.info("stored key=%s size=%d", key[:12], len(data))

    async def _on_find(self, msg: dict, addr: tuple):
        if msg["from"] not in self._registered:
            return
        key = msg["payload"].get("key", "")
        ch = self.channels.get(msg["channel"])
        if ch:
            ts = await self.trust.score(msg["from"])
            if not ch.admits(msg["from"], ts):
                return
            if await self.content.has(key, msg["channel"]):
                data = await self.content.get(key, msg["channel"])
                if data is None:
                    return
                self._send("found", {"key": key, "data": data.hex()},
                           addr, msg["channel"])
            elif msg["ttl"] > 0 and key:
                self.find_routes.register(msg["channel"], key, addr)
                await self._forward(msg)
            return
        if msg["ttl"] > 0 and key:
            self.find_routes.register(msg["channel"], key, addr)
            await self._forward(msg)

    async def _on_found(self, msg: dict, addr: tuple):
        if msg["from"] not in self._registered:
            return
        key = msg["payload"].get("key", "")
        try:
            data = bytes.fromhex(msg["payload"].get("data", ""))
        except ValueError:
            return
        if not DiskGuard.item_size_ok(data):
            return
        if hashlib.sha256(data).hexdigest() != key:
            log.warning("found key=%s HASH MISMATCH", key[:12])
            return
        prev_addrs = self.find_routes.pop(msg["channel"], key)
        if prev_addrs:
            for prev_addr in prev_addrs:
                self._send_raw(msg, prev_addr)
            return

        ch = self.channels.get(msg["channel"])
        if not ch:
            return
        ts = await self.trust.score(msg["from"])
        if not ch.admits(msg["from"], ts):
            return
        if await self.content.put(data, msg["channel"], msg["from"]):
            log.info("found key=%s OK", key[:12])

    async def _on_route(self, msg: dict, addr: tuple):
        if msg["ttl"] > 0:
            await self._forward(msg)

    async def _on_channel_join(self, msg: dict, addr: tuple):
        payload = msg.get("payload", {})
        ch = None
        descriptor = payload.get("channel")
        if isinstance(descriptor, dict):
            ch = self._merge_channel(descriptor)
            if ch and ch.channel_id != msg["channel"]:
                return
        if ch is None:
            ch = self.channels.get(payload.get("channel_id", "") or msg["channel"])
        if not ch or ch.channel_id == ALLJUNK_CHANNEL:
            return

        proof = payload.get("proof", "")
        member_id = payload.get("member_id", msg["from"])
        ok = False
        if member_id == msg["from"]:
            ok = ch.verify_member(msg["from"], msg["pub"], proof)
            if ok:
                ch.members.add(member_id)
                ch.member_proofs[member_id] = proof
                self._queue_member_persist(ch, member_id, proof)
        elif msg["from"] == ch.owner_id and msg["pub"] == ch.owner_pub:
            ok = ch.verify_member_id(member_id, proof)
            if ok:
                ch.members.add(member_id)
                ch.member_proofs[member_id] = proof
                self._queue_member_persist(ch, member_id, proof)

        log.info("channel %s: %s %s", ch.name, member_id[:8],
                 "admitted" if ok else "rejected")

    async def _on_onion(self, msg: dict, addr: tuple):
        try:
            wire_frame = bytes.fromhex(msg["payload"].get("cell", ""))
        except ValueError:
            return
        if len(wire_frame) != WIRE_FRAME_SIZE:
            return

        result = OnionRouter.peel_frame(self.identity, wire_frame)
        if result is None:
            return

        role = result["role"]

        if role == "drop":
            log.debug("onion: drop cell -- discarded")
            return

        if role == "relay":
            async def _delayed_forward(inner_hex: str, host: str,
                                       port: int, ch: str):
                delay = random.expovariate(1.0 / RELAY_DELAY_MEAN)
                await asyncio.sleep(delay)
                self._send("onion", {"cell": inner_hex}, (host, port), ch)
                log.debug("onion relay (delay=%.2fs) -> %s:%d", delay, host, port)

            asyncio.ensure_future(_delayed_forward(
                result["inner_frame"].hex(),
                result["next_host"],
                result["next_port"],
                msg["channel"],
            ))
            return

        if role == "exit":
            await self._execute_onion_payload(result["payload"], msg["channel"])

    async def _execute_onion_payload(self, payload: bytes, channel_id: str):
        try:
            cmd_obj = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        cmd = cmd_obj.get("cmd")

        if cmd == "store":
            try:
                data = bytes.fromhex(cmd_obj["data"])
            except (ValueError, KeyError):
                return
            if not DiskGuard.item_size_ok(data):
                return

            ch_id = cmd_obj.get("channel", channel_id)
            ch = None
            descriptor = cmd_obj.get("channel_desc")
            if isinstance(descriptor, dict):
                ch = self._merge_channel(descriptor)
                if ch and ch.channel_id != ch_id:
                    return
            if ch is None:
                ch = self.channels.get(ch_id)
            if not ch:
                return

            # Enforce channel policy for onion store.
            if ch.channel_id != ALLJUNK_CHANNEL:
                sender_id = cmd_obj.get("from", "")
                sender_pub = cmd_obj.get("pub", "")
                proof = cmd_obj.get("proof", "")
                auth_nonce = cmd_obj.get("auth_nonce", "")
                auth_sig = cmd_obj.get("auth_sig", "")
                if not (sender_id and sender_pub and proof):
                    return
                if not ch.verify_member(sender_id, sender_pub, proof):
                    return
                if not (auth_nonce and auth_sig):
                    return
                data_key = hashlib.sha256(data).hexdigest()
                auth_bytes = f"{ch.channel_id}|store|{data_key}|{auth_nonce}".encode()
                if not self.identity.verify(sender_pub, auth_bytes, auth_sig):
                    return
                ts = await self.trust.score(sender_id)
                if ts < ch.trust_min:
                    return
                ch.members.add(sender_id)
                ch.member_proofs[sender_id] = proof
                self._queue_member_persist(ch, sender_id, proof)
                from_node = sender_id
            else:
                from_node = "onion"

            key = await self.content.put(data, ch.channel_id, from_node)
            if key:
                log.info("onion store key=%s size=%d OK", key[:12], len(data))

        elif cmd == "find":
            key         = cmd_obj.get("key", "")
            reply_token = cmd_obj.get("reply_token", "")
            reply_host  = cmd_obj.get("reply_host", "")
            reply_port  = int(cmd_obj.get("reply_port", 0))
            reply_key_h = cmd_obj.get("reply_key", "")

            if not (reply_token and reply_host and reply_port and reply_key_h):
                log.debug("onion find: missing reply fields")
                return
            ch = None
            descriptor = cmd_obj.get("channel_desc")
            if isinstance(descriptor, dict):
                ch = self._merge_channel(descriptor)
                if ch and ch.channel_id != channel_id:
                    return
            if ch is None:
                ch = self.channels.get(channel_id)
            if not ch:
                return

            # Enforce channel policy for onion find (non-public channels require proof).
            if ch.channel_id != ALLJUNK_CHANNEL:
                sender_id = cmd_obj.get("from", "")
                sender_pub = cmd_obj.get("pub", "")
                proof = cmd_obj.get("proof", "")
                auth_nonce = cmd_obj.get("auth_nonce", "")
                auth_sig = cmd_obj.get("auth_sig", "")
                if not (sender_id and sender_pub and proof):
                    return
                if not ch.verify_member(sender_id, sender_pub, proof):
                    return
                if not (auth_nonce and auth_sig):
                    return
                auth_bytes = f"{ch.channel_id}|find|{key}|{auth_nonce}".encode()
                if not self.identity.verify(sender_pub, auth_bytes, auth_sig):
                    return
                ts = await self.trust.score(sender_id)
                if ts < ch.trust_min:
                    return
                ch.members.add(sender_id)
                ch.member_proofs[sender_id] = proof
                self._queue_member_persist(ch, sender_id, proof)

            if not await self.content.has(key, ch.channel_id):
                log.info("onion find key=%s -- not found locally", key[:12])
                return

            data = await self.content.get(key, ch.channel_id)
            if data is None:
                return
            if len(data) > REPLY_CONTENT_MAX:
                log.warning("onion find key=%s -- content too large (%d > %d)",
                            key[:12], len(data), REPLY_CONTENT_MAX)
                return

            try:
                reply_key  = bytes.fromhex(reply_key_h)
                nonce      = os.urandom(12)
                aad = REPLY_AAD_CONTEXT + b"|" + reply_token.encode()
                ciphertext = ChaCha20Poly1305(reply_key).encrypt(nonce, data, aad)
            except (InvalidTag, ValueError) as e:
                log.error("onion find reply encrypt: %s", e)
                return

            # BLUE-7: exit jitter -- Exp(mean=0.5s) before reply emission
            _reply_payload = {
                "token": reply_token,
                "nonce": nonce.hex(),
                "ct":    ciphertext.hex(),
            }
            _reply_addr = (reply_host, reply_port)
            _key_log    = key[:12]

            async def _jittered_reply():
                delay = random.expovariate(1.0 / RELAY_DELAY_MEAN)
                await asyncio.sleep(delay)
                self._send("onion_reply_deliver", _reply_payload, _reply_addr)
                log.info("onion find key=%s -- reply -> %s:%d (delay=%.2fs)",
                         _key_log, _reply_addr[0], _reply_addr[1], delay)

            asyncio.ensure_future(_jittered_reply())

        elif cmd == "reply_register":
            token      = cmd_obj.get("token", "")
            next_host  = cmd_obj.get("next_host", "")
            next_port  = int(cmd_obj.get("next_port", 0))
            next_token = cmd_obj.get("next_token", "")
            if token and next_host and next_port and next_token:
                self.reply_router.register(token, next_host, next_port, next_token)

        elif cmd == "drop":
            pass

    async def _on_onion_reply_deliver(self, msg: dict, addr: tuple):
        token   = msg["payload"].get("token", "")
        nonce_h = msg["payload"].get("nonce", "")
        ct_h    = msg["payload"].get("ct", "")

        if token in self._pending_replies:
            fut = self._pending_replies.pop(token)
            key = self._pending_reply_keys.pop(token, None)
            if key and not fut.done():
                try:
                    aad = REPLY_AAD_CONTEXT + b"|" + token.encode()
                    content = ChaCha20Poly1305(key).decrypt(
                        bytes.fromhex(nonce_h), bytes.fromhex(ct_h), aad)
                    fut.set_result(content)
                    log.info("onion reply delivered OK token=%s size=%d",
                             token[:8], len(content))
                except (InvalidTag, ValueError) as e:
                    log.warning("onion reply decrypt failed token=%s: %s",
                                token[:8], e)
                    fut.set_exception(e)
            return

        route = self.reply_router.lookup(token)
        if route:
            self._send("onion_reply_deliver", {
                "token": route.next_token,
                "nonce": nonce_h,
                "ct":    ct_h,
            }, (route.next_host, route.next_port))
            log.debug("reply relay token=%s -> %s:%d",
                      token[:8], route.next_host, route.next_port)

    async def _forward(self, msg: dict):
        msg = dict(msg)
        msg["ttl"] = max(0, int(msg.get("ttl", 0)) - 1)
        ch = self.channels.get(msg.get("channel", ""), Channel.all_junk())
        nh = self.routing.probabilistic_next_hop(ch)
        if nh:
            self._send_raw(msg, nh.addr)

    async def find_content(self, key: str,
                           channel_id: str = ALLJUNK_CHANNEL) -> Optional[bytes]:
        if await self.content.has(key, channel_id):
            return await self.content.get(key, channel_id)
        ch = self.channels.get(channel_id, Channel.all_junk())
        nh = self.routing.ssep_next_hop(key, ch)
        if nh:
            self._send("find", {"key": key}, nh.addr, channel_id)
        return None

    async def publish(self, data: bytes,
                      channel_id: str = ALLJUNK_CHANNEL) -> Optional[str]:
        key = await self.content.put(data, channel_id, self.identity.node_id)
        if not key:
            return None
        ch = self.channels.get(channel_id, Channel.all_junk())
        nh = self.routing.probabilistic_next_hop(ch)
        if nh:
            self._send("store", {"data": data.hex()}, nh.addr, channel_id)
        log.info("published key=%s", key[:12])
        return key

    async def publish_onion(self, data: bytes,
                            channel_id: str = ALLJUNK_CHANNEL) -> Optional[str]:
        hops = self.routing.onion_capable_peers(CIRCUIT_HOPS)
        if len(hops) < CIRCUIT_HOPS:
            log.error("onion publish aborted: only %d onion peers", len(hops))
            return None

        payload_obj = {
            "cmd": "store",
            "data": data.hex(),
            "channel": channel_id,
        }
        # For non-public channels, include membership proof so exits can enforce policy.
        if channel_id != ALLJUNK_CHANNEL:
            if channel_id not in self.channels:
                log.error("onion publish: unknown channel")
                return None
            auth_nonce = os.urandom(8).hex()
            data_key = hashlib.sha256(data).hexdigest()
            auth_bytes = f"{channel_id}|store|{data_key}|{auth_nonce}".encode()
            proof = self.channels.get(channel_id, Channel.all_junk()).membership_proof(self.identity)
            if not proof:
                log.error("onion publish: missing local membership proof")
                return None
            payload_obj.update({
                "from": self.identity.node_id,
                "pub": self.identity.pub_hex,
                "proof": proof,
                "channel_desc": self.channels[channel_id].descriptor(),
                "auth_nonce": auth_nonce,
                "auth_sig": self.identity.sign(auth_bytes),
            })
        payload = json.dumps(payload_obj, separators=(",", ":")).encode()
        if len(payload) > EXIT_PLAIN - PLAIN_HEADER:
            log.error("onion publish: payload too large")
            return None

        try:
            wire_frame = OnionRouter.build_circuit(hops, payload)
        except ValueError as e:
            log.error("build_circuit: %s", e)
            return None

        self._send("onion", {"cell": wire_frame.hex()}, hops[0].addr, channel_id)
        key = await self.content.put(data, channel_id, self.identity.node_id)
        log.info("onion publish key=%s circuit=[%s]",
                 key[:12] if key else "?",
                 "->".join(h.node_id[:6] for h in hops))
        return key

    async def find_onion(self, key: str,
                         channel_id: str = ALLJUNK_CHANNEL,
                         timeout: float = 15.0) -> Optional[bytes]:
        """
        Anonymous content retrieval.
        Forward:  self -> fh1 -> fh2 -> fh3 (exit)
        Reply:    exit -> rh1 -> rh2 -> rh3 -> self
        """
        if await self.content.has(key, channel_id):
            return await self.content.get(key, channel_id)

        all_hops = self.routing.onion_capable_peers(CIRCUIT_HOPS * 2)
        if len(all_hops) < CIRCUIT_HOPS * 2:
            log.error("find_onion aborted: %d peers (need %d)",
                      len(all_hops), CIRCUIT_HOPS * 2)
            return None

        fwd_hops   = all_hops[:CIRCUIT_HOPS]
        reply_hops = all_hops[CIRCUIT_HOPS:]

        reply_key    = os.urandom(32)
        tokens       = [os.urandom(16).hex() for _ in range(CIRCUIT_HOPS + 1)]
        token_origin = tokens[-1]

        for i in range(CIRCUIT_HOPS):
            hop = reply_hops[i]
            if i + 1 < CIRCUIT_HOPS:
                next_host = reply_hops[i + 1].host
                next_port = reply_hops[i + 1].port
            else:
                next_host = self.public_host
                next_port = self.port

            reg_payload = json.dumps({
                "cmd":        "reply_register",
                "token":      tokens[i],
                "next_host":  next_host,
                "next_port":  next_port,
                "next_token": tokens[i + 1],
            }, separators=(",", ":")).encode()

            frame = OnionRouter.build_circuit([hop], reg_payload)
            self._send("onion", {"cell": frame.hex()}, hop.addr, channel_id)

        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self._pending_replies[token_origin]    = fut
        self._pending_reply_keys[token_origin] = reply_key

        await asyncio.sleep(0.3)

        find_obj = {
            "cmd":         "find",
            "key":         key,
            "reply_token": tokens[0],
            "reply_host":  reply_hops[0].host,
            "reply_port":  reply_hops[0].port,
            "reply_key":   reply_key.hex(),
        }
        if channel_id != ALLJUNK_CHANNEL:
            if channel_id not in self.channels:
                log.error("find_onion: unknown channel")
                return None
            auth_nonce = os.urandom(8).hex()
            auth_bytes = f"{channel_id}|find|{key}|{auth_nonce}".encode()
            proof = self.channels.get(channel_id, Channel.all_junk()).membership_proof(self.identity)
            if not proof:
                log.error("find_onion: missing local membership proof")
                return None
            find_obj.update({
                "from": self.identity.node_id,
                "pub": self.identity.pub_hex,
                "proof": proof,
                "channel_desc": self.channels[channel_id].descriptor(),
                "auth_nonce": auth_nonce,
                "auth_sig": self.identity.sign(auth_bytes),
            })
        find_payload = json.dumps(find_obj, separators=(",", ":")).encode()

        if len(find_payload) > EXIT_PLAIN - PLAIN_HEADER:
            log.error("find_onion: payload too large (%d)", len(find_payload))
            self._pending_replies.pop(token_origin, None)
            self._pending_reply_keys.pop(token_origin, None)
            return None

        try:
            fwd_frame = OnionRouter.build_circuit(fwd_hops, find_payload)
        except ValueError as e:
            log.error("find_onion build_circuit: %s", e)
            self._pending_replies.pop(token_origin, None)
            self._pending_reply_keys.pop(token_origin, None)
            return None

        self._send("onion", {"cell": fwd_frame.hex()}, fwd_hops[0].addr, channel_id)
        log.info("onion find key=%s fwd=[%s] reply=[%s]",
                 key[:12],
                 "->".join(h.node_id[:6] for h in fwd_hops),
                 "->".join(h.node_id[:6] for h in reply_hops))

        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            log.warning("onion find key=%s timed out (%.1fs)", key[:12], timeout)
        except (InvalidTag, ValueError) as e:
            log.error("onion find key=%s crypto error: %s", key[:12], e)
        finally:
            self._pending_replies.pop(token_origin, None)
            self._pending_reply_keys.pop(token_origin, None)
        return None

    def create_channel(self, name: str, trust_min: float = 0.5,
                       description: str = "") -> Channel:
        cid = hashlib.sha256(
            f"{name}{self.identity.node_id}".encode()).hexdigest()
        ch = Channel(cid, name, trust_min, description, {self.identity.node_id},
                     self.identity.node_id, self.identity.pub_hex)
        ch.owner_sig = self.identity.sign(ch.descriptor_bytes())
        owner_proof = ch.issue_membership(self.identity, self.identity.node_id)
        if owner_proof:
            ch.member_proofs[self.identity.node_id] = owner_proof
        self.channels[cid] = ch
        self._queue_channel_persist(ch)
        self._queue_member_persist(ch, self.identity.node_id, owner_proof)
        log.info("channel '%s' created trust_min=%.1f", name, trust_min)
        return ch

    def join_channel(self, channel: Channel, peer_addr: tuple):
        if channel.channel_id == ALLJUNK_CHANNEL:
            return
        member_id = self.identity.node_id
        proof = channel.membership_proof(self.identity)
        if self.identity.node_id == channel.owner_id:
            peer_id = self._lookup_peer_id(peer_addr)
            if peer_id and peer_id != self.identity.node_id:
                member_id = peer_id
                proof = channel.issue_membership(self.identity, peer_id)
                if proof:
                    channel.member_proofs[peer_id] = proof
                    channel.members.add(peer_id)
                    self._queue_member_persist(channel, peer_id, proof)
        if not proof:
            log.error("channel_join: missing membership proof")
            return
        self._send("channel_join",
                   {"channel": channel.descriptor(),
                    "member_id": member_id,
                    "proof": proof},
                   peer_addr, channel.channel_id)

    async def _ping_loop(self):
        while True:
            await asyncio.sleep(PING_INTERVAL)
            for nid, peer in list(self.routing.peers.items()):
                nonce = os.urandom(8).hex()
                self._ping_nonces[nonce] = time.time()
                self._send("ping", {"nonce": nonce}, peer.addr)

    async def _hot_table_loop(self):
        while True:
            await asyncio.sleep(HOT_TABLE_REFRESH)
            await self.routing.rebuild_hot_table(Channel.all_junk())

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(60)
            cutoff = time.time() - PING_NONCE_TTL
            for n in [n for n, ts in self._ping_nonces.items() if ts < cutoff]:
                del self._ping_nonces[n]
            self.rate_limiter.evict_old()
            self.reply_router.evict_expired()
            self.find_routes.evict_expired()

    async def _cover_loop(self):
        """RED-9: Poisson-rate cover traffic."""
        while True:
            interval = max(COVER_MIN_INTERVAL, random.expovariate(COVER_RATE))
            await asyncio.sleep(interval)
            peers = self.routing.onion_capable_peers(1)
            if not peers:
                continue
            try:
                drop_frame = OnionRouter.build_drop_cell(
                    bytes.fromhex(peers[0].x25519_pub))
                self._send("onion", {"cell": drop_frame.hex()}, peers[0].addr)
                log.debug("cover: drop -> %s:%d", peers[0].host, peers[0].port)
            except (ValueError, OSError) as e:
                log.debug("cover: drop cell error: %s", e)

    async def connect_peer(self, host: str, port: int):
        self._send("hello", {
            "port": self.port,
            "x25519_pub": self.identity.x25519_pub_hex,
        }, (host, port))

    def _send(self, msg_type: str, payload: dict, addr: tuple,
              channel_id: str = ALLJUNK_CHANNEL):
        data = make_message(self.identity, msg_type, payload, channel_id)
        self._send_bytes(data, addr)

    def _register_peer(self, msg: dict, addr: tuple, x25519_pub: str = ""):
        nid = msg["from"]
        if nid == self.identity.node_id:
            return
        if not x25519_pub:
            x25519_pub = msg.get("payload", {}).get("x25519_pub", "")
        self.routing.add_peer(Peer(
            node_id=nid, host=addr[0], port=addr[1],
            pub_hex=msg["pub"], x25519_pub=x25519_pub))
        self._registered.add(nid)
        asyncio.ensure_future(self._log_peer(nid, addr, x25519_pub))

    async def _log_peer(self, nid: str, addr: tuple, x25519_pub: str):
        ts = await self.trust.score(nid)
        log.info("peer +%s @ %s:%s trust=%.2f %s",
                 nid[:16], addr[0], addr[1], ts,
                 "onion+" if x25519_pub else "onion-")

    def _peer_list(self) -> list:
        return [{"node_id": p.node_id, "host": p.host, "port": p.port}
                for p in list(self.routing.peers.values())[:10]]

    async def status(self):
        total_mb = (await self.content.total_stored()) / (1024 * 1024)
        free_mb  = shutil.disk_usage(
            os.path.dirname(os.path.abspath(self.dbfile)) or ".").free / (1024*1024)
        onion_ct = sum(1 for p in self.routing.peers.values() if p.onion_capable)
        pending  = len(self._pending_replies)

        print("\n== Overnet Node v9 ==")
        print(f"  node_id     : {self.identity.node_id[:32]}...")
        print(f"  x25519_pub  : {self.identity.x25519_pub_hex[:32]}...")
        print(f"  address     : {self.host}:{self.port}  "
              f"(public: {self.public_host}:{self.port})")
        print(f"  peers       : {len(self.routing.peers)} "
              f"({onion_ct} onion-capable)")
        print(f"  hot table   : {len(self.routing._hot_nids)} peers")
        print(f"  stored      : {total_mb:.1f} / "
              f"{DISK_QUOTA_BYTES//(1024*1024)} MB")
        print(f"  disk free   : {free_mb:.0f} MB")
        print(f"  wire frame  : {WIRE_FRAME_SIZE}B  "
              f"(exit={_PLAIN_SIZES[0]} relay={_PLAIN_SIZES[1]} "
              f"entry={_PLAIN_SIZES[2]})")
        print(f"  routing     : SSEP-inspired  rho(band)=max(1-band/{SSEP_BAND_COUNT}, floor)"
              f"  floor={SSEP_BAND_FLOOR}")
        print(f"  trust decay : exp(-{TRUST_DECAY_RATE}*idle_h)  "
              f"floor={TRUST_DECAY_FLOOR}  half-life~6.9h  [BLUE-5]")
        top_sel = sorted(self.routing._selection_counts.items(),
                         key=lambda x: -x[1])[:3]
        sel_str = "  ".join(f"{n[:8]}={c}" for n, c in top_sel) if top_sel else "-"
        print(f"  route div.  : {len(self.routing._selection_counts)} peers tracked"
              f"  top3={sel_str}  [BLUE-9]")
        print(f"  cover rate  : {COVER_RATE:.1f} cells/sec (Poisson)")
        print(f"  relay delay : Exp(mean={RELAY_DELAY_MEAN}s) relay+exit  [RED-11/BLUE-7]")
        print(f"  reply routes: {len(self.reply_router._routes)} / "
              f"{ReplyRouter.MAX_ROUTES} (LRU)  "
              f"dest cap={MAX_TOKENS_PER_DEST}  [RED-10/BLUE-6]")
        print(f"  reply depth : {CIRCUIT_HOPS} hops = forward depth  [RED-12]")
        print(f"  pending find: {pending} awaiting reply")
        for ch in self.channels.values():
            items = await self.content.list_channel(ch.channel_id)
            print(f"  [{ch.name}] {len(items)} items  trust_min={ch.trust_min}")
        print("======================\n")


# ---------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(description="Overnet Node v9")
    parser.add_argument("--host",          default="0.0.0.0")
    parser.add_argument("--port",          type=int, default=9000)
    parser.add_argument("--public-host",   default="127.0.0.1",
                        help="Routable IP for reply-circuit return address")
    parser.add_argument("--peer",          type=int, default=None)
    parser.add_argument("--peer-host",     default="127.0.0.1")
    parser.add_argument("--db",            default="overnet.db")
    parser.add_argument("--publish",       default=None)
    parser.add_argument("--publish-onion", default=None)
    parser.add_argument("--channel",       default=None)
    parser.add_argument("--trust-min",     type=float, default=0.5)
    parser.add_argument(
        "--avoid-peer",
        action="append",
        default=[],
        help="Prefer to avoid routing to a peer; node_id prefix (hex) or host:port. Repeatable.",
    )
    parser.add_argument(
        "--avoid-extra-latency-ms",
        type=float,
        default=0.0,
        help="Extra artificial latency (ms) added to avoided peers during Markov weighting.",
    )
    parser.add_argument(
        "--avoid-latency-noise-ms",
        type=float,
        default=0.0,
        help="Uniform random jitter (0..N ms) added to avoided peers during Markov weighting.",
    )
    parser.add_argument("--no-cli",        action="store_true",
                        help="Run without interactive prompt (recommended for Docker).")
    args = parser.parse_args()

    avoid_prefixes, avoid_hostports = _parse_avoid_peers(args.avoid_peer)

    node = Node(
        host=args.host,
        port=args.port,
        dbfile=args.db,
        public_host=args.public_host,
        avoid_node_prefixes=avoid_prefixes,
        avoid_hostports=avoid_hostports,
        avoid_extra_latency_ms=args.avoid_extra_latency_ms,
        avoid_latency_noise_ms=args.avoid_latency_noise_ms,
    )
    await node.start()

    if args.peer:
        await node.connect_peer(args.peer_host, args.peer)
        await asyncio.sleep(1.5)

    if args.channel:
        node.create_channel(args.channel, trust_min=args.trust_min)

    if args.publish:
        key = await node.publish(args.publish.encode())
        if key:
            print(f"published (plaintext): {key}")

    if args.publish_onion:
        key = await node.publish_onion(args.publish_onion.encode())
        if key:
            print(f"published (onion): {key}")

    await node.status()

    # Non-interactive mode: keep the node alive for Docker/compose.
    if args.no_cli or not sys.stdin.isatty():
        stop_evt = asyncio.Event()

        def _stop(*_a):
            stop_evt.set()

        try:
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, _stop)
                except NotImplementedError:
                    pass
        except RuntimeError:
            pass

        await stop_evt.wait()
        return

    print("Commands: status | publish <text> | onion <text> | "
          "find <key> | fetch <key> | quit")
    print("  find  = plaintext find  |  fetch = anonymous find + reply circuit")
    loop = asyncio.get_event_loop()
    while True:
        try:
            cmd = await loop.run_in_executor(None, input, "> ")
            parts = cmd.strip().split(None, 1)
            if not parts:
                continue
            if parts[0] == "status":
                await node.status()
            elif parts[0] == "publish" and len(parts) > 1:
                key = await node.publish(parts[1].encode())
                if key:
                    print(f"key: {key}")
            elif parts[0] == "onion" and len(parts) > 1:
                key = await node.publish_onion(parts[1].encode())
                print(f"key (onion): {key}" if key else "onion publish failed")
            elif parts[0] == "find" and len(parts) > 1:
                result = await node.find_content(parts[1])
                if result:
                    print(f"content: {result.decode(errors='replace')}")
                else:
                    print("not found locally - query forwarded")
            elif parts[0] == "fetch" and len(parts) > 1:
                print("building reply circuit...")
                result = await node.find_onion(parts[1])
                if result:
                    print(f"content (reply circuit): "
                          f"{result.decode(errors='replace')}")
                else:
                    print("onion find timed out or failed")
            elif parts[0] == "quit":
                break
        except (EOFError, KeyboardInterrupt):
            break


if __name__ == "__main__":
    asyncio.run(main())

