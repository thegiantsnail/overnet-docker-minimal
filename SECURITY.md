# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v10 / `main` (latest) | ✅ Yes |
| Older commits | ❌ No — update to `main` |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
Doing so publicly discloses details before a fix is available.

### Preferred method — GitHub private vulnerability reporting

1. Go to **Settings → Security → Report a vulnerability** on this repository, or
   use the [GitHub Security Advisory](https://github.com/thegiantsnail/overnet-docker-minimal/security/advisories/new) form directly.
2. Fill in the affected version, a description of the vulnerability, and
   reproduction steps.

### Alternative — direct contact

Email the repository owner. The address is available in the commit history or
via the GitHub profile.

### What to include in your report

- Affected commit SHA or version
- Step-by-step reproduction instructions
- Impact assessment (what an attacker could achieve)
- Any suggested remediation or patch

### Response timeline

| Stage | Target |
|---|---|
| Acknowledgement | Within **7 days** of receipt |
| Initial assessment | Within **14 days** |
| Patch / coordinated disclosure | Depends on severity; communicated in the advisory |

After a report is received we will: acknowledge it, assess severity, develop a
patch (crediting the reporter if they wish), and coordinate a disclosure date
with the reporter before any public announcement.

## Scope

### In scope

- `overnet.py` — the node implementation (routing, crypto, rate limiting, trust)
- `Dockerfile` and `docker-compose.yml` — container configuration
- The cryptographic layer (key generation, onion encryption, replay protection)

### Out of scope

- Third-party dependencies (`cryptography`, `aiosqlite`) — please report those
  to the upstream projects
- Issues that require physical access to the host machine
- Denial-of-service findings against the local testnet that are already
  documented and mitigated (token bucket, replay cache, disk guard)

## Cryptographic Primitives

All cryptography is provided by the Python [`cryptography`](https://cryptography.io) library. No
custom or home-grown cryptographic primitives are used.

| Primitive | Usage |
|---|---|
| Ed25519 | Node identity signing / verification |
| X25519 | Ephemeral key exchange for onion layers |
| ChaCha20-Poly1305 | Symmetric AEAD encryption of all wire frames |
| HKDF-SHA256 | Key derivation from shared secrets |
