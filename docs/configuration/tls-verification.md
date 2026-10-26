# TLS Certificate Verification (`TrustPolicy` & `TrustStore`)

Check Point Management and MDSM servers frequently use self-signed or internal CA certificates, and MDSM standby/member CMA IPs often present a certificate issued to the primary MDS hostname. Standard hostname-based TLS verification breaks on CMA IP routing, while disabling TLS verification (`verify_ssl=False`) exposes automation to man-in-the-middle attacks.

Arodonata v2 solves this with **post-handshake, pre-request SHA-256 DER certificate fingerprint verification** (`src/arodonata/adapters/checkpoint/tls.py`).

## How Verification Works

1. Before sending any HTTP request headers or Check Point credentials (`api-key` / `password` / `X-chkp-sid`) over an `aiohttp` connection, `ApiTransport` inspects the peer's raw DER certificate from `transport.get_extra_info("ssl_object").getpeercert(binary_form=True)`.
2. It computes the uppercase SHA-256 hex digest and validates it against `TrustPolicy` **before a single byte of HTTP payload leaves the socket**.
3. If the certificate does not match, the connection is aborted immediately with `CertificateMismatchError` or `UnknownServerCertificateError`.

## Trust Modes (`ARODONATA_TLS_TRUST`)

| Mode | Behavior | Recommended Use |
| --- | --- | --- |
| `"pinned"` | Strictly requires the server's SHA-256 fingerprint to exist in `ARODONATA_TLS_FINGERPRINTS` or `tls_known_hosts.json`. Rejects unknown certificates with `UnknownServerCertificateError`. | **Production** |
| `"tofu"` (default) | **Trust On First Use**: pins the certificate fingerprint to `~/.config/arodonata/tls_known_hosts.json` (with `0600` permissions and `fcntl.flock` cross-process locking) on first contact, and raises `CertificateMismatchError` if it ever changes. | **Staging / CLI / Standard Deployments** |
| `"lab-memory"` | Stores TOFU pins in memory for the lifetime of the process without writing to disk. Refuses to activate unless `ARODONATA_LAB` is set or explicitly configured for tests. | **CI / Ephemeral Lab Tests** |

## Cross-IP MDSM Member Recognition

On Multi-Domain servers, `show-domains` discovers domain CMA IPs and active MDS member IPs (`active_mds_ip`) that share the same physical server certificate as the primary `mgmt_ip`.

When `TrustPolicy` connects to an MDSM member IP whose certificate SHA-256 fingerprint matches an already-trusted entry in the same management cluster, it automatically recognizes and records that `(host, port)` endpoint without failing.

## Configuring Pinned Fingerprints

You can supply pinned fingerprints via environment variable:

```ini
ARODONATA_TLS_TRUST=pinned
# Host-scoped or global comma-separated SHA-256 fingerprints:
ARODONATA_TLS_FINGERPRINTS="10.10.1.10:443=SHA256:A1B2C3...,10.20.1.10:443=SHA256:D4E5F6..."
```
