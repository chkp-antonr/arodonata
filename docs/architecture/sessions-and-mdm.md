# Sessions & Multi-Domain

## Session lifecycle

- **[`login_coordinator.py`](../api/arodonata/asdk/login_coordinator.md)** —
  handles initial login, and re-login/backoff if a session expires mid-use.
- **[`session_cleaner.py`](../api/arodonata/asdk/session_cleaner.md)** —
  background cleanup of stale sessions, so long-running processes don't leak
  SIDs on the management server. At startup the cleanup logs in to each server's system domain and keeps that session in the SID cache for the first real call, unless a SID is already cached or a login for it is in flight (then it logs the session out, as the cleanup after a max-sessions refusal always does).
- **[`rate_limiter.py`](../api/arodonata/asdk/rate_limiter.md)** — per-MDS-member
  concurrency gating (`ArodonataSettings.concurrent_limit`), so a burst of
  cache-refresh work doesn't overload a single management server.

Session and login retry behavior is configured through
`ArodonataSettings.session_expire_seconds`, `session_timeout`,
`login_retry_backoff`, and `login_max_retries` — see the
[Configuration Guide](../configuration/index.md).

## Multi-domain (MDM) resolution

Check Point Multi-Domain Management servers expose multiple domains behind
one management IP. Arodonata resolves and propagates domain context through
[`domain_service.py`](../api/arodonata/api/services/domain_service.md), so
every cache row and every helper-method result carries its owning
`mgmt_name`/`domain_name` pair — letting callers filter
(`client.get_hosts(domain_names=["Domain1"])`) without re-deriving domain
membership themselves.

## Server identity per member

Each Gaia install, that is each MDS member (primary or secondary) and each SmartCenter, has its own self-signed API certificate, so the trusted identity is recorded per `host:port` and a standby member is a separate identity from the active one.
A domain server IP hosted on a member most likely presents that member's certificate.
When a new address presents a certificate that is already trusted for another address (in the trust store or in `ARODONATA_TLS_FINGERPRINTS`), it is accepted and, in `tofu` mode, recorded as `known-identity`; an unknown certificate at a new address is learned in `tofu` and refused in `pinned`.
Identity failures are never retried by the login, keepalive or task-wait paths.
See [TLS Verification](../configuration/tls-verification.md).
