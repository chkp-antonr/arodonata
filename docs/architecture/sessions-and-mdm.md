# Sessions & Multi-Domain

## Session lifecycle

- **[`login_coordinator.py`](../api/arodonata/asdk/login_coordinator.md)** —
  handles initial login, and re-login/backoff if a session expires mid-use.
- **[`session_cleaner.py`](../api/arodonata/asdk/session_cleaner.md)** —
  background cleanup of stale sessions, so long-running processes don't leak
  SIDs on the management server.
- **[`rate_limiter.py`](../api/arodonata/asdk/rate_limiter.md)** — per-server
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
