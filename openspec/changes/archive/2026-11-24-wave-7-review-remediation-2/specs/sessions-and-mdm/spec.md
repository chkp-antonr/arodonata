# Spec Delta

## ADDED Requirements

### Requirement: Hostname-Bound TLS Fingerprint Enforcement Across Canonical IP Pinning

**ID**: REQ-SESS-012\
**Intent**: Prevent TOFU first-contact bypass or cross-host pin substitution when an explicit hostname is resolved and connected via its pinned canonical IP literal.\
**Non-goals**: Unresolvable hostname rejection (`REQ-SESS-010`) or DNS-rebinding subset validation (`REQ-SESS-008`).

When an explicit `server_ip` hostname is resolved and pinned to a canonical trusted IP literal before connecting, TLS certificate fingerprint verification (`TrustPolicy` in `"pinned"`, `"tofu"`, and `"lab-memory"` modes) SHALL also enforce any certificate fingerprint pinned or previously persisted under that hostname (`<hostname>:<port>`), rejecting mismatched peer certificates with `CertificateMismatchError` before transmitting any HTTP request or `X-chkp-sid`.

#### Scenario: SCN-SESS-012-1 — Hostname-pinned and TOFU-learned TLS fingerprints remain enforced when connecting to a resolved canonical IP

- **GIVEN** a management endpoint with a certificate fingerprint pinned in `ARODONATA_TLS_FINGERPRINTS` or previously persisted in `tls_known_hosts.json` under `mgmt.example.com:443` while `mgmt.example.com` resolves to trusted IP `10.0.0.50`
- **WHEN** `AMgmtClient` executes an API call, read-only login, keepalive, or logout with `server_ip="mgmt.example.com"` and `10.0.0.50:443` presents either the expected fingerprint or a different certificate (including another server's pinned fingerprint or an unknown MITM certificate in `"tofu"` mode)
- **THEN** the connection SHALL dial `10.0.0.50:443` directly without connect-time DNS re-resolution and succeed when `10.0.0.50:443` presents `mgmt.example.com:443`'s fingerprint
- **AND** any certificate mismatch against `mgmt.example.com:443`'s pinned or TOFU-stored fingerprint SHALL raise `CertificateMismatchError` before sending HTTP headers or `X-chkp-sid`
