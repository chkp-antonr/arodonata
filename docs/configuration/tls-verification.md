# TLS Verification

Arodonata verifies the identity of every Check Point management server it talks to, and bounds every network operation with a timeout.
This page covers what is verified, the three trust modes, the trust store, how to get and pin a fingerprint, certificate rotation, lab setup, timeouts and the limits of the model.

## What is verified, and why a fingerprint

On-premises management servers (SmartCenter and MDS) serve the Management API from Gaia's web server with `/web/conf/server.crt`.
That certificate is self-signed and unique per Gaia install, it is not issued by the ICA, and it has no usable hostname (the common name is the management IP at generation time and there is no subject alternative name).
There is no certificate authority to check it against and a hostname check would prove nothing, so Arodonata pins the certificate itself: the SHA-256 fingerprint of the server certificate presented at `host:port` must be the one that was trusted for that address.
Expiry is not checked either, because Check Point does not renew this certificate automatically and a pin keeps working after it expires.

The check runs in the connection, after the TLS handshake and before the first application byte, so a refused server never receives a login, an API key or a command.
The message of every refusal says "No request was sent."
Arodonata does not use cpapi's own fingerprint handling (`fingerprints.txt` in the working directory and an interactive prompt); it never reads or writes that file.

## Trust modes

`ARODONATA_TLS_TRUST` selects how a certificate that is not yet trusted for an address is treated.

| Mode | Behaviour |
|---|---|
| `tofu` (default) | Trust on first use. The first certificate seen at `host:port` is trusted and recorded in the [trust store](#the-trust-store); afterwards a different certificate is refused. Needs no configuration. |
| `pinned` | Nothing is learned and nothing is written. Only certificates recorded in the store or listed in `ARODONATA_TLS_FINGERPRINTS` are accepted; any other certificate is refused. |
| `lab-memory` | Like `tofu`, but the certificate is remembered in memory for the lifetime of the process only and nothing is written. Honoured only when `ARODONATA_LAB` is set; otherwise client construction fails with a configuration error. See [Lab setup](#lab-setup). |

In every mode a certificate whose fingerprint is already trusted for another address (in the store, or in `ARODONATA_TLS_FINGERPRINTS`) is accepted for a new address as well, and in `tofu` it is recorded for that address.
This is what lets every domain IP of a Multi-Domain server, which is served by a member's certificate, work after the member itself is trusted.

## The trust store

The store is a JSON file.
The default location is `${XDG_STATE_HOME:-~/.local/state}/arodonata/tls_known_hosts.json`; set `ARODONATA_TLS_KNOWN_HOSTS_PATH` to use another file (needed for a read-only home directory, a container or any host where the default directory is not writable).
A relative value is resolved against the current directory.

```json
{
  "version": 1,
  "hosts": {
    "192.0.2.10:443": {
      "sha256": "<64 lowercase hex digits>",
      "pem": "<the certificate in PEM form>",
      "first_seen": "2026-10-04T10:45:08+00:00",
      "source": "tofu"
    }
  }
}
```

- The key is `host:port` exactly as dialled, with the port always explicit (443 by default). IP addresses are normalised, IPv6 addresses are bracketed and host names are lowercased.
- `source` is `tofu` (learned on first use), `known-identity` (accepted for a new address because the same certificate was already trusted elsewhere) or `manual` (written by hand). A hand-written entry may omit `pem`; the certificate is then fetched from the server and must match `sha256`.
- The file is created with mode 0600 inside a directory created with mode 0700. Writes are atomic and serialised across processes with a lock file next to it (`<name>.lock`).
- A file owned by another user, or writable by everyone, is refused. A group-writable file works but logs a warning. A file that is not valid JSON or has a malformed entry is refused with an error naming the file and is never rewritten.
- In `tofu`, a store whose directory cannot be created or written is an error at the moment Arodonata would learn a certificate, before anything is sent. It never falls back to memory silently.

## Getting a fingerprint

Take the fingerprint from the management server, not from the machine that connects to it.
On the server, in expert mode or clish:

```bash
api fingerprint -f json
```

The value to use is the `fingerprint-sha256` key of the output.
The same value comes from:

```bash
cpopenssl x509 -in /web/conf/server.crt -noout -fingerprint -sha256
```

Two commands that look similar print something else and are rejected with a hint if pasted: `cp_conf finger` (and SmartConsole) show the ICA's fingerprint as words, and `fwm fingerprint` prints an MD5 of the ICA key.
Neither is the API certificate.
SHA-1 values (40 hex digits) are rejected as well; only SHA-256 is accepted.

## Pinning with ARODONATA_TLS_FINGERPRINTS

`ARODONATA_TLS_FINGERPRINTS` is a comma-separated list of SHA-256 fingerprints that are trusted at any address.
Each value may be in any case, with colons or spaces or neither, and with an optional `sha256:` or `SHA256 Fingerprint=` prefix, so the output of `openssl` can be pasted unchanged.

```bash
ARODONATA_TLS_TRUST=pinned
ARODONATA_TLS_FINGERPRINTS=AB:CD:...:EF,12:34:...:90
```

Fingerprints are public data, not secrets, so they may live in an ordinary env file.
An invalid value is a configuration error at startup, not a surprise at the first connection.

## Certificate rotation

The server certificate changes when an administrator regenerates or replaces it, when the management IP changes, and, on Endpoint management servers that serve the ICA-issued `sic_cert.pem` on port 443, when SIC renews it.
Arodonata then refuses the connection (see [What a mismatch looks like](#what-a-mismatch-looks-like)); an unexpected change is exactly what the check exists to catch, so confirm it on the management server first.

If the change is legitimate, either replace the `sha256` value of that host in the store file (keep the entry, do not delete it: a deleted entry would let `tofu` trust whatever answers next) or add the new fingerprint to `ARODONATA_TLS_FINGERPRINTS`, which takes precedence over the store.
After a store edit a running process needs no restart: the store is re-read on every check, so the next connection attempt to that host is refused once with "changed during the connection", and the one after it uses the new value. `ARODONATA_TLS_FINGERPRINTS` is read from the environment when the process starts, so a running process (for example `arodonata-mcp`) needs a restart after that value changes.

## What a mismatch looks like

The message names the address, both fingerprints in colon form and the way to check on the server, and says that no request was sent:

```text
TLS certificate of 192.0.2.10:443 does not match the trusted one. No request was sent.
  expected SHA-256:  AB:CD:...:EF (from /home/user/.local/state/arodonata/tls_known_hosts.json)
  presented SHA-256: 12:34:...:90
  presented SHA-1:   ...
Check on the management server: 'api fingerprint -f json', or 'cpopenssl x509 -in /web/conf/server.crt -noout -fingerprint -sha256'.
If the change is legitimate, replace the sha256 value of 192.0.2.10:443 in /home/user/.local/state/arodonata/tls_known_hosts.json (do not delete the entry), or add the new value to ARODONATA_TLS_FINGERPRINTS.
```

In `pinned` mode an unknown certificate is reported as "is not trusted" with the presented fingerprint.
These failures are never retried; the login, the keepalive and task polling all stop at once.

Logging: a first trust is a WARNING, a certificate accepted because it is already trusted elsewhere is INFO, and every refusal is logged once per address and presented fingerprint per process at ERROR with the full message.

Through the [MCP server](../mcp/index.md) the model receives the address, the presented and expected fingerprints, "No request was sent.", that the check is `api fingerprint -f json` on the management server, and that re-trusting is the operator's job on the MCP host, never a ready-to-run command.
The full detail is in the MCP server's log.
No MCP tool can change trust.

## Lab setup

For a lab, pin the servers instead of learning them: harvest each member's fingerprint once and put it in the lab's env file.

```bash
# .env.lab.<profile>
ARODONATA_TLS_TRUST=pinned
ARODONATA_TLS_FINGERPRINTS=<one SHA-256 per member, comma-separated>
```

Nothing is then written and nothing is learned.
`lab-memory` exists for a lab whose fingerprints have not been harvested yet: it reads the store if there is one, never creates a directory, file or lock file, and trusts each process's first contact.
It logs a WARNING when it starts and for each host it learns, and it refuses a certificate change within the process.
It works only when `ARODONATA_LAB` is set, so it cannot be switched on by accident in production.

## Timeouts

Before this feature the underlying cpapi had no socket timeout at all, so an unresponsive server could block a call forever.
Two timeouts now apply to every connection:

- `ARODONATA_CONNECT_TIMEOUT` (default 30 seconds) bounds the TCP connect and the TLS handshake. DNS resolution is not covered, because Arodonata dials IP addresses.
- The read timeout bounds each wait for the server's answer. A call with a budget of its own (an `api_call` with a timeout, and logins) gets that budget plus 5 seconds. Every other call, including `show-task` polls, gets `max(ARODONATA_API_TIMEOUT, ARODONATA_LOGIN_TIMEOUT) + 5` seconds, which is 125 seconds with the defaults.

`asyncio.wait_for` stays the overall deadline of a call.
Long operations such as publish and install-policy return a task ID at once and are then polled, so they are not affected by the read timeout.

A timeout raises `ApiTimeoutError` (a `TimeoutError`) whose `phase` is `connect` or `read`.
A request that has been sent is never sent a second time after a read timeout; the message says the command may still have run on the server, so check the server before repeating a change.
For logins a timeout counts as "slow", not "unreachable", and one slow `show-task` poll no longer ends a publish or install wait.

## Security model and residuals

- **First contact in `tofu`.** The first certificate seen at an address is trusted without any outside confirmation. Anyone who can intercept that very first connection can be recorded as the server. Use `pinned` with fingerprints taken from the server where that matters.
- **New addresses.** A new address with an unknown certificate is learned in `tofu`, so a changed IP in `MGMT_SERVERS` is trusted on first contact like a new server.
- **`lab-memory`.** Each process trusts its first contact and forgets it on exit. Use it only for labs, and prefer pins.
- **Endpoint management.** Servers that present `sic_cert.pem` change certificate when SIC renews; expect a refusal and re-trust as described under [rotation](#certificate-rotation).
- **The store is a trust root.** Whoever can write the store file can change who is trusted. Keep it owned by the service user with mode 0600.
- **Not covered.** The check authenticates the server, not the network path; DNS is not involved because IP addresses are dialled. The MCP server's own inbound TLS (`--ssl-certfile`) is a separate matter, see [MCP Server](../mcp/index.md#tls).

## Settings

| Variable | Default | Description |
|---|---|---|
| `ARODONATA_TLS_TRUST` | `tofu` | `tofu`, `pinned` or `lab-memory`. |
| `ARODONATA_TLS_FINGERPRINTS` | empty | Comma-separated SHA-256 fingerprints trusted at any address. |
| `ARODONATA_TLS_KNOWN_HOSTS_PATH` | empty (default location) | The trust store file. |
| `ARODONATA_CONNECT_TIMEOUT` | `30` | Seconds for TCP connect plus TLS handshake. |
