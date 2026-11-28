# Offline Replay & Mock Testing Guide

Always validate Check Point automation scripts offline against `arodonata.testing` before touching a live Management Server or MDSM lab.

## 1. Zero-Socket Unit Testing (`FileReplayApiMock` & `FileReplayCliMock`)

Inject `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) directly into `ArodonataClient`:

```python
from arodonata import ArodonataClient, ArodonataSettings
from arodonata.testing import FileReplayApiMock, FileReplayCliMock

cli_mock = FileReplayCliMock()
api_mock = FileReplayApiMock(cli_mock=cli_mock)
settings = ArodonataSettings(
    mgmt_name="mds-replay",
    mgmt_ip="127.0.0.1",
    api_key="offline-replay-placeholder",
)

async with ArodonataClient(settings=settings, api=api_mock, gateway_cli=cli_mock) as client:
    domains = await client.get_domains("mds-replay")
    gateways = await client.get_gateways("mds-replay", domains[0].name)
```

Key properties of the built-in enterprise dataset (`ensure_enterprise_raw_dataset()`):

- **10 MDSM domains**: 9 user domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`.
- **Gateways & VSX assets**: Simple gateways, ClusterXL clusters and members, VSX chassis, and cross-domain Virtual Systems, with `vsx stat -l`, `ip -4 route show`, and `clish` CLI fixtures.
- **Stateful session overlays**: Supports `read-only` sessions, per-object locks, `publish`/`discard`, `where-used` referential integrity, and `Global` read-only protection (`generic_err_object_read_only`).

## 2. Fast Test Isolation & Call-Log Assertions

Use `FileReplayApiMock` snapshots and assertion helpers to verify scripts behave safely:

- **Snapshot / Restore**:
  - `snap = api_mock.snapshot_state()` before a mutating test case and `api_mock.restore_state(snap)` afterwards (or `api_mock.reset()`).
- **Safety Assertions**:
  - `api_mock.assert_no_global_mutations()` — proves the script never attempted writes against the `Global` domain.
  - `api_mock.assert_no_full_object_scans()` — proves CPCRUD/lookup code used targeted queries rather than downloading entire tables.
  - `api_mock.assert_command_called("show-gateways-and-servers", domain="Branch")` / `api_mock.assert_command_not_called("publish")`.
  - `api_mock.get_calls(domain="Branch", mutating_only=True)` — inspects redacted call records (`sid_ref`, `command`, `payload_summary`, `success`, `error_code`).
- **Dynamic Fixture Overrides**:
  - `api_mock.update_gateway_cli_stdout(node_name, stdout, vsid=0)` to simulate custom `cpinfo -y all`, `cplp list`, or `autoupdatercli show` outputs.
  - `FileReplayCliMock(fail_ssh_nodes={"br-hq-node-1b"})` to test partial SSH failure handling.

## 3. Testing `ScriptRepositoryService` RBAC Modes

Test on-box repository script workflows under strict RBAC policies by configuring `FileReplayApiMock`:

```python
api_mock = FileReplayApiMock(
    allow_one_time_script=False,
    allow_repository_script=True,
    manage_repository_scripts="read",
)
```

- Use `"write"` to test `ensure_repository_script()` + `run_repository_script()`, `"read"` to verify pre-staged script execution without write permissions, and `"none"` to test RBAC failure reporting.

## 4. Localhost HTTPS Integration (`CheckPointReplayHttpServer`)

When testing full TLS/TOFU, HTTP transport, or external CLI subprocesses (including `uv run my_script.py`), launch `CheckPointReplayHttpServer`:

```bash
uv run python -m arodonata.testing.mock_server --host 127.0.0.1 --port 8443
```

Or embed `CheckPointReplayHttpServer(host="127.0.0.1", port=0)` in an async pytest fixture, pass `mgmt_ip="127.0.0.1"`, `mgmt_port=server.port`, `tls_trust="pinned"`, and `tls_fingerprints=server.fingerprint` to `ArodonataSettings`, and call `server.snapshot_state()` / `server.restore_state()` between cases.
