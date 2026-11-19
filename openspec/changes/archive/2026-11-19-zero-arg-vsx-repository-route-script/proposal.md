# Proposal

## Why

Live testing on Check Point R82 MDSM using a least-privilege Read-Only service API key (`Run Repository Script = ON`, `Manage Repository Scripts = Read`, `Run One Time Script = OFF`) uncovered two blocking behaviors:

1. Check Point R82 `show-repository-script` returns the Base64-encoded script payload inside `"script-body"` instead of `"script-body-base64"`, causing `RepositoryScript.from_cp_dict()` to compare raw Base64 against plaintext bash and falsely flag freshly published scripts as outdated (`matches_expected=False`).
2. Check Point R81.20/R82 rejects `run-script` (`script-type="repository"`) whenever `"args"` is non-empty unless `Run One Time Script` is also enabled (`HTTP 400 err_validation_failed`: `"Insufficient permissions to run this script with arguments."`), whereas the identical call with `"args"` omitted succeeds (`HTTP 200`).

Enabling `Run One Time Script` on background Read-Only service accounts violates customer security least-privilege policies, because it permits arbitrary shell command execution on gateways. Making the canonical `"arodonata-collect-routes-v1"` repository script self-detecting without arguments eliminates both blockers and dramatically reduces Check Point `run-script` invocations on VSX hosts.

## What Changes

- **Decode R82 Base64 `"script-body"` responses**: Update `RepositoryScript.from_cp_dict()` so Base64-encoded `"script-body"` strings returned by Check Point R82 `show-repository-script` are transparently decoded to UTF-8 while preserving plaintext `"script-body"` and `"script-body-base64"` compatibility (`REQ-CLIENT-010`).
- **Self-detecting zero-argument canonical route script**: Upgrade `"arodonata-collect-routes-v1"` (`build_route_collection_repository_script()`) so zero-argument execution (`$# -eq 0`) applies a built-in `50000` route limit, auto-detects VSX chassis via `vsx stat -l </dev/null`, and emits a compact marker bundle (`===ARODONATA_VSX_BUNDLE_START===` / `===ARODONATA_VS_START vsid=<id> name=<name>===` ... `===ARODONATA_VS_END===` / `===ARODONATA_VSX_BUNDLE_END===`) covering all L3 Virtual Systems/Virtual Routers (`VSID > 0`, skipping L2 Virtual Switches) in a single execution, while keeping non-VSX gateways on standard `IP_ROUTE`/`CLISH_ROUTE` markers and preserving parameterized execution (`$1=max_routes $2=vsid [$3=vs_name]`) when arguments are explicitly passed (`REQ-TOPO-008`).
- **Zero-argument default execution and per-node VSX coalescing**: Switch default repository-mode route collection (`repository_script_args_fn=None`) to omit `"args"` from `run-script` payloads across standalone, cluster, and VSX targets; parse VSX bundle slices by `vsid` / `vs_name` fallback; and coalesce sibling Virtual Systems sharing `(mgmt_name, domain_name, node_key)` onto a single `run-script` invocation per `collect_gateway_routes()` run (`REQ-TOPO-008`).
- **Offline replay mock parity**: Update `FileReplayApiMock` to enforce Check Point R81.20/R82 `"args"` permission semantics (rejecting non-empty `"args"` when `allow_repository_script=True` and `allow_one_time_script=False`), synthesize zero-arg VSX bundles for VSX replay fixtures, and optionally return Base64-encoded `"script-body"` from `show-repository-script` (`REQ-TOPO-018`).

## Capabilities

### New Capabilities

No new capabilities introduced.

### Modified Capabilities

- `client-and-facade`: Update `REQ-CLIENT-010` to handle Base64-encoded `"script-body"` values returned by Check Point R82 `show-repository-script` without false outdated drift.
- `gateway-topology`: Update `REQ-TOPO-008` for default zero-argument `"repository"` execution, self-detecting VSX multi-VS marker bundles, per-physical-node coalescing, and per-VS error isolation; update `REQ-TOPO-018` so `FileReplayApiMock` emulates R82 `"args"` permission rejection, zero-arg VSX bundles, and Base64 `"script-body"` responses.

## Impact

- Affected source modules: `src/arodonata/core/models/scripts.py`, `src/arodonata/core/services/topology/route_scripts.py`, `src/arodonata/core/services/topology/route_parsers.py`, `src/arodonata/core/services/topology/route_executor.py`, `src/arodonata/core/services/topology/route_collection.py`, `src/arodonata/core/services/topology/__init__.py`, `src/arodonata/core/services/route_collector.py`, and `src/arodonata/testing/replay_mock.py`.
- Affected tests: `tests/unit/test_script_repository.py`, `tests/unit/test_topology_service.py`, `tests/unit/test_topology_compat_and_security.py`, `tests/unit/test_replay_mock_repository_scripts.py`, `tests/spec/test_spec_client_and_config.py`, and `tests/spec/test_spec_mcp_and_topology.py`.
- Downstream compatibility (including FPCR v2): Zero breaking API changes. Existing domains with the legacy parameterized `arodonata-collect-routes-v1` script are cleanly flagged as outdated once so an administrator can update the repository script via `ensure_route_collection_script`; thereafter, both R82 check comparisons and zero-arg route collection succeed under minimal `Run Repository Script` permissions without `Run One Time Script`.
