# Design

## Context

See `proposal.md` for live-lab failure evidence on Check Point R82 (`192.168.5.170`) and behavioral constraints under least-privilege `Run Repository Script = ON`, `Manage Repository Scripts = Read`, `Run One Time Script = OFF`. Currently:

- `RepositoryScript.from_cp_dict()` (`src/arodonata/core/models/scripts.py`) decodes Base64 only when the Management API sets `"script-body-base64"`, whereas Check Point R82 returns a single-line Base64 string directly inside `"script-body"`.
- `_run_repository_cprid()` (`src/arodonata/core/services/topology/route_executor.py`) always passes `format_route_collection_repository_args(target, max_routes=max_routes)` (emitting e.g. `"50000 0"` or `"50000 3"`) in `run-script["args"]`, causing Check Point R81.20/R82 to reject every gateway under a repository-only permission profile.
- Existing `build_route_collection_repository_script()` (`src/arodonata/core/services/topology/route_scripts.py`) relies on `$1`, `$2`, and `$3` for VSX switching and route truncation, and executes once per Virtual System target.

Architectural constraints preserved: Hexagonal boundaries (`core` touches only `ApiPort`, `CachePort`, and pure models), full backward compatibility of shim imports (`arodonata.core.services.route_collector` and `arodonata.core.services.topology_service`), strict SID/secret redaction, and spec traceability (`REQ-*`/`SCN-*`).

## Goals / Non-Goals

**Goals:**

- Enable both `check_route_collection_script()` and `collect_gateway_routes(cprid_script_mode="repository")` (across standalone gateways, clusters, and multi-VS VSX hosts) to operate with zero `"args"` and without `Run One Time Script`.
- Eliminate redundant per-VS `run-script` calls on VSX chassis/members by collecting all L3 Virtual Systems in one zero-argument execution and coalescing sibling VS targets per physical node.
- Preserve 100% compatibility when callers supply an explicit `repository_script_args_fn` or pass legacy positional arguments to `arodonata-collect-routes-v1`.
- Bring `FileReplayApiMock` into strict parity with real Check Point R82 behavior.

**Non-Goals:**

- Modifying `"inline"` mode (`Run One Time Script`), which continues passing parameterized per-VS inline scripts.
- Changing FPCR v2 or changing the default repository script name `"arodonata-collect-routes-v1"`.
- Supporting custom `max_routes > 50000` in zero-argument mode (callers requiring dynamic server-side limits beyond `50000` continue providing `repository_script_args_fn` under a one-time-script-permitted profile).

## Decisions

### Decision 1: Safe Base64 Detection for Check Point R82 `"script-body"` (`src/arodonata/core/models/scripts.py`)

**Choice:** Introduce `_decode_repository_script_body(raw_body: str) -> str` invoked by `RepositoryScript.from_cp_dict()` when `"script-body"` is a string.

**Rationale & Heuristic:** Check Point R82 returns a single contiguous Base64 string inside `"script-body"`, whereas tests, replay mocks, and older Management versions return multi-line bash or plaintext commands. To avoid false-decoding a short single-word command (such as `"ls"` or `"date"` -> 4 chars matching base64 alphabet), `_decode_repository_script_body()` applies strict guards:

1. Reject immediately if `raw_body` contains newlines (`\n`/`\r`) or whitespace (` ` / `\t`), is shorter than 8 characters, or fails Base64 character/length (`% 4 == 0` when padded) checks.
2. Decode with strict `base64.b64decode(cleaned, validate=True)` and UTF-8 strict decoding (`errors="strict"`, no replacement chars).
3. Verify the decoded output contains multiline script structure, shell syntax/whitespace (`\n`, ` `, `=`, `#`, `echo`, etc.), and >= 90% printable/whitespace ASCII/UTF-8 characters; otherwise return `raw_body` unchanged.
4. Reversing Check Point `"script-body-base64"` continues taking explicit precedence or equal fallback handling as before.

**Alternatives considered:** Always decoding `"script-body"` with `validate=True` when `len >= 4` — rejected because 4/8-character plaintext tokens (e.g., `"show"` or `"hostname"`) are valid Base64 of arbitrary bytes.

---

### Decision 2: Self-Detecting Zero-Argument Canonical Script & Text Marker Bundle (`route_scripts.py`)

**Choice:** Update `build_route_collection_repository_script()` to branch cleanly on `[ "$#" -eq 0 ]` vs parameterized `[ "$#" -gt 0 ]`, using compact text markers for multi-VS bundles.

**Wire Format (`$# -eq 0` on VSX):**

```text
===ARODONATA_VSX_BUNDLE_START===
===ARODONATA_VS_START vsid=1 name=VS_Corp===
===ARODONATA_IP_ROUTE_START===
10.10.0.0/24 dev eth1 proto kernel scope link src 10.10.0.1
===ARODONATA_IP_ROUTE_END===
===ARODONATA_VS_END===
===ARODONATA_VS_START vsid=2 name=VS_DMZ===
===ARODONATA_VS_ERROR vsid=2 name=VS_DMZ error=vsenv 2 failed===
===ARODONATA_VS_END===
===ARODONATA_VSX_BUNDLE_END===
```

**Exported Constants (`route_scripts.py`, `topology/__init__.py`, `route_collector.py`):**

- `DEFAULT_REPOSITORY_MAX_ROUTES = 50000`
- `VSX_BUNDLE_START_MARKER = "===ARODONATA_VSX_BUNDLE_START==="`
- `VSX_BUNDLE_END_MARKER = "===ARODONATA_VSX_BUNDLE_END==="`
- `VS_START_PREFIX = "===ARODONATA_VS_START "`
- `VS_END_MARKER = "===ARODONATA_VS_END==="`
- `VS_ERROR_PREFIX = "===ARODONATA_VS_ERROR "`

**Bash Execution Logic (`[ "$#" -eq 0 ]`):**

1. Detect VSX safely (`command -v vsx >/dev/null 2>&1 && command -v vsenv >/dev/null 2>&1`).
2. When VSX tools exist, run `vsx stat -l </dev/null 2>/dev/null` and pipe into a POSIX `awk` parser that accumulates per-block `VSID`, `Name`, and `Type` (flushing on blank lines, new `VSID:` headers, or `END` so field order variations across Gaia R81.20/R82 do not break), emitting `vsid<TAB>name` strictly for records where `vsid + 0 > 0` and `tolower(type)` does not contain `"switch"` (skipping VS0 management context and L2 Virtual Switches that have no IPv4 routing table).
3. If the VS list is non-empty (`VSX` mode):
   - Set built-in cap `max_routes=50000`.
   - Print `===ARODONATA_VSX_BUNDLE_START===`.
   - Loop `while IFS=' ' read -r vid vname; do ... done` (with `</dev/null` inside `vsenv "$vid"`, `ip -4 route show`, and `awk` so loop stdin is never consumed).
   - Print `===ARODONATA_VS_START vsid=${vid} name=${vname}===`.
   - Verify `vsenv "$vid" >/dev/null 2>&1 </dev/null` and `$FWDIR` contains `CTX%05d`; on failure print `===ARODONATA_VS_ERROR vsid=${vid} name=${vname} error=...===` and continue to the next VS instead of aborting the whole chassis with `exit 1`.
   - On context switch success, emit `===ARODONATA_IP_ROUTE_START===`, `ip -4 route show 2>/dev/null </dev/null | awk -v lim=50000 ...` (emitting `===ARODONATA_ROUTE_LIMIT_REACHED===` at `lim + 1`), and `===ARODONATA_IP_ROUTE_END===`, followed by `===ARODONATA_VS_END===`.
   - Note: `clish -c "show route"` is omitted per-VS on VSX (matching existing VSX script behavior in `build_route_collection_script()` where VS contexts rely on kernel/routed routes in `ip -4 route show` without multi-minute `clish` overhead per VS).
   - Finally restore or exit cleanly after printing `===ARODONATA_VSX_BUNDLE_END===`.
4. If VSX tools are absent OR `vsx stat -l` yields no `VSID > 0` records (standalone / non-VSX cluster member): execute the non-VSX flow with `max_routes=50000`, `skip_thr=10000`, emitting standard `===ARODONATA_IP_ROUTE_START===` and optional `===ARODONATA_CLISH_ROUTE_START===`.
5. When `[ "$#" -gt 0 ]`: preserve the existing `$1` (`max_routes`), `$2` (`vsid`), `$3` (`vs_name`) behavior identically for caller overrides and legacy compatibility.

**Alternatives considered:** Constructing JSON via `awk`/`printf` in Gaia `/bin/sh` — rejected due to fragile JSON string escaping on `vs_name`/`error` text, absence of guaranteed `jq`/`python3` on Gaia, and ~40% larger Base64 task payloads vs text markers consistent with existing `===ARODONATA_*===` delimiters.

---

### Decision 3: Default Zero-Argument Repository Execution (`route_executor.py`)

**Choice:** In `_run_repository_cprid()`:

- When `repository_script_args_fn is not None`, continue invoking `repository_script_args_fn(target, max_routes)` and passing the returned string as `args`.
- When `repository_script_args_fn is None`, set `args_val = None` so `ScriptRepositoryService.run_repository_script()` omits `"args"` from the `run-script` JSON payload completely.
- Keep `format_route_collection_repository_args()` exported unchanged as a public utility for callers that explicitly configure `repository_script_args_fn=format_route_collection_repository_args`.

**Rationale:** Directly prevents `"Insufficient permissions to run this script with arguments."` under Check Point R81.20/R82 `Run Repository Script = ON`, `Run One Time Script = OFF`.

---

### Decision 4: Bundle Parsing & Per-Node Coalescing (`route_parsers.py` and `route_collection.py`)

**Bundle Parser (`route_parsers.py`):**

- Add `VsxBundleSlice` dataclass (`vsid: int`, `vs_name: str`, `raw_output: str`, `error: str | None = None`).
- Add `parse_vsx_bundle_output(stdout: str) -> list[VsxBundleSlice]`: parses lines between `===ARODONATA_VSX_BUNDLE_START===` and `===ARODONATA_VSX_BUNDLE_END===`, extracting `vsid`, `name`, any `===ARODONATA_VS_ERROR ... error=...===` line, and inner body up to `===ARODONATA_VS_END===`.
- Add `extract_vs_slice_from_bundle(stdout: str, *, vsid: int | None, vs_name: str | None) -> GatewayCliResult`:
  - Matches first by `vsid` when `vsid is not None and vsid > 0`.
  - Falls back to case-insensitive `vs_name` match when `vsid` is absent/unresolved (`None` or `0`) or not matched directly (handling asset names vs Check Point VS display names safely).
  - If matched with `slice.error`, returns failed `GatewayCliResult(success=False, error_message=slice.error, exit_code=1)`.
  - If `===ARODONATA_VSX_BUNDLE_START===` is present in `stdout` but no matching slice exists, returns failed `GatewayCliResult` explaining the VS was missing from the bundle (never returning routes from another VS or `VS0`).
  - If bundle markers are absent (non-VSX host or custom single-VS script), returns successful `GatewayCliResult(stdout=stdout, ...)`.

**Per-Node Coalescing (`route_collection.py`):**

- Inside `_collect_gateway_routes_impl()`, determine when zero-arg coalescing applies:
  - `eff_cli is None` (or SSH already fell back into repository `cprid`), `eff_script_mode in ("repository", "auto")`, and `repository_script_args_fn is None`.
  - Coalesce per-physical-node execution under an in-memory `repo_node_flights: dict[tuple[str, str], asyncio.Future[GatewayCliResult]]`.
  - Key: `(target.mgmt_name, node_key)` where `node_key = str(target.node_uid or target.node_ipv4 or target.node_name or target.gateway_uid)`. When the first VS on `node_key` executes the zero-argument repository `run-script` (omitting `args`), sibling VS tasks hosted on the same physical chassis node (including across customer domains on MDS) await the single leader flight without issuing duplicate Check Point API calls.
  - Sibling followers await the shared `flight_fut`, then extract their specific Virtual System slice using `extract_vs_slice_from_bundle()`.
  - Cancellation safety: If the leader task is cancelled, the shared flight stores a non-cancellation exception to avoid broadcasting `CancelledError` to followers across independent gateways.
  - Note for `"auto"` mode: resolve domain auto-mode probe first; once domain resolves to `"repository"` (and `repository_script_args_fn is None`), sibling VS targets on the same physical node share the flight; if the domain falls back to `"inline"`, bypass bundle coalescing and execute each VS inline.

---

### Decision 5: `FileReplayApiMock` R82 Parity (`src/arodonata/testing/replay_mock.py`)

**Choice:** Extend `FileReplayApiMock`:

1. Add `encode_repository_script_body_base64: bool = False` constructor option; when `True`, `show-repository-script` encodes `"script-body"` as Base64 UTF-8 matching live R82 appliances.
2. In `_handle_run_script`, when `script_type == "repository"`, `allow_repository_script=True`, `allow_one_time_script=False`, and `str(payload.get("args") or "").strip()` is non-empty, return Check Point's exact error:
   - `status_code=400`, `code="err_validation_failed"`, `message="Insufficient permissions to run this script with arguments."`
3. When `script_type == "repository"` runs with empty/omitted `"args"` on a target node that has VS CLI data in `self._cli_mock` (`cli_outputs` containing `(node_name, vsid)` for `vsid > 0` or `resolve_vsids` via `Asset`s/CLI mock), synthesize the exact `===ARODONATA_VSX_BUNDLE_START===` ... `===ARODONATA_VSX_BUNDLE_END===` output containing every non-switch VS on that physical node; for non-VSX nodes emit standard `ip route` + `clish` output honoring the `10000`-line `clish` skip threshold.

## Risks / Trade-offs

- **Existing deployments holding old `arodonata-collect-routes-v1` script body** → Check Point R82 installations already running the old parameterized script will see `matches_expected=False` (`outdated`) once until an administrator clicks Approve/Update (`ensure_route_collection_script`). This is expected and desirable so existing domains upgrade smoothly to zero-arg VSX execution.
- **Large VSX hosts with many Virtual Systems producing large task stdout** → Mitigated by enforcing the `50000`-route cap per VS, omitting `clish -c "show route"` inside VS contexts, and skipping L2 Virtual Switches.
- **`max_routes_per_gateway != 50000` in default zero-arg mode** → The script enforces `50000` on-box and `parse_combined_cli_routes_with_status(..., max_routes=settings.max_routes_per_gateway)` still enforces smaller `settings.max_routes_per_gateway` client-side; deployments needing server-side `max_routes > 50000` can supply `repository_script_args_fn=format_route_collection_repository_args` alongside `Run One Time Script`.
- **`_decode_repository_script_body` false-positive Base64 decoding** → Mitigated by strict `>= 8` char length, zero whitespace/newline, `validate=True` Base64, strict UTF-8, and script-structure checks, verified on short single-token scripts in unit tests.

## Migration Plan

1. Upgrade `arodonata` containing these changes.
2. In each Check Point domain where `arodonata-collect-routes-v1` was previously provisioned, an administrator approves the one-time update via `ensure_route_collection_script` (for example, when FPCR v2 prompts that `arodonata-collect-routes-v1` is outdated).
3. Future `check_route_collection_script` inspections and `collect_gateway_routes(cprid_script_mode="repository")` runs across standalone gateways, clusters, and VSX hosts will succeed automatically with `Run Repository Script = ON` and `Run One Time Script = OFF`.
