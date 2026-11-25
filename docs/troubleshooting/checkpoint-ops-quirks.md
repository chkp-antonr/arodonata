# Check Point Operational Automation & CLI Quirks

Operational rules and field-proven edge cases for building Check Point automation scripts on top of Arodonata v2, Gaia OS (`clish`, `python3`, `cpinfo`, `cplp`, `autoupdatercli`), Central Deployment Tool (CDT), and `arlogi`.

## 1. Asset, ClusterXL, VSX & Platform Boundaries

- **Native `Asset` Resolution vs. Platform/Role Classification**:
  - Arodonata's `Asset` model natively resolves ClusterXL (`CLUSTER_PARENT_TYPES` / `CLUSTER_MEMBER_TYPES`) and VSX (`VSX_PARENT_TYPES` / `VSX_CHILD_TYPES`) parent-child graphs, populating `parent_uid`, `parent_name`, `parent_id`, `parent_asset_id`, `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`.
  - Deeper vendor/platform role classification (such as Maestro `MHO`/`SMO`/`SGM` roles, `MDS` vs. `MLM` management roles, or hardware family categorization) is **not** built into `Asset`; inspect `Asset.type`, `Asset.hardware`, `Asset.os_name`, and `Asset.raw_data` explicitly rather than assuming built-in role enums.
- **Documented API Types vs. `Cpmi*` Generic Objects**: Standard `show-gateways-and-servers` responses can surface simplified documented types (`simple-gateway`, `simple-cluster`, `cluster-member`), whereas `show-generic-objects` and VSX queries expose internal `Cpmi*` classes (`CpmiGatewayCluster`, `CpmiClusterMember`, `CpmiVsxNetobj`, `CpmiVsxClusterNetobj`, `CpmiVsNetobj`, `CpmiVsSlotObj`). Always handle both sets when inspecting `Asset.type`.
- **Cluster Member Hardware Inheritance**: Cluster member objects returned by Check Point APIs frequently omit `hardware` or appliance model fields on the member itself; inherit missing hardware metadata from the parent cluster (`Asset.parent_uid`) when generating physical inventory reports.
- **Policy Targets vs. Physical Execution Targets**: Policy installation (`install-policy`) targets logical cluster or Virtual System objects, whereas on-box CLI execution (`run-script`), hotfix checks, and upgrades target physical gateways or individual cluster members (`member_uids`). Never pass a logical cluster or VS object directly to per-blade OS commands expecting a physical host response.
- **MDS Active Server vs. Single-Domain SMS**:
  - On MDSM, `DomainInfo.active_ip` resolves from `servers[].active == True` (`parse_domain_entry`); standby MDS/CMA IPs remain in `DomainInfo.standby_ips`.
  - Single-domain SmartCenter (SMS) deployments report domain `""` or `"SMC User"` in `show-domains` / session payloads; pass `domain=None` (or the configured SMS domain label) consistently.
- **Zero-Asset Failed-Scope Guard**: Never treat an empty `get_assets()` result after a failed or partially failed `refresh_assets()` (`RefreshOutcome.failed_domains` non-empty) as "zero gateways exist"—abort or report the failed domain scope before making inventory or cleanup decisions.
- **Maestro & Quantum Spark Platform Nuances**:
  - **Check Point Maestro**: Single Management Objects (`SMO`) and Security Group Members (`SGM`) use `gclish` and `asg_cp2blades` for multi-blade operations; non-interactive scripts invoked over `run-script` or SSH must source `/etc/profile.d/CP.sh` (or `$CPDIR/tmp/.CPprofile.sh`) so Check Point environment variables (`$CPDIR`, `$FWDIR`) are defined.
  - **Quantum Spark / SMB (`Gaia Embedded`)**: Runs BusyBox POSIX `sh` with a restricted CLI and **no `python3`**; any script targeting SMB appliances must avoid bashisms, GNU-only flags, and Python dependencies.

## 2. On-Box Execution (`run-script`, `ScriptRepositoryService`, Gaia `python3`, `clish`)

- **Gaia Stdlib `python3` vs. Gaia Embedded `sh`**:
  - Standard Gaia (`R81.x` / `R82+`) ships a system `python3` interpreter (`~3.9` / `$CPDIR/Python/bin/python3`) containing only Python's standard library (no third-party PyPI packages). Using stdlib `python3` (`json`, `re`, `subprocess`, `xml.etree.ElementTree`) inside `run-script` or CDT helpers avoids brittle `awk`/`sed` quoting bugs when parsing structured outputs.
  - Reserve pure POSIX `sh` for minimal bootstrap wrappers or Quantum Spark (`Gaia Embedded`) targets where `python3` is absent.
- **`ScriptRepositoryService` Mechanics**:
  - Prefer `script-type="repository"` via `ScriptRepositoryService.ensure_repository_script()` and `ScriptRepositoryService.run_repository_script()` (or `ArodonataClient`'s repository script facade methods) over one-time inline scripts in restricted RBAC environments.
  - Execution sessions used by `ScriptRepositoryService` operate cleanly without requiring a destructive `publish` of policy changes; keep repository script registration (`add-repository-script` / `set-repository-script`) separated from read-only target execution when possible.
  - Check Point encodes `run-script` output inside Base64 `responseMessage` fields (and R82+ `show-repository-script` encodes script contents in `script-body`); Arodonata's `decode_base64_task_message()` and `ScriptRepositoryService` handle this decoding automatically.
  - Omit `"args"` completely from `run-script` payloads when arguments are empty—sending `args=""` triggers RBAC permission errors on accounts that lack one-time-script execution privileges.
- **`clish` Automation Rules**:
  - Execute configuration commands line-by-line via `clish -c "<cmd>" < /dev/null` (redirecting stdin from `/dev/null` prevents `clish` from hanging on interactive prompts or consuming heredoc input).
  - Always run `clish -c "lock database override" < /dev/null` before mutating commands: treat `CLICMD0201` (already locked by the current context) as benign, but **abort immediately** on `CLINFR0771` (database locked by another active administrator/session).
  - Issue a single trailing `clish -c "save config" < /dev/null` after all `set`/`add`/`delete` commands succeed rather than saving after every line.
  - Watch for Gaia `R81.x` vs. `R82+` `clish` grammar differences (for example, NTP server syntax errors returning `CLINFR0329` and stricter multi-line MOTD/banner quoting on R82+).
  - **Never** run `clish -c "show route"` on gateways carrying large BGP/OSPF routing tables (`>10,000` routes)—`clish` serialization can stall management CPU (`confd`); use kernel `ip route` / `vtysh` or Arodonata's `TopologyService` (`collect_gateway_routes`) instead.

## 3. Software Inventory, Hotfixes & Central Deployment Tool (CDT, `sk111158`)

- **Single-Pass `cpinfo -y all`**: Run `cpinfo -y all` once and parse both `[FW1]` (major release and `Jumbo_Take`) and `[CPUpdates]` (installed hotfix bundles and Takes-less individual hotfixes) from that single output. Never invoke `cpinfo -y FW1` and `cpinfo -y CPUpdates` separately, as each invocation duplicates heavy package inspection overhead.
- **`cplp list` Live Patch Inventory**:
  - Invoke `/opt/cplp/bin/cplp list --json` (or `cplp list` with plain-text fallback when older builds lack `--json`).
  - Account for Check Point's `14`-day live patch retention/lifetime metadata when tracking temporary hotfixes that are not persisted across full Jumbo Hotfix Accumulator (JHA) upgrades.
- **`autoupdatercli show` Quirks**:
  - Parse `"repository-packages"` defensively: Check Point emits the literal string `"empty"` when no packages are present instead of an empty JSON array `[]`.
  - Parse boolean-looking fields defensively: Check Point frequently emits string literals `"true"` and `"false"` rather than JSON booleans.
- **CDT (`sk111158`) XML & CSV Constraints**:
  - Ensure all CDT pre/post/custom helper scripts carry `0700` executable permissions (`chmod 0700`) and Unix LF line endings (strip CRLF `\r\n` -> `\n` before bundling, as Windows line endings break `/bin/sh` shebangs on Gaia).
  - CDT `<execute_script>` XML elements are **non-parameterized**: pass configuration variations via distinct helper wrappers or environment/config files staged alongside the package rather than expecting parameterized XML attributes.
  - Interpret CDT script exit codes accurately: `0` means success with no reboot required, `222` means success requiring a gateway reboot/continuation step, and any other non-zero code signals failure.

## 4. Standalone CLI Lifecycle (`arodonata` SQLite Cache + `arlogi`)

- **Ephemeral `:memory:` vs. Persistent SQLite Cache**:
  - For single-shot read/check CLI scripts, omit `engine` (`engine=None`, defaulting to `sqlite+aiosqlite:///:memory:`) and wrap `ArodonataClient` in `async with` (which calls `await client.close(logout=True)` cleanly).
  - For multi-step human-in-the-loop CLI workflows (`plan` -> review -> `apply`), configure a file-backed SQLite URL (`ARODONATA_DATABASE_URL="sqlite+aiosqlite:///./state/arodonata_cache.db"`) so warm cache tables survive across invocations.
  - Never hold open SQLite write transactions across `api_call()` network I/O (`ArodonataClient` and `SqlCacheAdapter` keep DB reads/writes short and outside HTTP awaits to avoid `database is locked` contention).
- **Idiomatic `arlogi` CLI Logging**:
  - Initialize logging once at CLI startup with `arlogi.setup_logging(level="INFO", json_file_name="logs/cli.jsonl", json_file_only=False)` so human-readable logs appear on stderr/stdout while structured JSONL records are written to disk, and obtain module loggers via `arlogi.get_logger(__name__)`.
  - Pass structured metadata via keyword arguments (`logger.info("sync completed", domain=domain, count=total)`) and **never** pass `sid`, `api_key`, `password`, or raw auth headers in log messages or `extra` kwargs.
