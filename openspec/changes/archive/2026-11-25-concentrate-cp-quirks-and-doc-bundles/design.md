# Design

## Context

See `proposal.md` for motivation and `specs/ai-builder/spec.md` for normative behavior contracts.

Today in Arodonata v2:

1. `docs/troubleshooting/checkpoint-api-quirks.md` captures core Web API transport and session quirks (`70s` login cooldown, dirty `logout` lock retention, `take-over-session`, `show-changes`, `Any`/`Original` sentinels, `Global` domain routing), while rich operational knowledge accumulated across `FPCR`, `MMP`, `Sync_MDM`, and `cp_all_gw_config` remains scattered in external repositories.
2. `docs/scripts/build_notebooklm_docs.py` hardcodes legacy version/table strings (`2.0.0`, `15 Tables`), omits newer guides (`guides/enterprise-replay-mock-server.md`, `guides/mock-testing-scenarios.md`, `troubleshooting/*`) and `examples/13-gateway-topology-matching.md`, and emits only full multi-megabyte bundles (`docs-notebooklm/01..04.md`) that are too large to load directly inside lightweight AI agent skills.
3. `pyproject.toml` restricts `[tool.hatch.build.targets.wheel]` to `packages = ["src/arodonata"]`, but lacks an explicit `[tool.hatch.build.targets.sdist]` exclusion list for upcoming `plugins/arodonata-aibuilder/` assets and generated knowledge bundles.

## Goals / Non-Goals

**Goals:**

- Establish a clean two-document split in `docs/troubleshooting/` separating **Management Web API / SDK quirks** (`checkpoint-api-quirks.md`) from **operational Check Point & CLI scripting quirks** (`checkpoint-ops-quirks.md`).
- Explicitly preserve factual platform boundaries:
  - Standard Check Point Gaia (`R81.x` / `R82+`) ships system `python3` (`~3.9` / `$CPDIR/Python/bin/python3`) with Python's standard library (no third-party PyPI packages), making stdlib `python3` viable inside on-box `run-script` / CDT helpers alongside `bash`/`clish`, whereas Quantum Spark / SMB (`Gaia Embedded`) provides BusyBox shell without Python.
  - Arodonata's `Asset` model natively resolves cluster (`CLUSTER_PARENT_TYPES` / `CLUSTER_MEMBER_TYPES`) and VSX (`VSX_PARENT_TYPES` / `VSX_CHILD_TYPES`) parent-child graphs (`parent_uid`, `member_uids`, `virtual_system_uids`), while deeper role/platform classification (e.g., Maestro `MHO`/`SMO`/`SGM`, `MDS` vs. `MLM`, hardware family) is NOT currently built into `Asset` and will be designed separately as a clean vendor-neutral Arodonata capability rather than importing customer-specific rules from `MMP`.
- Extend `docs/scripts/build_notebooklm_docs.py` to produce `docs-notebooklm/05-sdk-quickref.md` (and reusable helper functions so `plugins/arodonata-aibuilder` in Step 2 can sync the exact same quick-reference directly into skill `references/`).
- Guarantee zero bloat for `uv add arodonata` across both wheel and sdist builds.

**Non-Goals:**

- Implementing native `Asset` role/platform classification in `src/arodonata/core/models/assets.py` in this change (reserved for its own dedicated OpenSpec change).
- Authoring the `plugins/arodonata-aibuilder/` skill definitions and end-to-end English playbooks (scheduled for Steps 2 and 3).

## Decisions

### 1. Two-Tier Troubleshooting Taxonomy (`checkpoint-api-quirks.md` vs. `checkpoint-ops-quirks.md`)

- **Choice**: Keep Management Web API protocol, pagination, object filter, MDSM Global/Local layer, and session/lock mechanics in `docs/troubleshooting/checkpoint-api-quirks.md`, and place gateway/OS/CLI/workflow mechanics in `docs/troubleshooting/checkpoint-ops-quirks.md`:
  1. **Asset & Topology Boundaries**: Documented vs. `Cpmi*` types, cluster member hardware inheritance from parent cluster, policy installation targets vs. physical CLI/upgrade execution targets, MDS active domain server (`servers[].active`) vs. SMS `domain=""` / `"SMC User"`, zero-asset failed-scope guard, and optional platform awareness (Maestro `gclish` / `asg_cp2blades` / `/etc/profile.d/CP.sh`, Quantum Spark Gaia Embedded).
  2. **On-Box Execution (`run-script`, Gaia `python3`, `clish`)**: Standard Gaia `python3` (stdlib JSON/regex parsing) vs. Gaia Embedded POSIX `sh`; `ScriptRepositoryService` (`script-type="repository"`, non-publish session, Base64 `responseMessage` and R82 `script-body`, omitting `"args"` when lacking one-time-script permission); per-line `clish -c "<cmd>" < /dev/null`, `lock database override` (`CLICMD0201` benign vs. `CLINFR0771` active foreign lock), single trailing `save config`, R81.x vs. R82+ `clish` grammar changes (NTP `CLINFR0329`, multi-line banner), and skipping `clish -c "show route"` on large BGP tables (`>10,000` routes).
  3. **Software Inventory, Hotfixes & CDT (`sk111158`)**: Single-call `cpinfo -y all` performance rule (avoiding separate `cpinfo -y FW1`), parsing `[FW1]` `Jumbo_Take` vs. `[CPUpdates]` bundles and Takes-less hotfixes, `cplp list` (`14`-day live patch lifetime, `--json` fallback, `/opt/cplp/bin`), `autoupdatercli show` (`"repository-packages": "empty"` string vs. array, `"true"` string vs. boolean), and CDT XML/CSV deployment constraints (`0700` executable permissions, exit `222` reboot vs. `0` no-reboot, CRLF stripping, non-parameterized `<execute_script>`).
  4. **Standalone CLI Lifecycle (`arodonata` SQLite + `arlogi`)**: Ephemeral `:memory:` (`close(logout=True)`) vs. persistent file-backed SQLite cache across multi-step human-in-the-loop CLI commands, avoiding open DB transactions across `api_call()`, and `arlogi.setup_logging(..., json_file_only=False)` with strict prohibition on passing `sid` or credentials in structured `extra` kwargs.
- **Alternatives considered**: Dumping everything into `checkpoint-api-quirks.md` was rejected because mixing HTTP/JSON API edge cases with on-box Gaia `clish`/`cpinfo`/CDT guidance makes both harder for humans and AI skills to navigate selectively.

### 2. Compact AST-Derived `05-sdk-quickref.md` Generator in `build_notebooklm_docs.py`

- **Choice**: Add a `build_sdk_quickref() -> str` builder inside `docs/scripts/build_notebooklm_docs.py` that reads `arodonata.__version__` dynamically via AST and extracts concise, deterministic signatures and field tables for curated entry points (`ArodonataClient`, `ArodonataSettings`, `Asset`, `CPObject`, `CPService`, `DomainInfo`, `ScriptRepositoryService`, `CPCRUDService`, `ApiReferenceEngine` helpers, `ChangeReport` helpers, and `arodonata.testing` mocks) alongside a verified `arlogi` CLI bootstrap snippet and the 3-tier API lookup ladder (`arodonata.api_reference` -> Context7 / Check Point docs MCP -> explicit verification flag).
- **Rationale**: `02-api-reference.md` spans every internal and public class across the entire codebase, whereas an AI coding skill needs a `< 25 KB` zero-hallucination cheat sheet that stays 100% synchronized with `src/arodonata` on every doc rebuild.

### 3. Explicit `sdist` Exclusion in `pyproject.toml`

- **Choice**: Add `[tool.hatch.build.targets.sdist]` excluding `plugins/`, `docs-notebooklm/`, `docs/_html/`, `openspec/`, and `examples/` (while keeping `src/arodonata`, `README.md`, `LICENSE`, `pyproject.toml`).
- **Rationale**: Guarantees `uv add arodonata` (even with `--no-binary` / source builds) never ships AI plugins, playbooks, or multi-megabyte LLM bundles to production servers.

## Risks / Trade-offs

- **[Risk] Drift between `mkdocs.yml` example/guide lists and `build_notebooklm_docs.py`** → Mitigation: Discover `docs/examples/[0-9][0-9]-*.md` dynamically in sorted order and verify via unit test (`SCN-AIBUILD-002-2`) that every tracked example and troubleshooting quirk file is included in the generated bundles.
- **[Risk] `check_spec_traceability.py` rejects unknown capability directory `ai-builder`** → Mitigation: Register `"ai-builder": "AIBUILD"` in `CAPABILITY_PREFIXES` inside `scripts/check_spec_traceability.py` and cover all four scenarios (`SCN-AIBUILD-001-1`, `SCN-AIBUILD-002-1`, `SCN-AIBUILD-002-2`, `SCN-AIBUILD-003-1`) with offline unit tests in `tests/unit/test_aibuilder_docs_and_packaging.py`.
