# Testing & Quality Gates

Arodonata v2 enforces strict offline unit test coverage, static typing, linting, OpenSpec specification validation, and a 7-bucket live Check Point MDSM integration suite.

## 1. Unified Test Runner (`./pytest.sh`)

All test execution goes through `./pytest.sh`:

```bash
# Fast offline unit tests (mandatory pre-PR quality gate; zero network access)
./pytest.sh
./pytest.sh unit

# Pass extra pytest arguments (e.g. -k or specific test file)
./pytest.sh unit tests/unit/test_mcp_server.py
```

### Live Check Point MDSM/SMS Integration Buckets (`b1`..`b7`)

Live integration tests require `.env.test`, `.env.secrets`, and an optional lab overlay `.env.lab.<ARODONATA_LAB>` (e.g., `ARODONATA_LAB=home`). They acquire a non-blocking process-wide lock (`tests/integration/run_lock.py`), probe server readiness (`lab_ready.py`), and automatically snapshot and restore mutated domains via `revert-to-revision` (`cp_revision.py`).

| Command | Bucket | Scope |
| --- | --- | --- |
| `./pytest.sh int-1` | `bucket_1` | Authentication, session lifecycle, rate limiter, cached reads, search, rulebase reads, change reports |
| `./pytest.sh int-2` | `bucket_2` | Cache build, streaming sync events (`SyncProgressEvent`), live CPCRUD (`plan` / `apply` / `inverse`) |
| `./pytest.sh int-3` | `bucket_3` | `WriteSession` + `SessionOverlay`, `publish`, `discard`, `revert-to-revision`, and `70s` login throttle recovery |
| `./pytest.sh int-4` | `bucket_4` | Multi-domain isolation (`Domain4` vs `Domain5` vs `Global`) and `CacheMode` matrix (`cache`, `smart`, `smart-fast`, `force`) |
| `./pytest.sh int-5` | `bucket_5` | Full rebuilds, 120-rule layer pagination stitching, publish matrix, and session change reports |
| `./pytest.sh int-6` | `bucket_6` | Bounded soak loop (repeated `publish` → `smart-fast` → `revert` stability cycles) |
| `./pytest.sh int-7` | `bucket_7` | Live MCP server and consolidated tool surface verification |
| `./pytest.sh int-full` | `b1..b7` | Full sequential integration suite |

## 2. Mandatory Pre-Commit / Pre-PR Quality Gates

```bash
# 1. Python lint and formatting
uv run ruff check .
uv run ruff format --check .

# 2. Strict MyPy type checking (Python 3.13)
uv run mypy src

# 3. Offline unit test suite
./pytest.sh unit

# 4. Markdown linting
npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix

# 5. OpenSpec specification validation
openspec validate --specs --no-interactive
```
