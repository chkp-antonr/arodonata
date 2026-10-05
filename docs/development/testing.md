# Testing

arodonata ships two test layers: an offline **unit suite** that anyone can run,
and a tiered **integration suite** that exercises a real Check Point
management server.

## Unit suite

```bash
uv run pytest
```

- Lives in `tests/unit/`, mirroring the `src/arodonata/` package tree one test
  module per source module.
- Fully offline — no credentials, no network, in-memory SQLite where a real
  database engine is needed.
- Coverage is enforced at **≥85%** (`--cov-fail-under`), with core logic
  (cache refresh coordinator, change processor, client facade, login
  coordinator, repository) held near 100%.
- Shared infrastructure: `tests/unit/doubles.py` provides protocol-satisfying
  `FakeApi`/`FakeCache` doubles for the ports; `tests/unit/conftest.py`
  neutralizes the distributed-lock manager.
- `tests/unit/test_db_utils_postgres.py` is the one opt-in unit test: it runs against a real PostgreSQL database (in a throwaway schema) only when `ARODONATA_PG_TEST_URL` is set to a `postgresql+asyncpg://...` URL, and skips otherwise.

CI (`.github/workflows/ci.yml`, Python 3.13) runs `uv sync --all-extras --dev`, `uv run ruff check src/ tests/`, `uv run mypy src/` and `uv run pytest`, in that order; it does not run `ruff format --check` or `mkdocs build`. Run all four locally before pushing. `--all-extras` matters: the tests under `tests/unit/mcp` import the `mcp` extra and fail without it. Integration tests are excluded from default runs by the `-m "not integration"` marker expression.

## Integration suite

```bash
./pytest.sh int-1        # one bucket
./pytest.sh int-7        # ...
./pytest.sh int-full     # all seven, back-to-back (~2 h)
```

`int-full` pauses `BUCKET_PAUSE_SECONDS` (default `90`) between buckets so the next one does not open into Check Point's login rate-limit window; set `BUCKET_PAUSE_SECONDS=0` for a server that does not enforce one.

Tests live in `tests/integration/b1`..`b7`; the `bucket_N` marker is applied
automatically from the directory path. Buckets are sized for roughly equal
wall-clock time (~10–15 min each), **not** by topic, and each runs as its own
pytest session — its own run lock, baseline snapshot and restore — so they are
independent and can be run in any order or alone. `int-full` runs the seven
sessions back-to-back rather than one long session with a single restore at
the end.

| Bucket | Contents |
|---|---|
| `b1` | Logins for every configured identity (API key + credential users), auth failures, SID lifecycle incl. stale-SID recovery, rate limiting, concurrent admins, live session naming, cache-first reads and search, rulebase reads. Mutates nothing. |
| `b2` | Live CPCRUD create/update/delete with real publishes, single-domain cache builds and check-mode partial refresh |
| `b3` | create→publish→verify→revert cycles, plus throttling (deliberately drives the server into `err_too_many_requests`; sorts last within the bucket) |
| `b4` | Cache-mode matrix (cache/smart/smart-fast/force) incl. live fallback triggers, multi-domain isolation |
| `b5` | Whole-server rebuilds with asset relationship phases, cross-user/cross-domain publish/discard/revert matrix |
| `b6` | Bounded soak: repeated publish → smart-fast → revert cycles |
| `b7` | MCP server tools over a real client: init, cache-backed lists, live single-object and list tools, the live rulebase path, search, and the `api_call` write gate. Mutates nothing. The one topical bucket: MCP tests live here together rather than being spread for balance. |

Every bucket run prints its 15 slowest tests (`--durations=15`). The
assignment is an estimate — publishes, `revert-to-revision` and whole-server
rebuilds dominate, not test count — so when the numbers say a bucket is
lopsided, rebalance with a `git mv`; the marker follows the directory.

Only one integration run at a time: see [Contributing](https://github.com/chkp-antonr/arodonata/blob/master_v1/CONTRIBUTING.md)
for the run lock and the reasons behind it.

### Configuration

The integration conftest loads `.env.test` then `.env.secrets` from the repo root, then `.env.lab.<profile>` when a lab profile is selected; each file overrides values already in the environment. Select a profile by setting `ARODONATA_LAB=<profile>` (in the shell, or in `.env.test`/`.env.secrets`); without it the run uses the default lab from `.env.test`. A selected profile whose `.env.lab.<profile>` file does not exist is an error, not a fallback to the default lab. See `.env.example` for the variable names; the important ones:

- `API_MGMT` — management server IP
- `APIKEY`, `USER_admin`, `USER_AntonR`, `USER_Eng1..4` — identities
- `TEST_DOMAIN_A`, `TEST_DOMAIN_B` — sandbox domains for mutating tests
- `DATABASE_URL` — SQLite path for the test cache (default `_tmp/`)

Missing variables **skip** the affected tests, so a machine without lab
access still runs everything else.

Lab runs verify the server certificate like production does (see [TLS Verification](../configuration/tls-verification.md)).
Pin the lab servers instead of learning them: put `ARODONATA_TLS_TRUST=pinned` and `ARODONATA_TLS_FINGERPRINTS=<one SHA-256 per member>` in `.env.lab.<profile>`, taking each value from `api fingerprint -f json` on the member.
Fingerprints are public data, so they may live in that file.
`ARODONATA_TLS_TRUST=lab-memory` is for a lab whose fingerprints are not harvested yet: it trusts each process's first contact in memory, writes nothing (it only reads an existing store) and is honoured only when `ARODONATA_LAB` is set.

### Mutation safety

Tests that change server state are marked `cp_mutates` and confine
themselves to the sandbox domains, reverting to the pre-test revision when
they finish. Independently of that, the harness snapshots the last published revision of the sandbox domains (`TEST_DOMAIN_A`/`TEST_DOMAIN_B`, no other domain) to `_tmp/cp_baseline/baseline-<timestamp>.json` **before any test runs**; with neither set, no snapshot is taken (no mutating test can run). At session end, only if a `cp_mutates` test ran, it reverts the snapshotted domains that drifted. A failed snapshot aborts the whole session (exit code 5) before any test runs: no safety net, no run. After a crashed run, restore manually:

```bash
uv run tests/integration/restore_baseline.py _tmp/cp_baseline/baseline-<timestamp>.json
```

The baseline files are never deleted automatically — they are your recovery
handle.

### Serial by design

Integration tests run serially (no `pytest-xdist`): the suite deliberately
exercises rate limits and session caps, so parallel workers would poison
each other's results.
