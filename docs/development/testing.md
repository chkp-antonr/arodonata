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

This is what CI runs — integration tests are excluded from default runs by
the `-m "not integration"` marker expression.

## Integration suite

```bash
./pytest.sh int-fast     # ~3 min
./pytest.sh int-medium   # ~5 min  (fast + medium)
./pytest.sh int-full     # ~25 min (everything)
```

Tests live in `tests/integration/{fast,medium,full}/`; tier markers are
applied automatically from the directory path, and runs are cumulative.

| Tier | Contents |
|---|---|
| `fast` | Logins for every configured identity (API key + credential users), auth failures, SID lifecycle incl. stale-SID recovery, throttling, rate limiting, concurrent admins, live session naming |
| `medium` | Cache-first reads and search, single-domain cache builds and check-mode partial refresh, rulebase reads, first mutating tests: create→publish→verify→revert cycles |
| `full` | Cache-mode matrix (cache/smart/smart-fast/force) incl. live fallback triggers, multi-domain isolation, whole-server rebuilds with asset relationship phases, cross-user publish/discard/revert matrix, bounded soak |

### Configuration

The integration conftest loads `.env.test` then `.env.secrets` from the repo
root. See `.env.example` for the variable names; the important ones:

- `API_MGMT` — management server IP
- `APIKEY`, `USER_admin`, `USER_AntonR`, `USER_Eng1..4` — identities
- `TEST_DOMAIN_A`, `TEST_DOMAIN_B` — sandbox domains for mutating tests
- `DATABASE_URL` — SQLite path for the test cache (default `_tmp/`)

Missing variables **skip** the affected tests, so a machine without lab
access still runs everything else.

### Mutation safety

Tests that change server state are marked `cp_mutates` and confine
themselves to the sandbox domains, reverting to the pre-test revision when
they finish. Independently of that, the harness snapshots every domain's
last published revision to `_tmp/cp_baseline/baseline-<timestamp>.json`
**before any test runs** and reverts drifted domains at session end. After
a crashed run, restore manually:

```bash
uv run tests/integration/restore_baseline.py _tmp/cp_baseline/baseline-<timestamp>.json
```

The baseline files are never deleted automatically — they are your recovery
handle.

### Serial by design

Integration tests run serially (no `pytest-xdist`): the suite deliberately
exercises rate limits and session caps, so parallel workers would poison
each other's results.
