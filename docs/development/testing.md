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
./pytest.sh int-1        # one bucket
./pytest.sh int-6        # ...
./pytest.sh int-full     # all six, back-to-back (~60 min measured 2026-09-12)
```

Tests live in `tests/integration/b1`..`b6`; the `bucket_N` marker is applied
automatically from the directory path. Buckets are sized for roughly equal
wall-clock time (~10–15 min each), **not** by topic, and each runs as its own
pytest session — its own run lock, baseline snapshot and restore — so they are
independent and can be run in any order or alone. `int-full` runs the six
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

Every bucket run prints its 15 slowest tests (`--durations=15`). The
assignment is an estimate — publishes, `revert-to-revision` and whole-server
rebuilds dominate, not test count — so when the numbers say a bucket is
lopsided, rebalance with a `git mv`; the marker follows the directory.

Only one integration run at a time: see [Contributing](../../CONTRIBUTING.md)
for the run lock and the reasons behind it.

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
