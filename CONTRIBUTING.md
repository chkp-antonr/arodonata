# Contributing to arodonata

Thanks for your interest in contributing!

## Development setup

This project uses [`uv`](https://docs.astral.sh/uv/) for dependency
management.

```bash
git clone https://github.com/chkp-antonr/arodonata.git
cd arodonata
uv sync
uv run pre-commit install
```

Run the checks locally before opening a PR:

```bash
./check                 # ruff + mypy
uv run pytest           # unit suite (offline; enforces >=85% coverage)
```

## Testing

The suite has two layers:

- **Unit tests** (`tests/unit/`, mirrors `src/arodonata/`) — offline, no
  credentials, run by CI and by a bare `uv run pytest`. Coverage is
  enforced at ≥85% (`--cov-fail-under`); core logic is held near 100%.
- **Integration tests** (`tests/integration/`) — run against a real
  Check Point management server and are excluded from default runs. They
  are split into six buckets (`tests/integration/b1`..`b6`) sized for
  roughly equal wall-clock time, not by topic. Each bucket runs as its own
  pytest session — its own run lock, baseline snapshot, and restore — so
  buckets are independent and can be run in any order or on their own:

```bash
./pytest.sh int-1        # auth, sessions, rate limits, concurrency, reads/search, rulebase reads
./pytest.sh int-2        # cpcrud live publishes, cache builds
./pytest.sh int-3        # publish/revert cycles, throttling (deliberately slow; sorts last)
./pytest.sh int-4        # cache-mode matrix, multi-domain
./pytest.sh int-5        # whole-server rebuilds, cross-user/domain publish matrix
./pytest.sh int-6        # soak: repeated publish -> smart-fast -> revert cycles
./pytest.sh int-full     # all six, back-to-back sessions; ~60 min total measured 2026-09-12
```

Every bucket run prints its 15 slowest tests (`--durations=15`). The bucket
assignment is an estimate (publishes, `revert-to-revision`, and whole-server
rebuilds dominate, not test count) — when the numbers say a bucket is
lopsided, rebalance with a `git mv`; the `bucket_N` marker follows the
directory automatically.

**Only one integration run at a time.** Every run shares one lab server
(same domains, policies, and reverts) and one SQLite cache file that is
deleted on teardown, so overlapping runs corrupt each other. A session-scoped
lock (`tests/integration/run_lock.py`, file `_tmp/integration.lock`) makes a
second run — from `pytest.sh`, bare `pytest`, or an IDE — exit immediately
with the holder's PID. The kernel releases it if the holder dies, so a killed
run never leaves a stale lock. Two gotchas learned the hard way: the conftest
loads `.env.test` with `override=True`, so blanking `API_MGMT=` on the command
line does **not** keep a run off the lab; and if you must stop a run, kill it
by PID — pattern-matching on `pytest` will hit other runs (and your own
wrapper shell) too.

Integration configuration loads from `.env.test` + `.env.secrets` in the
repo root (see `.env.example` for the variable names — never commit real
values). Mutating tests are marked `cp_mutates`, confine themselves to the
`TEST_DOMAIN_A`/`TEST_DOMAIN_B` sandbox domains, and revert to the
pre-test revision on completion. As an extra safety net, the harness
snapshots every domain's last published revision to
`_tmp/cp_baseline/baseline-<timestamp>.json` before any test runs and
reverts drifted domains at session end; after a crashed run you can
restore manually:

```bash
uv run tests/integration/restore_baseline.py _tmp/cp_baseline/baseline-<timestamp>.json
```

## Commit messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>
```

Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `perf`, `test`,
`ci`, `build`. A `commitizen` pre-commit hook enforces this format — it
also drives `CHANGELOG.md` generation, so a clear, correctly-typed message
matters.

## Pull requests

- Keep PRs focused on one change.
- Add or update tests for behavior changes.
- Make sure `./check` and `uv run pytest` pass locally.
- Describe *why* the change is needed, not just what it does.

## Where things live

See `CLAUDE.md` for how this project organizes working artifacts (most of
which live in a private, non-public location — nothing to worry about as a
contributor, just don't expect to find design docs for older features in
this repo's git history).
