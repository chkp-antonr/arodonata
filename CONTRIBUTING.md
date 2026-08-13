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
  are organized in cumulative tiers, selected via `pytest.sh`:

```bash
./pytest.sh int-fast     # ~3 min: auth, sessions, throttling, rate limits, concurrency
./pytest.sh int-medium   # ~5 min: + reads/search, cache builds, light publish/revert cycles
./pytest.sh int-full     # ~25 min: + cache-mode matrix, multi-domain, cross-user publish, soak
```

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
