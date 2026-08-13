#!/usr/bin/env bash
# Test runner for arodonata.
#
# Usage:
#   ./pytest.sh                # unit suite (default pytest run, with coverage)
#   ./pytest.sh int-fast       # integration fast tier            (~5 min)
#   ./pytest.sh int-medium     # fast + medium tiers              (~30 min)
#   ./pytest.sh int-full       # all integration tiers            (hours)
#   ./pytest.sh <pytest args>  # passthrough (e.g. -k pattern, a file path)
#
# Integration credentials load from .env.test + .env.secrets via conftest.
# Integration tiers run serially and without coverage by design.

set -euo pipefail

tier="${1:-}"
case "$tier" in
    int-fast)
        shift
        exec uv run pytest --override-ini=addopts= --no-cov -ra \
            tests/integration/fast "$@"
        ;;
    int-medium)
        shift
        exec uv run pytest --override-ini=addopts= --no-cov -ra \
            tests/integration/fast tests/integration/medium "$@"
        ;;
    int-full)
        shift
        exec uv run pytest --override-ini=addopts= --no-cov -ra \
            tests/integration "$@"
        ;;
    "")
        exec uv run pytest
        ;;
    *)
        exec uv run pytest "$@"
        ;;
esac
