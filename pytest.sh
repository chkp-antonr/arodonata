#!/usr/bin/env bash
# Test runner for arodonata.
#
# Usage:
#   ./pytest.sh                 # unit suite (default pytest run, with coverage)
#   ./pytest.sh int-1 .. int-6  # one integration bucket, as its own pytest session
#   ./pytest.sh int-full        # all six buckets, each as its own pytest session
#   ./pytest.sh <pytest args>   # passthrough (e.g. -k pattern, a file path)
#
# Integration buckets (tests/integration/b1..b6) are sized for roughly equal
# wall-clock time (~10-15 min each against the lab) and are independent: every
# bucket runs as its own pytest session, so each one takes the run lock,
# snapshots the lab baseline, and restores it at teardown if the bucket
# mutated anything. int-full runs the six sessions back-to-back -- continue on
# failure, non-zero exit if any bucket failed -- instead of one long session
# with a single restore at the very end. It pauses BUCKET_PAUSE_SECONDS between
# buckets so the next one does not open into Check Point's login rate-limit
# window; override it (e.g. BUCKET_PAUSE_SECONDS=0) if your server does not
# enforce one.
#
# Every bucket run prints its 15 slowest tests (--durations=15); use those
# numbers to rebalance the buckets -- moving a test file is a `git mv`.
#
# Integration credentials load from .env.test + .env.secrets via conftest.
# Integration buckets run serially and without coverage by design.
#
# For a run you cannot explain from the log alone, ARODONATA_TEST_TRACE=1 exports
# OTel spans to _tmp/otel_traces/ -- per-login, per-call and per-slot durations.
# Off by default; see the integration_tracing fixture in conftest.

# No `set -e`: int-full must keep going after a failed bucket and report all
# of them at the end. Failures are handled explicitly below.
set -uo pipefail

INT_ROOT=tests/integration
BUCKETS=(1 2 3 4 5 6)
INT_OPTS=(--override-ini=addopts= --no-cov -ra --durations=15)

# Gap between buckets in int-full. Every bucket opens with a burst of logins --
# the baseline snapshot alone logs in to each domain -- and Check Point allows 3
# logins per minute per user per server IP, re-arming that window on every
# rejected attempt. Starting the next bucket immediately walks into a window the
# previous one just armed; this waits it out with margin (the window is ~70s,
# see LOGIN_THROTTLE_WINDOW_SECONDS). Costs ~7 minutes across a ~2 hour run.
BUCKET_PAUSE_SECONDS="${BUCKET_PAUSE_SECONDS:-90}"

run_bucket() {  # $1 = bucket number; remaining args passed through to pytest
    local n="$1"
    shift
    uv run pytest "${INT_OPTS[@]}" "$INT_ROOT/b$n" "$@"
}

tier="${1:-}"
case "$tier" in
    int-[1-6])
        n="${tier#int-}"
        shift
        exec uv run pytest "${INT_OPTS[@]}" "$INT_ROOT/b$n" "$@"
        ;;
    int-full)
        shift
        failed=()
        for n in "${BUCKETS[@]}"; do
            echo "=================== integration bucket b$n ==================="
            if ! run_bucket "$n" "$@"; then
                failed+=("b$n")
            fi
            # ${BUCKETS[-1]} would be neater but negative subscripts need bash
            # 4.2+, and `env bash` finds macOS's 3.2 unless a newer one happens
            # to be earlier on PATH.
            if [[ "$n" != "${BUCKETS[$((${#BUCKETS[@]} - 1))]}" ]]; then
                echo "--- pausing ${BUCKET_PAUSE_SECONDS}s to clear Check Point's login window ---"
                sleep "$BUCKET_PAUSE_SECONDS"
            fi
        done
        echo "=================== int-full summary ==================="
        if ((${#failed[@]})); then
            echo "FAILED buckets: ${failed[*]}"
            exit 1
        fi
        echo "all ${#BUCKETS[@]} buckets passed"
        exit 0
        ;;
    int-*)
        # Catch retired tier names (int-fast/int-medium/int-slow) and typos
        # before they fall through to passthrough, where pytest would report a
        # baffling "file or directory not found: int-fast".
        echo "Unknown integration target '$tier'." >&2
        echo "Buckets replaced the old fast/medium/slow tiers: use int-1 .. int-6, or int-full." >&2
        exit 2
        ;;
    "")
        exec uv run pytest
        ;;
    *)
        exec uv run pytest "$@"
        ;;
esac
