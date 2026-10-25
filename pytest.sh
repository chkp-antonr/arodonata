#!/usr/bin/env bash
# Test runner for arodonata v2.
#
# Usage:
#   ./pytest.sh                  fast unit tests (default)
#   ./pytest.sh unit             fast unit tests
#   ./pytest.sh int-1            integration bucket 1: auth, sessions, read/search, rate limit
#   ./pytest.sh int-2            integration bucket 2: cache build + CPCRUD engine
#   ./pytest.sh int-3            integration bucket 3: publish, revert, throttling (~100s)
#   ./pytest.sh int-4            integration bucket 4: multi-domain + cache mode matrix
#   ./pytest.sh int-5            integration bucket 5: rulebase, large layer, change report
#   ./pytest.sh int-6            integration bucket 6: soak / stability
#   ./pytest.sh int-7            integration bucket 7: MCP server and tools
#   ./pytest.sh int-full         all integration buckets sequentially (b1 -> b7)
#
# Any extra arguments are forwarded to pytest:
#   ./pytest.sh int-1 -k login -vv
#   ./pytest.sh -k cache

set -uo pipefail
cd "$(dirname "$0")"

INT_ROOT="tests/integration"
BUCKETS=(1 2 3 4 5 6 7)
INT_OPTS=(-v -ra --strict-markers --durations=15 --tb=short -o log_cli=true --log-cli-level=INFO)
BUCKET_PAUSE_SECONDS="${BUCKET_PAUSE_SECONDS:-${ARODONATA_TEST_BUCKET_PAUSE:-90}}"

run_bucket() {
  local n="$1"
  shift
  has_path=0
  for arg in "$@"; do
    if [[ "$arg" != -* && ( -e "$arg" || "$arg" == tests/* ) ]]; then
      has_path=1
      break
    fi
  done
  if [[ "$has_path" -eq 1 ]]; then
    uv run pytest "${INT_OPTS[@]}" -m "bucket_${n}" "$@"
  else
    uv run pytest "${INT_OPTS[@]}" "${INT_ROOT}/b${n}" -m "bucket_${n}" "$@"
  fi
}

mode="${1:-unit}"

case "$mode" in
  unit)
    shift || true
    exec uv run pytest -v tests/unit "$@"
    ;;
  int-1|int-2|int-3|int-4|int-5|int-6|int-7)
    n="${mode#int-}"
    shift
    has_path=0
    for arg in "$@"; do
      if [[ "$arg" != -* && ( -e "$arg" || "$arg" == tests/* ) ]]; then
        has_path=1
        break
      fi
    done
    if [[ "$has_path" -eq 1 ]]; then
      exec uv run pytest "${INT_OPTS[@]}" -m "bucket_${n}" "$@"
    else
      exec uv run pytest "${INT_OPTS[@]}" "${INT_ROOT}/b${n}" -m "bucket_${n}" "$@"
    fi
    ;;
  int-full)
    shift
    failed=()
    for n in "${BUCKETS[@]}"; do
      echo "=================== integration bucket b${n} ==================="
      if ! run_bucket "$n" "$@"; then
        failed+=("b${n}")
      fi
      if [[ "$n" != "${BUCKETS[$((${#BUCKETS[@]} - 1))]}" ]] && [[ "${BUCKET_PAUSE_SECONDS}" -gt 0 ]]; then
        echo "--- pausing ${BUCKET_PAUSE_SECONDS}s between buckets ---"
        sleep "${BUCKET_PAUSE_SECONDS}"
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
  -*)
    # Bare flags: "./pytest.sh -k foo" -> unit with those flags
    exec uv run pytest -v tests/unit "$@"
    ;;
  *)
    echo "Unknown mode: $mode" >&2
    echo "Valid: unit | int-1 .. int-7 | int-full" >&2
    exit 2
    ;;
esac
