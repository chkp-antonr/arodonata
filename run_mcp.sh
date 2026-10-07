#!/usr/bin/env bash
set -euo pipefail

# 1. Ensure working directory is repo root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# 2. Ensure persistent storage directory exists
mkdir -p _tmp

# 3. Environment file override (_tmp/.env by default if it exists)
ENV_FILE="${ENV_FILE:-_tmp/.env}"

DEFAULT_ARGS=()
if [[ ! " $* " =~ " --env-file " ]]; then
    if [ -f "$ENV_FILE" ]; then
        DEFAULT_ARGS+=(--env-file .env.lib --env-file .env.secrets --env-file "$ENV_FILE")
    else
        DEFAULT_ARGS+=(--env-file .env.lib --env-file .env.secrets)
    fi
fi

# 4. Read values from env file if present for banner display
DATABASE_URL="${DATABASE_URL:-}"
ARODONATA_MCP_TOKEN_VARS="${ARODONATA_MCP_TOKEN_VARS:-}"

if [ -f "$ENV_FILE" ]; then
    while IFS='=' read -r key val || [ -n "$key" ]; do
        key="$(echo "$key" | tr -d ' ')"
        val="$(echo "$val" | tr -d '\r')"
        [[ "$key" =~ ^#.*$ ]] && continue
        [ -z "$key" ] && continue
        if [ "$key" = "DATABASE_URL" ] && [ -z "$DATABASE_URL" ]; then DATABASE_URL="$val"; fi
        if [ "$key" = "ARODONATA_MCP_TOKEN_VARS" ] && [ -z "$ARODONATA_MCP_TOKEN_VARS" ]; then ARODONATA_MCP_TOKEN_VARS="$val"; fi
    done < "$ENV_FILE"
fi

export DATABASE_URL="${DATABASE_URL:-sqlite+aiosqlite:///./_tmp/arodonata.db}"
export ARODONATA_MCP_TOKEN_VARS="${ARODONATA_MCP_TOKEN_VARS:-MCP_LOCAL_TOKEN}"

# 5. Host & Port defaults (allows 0.0.0.0 binding for remote/container access)
HOST="${HOST:-${ARODONATA_MCP_HOST:-0.0.0.0}}"
PORT="${PORT:-${ARODONATA_MCP_PORT:-8765}}"

if [[ ! " $* " =~ " --host " ]]; then
    DEFAULT_ARGS+=(--host "$HOST")
fi
if [[ ! " $* " =~ " --port " ]]; then
    DEFAULT_ARGS+=(--port "$PORT")
fi

# 6. Display startup banner
echo "=================================================="
echo " Starting Arodonata MCP Server"
echo "=================================================="
echo " Host:      $HOST"
echo " Port:      $PORT"
echo " Endpoint:  http://${HOST}:${PORT}/mcp"
echo " Database:  $DATABASE_URL"
echo " Auth Var:  $ARODONATA_MCP_TOKEN_VARS"
if [ -f "$ENV_FILE" ]; then
echo " Env File:  $ENV_FILE"
fi
echo "=================================================="
echo "To test with curl:"
echo "  curl -i -H 'Authorization: Bearer <token>' http://${HOST}:${PORT}/mcp"
echo "=================================================="
echo ""

# 7. Execute arodonata-mcp CLI with default & forwarded arguments
exec uv run arodonata-mcp "${DEFAULT_ARGS[@]}" "$@"
