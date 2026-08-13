"""Same cache refresh as 04_smart_refresh.py, but with OTel tracing enabled.

Run: uv run examples/08_otel_smart_refresh.py

arodonata never owns a TracerProvider -- it's a provider-agnostic span
producer (depends on opentelemetry-api only; every @traced call is a no-op
if nothing configured a provider). A standalone script that wants tracing
sets one up itself, same as this example does via arlogi.otel.setup_tracing().
Inside a host application (e.g. one that already calls setup_tracing() for
its own FastAPI/SQLAlchemy tracing), arodonata's spans just nest into that
trace automatically -- no wiring needed on arodonata's side either way.

This prints the same wall-clock total as 04_smart_refresh.py for a direct
before/after comparison, plus a per-span-name timing breakdown read back
from the exported trace files -- the kind of login/transport/lock visibility
that motivated adding tracing in the first place (see docs/architecture).
"""

import asyncio
import json
import os
import shutil
import time
from pathlib import Path

# Load environment variables BEFORE importing arodonata modules
from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arlogi.otel import setup_tracing, shutdown_tracing
from sqlalchemy.ext.asyncio import create_async_engine

from arodonata import ArodonataClient, ArodonataSettings
from arodonata.api.schemas import SSEEventType

TRACE_DIR = Path(__file__).parent / "_tmp" / "otel_traces"


def _settings_from_env() -> ArodonataSettings:
    api_key_vars = os.getenv("API_KEY_VARS", "").split(",")
    api_keys = ",".join(os.getenv(var, "") for var in api_key_vars)
    return ArodonataSettings(
        mgmt_names=os.getenv("MGMT_NAMES", "mgmt1"),
        mgmt_servers=os.getenv("MGMT_SERVERS", "10.0.0.1"),
        api_keys=api_keys,
    )


def _iter_spans(trace_dir: Path):
    """Yield every span dict across all rotated JSONL trace files."""
    for f in sorted(trace_dir.glob("*.jsonl")):
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            for resource_span in payload.get("resourceSpans", []):
                for scope_span in resource_span.get("scopeSpans", []):
                    yield from scope_span.get("spans", [])


def _print_span_summary(trace_dir: Path) -> None:
    durations_ms: dict[str, list[float]] = {}
    for span in _iter_spans(trace_dir):
        start = int(span.get("startTimeUnixNano", 0))
        end = int(span.get("endTimeUnixNano", 0))
        durations_ms.setdefault(span.get("name", "?"), []).append(max(end - start, 0) / 1e6)

    if not durations_ms:
        print("  (no spans exported -- is arlogi[otel] installed? check TRACE_DIR)")
        return

    print(f"\n{'Span':<82} {'Count':>6} {'Total ms':>10} {'Avg ms':>10}")
    for name, values in sorted(durations_ms.items(), key=lambda kv: -sum(kv[1])):
        print(f"  {name:<80} {len(values):>6} {sum(values):>10.1f} {sum(values) / len(values):>10.1f}")


async def main() -> None:
    shutil.rmtree(TRACE_DIR, ignore_errors=True)
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    setup_tracing(service_name="arodonata-example", file_dir=TRACE_DIR)

    engine = create_async_engine(os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
    client = ArodonataClient(engine=engine, settings=_settings_from_env())

    start_time = time.perf_counter()

    try:
        async with client:
            print("Refreshing domains and gateways...")
            async for event in client.build_refresh_assets_cache():
                if event.event_type == SSEEventType.LOG:
                    print(f"  {event.data.get('message', '')}")
                elif event.event_type == SSEEventType.COMPLETE:
                    print(f"  done: {event.data}")

            print("\nRefreshing objects (hosts/networks/groups)...")
            async for event in client.refresh_objects(mode="force"):
                data = event.data or {}
                if data.get("status") in {"type_complete", "domain_complete"}:
                    print(f"  {event.message}")
    finally:
        await engine.dispose()
        shutdown_tracing()

    duration = time.perf_counter() - start_time
    print(f"\nTotal time: {duration:.2f}s")
    _print_span_summary(TRACE_DIR)


if __name__ == "__main__":
    asyncio.run(main())
