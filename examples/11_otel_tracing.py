"""Example 11 — Provider-agnostic OpenTelemetry tracing with per-span timing breakdown.

Run:
    uv run examples/11_otel_tracing.py

Arodonata v2 is a provider-agnostic OpenTelemetry span producer (`opentelemetry-api` +
`arlogi.otel.traced`) and never owns or configures a global `TracerProvider`. When an application
or script configures tracing via `arlogi.otel.setup_tracing()`, all `@traced` methods across
`ArodonataClient`, `DomainSyncCoordinator`, `ObjectService`, `AMgmtClient`, and `ApiTransport`
automatically emit nested spans with sanitized attributes (never leaking SIDs or secrets).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv(".env.lib", override=True)
load_dotenv(".env.secrets", override=True)

from arlogi.otel import setup_tracing, shutdown_tracing  # noqa: E402

from arodonata import ArodonataClient, ArodonataSettings  # noqa: E402
from arodonata.core.telemetry import set_trace_modules  # noqa: E402

TRACE_DIR = Path(__file__).parent / "_tmp" / "otel_traces"


def _iter_spans(trace_dir: Path) -> Iterator[dict[str, Any]]:
    """Yield every exported span dict across rotated JSONL trace files."""
    for file_path in sorted(trace_dir.glob("*.jsonl")):
        for line in file_path.read_text(encoding="utf-8").splitlines():
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
        print("  (no spans exported in TRACE_DIR)")
        return

    print(f"\n{'Span Name':<65} {'Count':>6} {'Total ms':>10} {'Avg ms':>10}")
    print("-" * 95)
    for name, values in sorted(durations_ms.items(), key=lambda kv: -sum(kv[1])):
        print(f"  {name:<63} {len(values):>6} {sum(values):>10.1f} {sum(values) / len(values):>10.1f}")


async def main() -> None:
    """Run asset and object refresh with OpenTelemetry JSONL trace export and summarize spans."""
    shutil.rmtree(TRACE_DIR, ignore_errors=True)
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    setup_tracing(service_name="arodonata-example-11", file_dir=TRACE_DIR)
    set_trace_modules({"arodonata": True})

    settings = ArodonataSettings(trace_modules="arodonata:on")
    target_domains = [os.environ["EXAMPLE_DOMAIN"]] if os.getenv("EXAMPLE_DOMAIN") else None
    t0 = time.perf_counter()

    try:
        async with ArodonataClient(settings=settings) as client:
            print("[Step 1/2] Refreshing assets with OpenTelemetry tracing active...", flush=True)
            await client.refresh_assets(domains=target_domains, mode="smart")

            print("[Step 2/2] Refreshing network objects with OpenTelemetry tracing active...", flush=True)
            await client.refresh_objects(domains=target_domains, types=["host", "network"], mode="smart")
    finally:
        shutdown_tracing()

    print(f"\nTotal wall time: {time.perf_counter() - t0:.2f}s")
    _print_span_summary(TRACE_DIR)


if __name__ == "__main__":
    asyncio.run(main())
