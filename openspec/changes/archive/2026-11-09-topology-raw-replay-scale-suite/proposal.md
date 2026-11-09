# Proposal

## Why

Existing topology unit tests validate individual parser functions or lightweight in-memory doubles, while live integration buckets (`b1..b7`) run against a small lab appliance where provisioning hundreds of gateways, 8–10 MDSM domains, 6–7-level nested object groups, 1,000+ policy rules, and 7–10-hop cross-domain routing chains is impractical. Furthermore, downstream applications built on Arodonata (such as MMP and FPCR) need a deterministic, zero-latency Check Point Management Web API mock server (`https://localhost:443` or custom port) backed by the exact same raw enterprise dataset so full-stack application workflows can be exercised against hundreds of gateways and thousands of rules through real `ArodonataClient` transport, pagination, caching, and topology services.

## What Changes

- **Deterministic Enterprise Raw Dataset & Generator (`tests/fixtures/enterprise_raw_dataset/` & `arodonata.testing`)**:
  - Introduce a deterministic (fixed-seed) generator and compact on-disk raw fixture corpus representing an enterprise MDSM deployment with 9 user domains (`Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DC_Spine`, `DC_Pod`, `DB_Seg`, `Partner_DMZ`) plus `Global`, 260+ gateways/clusters/VSX Virtual Systems, 2,500+ network/service objects (including 6–7-level nested groups and address ranges), and 1,000+ access and NAT rules across domain and Global policy packages.
  - Include raw Check Point Management API JSON payloads per domain (`show-domains`, `show-sessions`, `show-last-published-session`, `show-session`, `show-gateways-and-servers`, `show-simple-gateway`, `show-simple-cluster`, `show-generic-object`, `show-generic-objects` for `CpmiVsNetobj`, `CpmiVsxNetobj`, `CpmiVsxSlotObj`, and `CpmiVsSlotObj` with varied `interfaces`, `leads-to-specific-network`, `anti-spoofing-settings`, and `routes_installed`, `show-hosts`, `show-networks`, `show-address-ranges`, `show-groups`, `show-services-tcp`, `show-services-udp`, `show-services-icmp`, `show-service-groups`, `show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`).
  - Include raw CLI routing outputs per gateway, cluster member node, and VSX chassis (`vsx stat -l`, `ip -4 route show`, and `clish -c "show route"` covering `kernel`/`C`, `static`/`S`, `bgp`/`B`, `ospf`/`O`, `routed`/`R`, `I` IS-IS, ECMP multi-next-hop routes, and cluster member routing drift), plus Base64-encoded `run-script` / `show-task` payloads (`responseMessage`) for `cprid` fallback verification.
- **File-Backed Replay Adapters (`FileReplayApiMock` & `FileReplayCliMock`)**:
  - Implement `FileReplayApiMock` (`ApiPort`) and `FileReplayCliMock` (`GatewayCliPort`) reading from the raw dataset directory on disk.
  - Emulate Check Point pagination (`limit`, `offset` -> `from`, `to`, `total`), `details-level` (`uid`, `standard`, `full`), `uid`/`name` lookup, `class-name` filtering on `show-generic-objects`, and `run-script` + `show-task` Base64 execution.
  - Validate incoming bash scripts in `FileReplayCliMock` (verifying `vsenv "$vsid"` / `vsx stat -l` resolution and `CTX%05d` `$FWDIR` checks for VSX Virtual Systems) before returning the target node/VS raw stdout/stderr.
  - Track granular per-domain and per-command API/CLI call counters and logs to assert `smart` / `cache` / `force` cache behavior and single-gateway targeted refreshes (`gateways=[...]`).
- **Standalone & Embeddable Check Point HTTPS Mock Server (`arodonata.testing.mock_server`)**:
  - Provide an `aiohttp.web` HTTPS server (`CheckPointReplayHttpServer` and CLI entrypoint `python -m arodonata.testing.mock_server --host 0.0.0.0 --port 443`) exposing `/web_api/{cmd}` over TLS (auto-generating a self-signed certificate or loading user-supplied PEM files).
  - Track per-domain sessions via `/web_api/login` (`domain` payload -> `X-chkp-sid` mapping) and rewrite CMA/MDS server `ipv4-address` fields in `show-domains` to the mock server's bound host so external applications (MMP, FPCR) pointed at `localhost:443` seamlessly traverse all domains, objects, rulebases, and `run-script`/`show-task` route collection through real `ArodonataClient` HTTPS transport without artificial rate limits or login throttling.
- **Comprehensive Raw-Replay Scale Test Suite (`tests/unit/test_topology_raw_replay_scale.py`)**:
  - Execute a 6-stage end-to-end verification pipeline (plus loopback HTTPS transport verification): cold sync from raw files into `SqlCacheAdapter`, `smart`/`cache` zero-query verification, full static diagnostics and live route reconciliation across all anomaly types, persistent administrator `TopologyAnnotation` overrides and IPAM prefix export, 9-hop cross-domain chain discovery with ECMP/Standby/LPM matryoshka (`/8`..`/32`) and `20x20+` batch matrix queries, and targeted single-gateway live mutation and refresh.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `integration-testing-and-examples`: Add requirements for the deterministic enterprise raw dataset generator, `FileReplayApiMock` / `FileReplayCliMock` test doubles, and the standalone/embeddable HTTPS `/web_api/{cmd}` mock server for downstream applications (MMP, FPCR).
- `gateway-topology`: Add scale and fidelity requirements for end-to-end raw-replay topology synchronization, 7–10-hop inter-domain transit chain resolution, ECMP and standby path filtering, `/8..32` LPM matryoshka specificity, `20x20+` batch matrix order preservation, and targeted single-gateway refresh verification.

## Impact

- **New Package / Module**: `src/arodonata/testing/` (`dataset_generator.py`, `replay_mock.py`, `mock_server.py`, `__main__.py`) providing reusable dataset generation, `FileReplayApiMock`, `FileReplayCliMock`, and `CheckPointReplayHttpServer`.
- **New Test Fixtures & Suite**: `tests/fixtures/enterprise_raw_dataset/` (deterministic raw fixture files/manifest) and `tests/unit/test_topology_raw_replay_scale.py`.
- **Downstream Consumers (MMP, FPCR)**: Can run `uv run python -m arodonata.testing.mock_server --port 443` (or any port) and point their `ArodonataClient` configuration to `localhost:443` to test full-scale MDSM discovery, 260+ gateways, 2,500+ objects, 1,000+ rules, and topology/route analysis without a live Check Point appliance.
- **No Breaking Changes**: Existing `ApiPort`, `CachePort`, `GatewayCliPort`, and `ArodonataClient` public signatures remain backward-compatible.
