# Spec Delta

## ADDED Requirements

### Requirement: Read-Only Topology Cache Isolation, Accurate Route Parsing, and Unified Indexing

**ID**: REQ-TOPO-024\
**Intent**: Prevent `mode="cache"` SQL mutations, cold-domain route skips, dropped ECMP/`proto routed` routes, VSX bundle error masking, and drifted topology scoring or index lookups.\
**Non-goals**: Changing default confidence score weights or adding new routing protocols.

Targeted `refresh_topology(mode="cache")` MUST remain strictly read-only, `WriteSession` overlays MUST NOT leak into shared SQL topology tables, `collect_gateway_routes()` MUST hydrate missing requested domains, and single-flight coalescing MUST key on effective `cache_ttl`. CLI/API parsers and scoring MUST preserve ECMP/`proto routed` routes, `group-with-exclusion` `except` members, and same-interface live summaries.

#### Scenario: SCN-TOPO-024-1 — Read-only cache mode, WriteSession isolation, TTL coalescing, and per-domain route hydration

- **GIVEN** targeted `refresh_topology(gateways=..., mode="cache")`, an active `WriteSession` during topology refresh, concurrent callers with differing `cache_ttl`, or a partially cached multi-domain server in `collect_gateway_routes()`
- **WHEN** topology refresh or route collection executes
- **THEN** `mode="cache"` SHALL perform zero SQL writes and shared persistence SHALL ignore uncommitted `WriteSession` overlays
- **AND** single-flight coalescing SHALL isolate distinct `cache_ttl` values while `collect_gateway_routes()` hydrates any uncached requested domain

#### Scenario: SCN-TOPO-024-2 — Multi-line ECMP, Gaia proto routed, upstream bundle errors, and non-default destinations

- **GIVEN** multi-line Linux/Gaia `ip -4 route show` ECMP output, Gaia `clish` `proto routed` routes, a failed VSX `run-script` missing the leader VS, or unresolved/`subnet4`/IPv6 route dictionaries
- **WHEN** route parsers, VSX bundle extractors, or route destination normalizers execute via unified script builders
- **THEN** multi-line ECMP legs and `proto routed` BGP/OSPF upgrades SHALL be preserved, failed `run-script` tasks SHALL NOT be flipped to `success=True`, and non-default unrecognized dicts SHALL return `None` instead of `0.0.0.0/0`

#### Scenario: SCN-TOPO-024-3 — Exclusion groups, same-interface summary scoring, and case-insensitive object lookups

- **GIVEN** a `group-with-exclusion` topology object, static prefixes covered by same-interface summary live routes or wildcard annotations, or mixed-case object references in topology indexing
- **WHEN** topology object expansion, interface scoring, or index lookups run
- **THEN** `group-with-exclusion` `except` members SHALL be excluded from expanded intervals and same-interface covering live routes / wildcard annotations SHALL suppress false conflict penalties
- **AND** all topology object lookups SHALL resolve exact and `.lower()` keys uniformly through decomposed helper functions
