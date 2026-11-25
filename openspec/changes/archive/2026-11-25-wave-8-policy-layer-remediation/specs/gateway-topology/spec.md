# Spec Delta

## ADDED Requirements

### Requirement: Domain-Scoped Route Sync Atomicity, VSX Coalescing Isolation, and Manual Prefix Parity

**ID**: REQ-TOPO-021\
**Intent**: Prevent premature whole-domain route freshness stamps, cross-domain VSX coalescing collisions, dropped list next-hops, and swallowed `ServerIdentityError` during topology operations.\
**Non-goals**: Base VSX bundle parsing (`REQ-TOPO-008`) or LPM candidate matching (`REQ-TOPO-011`).

`TopologyService` SHALL propagate `ServerIdentityError` in group enrichment, defer domain-level `("topology", "routes")` sync state until full-domain route collection completes, key repository VSX coalescing by `(mgmt_name, domain_name, node_key)` while preserving upstream errors, unwrap list-valued Gaia/CPMI `next-hop` objects, match space-containing VS names on error markers, and include `disposition="manual"` prefixes in `export_topology_prefixes(include_ignored=True)`.

#### Scenario: SCN-TOPO-021-1 — Full-domain route sync state, VSX domain coalescing, and fail-fast TLS identity propagation

- **GIVEN** a targeted `gateways=[...]` or partial multi-gateway route collection, concurrent VSX domains sharing a chassis, or a `ServerIdentityError` during group enrichment
- **WHEN** `collect_gateway_routes()` or `refresh_topology()` executes
- **THEN** targeted or aborted per-gateway runs SHALL NOT stamp whole-domain `("topology", "routes")` `status="ok"` prematurely
- **AND** repository VSX coalescing SHALL isolate by `(mgmt_name, domain_name, node_key)`, preserve upstream command errors instead of overwriting with `vsx_bundle_missing`, publish `auto`-probed bundles, and propagate `ServerIdentityError`

#### Scenario: SCN-TOPO-021-2 — List-valued next-hops, space-containing VS error markers, and manual prefix export

- **GIVEN** a Gaia/CPMI static route with a list-valued `next-hop`, a VS error marker whose name contains spaces, or `disposition="manual"` topology annotations
- **WHEN** topology normalization, VSX bundle parsing, or `export_topology_prefixes(include_ignored=True)` runs
- **THEN** list-valued `next-hop` entries SHALL be unwrapped, space-containing VS error markers SHALL populate `VsxBundleSlice.error`, and `export_topology_prefixes(include_ignored=True)` SHALL retain all `manual` prefixes and manual-only gateways
