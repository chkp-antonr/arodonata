# Spec Delta

## ADDED Requirements

### Requirement: WriteSession Cache Isolation, Server-Scoped CLI Targets, Canonical Annotations, and Zero-Prefix Routes

**ID**: REQ-TOPO-023\
**Intent**: Prevent uncommitted `WriteSession` overlays from leaking into persistent SQL topology caches, enforce clean-session checks on targeted gateway refreshes, avoid cross-management CLI target leakage, match all canonical annotation IDs, and preserve `/0` default routes.\
**Non-goals**: Coalescing leader error isolation (`REQ-TOPO-022`) or LPM penalty scoring (`REQ-TOPO-010`).

`TopologyService` SHALL skip SQL persistence during active `WriteSession` resolution, enforce clean sessions on targeted refresh, scope CLI target resolution to `gateway_asset.mgmt_name`, match all four canonical IDs in annotations, and preserve zero-length route prefixes.

#### Scenario: SCN-TOPO-023-1 — WriteSession SQL cache isolation, server-scoped CLI targets, canonical annotation IDs, and zero-prefix route normalization

- **GIVEN** an active `WriteSession` during on-demand topology object resolution, a targeted gateway refresh, multi-MDS cluster/VSX assets during `resolve_gateway_cli_targets()`, topology annotations using UID or composite IDs, or a static route with `mask-length: 0`
- **WHEN** topology resolution, targeted refresh, annotation lookup, or normalizer route parsing runs
- **THEN** on-demand object/global resolutions SHALL NOT write to persistent SQL tables under an active `WriteSession`, targeted refresh SHALL call `verify_session_clean()`, CLI targets SHALL be scoped to `gateway_asset.mgmt_name`, annotations SHALL match all 4 canonical keys, and `mask-length: 0` SHALL normalize to prefix `/0`
