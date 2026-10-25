# Spec Delta: Rulebase Introspection, Caching, and Numbering

## MODIFIED Requirements

### Requirement: Session-Aware Atomic Rulebase Snapshot Refresh

`RulebaseRefreshService` (`refresh_rulebases`, `stream_refresh_rulebases`) SHALL refresh a domain's entire rulebase snapshot (`arodonata_rulebase_access`, `arodonata_rulebase_nat`, `arodonata_rulebase_https`, `arodonata_rulebase_threat`, `arodonata_rulebase_layer`, `arodonata_rulebase_section`, `arodonata_rulebase_package_layer`) and `arodonata_domain_sync_state` (`scope="rulebase"`) in a single atomic database transaction protected by a per-domain distributed lock with periodic heartbeat renewal, tracking freshness against the domain's last published session UID and preserving `last_published_at=None` for never-published domains.

#### Scenario: Refusal to refresh when shared session is dirty

- **WHEN** `refresh_rulebases` runs for a domain whose shared API session currently holds unpublished changes or object locks (`number-of-published-changes` / `locks` non-zero) or where `show-session` fails
- **THEN** the refresh for that domain SHALL refuse to proceed (failing closed on `show-session` error), preserve any existing cached rulebase snapshot, and mark `arodonata_domain_sync_state.status = "failed"` (`scope="rulebase"`) with SID-redacted `last_error`

#### Scenario: Complete traversal of packages, ordered layers, inline layers, and global placeholders

- **WHEN** `refresh_rulebases` reads a clean domain
- **THEN** it SHALL fetch `show-packages`, the NAT rulebase of every package with `nat-policy`, every access/HTTPS/threat layer reachable from packages, layer listings, or inline-layer rule references, and for any global layer containing a domain `place-holder`, query the global layer with `package` context to resolve the parent rule and nested domain layer, replacing the domain's snapshot rows across `arodonata_rulebase_*` AND updating `arodonata_domain_sync_state` inside a single atomic database transaction under a renewed domain lock

#### Scenario: Rulebase pager merges split sections across page boundaries

- **WHEN** `rulebase/pager.py` pages `show-*-rulebase` in chunks of up to 100 rules and Check Point repeats a `rulebase-section` header across two consecutive pages
- **THEN** the pager SHALL merge the split section into a single section entry containing all of its rules in order and recover empty trailing sections
