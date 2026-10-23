# Rulebase Introspection, Caching, and Numbering Specification Delta

## MODIFIED Requirements

### Requirement: Session-Aware Atomic Rulebase Snapshot Refresh

`RulebaseRefreshService` (`refresh_rulebases`, `stream_refresh_rulebases`) SHALL refresh a domain's entire rulebase snapshot (`rulebase_access`, `rulebase_nat`, `rulebase_https`, `rulebase_threat`, `rulebase_layer`, `rulebase_section`, `rulebase_package_layer`) and `domain_sync_state` (`scope="rulebase"`) in a single atomic transaction protected by a per-domain distributed lock, tracking freshness against the domain's last published session UID.

#### Scenario: Refusal to refresh when shared session is dirty

- **WHEN** `refresh_rulebases` runs for a domain whose shared API session currently holds unpublished changes or object locks (`number-of-published-changes` / `locks` non-zero)
- **THEN** the refresh for that domain SHALL refuse to proceed with a `dirty session` error, preserve any existing cached rulebase snapshot, and mark `domain_sync_state.status = "failed"` (`scope="rulebase"`) with `last_error`

#### Scenario: Complete traversal of packages, ordered layers, inline layers, and global placeholders

- **WHEN** `refresh_rulebases` reads a clean domain
- **THEN** it SHALL fetch `show-packages`, the NAT rulebase of every package with `nat-policy`, every access/HTTPS/threat layer reachable from packages, layer listings, or inline-layer rule references, and for any global layer containing a domain `place-holder`, query the global layer with `package` context to resolve the parent rule and nested domain layer, replacing the domain's snapshot atomically under the domain lock

#### Scenario: Rulebase pager merges split sections across page boundaries

- **WHEN** `rulebase/pager.py` pages `show-*-rulebase` in chunks of up to 100 rules and Check Point repeats a `rulebase-section` header across two consecutive pages
- **THEN** the pager SHALL merge the split section into a single section entry containing all of its rules in order and recover empty trailing sections
