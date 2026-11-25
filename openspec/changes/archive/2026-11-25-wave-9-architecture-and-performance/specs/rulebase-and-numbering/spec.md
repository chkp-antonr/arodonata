# Spec Delta

## ADDED Requirements

### Requirement: Precomputed Group and Pattern Index for Rulebase Filtering

**ID**: REQ-RULE-008\
**Intent**: Eliminate quadratic `O(R * T * (|O| + |S|))` group-graph rebuilding and IP/CIDR re-parsing on the event loop during local rulebase filtering.\
**Non-goals**: Remote Check Point server-side rulebase search or SmartConsole rule numbering rules (`REQ-RULE-004`).

`filter_numbered_rulebase` SHALL precompute query IP/CIDR tokens, object and service `reverse_parents` membership graphs, and per-token matching identifier sets once per invocation and reuse them across all evaluated rules while preserving identical match results for both `filter_numbered_rulebase` and direct `rule_matches_filter` callers.

#### Scenario: SCN-RULE-008-1 — Precomputed rulebase filter index preserves exact match parity in linear group-graph time

- **GIVEN** a numbered rulebase with nested object/service groups and IP/CIDR or name filter tokens
- **WHEN** `filter_numbered_rulebase()` evaluates all rules alongside direct `rule_matches_filter()` calls on individual rules
- **THEN** `filter_numbered_rulebase()` SHALL build the object and service membership graphs at most once rather than per rule
- **AND** matched rule UIDs and ordering SHALL match direct `rule_matches_filter()` evaluation identically across nested group, IP, CIDR, range, and wildcard tokens
