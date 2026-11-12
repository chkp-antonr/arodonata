# Spec Delta: CPCRUD Declarative Policy-as-Code Engine

## ADDED Requirements

### Requirement: Targeted Cold-Cache Value Conflict Lookups During Planning

When a domain's object or service cache slice is not stamped fresh during `CPCRUDService.plan()`, value-conflict lookups for hosts, networks, address ranges, and TCP/UDP services SHALL query `show-objects` (`type`, `filter`, `ip-only`) with exact attribute verification and intra-plan overlays instead of paginating `show-hosts`, `show-networks`, or `show-services-tcp` / `show-services-udp`, while ICMP value lookups SHALL use single-page `show-services-icmp` / `show-services-icmp6` listing.

#### Scenario: Cold-cache ICMP lookup matches built-in services without numeric text filter

- **WHEN** `CPCRUDService.plan()` evaluates `add` / `present` for a `service-icmp` (`icmp-type: 8`, `icmp-code: 0`) on cold cache where built-in `echo-request` does not contain `"8"` in its name
- **THEN** the planner SHALL query `show-services-icmp` (memoized per domain) and match `echo-request` by exact `(icmp_type, icmp_code)` equality

#### Scenario: Cold-cache host and TCP service conflict checks avoid full domain listing

- **WHEN** `CPCRUDService.plan()` evaluates `add` / `present` operations for a `host` (`10.20.30.40`) and a `service-tcp` (`port: "8443"`) in a domain whose `arodonata_objects` and `arodonata_services` caches are empty
- **THEN** the planner SHALL query `show-objects` (`type="host"`, `filter="10.20.30.40"`, `ip-only=True`) and `show-objects` (`type="service-tcp"`, `filter="8443"`), filter returned candidates by exact IP/port/protocol equality while merging intra-plan virtual additions/deletions, and execute zero full-domain `show-hosts` or `show-services-tcp` queries

#### Scenario: Substring filter candidates are verified by exact value match

- **WHEN** Check Point `show-objects` (`type="service-tcp"`, `filter="80"`) returns both `TCP_80` (`port="80"`) and `TCP_8080` (`port="8080"`), or `show-objects` (`type="network"`, `filter="10.10.0.0"`, `ip-only=True`) returns both `10.10.0.0/24` and `10.10.0.0/16`
- **THEN** the planner SHALL match only the candidate with exact `(port="80", protocol)` or exact `(subnet4="10.10.0.0", mask_length4=24)` equality

#### Scenario: Graceful fallback when custom ApiPort adapter does not implement show-objects

- **WHEN** a custom or legacy `ApiPort` adapter returns `generic_err_command_not_recognized` for `show-objects` during a cold-cache value lookup, or returns `paging_inconsistent` / transport failure
- **THEN** `generic_err_command_not_recognized` SHALL fall back to type-scoped `show-hosts` / `show-services-*` listing, whereas genuine API or `paging_inconsistent` errors SHALL still fail closed as `Outcome.ERROR` (`StateLookupError`)
