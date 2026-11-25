# CPCRUD Declarative Policy-as-Code Engine Specification

## Purpose

Defines the declarative, idempotent Check Point Policy-as-Code CRUD service (`CPCRUDService`, `ArodonataClient.cpcrud`) and shorthand expression helpers for offline template validation, conflict-aware planning (`Plan`), dedicated-session execution and session staging (`ApplyReport`), and compensating rollback template generation across Security Management and MDSM domains.

## Requirements

### Requirement: Offline Template Schema Validation

**ID**: REQ-CPCRUD-001\
**Intent**: Reject malformed templates on the client before opening sessions or touching cache.\
**Non-goals**: Semantic or state-level conflicts (handled during planning, not schema validation).

`CPCRUDService.validate()` SHALL validate YAML/JSON templates against `checkpoint_ops_schema.json` (or `cpcrud_schema_path`) without making network or database calls.

#### Scenario: SCN-CPCRUD-001-1 — Invalid template returns errors offline

- **GIVEN** a template violating `checkpoint_ops_schema.json`
- **WHEN** `validate(template)` is called
- **THEN** it SHALL return a non-empty list of human-readable validation error strings
- **AND** perform zero API or database calls

### Requirement: Shorthand Object, Range, Domain, and Wildcard Application Expression Parsing

**ID**: REQ-CPCRUD-002\
**Intent**: Allow concise IP, address-range, DNS-domain, service, group, and wildcard-domain expressions with configurable naming conventions.\
**Non-goals**: Resolving live Check Point object conflicts or server-side existence (handled during planning).

`arodonata.cpcrud` SHALL parse shorthand host, network, full or compressed-octet address-range, DNS-domain, service, inline group, and wildcard application expressions (`*domain` and `*.domain`) into canonical CPCRUD specifications using `NamingPrefixes` for newly created object names while preserving legacy defaults.

#### Scenario: SCN-CPCRUD-002-1 — Compressed same-subnet IPv4 address-range naming and shorthand range input

- **GIVEN** `NamingPrefixes` configured with `address_range="Range_"`, `range_separator="_"`, and `compress_range_same_subnet=True`
- **WHEN** an expression or range object specifies `10.1.1.1` through `10.1.1.9` (including shorthand `10.1.1.1-9`) or a cross-`/24` range `10.1.1.1` through `10.1.2.9`
- **THEN** range parsing SHALL resolve bounds `("10.1.1.1", "10.1.1.9")` for `10.1.1.1-9`
- **AND** `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"Range_10.1.1.1_9"`
- **AND** `format_address_range("10.1.1.1", "10.1.2.9")` across distinct `/24` prefixes SHALL return `"Range_10.1.1.1_10.1.2.9"`

#### Scenario: SCN-CPCRUD-002-2 — Legacy default NamingPrefixes behavior remains backward compatible

- **GIVEN** `NamingPrefixes()` instantiated with default arguments
- **WHEN** default object names are formatted
- **THEN** `format_host("10.1.1.1")` SHALL return `"Host_10.1.1.1"`
- **AND** `format_network("10.1.1.0", 24)` SHALL return `"Net_10.1.1.0_24"`
- **AND** `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"IPR_10.1.1.1-10.1.1.9"`
- **AND** `format_group("WebServers")` SHALL return `"grpWebServers"`

#### Scenario: SCN-CPCRUD-002-3 — Wildcard application expressions normalize both leading-star and star-dot syntax

- **GIVEN** `NamingPrefixes(app_site="Site_", app_site_wildcard_marker="_")`
- **WHEN** an operator supplies `*chinacloudapi.cn` or `*.chinacloudapi.cn`
- **THEN** `format_app_site("chinacloudapi.cn", is_wildcard=True)` SHALL return `"Site__chinacloudapi.cn"` containing no `*` character
- **AND** the parsed `application-site` specification SHALL emit `primary-category: "Custom_Application_Site"`, `urls-defined-as-regular-expression: true`, and `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]`

#### Scenario: SCN-CPCRUD-002-4 — Group suffix and DNS domain shorthand expressions

- **GIVEN** `NamingPrefixes(group="", group_suffix="_Grp")`
- **WHEN** `format_group("AppAccess")` formats a group name or `.abc.com` is parsed as an object expression
- **THEN** `format_group("AppAccess")` SHALL return `"AppAccess_Grp"` without duplicating the suffix if already ending in `"_Grp"`
- **AND** `.abc.com` SHALL parse as `type: "dns-domain"`, `name: ".abc.com"`, and `is_sub_domain: true`

### Requirement: Two-Axis Conflict Resolution and Idempotent Planning

**ID**: REQ-CPCRUD-003\
**Intent**: Produce deterministic, side-effect-free execution plans that resolve name and value conflicts safely and fail closed on state-read errors.\
**Non-goals**: Opening write sessions or mutating Check Point state (handled during plan execution).

`CPCRUDService.plan()` SHALL record a `sid`-redacted `DomainStamp` per domain before state lookups, inspect domain state via an isolated per-run cache-first view gated by domain head freshness while maintaining intra-plan virtual overlay coherency across creations, updates, renames, and deletions, enforce the CPCRUD `type` allowlist and unique operation `id`s, evaluate `NameConflictPolicy` and `IpConflictPolicy`, compute `FieldChange` diffs, and return a deterministic `Plan`.

#### Scenario: SCN-CPCRUD-003-1 — Re-planning an already-applied template yields UNCHANGED or REUSE

- **GIVEN** a target domain where all desired objects, services, and rules already exist with matching attributes
- **WHEN** `CPCRUDService.plan(template)` runs against that domain
- **THEN** every `PlannedAction` SHALL have `Outcome.UNCHANGED` or `Outcome.REUSE`
- **AND** executing the resulting `Plan` in `apply()` SHALL require zero API write operations

#### Scenario: SCN-CPCRUD-003-2 — Value conflict with create_new auto-names object using NamingPrefixes

- **GIVEN** `on_ip_conflict="create_new"` is active
- **WHEN** a host, network, address-range, or service operation encounters an IP, subnet, range, or port/protocol match under a different name
- **THEN** `CPCRUDService.plan()` SHALL generate a convention-compliant name using `NamingPrefixes` (`Host_`, `Net_`, `IPR_`, `TCP_`, `UDP_`, `ICMP_` by default)

#### Scenario: SCN-CPCRUD-003-3 — Failed state lookup produces ERROR action rather than false CREATE

- **GIVEN** a domain where `show-last-published-session` fails, or a cache or API lookup (`dns-domain` leading-dot retry, name/IP lookup, service listing, rulebase read, or `where-used`) fails or returns `paging_inconsistent`
- **WHEN** `CPCRUDService.plan(template)` evaluates operations in that domain
- **THEN** it SHALL NOT treat the failure as "not found"
- **AND** it SHALL plan an `Outcome.ERROR` action (`lookup failed, nothing planned (re-plan to retry): ...`) with `sid`-redacted details
- **AND** it SHALL execute zero writes for that action and mark dependent actions as `skipped_dependency`

#### Scenario: SCN-CPCRUD-003-4 — Cache-first object and service lookups gated by exact domain head stamp

- **GIVEN** a target domain whose head `DomainStamp` (`last_published_at` and `last_session_uid`) was read at the start of `CPCRUDService.plan()`
- **WHEN** `plan()` looks up a `host`, `network`, `address-range`, `dns-domain`, `group`, or service
- **THEN** it SHALL read from the cached object or service store ONLY while the domain's stored sync state for that specific `(scope, item_type)` matches `DomainStamp.last_published_at` and `DomainStamp.last_session_uid`
- **AND** it SHALL fall back to live API queries otherwise

#### Scenario: SCN-CPCRUD-003-5 — Duplicate template operation IDs or unknown object types rejected

- **GIVEN** a template containing two operations with the same `id` or an `object_type` outside the canonical CPCRUD allowlist
- **WHEN** `CPCRUDService.plan(template)` runs
- **THEN** it SHALL raise `ValidationError` (or record a validation failure) rather than silently overwriting action results or constructing arbitrary `show-<type>` / `add-<type>` commands

#### Scenario: SCN-CPCRUD-003-6 — Intra-plan virtual overlay coherency across same-template updates, renames, and deletions

- **GIVEN** a template containing multiple sequential operations targeting the same `group`, `service-group`, network object (`host`, `network`, `application-site`, `dns-domain`), or service (`service-tcp`, `service-icmp`)
- **WHEN** an earlier step updates attributes, members, or name (`new-name`) or deletes an entity, and a subsequent step in the same `plan()` run looks up, modifies, deletes, or checks value conflicts against that entity or its prior/new values
- **THEN** `Planner` and `HybridStateReader` SHALL reflect the post-update model (including `group` and `service-group` members/metadata, object/service values, and renamed names) or deletion tombstone in the virtual overlay
- **AND** same-template updates or deletions of an earlier `CREATE` SHALL emit valid wire `"name"` identifiers instead of synthetic `"planned:"` UIDs
- **AND** a `set` targeting a virtually deleted entity SHALL fail closed with `Outcome.ERROR`, while a repeat identical update SHALL yield `Outcome.UNCHANGED`

### Requirement: Targeted Cold-Cache Value Conflict Lookups via show-objects

**ID**: REQ-CPCRUD-004\
**Intent**: Avoid expensive full-domain object and service pagination when planning against empty or stale domain caches.\
**Non-goals**: Cold-cache ICMP service value lookups (`REQ-CPCRUD-005`) or background cache synchronization.

When a domain's object or service cache slice is absent or stale during `CPCRUDService.plan()`, value-conflict lookups for `host`, `network`, `address-range`, `service-tcp`, and `service-udp` operations SHALL query `show-objects` (`type`, `filter`, `ip-only`) with exact attribute verification and intra-plan overlays instead of paginating `show-hosts`, `show-networks`, `show-services-tcp`, or `show-services-udp`.

#### Scenario: SCN-CPCRUD-004-1 — Cold-cache host and TCP service conflict checks avoid full domain listing

- **GIVEN** a target domain whose object and service cache slices are empty
- **WHEN** `CPCRUDService.plan()` evaluates `add` or `present` operations for a `host` (`10.20.30.40`) and a `service-tcp` (`port: "8443"`)
- **THEN** it SHALL query `show-objects` (`type="host"`, `filter="10.20.30.40"`, `ip-only=True`) and `show-objects` (`type="service-tcp"`, `filter="8443"`)
- **AND** it SHALL filter returned candidates by exact IP/port/protocol equality while merging intra-plan virtual additions and deletions
- **AND** it SHALL execute zero full-domain `show-hosts` or `show-services-tcp` queries

#### Scenario: SCN-CPCRUD-004-2 — Substring filter candidates are verified by exact value match

- **GIVEN** `show-objects` (`type="service-tcp"`, `filter="80"`) returns both `TCP_80` (`port="80"`) and `TCP_8080` (`port="8080"`)
- **AND** `show-objects` (`type="network"`, `filter="10.10.0.0"`, `ip-only=True`) returns both `10.10.0.0/24` and `10.10.0.0/16`
- **WHEN** `CPCRUDService.plan()` evaluates a value-conflict lookup for TCP port `"80"` or subnet `10.10.0.0/24`
- **THEN** it SHALL match only the candidate with exact `(port="80", protocol)` or exact `(subnet4="10.10.0.0", mask_length4=24)` equality

#### Scenario: SCN-CPCRUD-004-3 — Graceful fallback when custom ApiPort adapter does not implement show-objects

- **GIVEN** a cold-cache value lookup during `CPCRUDService.plan()`
- **WHEN** a custom or legacy `ApiPort` adapter returns `generic_err_command_not_recognized` for `show-objects`, or returns `paging_inconsistent` or a transport/API failure
- **THEN** `generic_err_command_not_recognized` SHALL fall back to type-scoped `show-hosts` / `show-networks` / `show-address-ranges` / `show-services-*` listing
- **AND** genuine API failures or `paging_inconsistent` errors SHALL still fail closed as `Outcome.ERROR` (`StateLookupError`)

### Requirement: Single-Page Cold-Cache ICMP Service Value Lookups

**ID**: REQ-CPCRUD-005\
**Intent**: Match built-in and custom ICMP services reliably on cold cache where `show-objects` text filters miss non-numeric names such as `echo-request`.\
**Non-goals**: Host, network, address-range, TCP, or UDP cold-cache lookups via `show-objects` (`REQ-CPCRUD-004`).

When a domain's service cache slice is absent or stale during `CPCRUDService.plan()`, ICMP value-conflict lookups SHALL query single-page `show-services-icmp` and `show-services-icmp6` listings (memoized per domain) instead of numeric text filtering on `show-objects`.

#### Scenario: SCN-CPCRUD-005-1 — Cold-cache ICMP lookup matches built-in services without numeric text filter

- **GIVEN** a target domain on cold cache where built-in `echo-request` does not contain `"8"` in its name
- **WHEN** `CPCRUDService.plan()` evaluates `add` or `present` for a `service-icmp` (`icmp-type: 8`, `icmp-code: 0`)
- **THEN** it SHALL query `show-services-icmp` (memoized per domain within the `plan()` run)
- **AND** it SHALL match `echo-request` by exact `(icmp_type, icmp_code)` equality

### Requirement: Declarative Lifecycle Support for Check Point Application-Site Objects

**ID**: REQ-CPCRUD-006\
**Intent**: Manage custom Check Point `application-site` objects end-to-end across validation, planning, rule references, and rollback.\
**Non-goals**: Incremental `url-list` add/remove patching and cross-name URL-list reuse (`REQ-CPCRUD-007`).

`CPCRUDService` SHALL validate, read, diff, plan (`add-application-site`, `set-application-site`, `delete-application-site`), and generate compensating `inverse()` rollback operations for Check Point `application-site` objects declared in `objects`, `services`, or `operations` sections, including `url-list` and `urls-defined-as-regular-expression` fields.

#### Scenario: SCN-CPCRUD-006-1 — Schema and semantic validation of application-site operations

- **GIVEN** an `application-site` operation in `objects`, `services`, or `operations` with `name`, `primary-category` (or `primary_category`), `url-list` (or `url_list`), and `urls-defined-as-regular-expression` (or `urls_defined_as_regular_expression`)
- **WHEN** `CPCRUDService.validate()` or `CPCRUDService.plan()` evaluates `application-site` operations
- **THEN** static validation SHALL succeed when `url-list` or `application-signature` is present, and reject `action="add"` operations omitting both
- **AND** static validation SHALL allow `present` metadata updates through, while `CPCRUDService.plan()` SHALL reject absent `present` targets that omit both `url-list` and `application-signature`

#### Scenario: SCN-CPCRUD-006-2 — Planning creation of a new regex application-site object

- **GIVEN** an absent `application-site` (`name: "Site_baidu.com"`, `primary-category: "Custom_Application_Site"`, `url-list: ["\\/baidu\\.com", "\\.baidu\\.com"]`, `urls-defined-as-regular-expression: true`)
- **WHEN** `CPCRUDService.plan()` evaluates a `present` or `add` operation for that object
- **THEN** it SHALL produce a `PlannedAction` with `Outcome.CREATE` and command `"add-application-site"`
- **AND** the action payload SHALL contain `"name"`, `"primary-category"`, `"url-list"`, and `"urls-defined-as-regular-expression": true`
- **AND** it SHALL register the resolved name for downstream `access-rule` `service` references

#### Scenario: SCN-CPCRUD-006-3 — Existing application-site with identical URL list and regex flag is planned as UNCHANGED

- **GIVEN** an `application-site` whose target name already exists in the domain with the same `primary-category`, the same set of URLs in `url-list`, and the same `urls-defined-as-regular-expression` boolean
- **WHEN** `CPCRUDService.plan()` evaluates the operation
- **THEN** it SHALL produce `Outcome.UNCHANGED` requiring zero write calls during `apply()`

#### Scenario: SCN-CPCRUD-006-4 — Existing application-site with different URL list respects NameConflictPolicy

- **GIVEN** an `application-site` whose target name already exists in the domain with a different `url-list` or `urls-defined-as-regular-expression` value
- **WHEN** `CPCRUDService.plan()` evaluates the operation under `on_name_conflict="error"` or `on_name_conflict="update"`
- **THEN** it SHALL produce `Outcome.ERROR` reporting `differs on [url-list]` when `on_name_conflict="error"`
- **AND** it SHALL produce `Outcome.UPDATE` with command `"set-application-site"` when `on_name_conflict="update"`

#### Scenario: SCN-CPCRUD-006-5 — Inverse rollback template restores or deletes application-site objects

- **GIVEN** a `Plan` (and optional `ApplyReport`) containing `CREATE`, `UPDATE`, or `DELETE` actions on `application-site` objects
- **WHEN** `CPCRUDService.inverse()` is called
- **THEN** it SHALL generate the corresponding compensating `delete`, `set`, or `add` `application-site` operation preserving `primary-category`, `url-list`, `urls-defined-as-regular-expression`, and `description`
- **AND** it SHALL order those operations after any dependent `access-rule` rollbacks

### Requirement: Incremental URL-List Updates and Value Reuse for Application-Site Objects

**ID**: REQ-CPCRUD-007\
**Intent**: Support safe partial `url-list` updates without clobbering concurrent entries and reuse existing `application-site` objects matching by URL set.\
**Non-goals**: Full-object creation, replacement, and deletion lifecycles for `application-site` (`REQ-CPCRUD-006`).

`CPCRUDService.plan()` SHALL accept `{"add": [...], "remove": [...]}` deltas on `application-site` `url-list` fields, compute idempotent `set-application-site` diffs, reject removals that leave `url-list` empty without `application-signature` (`DiffSafetyError` / `Outcome.ERROR`), and reuse pre-existing `application-site` objects matching by normalized URL list regardless of name.

#### Scenario: SCN-CPCRUD-007-1 — Adding and removing regex entries on an existing application-site

- **GIVEN** an existing `application-site` `"Site__chinacloudapi.cn"` containing `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]`
- **WHEN** `CPCRUDService.plan()` evaluates an update with `url-list: {"add": ["\\.partner\\.cn"], "remove": ["\\/chinacloudapi\\.cn"]}`
- **THEN** it SHALL produce `Outcome.UPDATE` (`set-application-site`) carrying the merged post-delta `url-list` (`["\\.chinacloudapi\\.cn", "\\.partner\\.cn"]`)
- **AND** it SHALL record a `FieldChange` capturing the prior and updated URL lists

#### Scenario: SCN-CPCRUD-007-2 — Removing the last URL from an application-site without an application signature fails closed

- **GIVEN** an existing `application-site` that lacks `application-signature`
- **WHEN** `CPCRUDService.plan()` evaluates a `url-list: {"remove": [...]}` delta that removes every remaining URL entry
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) explaining that an `application-site` cannot have an empty `url-list` without an `application-signature`

#### Scenario: SCN-CPCRUD-007-3 — Legacy-named application-site with identical URL list is reused on value conflict

- **GIVEN** `on_ip_conflict="reuse"` is active and an existing `application-site` `"Custom_ChinaCloud"` already holds `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]` with matching regex flag
- **WHEN** `CPCRUDService.plan()` evaluates `"Site__chinacloudapi.cn"` with that identical `url-list` and regex flag
- **THEN** it SHALL produce `Outcome.REUSE` resolving `"Site__chinacloudapi.cn"` to `"Custom_ChinaCloud"` without renaming or duplicating the existing object

### Requirement: Rule Identity Matching, Cleanup-Aware Positioning, and NAT Sentinels

**ID**: REQ-CPCRUD-008\
**Intent**: Match existing policy and NAT rules idempotently and prevent `"bottom"` insertions from landing below terminal cleanup rules.\
**Non-goals**: Incremental list-cell `add`/`remove` patching and anti-`"Any"`-widening guards (`REQ-CPCRUD-009`).

`CPCRUDService.plan()` SHALL resolve access, HTTPS, threat-prevention, and NAT rules by explicit key (`uid`, `name`, `rule_number`) or by traffic tuple, support cleanup-rule-aware `"bottom"` positioning, and normalize Check Point NAT `"Original"` and `"Any"` sentinel UIDs (`NAT_ORIGINAL_OBJECT_UID`, `NAT_ANY_OBJECT_UID`).

#### Scenario: SCN-CPCRUD-008-1 — Cleanup-aware bottom rule placement

- **GIVEN** a rulebase layer or section whose last rule is an `Any / Any / Any` cleanup rule
- **WHEN** `CPCRUDService.plan()` evaluates a new rule with `position="bottom"` or `position={"bottom": "<section>"}`
- **THEN** it SHALL anchor the new rule at `{"above": "<cleanup_rule_uid>"}` instead of placing it after the cleanup rule

#### Scenario: SCN-CPCRUD-008-2 — NAT rule traffic matching with Original sentinel normalization

- **GIVEN** a live NAT rulebase where Check Point dereferences untranslated fields to the `"Original"` sentinel UID (`NAT_ORIGINAL_OBJECT_UID`)
- **WHEN** a NAT rule with empty or `"Original"` `translated-*` fields is planned against that rulebase
- **THEN** `CPCRUDService.plan()` SHALL match `NAT_ORIGINAL_OBJECT_UID` as equivalent to no translation so re-applying the template reports `Outcome.UNCHANGED` rather than creating a duplicate rule

### Requirement: Incremental List-Cell Patching and Anti-Any-Widening Guards for Policy Rules

**ID**: REQ-CPCRUD-009\
**Intent**: Enable targeted member additions and removals on policy rule cells while preventing accidental rule widening to `"Any"` or silent rule creation.\
**Non-goals**: Rule position anchoring and NAT `"Original"` sentinel normalization (`REQ-CPCRUD-008`).

`CPCRUDService` SHALL support `{"add": [...], "remove": [...]}` deltas on list-valued policy rule fields (`source`, `destination`, `service`, `protected-scope`, `site-category`, `install-on`), enforce target existence on `set`/`update` and delta operations, block unsafe `"Any"` widening or collision (`DiffSafetyError` / `Outcome.ERROR`), generate `inverse()` rollbacks, and replicate these behaviors in `FileReplayApiMock`.

#### Scenario: SCN-CPCRUD-009-1 — Adding and removing sources, destinations, and services in an existing access rule

- **GIVEN** `"Host_10.1.1.1"` is created earlier in the same template and an `access-rule` exists in the target layer
- **WHEN** `CPCRUDService.plan()` evaluates `operation: "set"` with `uid` (or `name`/`rule_number`), `source: {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}`, and `service: {"add": ["TCP_8443"]}`
- **THEN** it SHALL plan `Outcome.UPDATE` (`set-access-rule`) with `depends_on` referencing the `"Host_10.1.1.1"` create action
- **AND** the wire payload SHALL carry incremental `{"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}` on `source` and `{"add": ["TCP_8443"]}` on `service`
- **AND** `CPCRUDService.inverse()` (`build_inverse_template()`) SHALL generate a compensating `set-access-rule` restoring the dereferenced `prior_state`

#### Scenario: SCN-CPCRUD-009-2 — Removing all remaining objects from a rule traffic or install cell is rejected to prevent Any widening

- **GIVEN** an existing policy rule with members in `source`, `destination`, `service`, `protected-scope`, `site-category`, or `install-on`
- **WHEN** `CPCRUDService.plan()` evaluates an incremental `{"remove": [...]}` patch that would leave that cell empty
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) refusing to empty the cell so Check Point cannot implicitly widen the rule to `"Any"`

#### Scenario: SCN-CPCRUD-009-3 — Adding specific objects to a rule cell currently set to Any requires explicit removal of Any

- **GIVEN** an existing policy rule with `source: ["Any"]`
- **WHEN** `CPCRUDService.plan()` evaluates `source: {"add": ["Host_10.1.1.1"]}` without `"Any"` in `remove`
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) requiring `"Any"` to be removed explicitly when narrowing a rule cell
- **AND** when `"Any"` IS explicitly listed in `remove`, `FieldChange.removed_items` SHALL record `["Any"]` while stripping `"Any"` from the Check Point wire `remove` array

#### Scenario: SCN-CPCRUD-009-4 — Adding Any via an incremental rule delta is rejected

- **GIVEN** an existing policy rule
- **WHEN** `CPCRUDService.plan()` evaluates an incremental `{"add": ["Any"]}` delta on a list-valued policy rule cell
- **THEN** it SHALL emit `Outcome.ERROR` (`DiffSafetyError`) refusing to add `"Any"` incrementally

#### Scenario: SCN-CPCRUD-009-5 — Unmatched rule with incremental cell deltas fails closed under any verb

- **GIVEN** no existing rule matches the target selector in the domain layer
- **WHEN** `CPCRUDService.plan()` evaluates a policy rule carrying `{"add": ...}` or `{"remove": ...}` cell deltas under `operation: "present"`, omitted `operation`, or `operation: "set"`
- **THEN** it SHALL emit `Outcome.ERROR` instead of falling back to `Outcome.CREATE` with `"Any"` traffic cells

#### Scenario: SCN-CPCRUD-009-6 — Explicit set or update operation targeting a missing rule, group, object, or service fails closed

- **GIVEN** a target rule, group, service, or object that does not exist in the domain
- **WHEN** `CPCRUDService.plan()` evaluates an operation with `operation: "set"` or `operation: "update"`
- **THEN** it SHALL emit `Outcome.ERROR` reporting that the target does not exist rather than creating a new rule or object

#### Scenario: SCN-CPCRUD-009-7 — FileReplayApiMock applies incremental url-list and rule cell updates faithfully

- **GIVEN** an active work session in `FileReplayApiMock`
- **WHEN** `FileReplayApiMock` processes `set-application-site` or `set-*-rule` with `{"add": [...], "remove": [...]}` patches or list replacements
- **THEN** subsequent reads and `show-changes` inside the emulator SHALL reflect the updated URL list or dereferenced rule traffic members accurately

### Requirement: Dedicated-Session Plan Execution and Stale-Plan Safeguards

**ID**: REQ-CPCRUD-010\
**Intent**: Execute planned writes atomically per domain only while the domain head matches the planned snapshot and guarantee session cleanup on failure.\
**Non-goals**: Retaining unpublished sessions for external approval or adopting staged sessions (`REQ-CPCRUD-011`).

`CPCRUDService.apply()` and `stream_apply()` SHALL execute only allowlisted `(object_type, operation)` commands in an isolated `WriteSession` per domain (defaulting omitted session names to `arodonata-cpcrud*`), re-verify the `DomainStamp` head before each pass and pre-`publish`, shield `discard` before `logout` on any `BaseException`, and invalidate domain caches post-`publish`.

#### Scenario: SCN-CPCRUD-010-1 — Stale plan abort when domain published after planning

- **GIVEN** a `Plan` recording a `DomainStamp` for a target domain
- **WHEN** `apply(plan, force=False)` or `stream_apply(plan, force=False)` runs on the initial pass, on any `retry_remaining` pass, or pre-`publish`
- **AND** the domain's `show-last-published-session` UID or `last_published_at` differs from `DomainStamp` (including `None -> published` or unreadable head)
- **THEN** `CPCRUDService` SHALL mark all remaining actions in that domain as `Outcome.PLAN_STALE`
- **AND** it SHALL discard any uncommitted write session if staleness is detected pre-`publish`
- **AND** it SHALL publish zero writes in that domain

#### Scenario: SCN-CPCRUD-010-2 — Forged or unlisted action command rejected before execution

- **GIVEN** a `Plan` containing a `PlannedAction` whose `(object_type, operation)` is outside the canonical CPCRUD command allowlist or whose `command` field disagrees with that allowlist
- **WHEN** `apply(plan)` or `stream_apply(plan)` is called
- **THEN** `CPCRUDService` SHALL raise `ValidationError` before opening a session or sending any Web API call

#### Scenario: SCN-CPCRUD-010-3 — Unhandled exception, cancellation, or publish failure discards uncommitted session before logout

- **GIVEN** an open domain write session during `apply()` or `stream_apply()` (unless `no_publish=True` and `keep_session=True` completed cleanly or recorded the staged session prior to error)
- **WHEN** an unhandled exception, `asyncio.CancelledError`, or `publish` transport/task failure occurs
- **THEN** `CPCRUDService` SHALL shield `discard` followed by `logout_sid` in `finally` so no uncommitted changes or object locks remain orphaned on the management server
- **AND** when `keep_session=True` is active, any opened staged session SHALL be recorded as soon as the session is created

#### Scenario: SCN-CPCRUD-010-4 — Post-publish domain cache invalidation and retry_remaining folding

- **GIVEN** `apply()` publishes changes in a domain or runs additional passes when `retry_remaining > 0`
- **WHEN** a domain `publish` succeeds or retry passes execute remaining failed actions
- **THEN** `client.invalidate_domain(mgmt_name, domain_name)` SHALL be called after `publish` so subsequent reads re-synchronize the domain
- **AND** each `retry_remaining` pass SHALL re-verify domain head freshness (never forcing `force=True` automatically) and fold its `ApplyReport` into the cumulative `ApplyReport`

### Requirement: Non-Disruptive Staged Session Retention, Adoption, Publish, and Discard

**ID**: REQ-CPCRUD-011\
**Intent**: Support external review and delayed commit/rollback of staged Web API sessions without disrupting SmartConsole or foreign administrator sessions.\
**Non-goals**: Immediate single-pass `apply()` publication (`REQ-CPCRUD-010`) or compensating template generation (`REQ-CPCRUD-012`).

`CPCRUDService` and `ArodonataClient` SHALL support `no_publish=True, keep_session=True` session staging (`arodonata-cpcrud-staged`) and `publish_staged_session`, `stream_publish_staged_session`, and `discard_staged_session` adoption only after `show-session` provenance verification, defaulting to non-disruptive `take-over-session` and disconnecting active sessions only under explicit `force_disconnect=True`.

#### Scenario: SCN-CPCRUD-011-1 — Keep-session staging mode preserves unpublished session for external workflow

- **GIVEN** an executable `Plan`
- **WHEN** `apply(plan, no_publish=True, keep_session=True)` or `stream_apply(plan, no_publish=True, keep_session=True)` is called
- **THEN** `CPCRUDService` SHALL assign a default `arodonata-cpcrud-staged` session name when none was supplied
- **AND** it SHALL leave the dedicated write session open without publishing
- **AND** it SHALL record `StagedSessionInfo` (`sid`, `server_ip`, `session_uid`, `session_name`, `sid` redacted in `repr()`/logs) in `ApplyReport.staged_sessions` and the internal `Executor._staged_sessions` LRU registry (256 entries) upon creation
- **AND** `stream_apply()` SHALL emit a `StagedSessionEvent`

#### Scenario: SCN-CPCRUD-011-2 — Staged session publication adopts ownership via take-over-session and invalidates domain cache

- **GIVEN** a previously staged open Web API session identified by `session_uid`
- **WHEN** `await client.publish_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` or `client.stream_publish_staged_session(...)` is called
- **THEN** the service SHALL reuse a caller-supplied `sid` directly when `show-session {}` confirms `uid == session_uid` in an open state
- **AND** otherwise it SHALL open a dedicated `arodonata-cpcrud-adopt` helper session and read `show-session {}` (`initial_uid`, `current_user`)
- **AND** it SHALL verify via `show-session {"uid": session_uid}` that the target session is open and eligible (`keep_session=True` registry, `arodonata*` name, `expected_session_name`, or same-user `WEB_API` when `allow_foreign=False`)
- **AND** when adopting via helper session, it SHALL issue `take-over-session` (`{"uid": session_uid}`) omitting `disconnect-active-session` unless `force_disconnect=True`
- **AND** it SHALL fall back to `switch-session` only after provenance verification passes, reporting both errors if both fail
- **AND** it SHALL immediately discard the detached helper session via `discard {"uid": initial_uid}` so no empty helper session remains open
- **AND** it SHALL execute `publish` while polling task progress, log out cleanly, and call `client.invalidate_domain(mgmt_name, domain)`

#### Scenario: SCN-CPCRUD-011-3 — Staged session discard adopts ownership via take-over-session before discarding

- **GIVEN** an open or orphaned staged session identified by `session_uid`
- **WHEN** `await client.discard_staged_session(mgmt_name, domain, session_uid=session_uid, ...)` is called
- **THEN** the service SHALL reuse an active matching `sid` when `show-session {}` confirms `uid == session_uid`, or verify open Web API / Arodonata provenance via an `arodonata-cpcrud-adopt` helper session
- **AND** when adopting via helper session, it SHALL issue non-disruptive `take-over-session` (`disconnect-active-session` omitted/`False` unless `force_disconnect=True`)
- **AND** it SHALL fall back to `switch-session` only after provenance verification passes, reporting both errors if both fail
- **AND** it SHALL discard the detached `arodonata-cpcrud-adopt` helper session via `discard {"uid": initial_uid}`
- **AND** it SHALL execute `discard` on the adopted session and log out cleanly

#### Scenario: SCN-CPCRUD-011-4 — Foreign, active SmartConsole, or already-finalized session UID refused during staged adoption

- **GIVEN** a `session_uid` belonging to a SmartConsole session, another user's Web API session (`allow_foreign=False`), a mismatched `expected_session_name`, an already published/discarded session, or an active session when `force_disconnect=False`
- **WHEN** `publish_staged_session`, `stream_publish_staged_session`, or `discard_staged_session` is called
- **THEN** the service SHALL refuse foreign, SmartConsole (`application` outside `""`/`"web_api"`/`"arodonata"`), or finalized sessions before issuing `take-over-session` or `switch-session`
- **AND** when `force_disconnect=False`, `take-over-session` SHALL omit `disconnect-active-session` so an active holder is never forcibly disconnected
- **AND** it SHALL log out any fresh helper session cleanly and return a failed `ApiCallResult` (or failure event)

### Requirement: Compensating Rollback Template Generation

**ID**: REQ-CPCRUD-012\
**Intent**: Build safe, schema-valid rollback templates that invert only confirmed mutations using concrete server UIDs and captured prior state.\
**Non-goals**: Executing the generated rollback template against Check Point (performed via a separate `plan()` and `apply()` run).

`CPCRUDService.inverse(plan, report)` (and `build_inverse_template()`) SHALL build a schema-valid compensating template from `Plan` and `ApplyReport`, inverting only actions that actually succeeded when `report` is supplied, targeting created objects by the concrete `uid` returned in `ApplyReport` (refusing unsafe delete-by-name for unexecuted `planned:` UIDs), and restoring all mutated fields present in `PlannedAction.prior_state`.

#### Scenario: SCN-CPCRUD-012-1 — Inverse template restores deleted and updated objects and removes created ones

- **GIVEN** a `Plan` and an `ApplyReport` from an apply pass where some actions succeeded and others failed or were skipped/stale
- **WHEN** `CPCRUDService.inverse(plan, report)` is called
- **THEN** it SHALL return a dictionary valid against `checkpoint_ops_schema.json` containing compensating operations ONLY for actions that succeeded in `report`
- **AND** it SHALL delete `CREATE` actions strictly by the concrete `uid` recorded in `report` (skipping any `CREATE` that lacks a real created UID)
- **AND** it SHALL restore all prior field values from `prior_state` for `UPDATE` actions and re-create `DELETE` actions from `prior_state`

### Requirement: Public CPCRUDService Options and Package Helper Exports

**ID**: REQ-CPCRUD-013\
**Intent**: Expose configurable conflict policies, naming overrides, schema path overrides, and pure helper primitives cleanly across `CPCRUDService` and `arodonata.cpcrud`.\
**Non-goals**: Internal multi-action plan execution semantics (`REQ-CPCRUD-010`, `REQ-CPCRUD-011`).

`CPCRUDService` SHALL support `schema_path=` on `validate()` and `on_name_conflict=`, `on_ip_conflict=`, `naming_prefixes=`, and `validate_schema=` on `plan()`, while `arodonata.cpcrud` SHALL export typed models (`Plan`, `PlannedAction`, `ApplyReport`, `ActionResult`, `StagedSessionInfo`, `NamingPrefixes`), enums (`Outcome`, conflict policies), and pure helper primitives.

#### Scenario: SCN-CPCRUD-013-1 — CPCRUDService.validate and plan accept explicit schema, policy, and naming overrides

- **WHEN** callers invoke `CPCRUDService.validate(template, schema_path=...)` and `CPCRUDService.plan(template, on_name_conflict=..., on_ip_conflict=..., naming_prefixes=..., validate_schema=False)`
- **THEN** `validate()` SHALL validate against the explicit `schema_path` offline
- **AND** `plan()` SHALL honor the per-call conflict policies, naming prefixes, and `validate_schema` toggle

### Requirement: Per-Rulebase Track Wire Encoding, Fail-Closed Defaults, and Validation Parity

**ID**: REQ-CPCRUD-014\
**Intent**: Ensure CPCRUD schema validation, planning, and rollback match Check Point Web API wire formats, fail-closed rule defaults, and anti-widening invariants across all rulebase types.\
**Non-goals**: Base shorthand expression parsing (`REQ-CPCRUD-002`) or rule list-cell patch syntax (`REQ-CPCRUD-009`).

`CPCRUDService` SHALL encode `track` as a settings object (`{"type": ...}`) for `access` rules and a plain string for `https`/`threat` rules, default omitted rule actions fail-closed (`"Drop"` for `access`, `"Inspect"` for `https`, `"Optimized"` for `threat`), reject empty list replacements (`[]`, `""`, `[""]`) and `default_any` coercion on `install-on`, and infer omitted `type` with `operation > state > action` precedence and `check_where_used` schema support during `validate()`.

#### Scenario: SCN-CPCRUD-014-1 — Access vs HTTPS/Threat track wire encoding and sub-field diffs

- **GIVEN** an existing `access`, `https`, or `threat` rule in Check Point
- **WHEN** `CPCRUDService.plan()` and `execute()` create, update, or roll back rules with `track` settings (including `accounting`, `per-session`, `per-connection`, `alert`, or `enable-firewall-session` on `access` rules)
- **THEN** `access` rule payloads SHALL encode `track` as a `TrackSettingsForRequest` object and detect sub-field diffs while `https` and `threat` payloads SHALL encode `track` as a plain string
- **AND** compensating rollback templates SHALL preserve the prior `track` object or string wire representation

#### Scenario: SCN-CPCRUD-014-2 — Fail-closed rule defaults, install-on anti-Any guard, and empty-list rejection

- **GIVEN** a CPCRUD rule operation omitting `rule_action`/`action`, omitting `install-on`, or attempting an empty list replacement (`[]`, `""`, `[""]`)
- **WHEN** `CPCRUDService.validate()` or `plan()` evaluates the rule operation
- **THEN** omitted rule actions SHALL resolve fail-closed to `"Drop"` (`access`), `"Inspect"` (`https`), or `"Optimized"` (`threat`) identically across planning and unnamed-rule traffic matching
- **AND** `install-on` SHALL NOT default to `"Any"`, empty list replacements SHALL fail with `ValidationError` / `DiffSafetyError`, and `is_cleanup_rule` SHALL require `Any`/`Any`/`Any` traffic even when `"cleanup"` appears in the rule name

#### Scenario: SCN-CPCRUD-014-3 — Offline validation parity, multi-target state continuity, and NAT/resolved-object parity

- **GIVEN** a multi-target CPCRUD template with omitted `type` on rules/groups, `check_where_used: true`, or NAT/access rules carrying `_resolved_objects`
- **WHEN** `CPCRUDService.validate()` and `plan()` execute across multiple targets referencing the same domain
- **THEN** `validate()` SHALL infer default types, apply `operation > state > action` precedence, and accept `check_where_used`
- **AND** `plan()` SHALL preserve failure propagation, name resolutions, and `depends_on` edges across targets on the same domain while passing resolved object dictionaries to NAT and traffic-tuple helpers

### Requirement: Hardened Staged Session Lifecycle, Provenance, and Placeholder-Free Rollback

**ID**: REQ-CPCRUD-015\
**Intent**: Prevent dedicated session leaks, stale staged publishes, synthetic UID leaks in rollback templates, and dead provenance checks in staged CPCRUD workflows.\
**Non-goals**: Base staged session registry persistence (`REQ-CPCRUD-011`) or compensating rollback ordering (`REQ-CPCRUD-012`).

`CPCRUDService` SHALL shield staged-session `logout_sid` cleanup under cancellation and `ServerIdentityError`, verify domain-head freshness before publishing staged sessions, align `arodonata*` session provenance checks with `REQ-CPCRUD-011`, strip synthetic `planned:` UIDs from rollback `UPDATE` operations, and restore parent-group memberships and `service-group` rollbacks accurately.

#### Scenario: SCN-CPCRUD-015-1 — Staged session cleanup shields cancellation and verifies head staleness before publish

- **GIVEN** an active or adopted staged `CPCRUDService` session (`publish_staged_session`, `discard_staged_session`, or `execute(..., keep_session=True)`)
- **WHEN** `asyncio.CancelledError` or `ServerIdentityError` interrupts registration, adoption, publish, or discard, OR the domain published head changed since staging
- **THEN** temporary/owned sessions SHALL be logged out via shielded `logout_sid` cleanup without leaking open Check Point sessions
- **AND** `publish_staged_session` SHALL reject stale domain heads when `allow_stale=False` and enforce consistent `arodonata*` provenance rules

#### Scenario: SCN-CPCRUD-015-2 — Rollback templates strip synthetic planned UIDs and invert group/service-group mutations

- **GIVEN** a CPCRUD plan that creates and subsequently updates an entity in the same run (`planned:<type>:<name>`), modifies group memberships, or modifies a `service-group`
- **WHEN** `CPCRUDService.inverse()` generates a compensating rollback template
- **THEN** rollback `UPDATE` operations SHALL omit synthetic `planned:` UIDs rather than emitting placeholder identifiers
- **AND** group and `service-group` rollbacks SHALL restore prior parent-group memberships and route `service-group` inversions to the group inverter

### Requirement: Unified CPCRUD State-Reader Lookups, Single-Pass Planning, and Split Differ/Executor/Inverse Helpers

**ID**: REQ-CPCRUD-016\
**Intent**: Eliminate behavioral drift across mirrored CPCRUD object/service lookup mixins, duplicated staged-session finalizers, repeated inverse helpers, duplicated step collection, and high-branching diff functions.\
**Non-goals**: Base CPCRUD expression evaluation (`REQ-CPCRUD-002`) or staged session registry persistence (`REQ-CPCRUD-011`).

`HybridStateReader` SHALL consolidate cache/overlay/live lookup helpers in `_HybridStateReaderBase` (with exact service-name checks), `Planner.decide` SHALL cache target steps in `_DomainPlanState`, `differ.py` SHALL delegate to per-type diff helpers, and `Executor`/`inverse.py` SHALL share staged-session and prior-field helpers.

#### Scenario: SCN-CPCRUD-016-1 — Unified state reader enforces exact service name match and shared staged/inverse helpers preserve semantics

- **GIVEN** a `HybridStateReader` service lookup where cache returns a mismatched service name, an adopted staged session interrupted by error or cancellation, or an inverse rollback over prior fields
- **WHEN** `get_service_by_name()`, `stream_publish_staged_session()`, `discard_staged_session()`, or `CPCRUDService.inverse()` executes
- **THEN** `get_service_by_name()` SHALL reject mismatched service names identically to `get_object_by_name()`
- **AND** adopted staged operations SHALL shield `logout_sid` cleanup through one shared runner, and `inverse()` SHALL copy prior fields uniformly via shared helpers

#### Scenario: SCN-CPCRUD-016-2 — Single-pass planner step collection and split object/rule differs maintain exact plan parity

- **GIVEN** a multi-target CPCRUD template modifying hosts, networks, ranges, application sites, NAT rules, and policy rules
- **WHEN** `Planner.decide()`, `compute_object_diff()`, and `compute_rule_diff()` compute actions
- **THEN** `_collect_ordered_steps` SHALL be evaluated at most once per target during `Planner.decide()` with per-domain state stored in `_DomainPlanState`
- **AND** per-type object and rule diff helpers SHALL produce identical actions and field diffs across every entity and rulebase type
