# Spec Delta

## ADDED Requirements

### Requirement: Shorthand Object, Range, Domain, and Wildcard Application Expression Parsing

`arodonata.cpcrud` SHALL parse shorthand host, network, full or compressed-octet address-range, DNS-domain, service, inline group, and wildcard application expressions (`*domain` and `*.domain`) into canonical CPCRUD specifications using `NamingPrefixes` for newly created object names while preserving legacy defaults.

#### Scenario: Compressed same-subnet IPv4 address-range naming and shorthand range input

- **WHEN** `NamingPrefixes` has `address_range="Range_"`, `range_separator="_"`, and `compress_range_same_subnet=True`, and an expression or range object specifies `10.1.1.1` through `10.1.1.9` (including shorthand `10.1.1.1-9`)
- **THEN** the parser SHALL resolve bounds `("10.1.1.1", "10.1.1.9")` and `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"Range_10.1.1.1_9"`, while ranges across distinct `/24` prefixes (such as `10.1.1.1` to `10.1.2.9`) SHALL format as `"Range_10.1.1.1_10.1.2.9"`

#### Scenario: Legacy default NamingPrefixes behavior remains backward compatible

- **WHEN** `NamingPrefixes()` is instantiated with default arguments
- **THEN** `format_host("10.1.1.1")` SHALL return `"Host_10.1.1.1"`, `format_network("10.1.1.0", 24)` SHALL return `"Net_10.1.1.0_24"`, `format_address_range("10.1.1.1", "10.1.1.9")` SHALL return `"IPR_10.1.1.1-10.1.1.9"`, and `format_group("WebServers")` SHALL return `"grpWebServers"`

#### Scenario: Wildcard application expressions normalize both leading-star and star-dot syntax

- **WHEN** an operator supplies `*chinacloudapi.cn` or `*.chinacloudapi.cn` with `NamingPrefixes(app_site="Site_", app_site_wildcard_marker="_")`
- **THEN** `format_app_site("chinacloudapi.cn", is_wildcard=True)` SHALL return `"Site__chinacloudapi.cn"` (containing no `*` character) and the parsed `application-site` spec SHALL emit `primary-category: "Custom_Application_Site"`, `urls-defined-as-regular-expression: true`, and `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]`

#### Scenario: Group suffix and DNS domain shorthand expressions

- **WHEN** `NamingPrefixes(group="", group_suffix="_Grp")` formats group `"AppAccess"` or the parser evaluates `.abc.com`
- **THEN** `format_group("AppAccess")` SHALL return `"AppAccess_Grp"` (avoiding double suffix if already ending in `_Grp`), and `.abc.com` SHALL parse as `type: "dns-domain"`, `name: ".abc.com"`, and `is_sub_domain: true`

### Requirement: Incremental URL-List Updates and Value Reuse for Application-Site Objects

`CPCRUDService` SHALL accept `{"add": [...], "remove": [...]}` deltas on `application-site` `url-list` fields, compute idempotent `set-application-site` diffs, block removals that empty `url-list` without `application-signature`, and reuse pre-existing `application-site` objects matching by normalized URL list regardless of name.

#### Scenario: Adding and removing regex entries on an existing application-site

- **WHEN** `plan()` evaluates an `application-site` update for `"Site__chinacloudapi.cn"` currently containing `["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]` with `url-list: {"add": ["\\.partner\\.cn"], "remove": ["\\/chinacloudapi\\.cn"]}`
- **THEN** `Planner` SHALL produce `Outcome.UPDATE` (`set-application-site`) carrying the merged post-delta `url-list` (`["\\.chinacloudapi\\.cn", "\\.partner\\.cn"]`) and a `FieldChange` recording the prior and updated lists

#### Scenario: Removing the last URL from an application-site without an application signature fails closed

- **WHEN** `plan()` evaluates a `url-list: {"remove": [...]}` operation that removes every remaining entry from an `application-site` that lacks `application-signature`
- **THEN** `Planner` SHALL emit `Outcome.ERROR` explaining that an `application-site` cannot have an empty `url-list` without an `application-signature`

#### Scenario: Legacy-named application-site with identical URL list is reused on value conflict

- **WHEN** `on_ip_conflict="reuse"` is active and `plan()` evaluates `"Site__chinacloudapi.cn"` with `url-list: ["\\/chinacloudapi\\.cn", "\\.chinacloudapi\\.cn"]` while an existing object `"Custom_ChinaCloud"` already holds that identical URL list and regex flag
- **THEN** `Planner` SHALL produce `Outcome.REUSE` resolving `"Site__chinacloudapi.cn"` to `"Custom_ChinaCloud"` without renaming or duplicating the existing object

### Requirement: Incremental List-Cell Patching and Anti-Any-Widening Guards for Policy Rules

`CPCRUDService` SHALL support `{"add": [...], "remove": [...]}` mutations on list-valued policy rule fields (`source`, `destination`, `service`, `protected-scope`, `site-category`, `install-on`), enforce strict existence on `set`/`update`, block unsafe `"Any"` widening or collision, support `inverse()` rollback, and replicate these behaviors in `FileReplayApiMock`.

#### Scenario: Adding and removing sources, destinations, and services in an existing access rule

- **WHEN** `plan()` evaluates an `access-rule` with `operation: "set"`, `uid` (or `name`/`rule_number`), `source: {"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}`, and `service: {"add": ["TCP_8443"]}` where `"Host_10.1.1.1"` is created earlier in the same template
- **THEN** `Planner` SHALL plan `Outcome.UPDATE` (`set-access-rule`) with `depends_on` referencing the `"Host_10.1.1.1"` create action and incremental wire payloads (`{"add": ["Host_10.1.1.1"], "remove": ["Host_10.0.0.5"]}` on `source` and `{"add": ["TCP_8443"]}` on `service`), and `build_inverse_template()` SHALL generate a compensating `set-access-rule` restoring the dereferenced `prior_state`

#### Scenario: Removing all remaining objects from a rule traffic or install cell is rejected to prevent Any widening

- **WHEN** `plan()` evaluates an incremental `{"remove": [...]}` patch on `source`, `destination`, `service`, `protected-scope`, `site-category`, or `install-on` that would leave the resulting list empty
- **THEN** `Planner` SHALL emit `Outcome.ERROR` refusing to empty the cell (preventing Check Point from implicitly widening the rule to `"Any"`)

#### Scenario: Adding specific objects to a rule cell currently set to Any requires explicit removal of Any

- **WHEN** an existing rule has `source: ["Any"]` and `plan()` evaluates `source: {"add": ["Host_10.1.1.1"]}` without `"Any"` in `remove`
- **THEN** `Planner` SHALL emit `Outcome.ERROR` informing the caller that `"Any"` must be removed explicitly when narrowing a rule cell (and when `"Any"` IS explicitly listed in `remove`, `FieldChange.removed_items` SHALL record `["Any"]` while stripping `"Any"` from the Check Point wire `remove` array)

#### Scenario: Adding Any via an incremental rule delta is rejected

- **WHEN** `plan()` evaluates an incremental `{"add": ["Any"]}` delta on a policy rule list cell
- **THEN** `Planner` SHALL emit `Outcome.ERROR` refusing to add `"Any"` incrementally

#### Scenario: Unmatched rule with incremental cell deltas fails closed under any verb

- **WHEN** `plan()` evaluates a policy rule with `{"add": ...}` or `{"remove": ...}` cell deltas under `operation: "present"` (or omitted `operation` / `"set"`) and no existing rule matches
- **THEN** `Planner` SHALL emit `Outcome.ERROR` instead of falling back to `Outcome.CREATE` with `"Any"` traffic cells

#### Scenario: Explicit set or update operation targeting a missing rule, group, object, or service fails closed

- **WHEN** `plan()` evaluates an operation with `operation: "set"` or `operation: "update"` whose target rule, group, service, or object does not exist in the domain
- **THEN** `Planner` SHALL emit `Outcome.ERROR` reporting that the target does not exist rather than creating a new rule or object

#### Scenario: FileReplayApiMock applies incremental url-list and rule cell updates faithfully

- **WHEN** `FileReplayApiMock` processes `set-application-site` or `set-*-rule` with `{"add": [...], "remove": [...]}` patches or list replacements inside a work session
- **THEN** subsequent reads and `show-changes` inside the emulator SHALL reflect the updated URL list or dereferenced rule traffic members accurately
