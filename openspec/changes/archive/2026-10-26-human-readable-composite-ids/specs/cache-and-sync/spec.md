# Spec Delta

## ADDED Requirements

### Requirement: Human-Readable Composite Identifiers and Dual Topology Links

`CPObject` (`arodonata_objects`), `CPService` (`arodonata_services`), and `Asset` (`arodonata_assets`) SHALL keep `id = "{mgmt_name}:{domain_name}:{uid}"` as primary key while persisting non-unique indexed human-readable keys (`object_id`, `service_id`, `asset_id` formatted as `"{mgmt_name}:{domain_name}:{name}"`) and dual UID/human-readable parent-child links on `Asset` and `GroupMembershipNode`.

#### Scenario: Duplicate-named objects with distinct UIDs coexist with identical human-readable IDs

- **WHEN** a domain contains two Check Point objects or services with the same `name` (such as `email`) and different `uid` values
- **THEN** both rows SHALL be stored without collision under their distinct `id` primary keys (`"{mgmt_name}:{domain_name}:{uid}"`) while both expose the same indexed `object_id` or `service_id` (`"{mgmt_name}:{domain_name}:{name}"`)

#### Scenario: Cluster and cross-domain VSX assets populate both UID and human-readable parent/child links

- **WHEN** `ClusterRelationshipManager` and `VSXRelationshipManager` enrich gateway, cluster, cluster-member, VSX, and virtual-system assets (including a virtual system in a tenant domain hosted on a VSX gateway/cluster in another domain on the same `mgmt_name`)
- **THEN** child assets SHALL populate `parent_uid`, `parent_name`, `parent_id` (`"{mgmt_name}:{parent_domain}:{parent_uid}"`), and `parent_asset_id` (`"{mgmt_name}:{parent_domain}:{parent_name}"`), and parent cluster/VSX assets SHALL populate `member_uids`, `member_asset_ids`, `virtual_system_uids`, and `virtual_system_asset_ids`

#### Scenario: Group membership traversal includes human-readable group composite IDs

- **WHEN** `search_objects()` resolves containing parent groups for matched objects
- **THEN** each `GroupMembershipNode` in `SearchResult.memberships` SHALL include `id` (`"{mgmt_name}:{domain_name}:{uid}"`), `object_id` (`"{mgmt_name}:{domain_name}:{name}"`), `parent_uids`, and `parent_object_ids`
