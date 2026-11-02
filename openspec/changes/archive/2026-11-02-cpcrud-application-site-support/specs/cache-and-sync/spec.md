# cache-and-sync Delta Specification

## ADDED Requirements

### Requirement: On-Demand Application-Site Object Model and Synchronization

`CPObject` and `ObjectService` SHALL support Check Point `application-site` objects on demand via `show-application-site` and `show-application-sites`, hydrating `primary_category`, `url_list`, and `urls_defined_as_regular_expression` fields from Check Point API responses and cached `raw_data`.

#### Scenario: CPObject hydrates application-site URL list and regex flag from Check Point dict and DB cache

- **WHEN** `CPObject.from_cp_dict()` or `SqlCacheAdapter` hydrates a Check Point `application-site` payload containing `primary-category`, `url-list`, and `urls-defined-as-regular-expression`
- **THEN** the resulting `CPObject` instance SHALL expose `type == "application-site"`, `primary_category`, `url_list` as `list[str]`, and `urls_defined_as_regular_expression` as `bool | None`

#### Scenario: On-demand refresh and query of application-site objects

- **WHEN** `refresh_objects(types=["application-site"])` or `get_objects(types=["application-site"])` is invoked
- **THEN** `ObjectService` SHALL query Check Point using `show-application-sites` (and `show-application-site` for single-item lookups), persist the rows in `arodonata_objects` with `item_type="application-site"` in `arodonata_domain_sync_state`, and return the hydrated `CPObject` entries
