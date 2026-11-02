# Design

## Context

See `proposal.md` for motivation and scope.

Check Point Management API represents custom URL/application filtering sites as `application-site` objects (`show-application-site`, `show-application-sites`, `add-application-site`, `set-application-site`, `delete-application-site`). In Unified Access Control layers, `application-site` objects are referenced in the `service` list of an `access-rule`.

In `arodonata` v2:

- `arodonata_objects` (`CPObject`) already supports storing `"application-site"` items with `raw_data` JSON persistence, but `CPObject` does not yet expose typed attributes for `primary_category`, `url_list`, or `urls_defined_as_regular_expression`, and `ObjectService` does not yet map `"application-site"` to `show-application-sites` / `show-application-site`.
- `cpcrud` (`checkpoint_ops_schema.json`, `validator.py`, `state_reader.py`, `differ.py`, `planner.py`, `inverse.py`) currently restricts `OBJECT_ITEM_TYPES` to `{"host", "network", "address-range", "dns-domain", "group"}` and `SERVICE_ITEM_TYPES` to `{"service-tcp", "service-udp", "service-icmp", "service-icmp6", "service-other", "service-group"}`.

## Goals / Non-Goals

**Goals:**

- Support `application-site` as a first-class `CPObject` type in `ObjectService` (on-demand sync; default `DEFAULT_OBJECT_TYPES` remains unchanged so default sync performance is unaffected) and `HybridStateReader`.
- Allow CPCRUD templates to declare `application-site` items in `objects:`, `services:`, or `operations:` sections so callers that treat `application-site` as a service-column item or an object item both work.
- Implement accurate field diffing (`primary-category`, set-normalized `url-list`, `urls-defined-as-regular-expression`, `description`), payload generation, and inverse rollback for `application-site`.

**Non-Goals:**

- Adding `"application-site"` to `DEFAULT_OBJECT_TYPES` (Check Point built-in application databases contain thousands of predefined sites; `application-site` sync must remain on-demand or targeted via `HybridStateReader.get_object` / `refresh_objects(types=["application-site"])`).

## Decisions

### 1. `CPObject` Representation and Storage Hydration

- Add optional fields to `CPObject` (`src/arodonata/core/models/objects.py`):
  - `primary_category: str | None = Field(default=None, validation_alias=AliasChoices("primary_category", "primary-category"))`
  - `url_list: list[str] = Field(default_factory=list, validation_alias=AliasChoices("url_list", "url-list"))`
  - `urls_defined_as_regular_expression: bool | None = Field(default=None, validation_alias=AliasChoices("urls_defined_as_regular_expression", "urls-defined-as-regular-expression"))`
  - `description: str = ""`
- Populate these fields in `CPObject.from_cp_dict()` from `data.get("primary-category")`, `data.get("url-list")`, `data.get("urls-defined-as-regular-expression")`, and `data.get("description")`.
- In `SqlCacheAdapter._row_to_object()` (`src/arodonata/adapters/storage.py`), hydrate these fields from `raw_data` so no destructive DB column migration is required on `arodonata_objects`.

### 2. Dual Bucket Acceptance in CPCRUD (`objects:` and `services:`)

- Because Check Point `access-rule` places `application-site` in the `service` column while Check Point's object model classifies it as an object (`arodonata_objects`), `checkpoint_ops_schema.json` and `validator.py` will accept `type: "application-site"` in `ObjectOperation`, `ServiceOperation`, and `GenericOperation`.
- In `Planner` (`src/arodonata/cpcrud/planner.py`), any item in `services:` with `type == "application-site"` is routed to `_plan_object_step()` so state lookup (`HybridStateReader.get_object`), diffing (`compute_object_diff`), and name resolution (`res_map`) use a single unified code path.

### 3. Diffing and Payload Construction for `application-site`

- **Payload construction (`_build_add_object_payload`)**:
  - `primary-category`: `str(spec.get("primary-category") or spec.get("primary_category") or "Custom_Application_Site").strip()` when `url-list` / `url_list` is present.
  - `url-list`: `[str(u).strip() for u in (spec.get("url-list") or spec.get("url_list") or []) if str(u).strip()]`.
  - `urls-defined-as-regular-expression`: `bool(val)` when specified in `spec`.
  - `description`: `str(spec["description"])` when present.
  - `application-signature` and `additional-categories`: passed through when present.
- **Diffing (`compute_object_diff`)**:
  - `url-list` comparison uses set equality (`set(req_urls) == set(cur_urls)`) because Check Point returns `url-list` as a deduplicated set of URL patterns whose order may vary across API responses.
  - `urls-defined-as-regular-expression` compares `bool(req_regex) == bool(cur_regex)`.
  - `primary-category` compares normalized strings (case-insensitive or exact Check Point category name).

### 4. Value-Based Reuse (`find_objects_by_value`)

- When `HybridStateReader.find_objects_by_value(mgmt_name, domain_name, obj_type="application-site", ...)` is called (for `on_ip_conflict="reuse"`), it matches `application-site` objects whose `set(url_list)` equals `set(desired_url_list)` and whose `bool(urls_defined_as_regular_expression)` matches `bool(desired_regex)`.

## Risks / Trade-offs

- **[Risk] Large built-in `show-application-sites` catalog on Check Point management servers** -> **Mitigation**: Keep `"application-site"` out of `DEFAULT_OBJECT_TYPES`; `HybridStateReader.get_object()` queries `show-application-site` by `name` or `uid` directly (`O(1)` API call) when the domain's `"application-site"` cache slice is not synced.
