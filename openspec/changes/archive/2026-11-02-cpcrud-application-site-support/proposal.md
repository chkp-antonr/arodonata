# Proposal

## Why

Downstream automation consumers (such as MMP Rule Creator) need declarative Policy-as-Code (`cpcrud`) and object cache support for Check Point `application-site` objects — in particular custom URL-list and regular-expression `application-site` objects (for example, `Site_baidu.com` with `url-list: ["\\/baidu\\.com", "\\.baidu\\.com"]`, `urls-defined-as-regular-expression: true`, and `primary-category: "Custom_Application_Site"`) referenced in the `service` column of Unified Access Control rules. Currently, `application-site` is absent from the CPCRUD schema, validator, state reader, differ, planner, inverse rollback generator, and `ObjectService` show command mappings.

## What Changes

- **CPCRUD Schema & Offline Validation (`checkpoint_ops_schema.json` & `validator.py`)**:
  - Allow `"application-site"` in `ObjectOperation`, `ServiceOperation`, and `GenericOperation` (supporting `application-site` definitions in `objects:`, `services:`, or `operations:` sections).
  - Add `application-site` attributes (`primary-category` / `primary_category`, `url-list` / `url_list`, `urls-defined-as-regular-expression` / `urls_defined_as_regular_expression`, `description`, `application-signature` / `application_signature`, `additional-categories` / `additional_categories`) to the schema and semantic validator.
- **CPCRUD State Reader, Differ, Planner, and Inverse Rollback (`state_reader.py`, `differ.py`, `planner.py`, `inverse.py`)**:
  - Register `"application-site"` in `OBJECT_ITEM_TYPES` and map it to `show-application-site` / `show-application-sites` in `HybridStateReader`, including value-based lookup (`find_objects_by_value`) by normalized `url-list` and `urls-defined-as-regular-expression`.
  - Implement field-level diffing (`compute_object_diff`) for `application-site` (`primary-category`, set-normalized `url-list`, `urls-defined-as-regular-expression`, `description`, and common metadata).
  - Support `add-application-site`, `set-application-site`, and `delete-application-site` in `Planner` (with `on_name_conflict="error"` / `"update"` and `on_ip_conflict="reuse"` / `"error"`) and compensating rollback generation in `build_inverse_template`.
- **Object Model & Cache Sync (`CPObject` & `ObjectService`)**:
  - Add `"app-site"` and `"application_site"` aliases to `OBJECT_TYPE_ALIASES`.
  - Add optional `primary_category`, `url_list`, and `urls_defined_as_regular_expression` fields to `CPObject` (`from_cp_dict` and `raw_data` hydration in `SqlCacheAdapter`).
  - Register `"application-site"` (`show-application-site` / `show-application-sites`) in `ObjectService` so on-demand `refresh_objects(types=["application-site"])` and `get_objects(types=["application-site"])` work seamlessly.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `cpcrud`: Add declarative validation, state lookup, diffing, planning (`add-application-site`, `set-application-site`, `delete-application-site`), conflict resolution, and inverse rollback support for `application-site` objects.
- `cache-and-sync`: Extend `CPObject` and `ObjectService` to hydrate and synchronize `application-site` objects on demand via `show-application-site` and `show-application-sites`.

## Impact

- `src/arodonata/core/models/common.py`: `OBJECT_TYPE_ALIASES`
- `src/arodonata/core/models/objects.py` & `src/arodonata/adapters/storage.py`: `CPObject` fields (`primary_category`, `url_list`, `urls_defined_as_regular_expression`)
- `src/arodonata/core/services/object_service.py`: `_TYPE_TO_SHOW_PLURAL_COMMAND` and `_TYPE_TO_SHOW_SINGLE_COMMAND`
- `src/arodonata/cpcrud/checkpoint_ops_schema.json`
- `src/arodonata/cpcrud/validator.py`
- `src/arodonata/cpcrud/state_reader.py`
- `src/arodonata/cpcrud/differ.py`
- `src/arodonata/cpcrud/planner.py`
- `src/arodonata/cpcrud/inverse.py`
- `tests/unit/test_cpcrud_*.py` and `tests/unit/test_object_service.py`
