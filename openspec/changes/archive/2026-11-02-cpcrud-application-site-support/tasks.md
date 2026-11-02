# Tasks

## 1. Domain Model & ObjectService Support for `application-site`

- [x] 1.1 Add `"app-site"` and `"application_site"` to `OBJECT_TYPE_ALIASES` in `src/arodonata/core/models/common.py`, extend `CPObject` (`src/arodonata/core/models/objects.py`) and `SqlCacheAdapter._row_to_object` (`src/arodonata/adapters/storage.py`) with `primary_category`, `url_list`, `urls_defined_as_regular_expression`, and `description`, and verify with unit tests in `tests/unit/test_models.py` and `tests/unit/test_storage.py`
- [x] 1.2 Add `"application-site"` (`show-application-sites` and `show-application-site`) to `_TYPE_TO_SHOW_PLURAL_COMMAND` and `_TYPE_TO_SHOW_SINGLE_COMMAND` in `src/arodonata/core/services/object_service.py`, and verify on-demand `refresh_objects(types=["application-site"])` in `tests/unit/test_object_service.py`

## 2. CPCRUD Schema & Validator

- [x] 2.1 Update `src/arodonata/cpcrud/checkpoint_ops_schema.json` and `src/arodonata/cpcrud/validator.py` to allow `type: "application-site"` in `ObjectOperation`, `ServiceOperation`, and `GenericOperation` with `primary-category` / `primary_category`, `url-list` / `url_list`, `urls-defined-as-regular-expression` / `urls_defined_as_regular_expression`, `description`, `application-signature`, and `additional-categories`, and verify in `tests/unit/test_cpcrud_validator.py`

## 3. CPCRUD State Reader, Differ, Planner, and Inverse

- [x] 3.1 Update `src/arodonata/cpcrud/state_reader.py` (`OBJECT_ITEM_TYPES`, `_TYPE_TO_SHOW_SINGLE`, `_TYPE_TO_SHOW_PLURAL`, and `find_objects_by_value`) to read and match `application-site` objects, and verify in `tests/unit/test_cpcrud_state_reader.py`
- [x] 3.2 Update `src/arodonata/cpcrud/differ.py` (`compute_object_diff`) and `src/arodonata/cpcrud/planner.py` (`_plan_object_step`, `_build_add_object_payload`, `_build_prior_object_state`, and routing `application-site` from `services:` / `objects:`) to plan `CREATE`, `UNCHANGED`, `UPDATE`, `DELETE`, and `ERROR` (`on_name_conflict="error"`) for `application-site` objects, and verify in `tests/unit/test_cpcrud_planner.py`
- [x] 3.3 Update `src/arodonata/cpcrud/inverse.py` (`_invert_object_action`) to restore/delete `application-site` fields (`primary-category`, `url-list`, `urls-defined-as-regular-expression`, `description`, `application-signature`, `additional-categories`), and verify in `tests/unit/test_cpcrud_inverse.py`

## 4. Quality Gates & Documentation

- [x] 4.1 Update `docs/architecture/cpcrud.md` and `docs/CAPABILITIES.md` to list `application-site` support, and run `uv run ruff check .`, `uv run mypy src`, `uv run pytest`, and `openspec validate --strict`
