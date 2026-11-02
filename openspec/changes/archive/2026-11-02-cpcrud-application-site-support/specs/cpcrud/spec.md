# cpcrud Delta Specification

## ADDED Requirements

### Requirement: Declarative Lifecycle Support for Check Point Application-Site Objects

`CPCRUDService` SHALL validate, read, diff, plan (`add-application-site`, `set-application-site`, `delete-application-site`), and generate compensating rollback operations for Check Point `application-site` objects declared in `objects`, `services`, or `operations` sections, including URL lists and regular-expression flags.

#### Scenario: Schema and semantic validation of application-site operations

- **WHEN** `CPCRUDService.validate()` is called on a template containing an `application-site` operation in `objects`, `services`, or `operations` with `name`, `primary-category` (or `primary_category`), `url-list` (or `url_list`), and `urls-defined-as-regular-expression` (or `urls_defined_as_regular_expression`)
- **THEN** validation SHALL succeed with zero errors, and SHALL reject `present`/`add` `application-site` operations that omit both `url-list` and `application-signature`

#### Scenario: Planning creation of a new regex application-site object

- **WHEN** `CPCRUDService.plan()` evaluates a `present` or `add` operation for an `application-site` (e.g., `name: "Site_baidu.com"`, `primary-category: "Custom_Application_Site"`, `url-list: ["\\/baidu\\.com", "\\.baidu\\.com"]`, `urls-defined-as-regular-expression: true`) that does not exist in the target domain
- **THEN** the planner SHALL produce a `PlannedAction` with `Outcome.CREATE`, command `"add-application-site"`, and payload containing `"name"`, `"primary-category"`, `"url-list"`, and `"urls-defined-as-regular-expression": true`, and SHALL register the resolved name for downstream `access-rule` `service` references

#### Scenario: Existing application-site with identical URL list and regex flag is planned as UNCHANGED

- **WHEN** `CPCRUDService.plan()` evaluates an `application-site` operation whose target name already exists in the domain with the same `primary-category`, the same set of URLs in `url-list`, and the same `urls-defined-as-regular-expression` boolean
- **THEN** the planner SHALL produce `Outcome.UNCHANGED` requiring zero write calls during `apply()`

#### Scenario: Existing application-site with different URL list respects NameConflictPolicy

- **WHEN** `CPCRUDService.plan()` evaluates an `application-site` operation whose target name already exists in the domain with a different `url-list` or `urls-defined-as-regular-expression` value
- **THEN** the planner SHALL produce `Outcome.ERROR` reporting `differs on [url-list]` when `on_name_conflict="error"`, or `Outcome.UPDATE` with command `"set-application-site"` when `on_name_conflict="update"`

#### Scenario: Inverse rollback template restores or deletes application-site objects

- **WHEN** `CPCRUDService.inverse()` is called for a plan/report containing `CREATE`, `UPDATE`, or `DELETE` actions on `application-site` objects
- **THEN** it SHALL generate the corresponding compensating `delete`, `set`, or `add` `application-site` operation preserving `primary-category`, `url-list`, `urls-defined-as-regular-expression`, and `description`, ordered after any dependent `access-rule` rollbacks
