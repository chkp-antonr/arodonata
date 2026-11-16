# Tasks

## 1. Enterprise Dataset v1.2.0 Expansion and Audit Remediation

- [x] 1.1 Update `src/arodonata/testing/dataset_generator.py` (`DATASET_VERSION = "1.2.0"`) with typed `_Extra*Spec` descriptors, heterogeneous standalone/cluster/VSX/cross-domain VS additions across all 9 user domains, globally sequenced unique VS internal `/24` subnets (`sub_octet = 40 + vs_seq`), complete `CpmiVsxSlotObj` / `CpmiVsSlotObj` entries for `dc-vsx-chassis-02` (`vsid` `2..15`), standardized `uid-slot-<vs_name>` UIDs, and unified `vsx_stat_lines_by_host` rendering.
- [x] 1.2 Regenerate `tests/fixtures/enterprise_raw_dataset/` deterministically (`ensure_enterprise_raw_dataset(force=True)`) and verify zero diff against a fresh temporary directory build.

## 2. Unit Tests, Documentation, and Canonical Spec Sync

- [x] 2.1 Rename `test_dataset_v120_global_refs_and_assignments` in `tests/unit/test_dataset_global_refs.py` and add assertions for `total_cli_targets == 325`, `total_network_objects == 2951`, `total_service_objects == 210`, per-domain gateway/interface IP and VS internal subnet uniqueness, CLI/task fixture coverage, `vsx stat -l` entries across all 6 VSX hosts, complete `dc-vsx-chassis-02` slots, and absence of `uid-slot-uid-` prefixes; update `tests/unit/test_topology_raw_replay_scale.py`, `src/arodonata/testing/mock_server.py`, `docs/guides/enterprise-replay-mock-server.md`, and `CHANGELOG.md`.
- [x] 2.2 Sync `integration-testing-and-examples` delta spec into `openspec/specs/integration-testing-and-examples/spec.md` and verify all repository quality gates (`ruff`, `mypy`, `markdownlint-cli`, `openspec validate`, `pytest`).
