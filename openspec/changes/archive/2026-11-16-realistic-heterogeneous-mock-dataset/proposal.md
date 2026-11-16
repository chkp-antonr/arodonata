# Proposal

## Why

Prior enterprise replay dataset `v1.1.0` concentrated Virtual Systems in `DC_Spine` and `DC_Pod` and left `Branch`, `Regional`, `WAN_Core`, `Perimeter`, `Transit`, `DB_Seg`, and `Partner_DMZ` without representative cross-domain VSX chassis, HA clusters, or Virtual Systems in every user domain. Downstream integration testing also expanded the stateful Check Point replay emulator (`verify-policy`, `install-policy`, `access-layer` / inline layers, `show-https-rulebase`, `show-threat-rulebase`, and staged `logout_sid()` invalidation) without a formal OpenSpec change record. An explicit OpenSpec change is required to capture the `v1.2.0` fixture scale baseline (`341` total assets, `315` gateways, `325` CLI targets), enforce per-domain IP/subnet uniqueness and complete VSX slot metadata, and sync canonical specs cleanly.

## What Changes

- **Enterprise Raw Replay Dataset v1.2.0 (`src/arodonata/testing/dataset_generator.py`, `tests/fixtures/enterprise_raw_dataset/`)**:
  - Add `+7` standalone `simple-gateway` appliances (`DC_Spine`, `DC_Pod`), `+7` `CpmiGatewayCluster` HA clusters (`+14` `cluster-member` nodes across `Branch`, `WAN_Core`, `Transit`, `DC_Spine`, `DC_Pod`, and internal-only `DB_Seg`), `+4` `CpmiVsxNetobj` physical VSX chassis (`Regional`, `Branch`, `Perimeter`, `DC_Pod`) with `CpmiVsxSlotObj` slot-0 metadata, and `+25` local and cross-domain `CpmiVsNetobj` Virtual Systems (`15+` cross-domain Virtual System pairs via `CpmiVsSlotObj` `targetCustomer`).
  - Ensure every one of the 9 MDSM user domains contains standalone gateways, HA clusters, and Virtual Systems while preserving baseline scale, 9-hop chain, rule `#1`, rule `#104` Global reference, and `DB_Seg` zero-warning invariants.
  - Remediate `2611160946` audit findings: assign globally sequenced unique `/24` internal subnets to new Virtual Systems (eliminating the `WAN_Core` `10.183.51.1` / `10.183.51.0/24` collision), complete `uid-slot0-chassis-02` and `CpmiVsSlotObj` entries for `dc-vsx-spine-vs02..15`, unify `vsx stat -l` accumulation, standardize `uid-slot-<vs_name>` UIDs, use typed `NamedTuple` specs, and strengthen unit assertions in `tests/unit/test_dataset_global_refs.py`.
- **Canonical Spec Alignment for Stateful Emulator Additions (`#87`)**:
  - Align `integration-testing-and-examples` spec requirements with `verify-policy`, `install-policy`, `access-layer` / inline-layer CRUD, `show-https-rulebase` / `show-threat-rulebase`, and `https-rule` / `threat-rule` CRUD.

## Capabilities

### New Capabilities

<!-- None -->

### Modified Capabilities

- `integration-testing-and-examples`: Bump deterministic raw replay dataset invariants to `DATASET_VERSION = "1.2.0"` (`341` cached assets, `315` gateways across heterogeneous types per domain, `>= 15` cross-domain Virtual Systems, `325` CLI routing targets, unique per-domain gateway/interface IPs and VS subnets, complete `CpmiVsxSlotObj` / `CpmiVsSlotObj` metadata) and sync emulator rulebase/layer/policy task requirements.

## Impact

- **Affected Modules & Fixtures**: `src/arodonata/testing/dataset_generator.py`, `src/arodonata/testing/mock_server.py`, `tests/fixtures/enterprise_raw_dataset/`, `tests/unit/test_dataset_global_refs.py`, `tests/unit/test_topology_raw_replay_scale.py`, `docs/guides/enterprise-replay-mock-server.md`, and `openspec/specs/integration-testing-and-examples/spec.md`.
- **Breaking Baseline Counts**: Dataset counts intentionally increase from `284` assets / `276` gateways / `279` CLI targets (`v1.1.0`) to `341` assets / `315` gateways / `325` CLI targets (`v1.2.0`), recorded canonically here for downstream consumers (MMP, FPCR).
