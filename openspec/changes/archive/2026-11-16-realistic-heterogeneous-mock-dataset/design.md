# Design

## Addressing & Uniqueness Scheme (`DATASET_VERSION = "1.2.0"`)

Section 11B of `generate_enterprise_raw_dataset()` uses disjoint IP ranges per domain (`domain_idx_map`, `1..9`) and asset category to guarantee zero IP or internal subnet collisions:

- **External / Management VIPs**: `172.29.<dom_idx>.<host_id>` for `+7` standalone gateways (`host_id` `1..4`), `172.29.<dom_idx>.<base>` / `.<base+1>` / `.<base+2>` for HA cluster VIPs and members (`base` `10`, `20`), and `172.29.<dom_idx>.50` for the `+4` extra VSX chassis hosts.
- **Internal Gateway & Cluster Subnets**: `10.<180 + dom_idx>.<1..4>.0/24` for standalone gateways, `10.<180 + dom_idx>.<10|20>.0/24` (plus `.<base+10>.0/24` for internal-only `DB_Seg` clusters).
- **Virtual System Internal Subnets**: Instead of `30 + vs_id` (which collided at `(WAN_Core, 21)` when two VSX hosts independently placed `vsid=21` in `WAN_Core`), each of the `25` extra Virtual Systems receives a monotonic sequence index `vs_seq` (`1..25`) yielding `sub_octet = 40 + vs_seq` (`41..65`). Both primary internal interfaces (`10.<180 + dom_idx>.<sub_octet>.1/24`) and secondary internal interfaces on `internal_only` VSs (`10.198.<sub_octet>.1/24`) are guaranteed unique across all domains.
- **Warp External Links**: `192.168.<240 + wrp_idx>.<10 + vs_id>/24` (`wrp_idx` `1..6` unique per VSX chassis, `vs_id` unique per chassis).

## Unified VSX Stat Rendering & Complete Slot Metadata

- `vsx_stat_lines_by_host` accumulates `VSID: 0` headers (`_init_vsx_stat`) and `Virtual System` blocks (`_append_vsx_stat`) identically across sections 8, 9, and 11B for all `6` VSX chassis (`dc-vsx-chassis-01`, `dc-vsx-chassis-02`, `reg-vsx-hub-01`, `br-vsx-campus-01`, `perim-vsx-chassis-01`, `dc-pod-vsx-local-01`), removing duplicated `range(2, 16)` generation and `dc-vsx-chassis-01` post-render string concatenation.
- `uid-slot0-chassis-02` (`CpmiVsxSlotObj`) and `CpmiVsSlotObj` entries (`uid-slot-spine-vs02..15`) are created alongside `chassis2_obj` in section 8 so all `19` Virtual Systems on `dc-vsx-chassis-02` carry full `vsxGateway` / `targetCustomer` slot metadata.
- New Virtual System slot UIDs use `f"uid-slot-{vs_spec.name}"` matching the existing `uid-slot-<short-name>` pattern.

## Preserved Scale & Topology Invariants

- All baseline 9-hop path entries, `cprid` fallback gateways (`br-reg-gw-138..140`), `Global` references in rule `#104`, untouched rule `#1` fixtures, `DB_Seg` internal-only zero-diagnostic-warning invariant, and `<250` topology-hydrated object count remain unchanged.
