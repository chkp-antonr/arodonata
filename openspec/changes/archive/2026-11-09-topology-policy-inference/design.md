# Design

## Context

See `proposal.md` for motivation and `specs/` for behavioral requirements.

`TopologyService` currently extracts static interface definitions (`interface_connected`, `interface_specific`, `vs_static_route`, `external_interface`) and live CLI routes (`connected_route`, `gaia_static_route`, `clish_route`, `bgp_route`, `ospf_route`) into `arodonata_gateway_topology`. Simultaneously, `RulebaseRefreshService` already caches full domain rulebases (`arodonata_rulebase_package_layer`, `arodonata_rulebase_layer`, `arodonata_rulebase_access_rule`, `arodonata_rulebase_nat_rule`), and `TopologyConfidenceWeights` already reserves Stage 2–4 confidence hooks.

## Goals / Non-Goals

**Goals:**

- Extract gateway/cluster VPN encryption domains (`vpn-domain` / `encryption-domain`) into `arodonata_gateway_topology` (`source_type="vpn_domain"`) and score them with `vpn_encryption_domain` (`+0.45`).
- Evaluate cached Access Control and NAT rules for a gateway's installed policy package in `O(1)` amortized per-domain lookup during `find_affected_gateways`, awarding `+policy_rule_evidence` (`+0.25`) to L3 cross-interface candidates and inferring `match_type="policy_inferred"` candidates for one-arm or incomplete-topology gateways when `include_policy_inferred=True`.
- Add `check_policy: bool = False` to `reconcile_gateway_topology` to detect `policy_topology_mismatch` anomalies for rules explicitly installed on a specific gateway (`install_on`).
- Execute all implementation and verification in a dedicated git worktree branched from `master_v2` (`_tmp/worktrees/topology-policy-inference` on `feat/topology-policy-inference`) so uncommitted work in the primary checkout is untouched.

**Non-Goals:**

- Full L4 port/service/application-site simulation (`service` matching remains out of scope for L3 gateway topology inference).
- Modifying database table schemas (existing `arodonata_gateway_topology` and `arodonata_rulebase_*` tables already store all required fields).

## Decisions

### 1. Isolated Git Worktree Execution

- **Choice**: Create a dedicated git worktree at `_tmp/worktrees/topology-policy-inference` (which is gitignored under `_tmp/`) on branch `feat/topology-policy-inference` starting from `master_v2`.
- **Rationale**: The main working tree has unstaged edits on `master_v2`; an isolated worktree inside `_tmp/` stays within the workspace boundary while guaranteeing a clean `master_v2` baseline.

### 2. `TopologyConfidenceWeights` Naming & Backward Compatibility

- **Choice**: Define `policy_rule_evidence: float = 0.25` and `vpn_encryption_domain: float = 0.45` on `TopologyConfidenceWeights` while preserving `policy_rule_match` and `vpn_domain_match` as synchronized fields/aliases via a Pydantic `@model_validator`.
- **Rationale**: Callers and specs referencing either `policy_rule_evidence` / `vpn_encryption_domain` or the earlier placeholder names `policy_rule_match` / `vpn_domain_match` work seamlessly without breaking existing configuration objects.

### 3. VPN Encryption Domain (`source_type="vpn_domain"`) Extraction and Interface Binding

- **Choice**:
  - Add `"vpn_domain"` to `TopologySourceType` and `STATIC_TOPOLOGY_SOURCES`.
  - In `TopologyService._extract_domain_topology_entries`, inspect `asset.raw_data` for `vpn-domain`, `vpn_domain`, `encryption-domain`, `encryption_domain`, or `vpn-settings.vpn-domain` (supporting string name/UID or dict `{"name": ..., "uid": ...}` when `vpn-domain-type` is not `"addresses_behind_gw"` / `"none"`).
  - Expand the referenced network or group object via `_expand_specific_reference`. For each expanded interval `(cidr_str, lo_int, hi_int, plen, src_ref)`, associate it with any internal interface whose connected/specific subnet contains or equals `[lo_int, hi_int]`, or fall back to the gateway's primary internal interface (or `"vpn-domain"` if the gateway has no internal interfaces).
  - In `_score_interface_group`, emit `ConfidenceDelta(code="vpn_encryption_domain", delta=weights.vpn_encryption_domain, detail=...)` when `"vpn_domain"` is present in `src_types`.
- **Alternatives considered**: Creating a separate table for VPN domains. Rejected because `arodonata_gateway_topology` already discriminates sources via `source_type` and supports unified longest-prefix matching and IPAM export.

### 4. Policy & NAT Rule Indexing for `policy_rule_evidence` and `policy_inferred`

- **Choice**:
  - Add `"policy_inferred"` to `FlowMatchType`.
  - Build a per-domain policy index lazily during `find_affected_gateways` from `self._cache.get_domain_rulebase(mgmt_name, domain_name)` and the domain's indexed `CPObject` maps (`obj_by_uid`, `obj_by_name`).
  - For a gateway with `installed_access_policy` / `policy_packages` (or explicit `install_on` rule target):
    - **Access Rules**: Collect rules from the package's access layers (and inline sublayers) where `enabled=True`, `source_negate=False`, `destination_negate=False`, and `install_on` either is empty, contains `"Policy Targets"` / `"All"` / `"*"` (`6c488338-8eec-4103-ad21-cd461ac2c476`), or explicitly matches the gateway (`uid`, `name`, `id`, `asset_id`). Require both `source` and `destination` to contain at least one explicit (non-`Any`) object that expands to IPv4 intervals.
    - **NAT Rules**: Collect rules from the package's NAT rulebase where `enabled=True` and `install_on` applies to the gateway. Extract explicit (non-`Any`, non-`"Original"`) IPv4 intervals from `(original_source, original_destination)` and `(translated_source, translated_destination)` (substituting `original_*` when `translated_*` is `"Original"` / `None`, provided both resulting sides are explicit non-`Any`).
  - **Evidence Bonus on L3 Gateways**: When a gateway has cross-interface `matched_flows` (`src_interface != dst_interface`), check each flow `(src_ep, dst_ep)` against the gateway's active explicit rules. If any rule covers `src_ep` and `dst_ep`, append `ConfidenceDelta(code="policy_rule_evidence", delta=weights.policy_rule_evidence, detail=...)` to the flow's `confidence_factors` and add `weights.policy_rule_evidence` to the flow's `confidence` (clamped to `1.0`).
  - **Policy Inference on One-Arm / Incomplete-Topology Gateways (`include_policy_inferred: bool = True`)**:
    - Identify gateways that produced zero cross-interface `matched_flows` AND are either:
      1. One-arm / external-only gateways (`len(interfaces) <= 1` or zero internal interfaces), or
      2. Gateways with incomplete topology (`not defined` or `network defined by routing` without collected routes on at least one interface).
    - Also include policy-enforcing gateways from `all_assets` that had zero `arodonata_gateway_topology` rows (`no_interfaces` or all interfaces `not defined`).
    - If `include_policy_inferred=True` and the gateway's active explicit Access or NAT rules cover `(src_ep, dst_ep)` (i.e., `src_ep` is covered by/overlaps the rule's explicit source intervals and `dst_ep` is covered by/overlaps the rule's explicit destination intervals), synthesize a `TrafficFlowMatch` with `match_type="policy_inferred"`, `src_interface` / `dst_interface` set to the gateway's single interface name (or `"policy"`), `src_source_type="policy_rule"`, `dst_source_type="policy_rule"`, and `confidence` computed from `topology_external_fallback` (when an external interface exists) + `policy_rule_evidence`, recording `ConfidenceDelta(code="policy_rule_evidence", ...)` in `confidence_factors`.

### 5. Policy vs Topology/Routes Reconciliation (`check_policy: bool = False`)

- **Choice**:
  - Add `"policy_topology_mismatch"` to `TopologyDiscrepancyType`.
  - When `reconcile_gateway_topology(..., check_policy=True)` is called, inspect enabled Access and NAT rules in the domain's cached rulebase whose `install_on` list **explicitly** references `gw_asset` (excluding generic `"Policy Targets"` / `"All"`).
  - For each such gateway-targeted rule with explicit (non-`Any`) source or destination objects, expand its explicit networks. If the gateway has internal topology or live route intervals (`static_internal` or `route_internal` or `vpn_domain` entries) and **neither** any explicit source network **nor** any explicit destination network overlaps any internal interval of `gw_asset`, emit a `TopologyDiscrepancy` with `discrepancy_type="policy_topology_mismatch"`, `interface_name="policy"`, `cidr_or_range` summarizing the unmatched rule networks, and `message` identifying the rule UID/name/number and gateway.

## Risks / Trade-offs

- **[Risk] Over-matching on broad `"Any"` rules during one-arm inference** → **Mitigation**: Strictly require **both** source and destination of an Access or NAT rule to be explicit (non-`Any`, non-`0.0.0.0/0`, non-negated) before a rule can qualify for `policy_rule_evidence` or `policy_inferred` discovery.
- **[Risk] Performance overhead when scanning rulebases across 250+ gateways** → **Mitigation**: Pre-expand rule object intervals once per `(mgmt_name, domain_name, package_name)` and cache interval tuples in memory during `find_affected_gateways` so per-gateway evaluation is a fast integer-interval comparison.
