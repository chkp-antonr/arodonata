# Tasks

## 1. Isolated Git Worktree & Core Topology Domain Models

- [x] 1.1 Create a dedicated git worktree from `master_v2` at `_tmp/worktrees/topology-policy-inference` on branch `feat/topology-policy-inference` (copying `openspec/changes/topology-policy-inference/` into the worktree) and verify `git status` in the worktree is clean against `master_v2`.
- [x] 1.2 Update `TopologyConfidenceWeights` in `src/arodonata/core/config.py` with `policy_rule_evidence: float = 0.25` and `vpn_encryption_domain: float = 0.45` (keeping synchronized backward-compatible aliases for `policy_rule_match` and `vpn_domain_match`) and update `src/arodonata/core/models/topology.py` (`TopologySourceType`, `STATIC_TOPOLOGY_SOURCES`, `FlowMatchType`, `TopologyDiscrepancyType`) to include `"vpn_domain"`, `"policy_inferred"`, and `"policy_topology_mismatch"`, verifying with `uv run mypy src` and unit tests in `tests/unit/test_topology_service.py`.

## 2. VPN Encryption Domain (`vpn_domain`) Extraction & Confidence Scoring

- [x] 2.1 Implement `vpn-domain` / `encryption-domain` extraction and recursive group/network expansion in `TopologyService._extract_domain_topology_entries` (`source_type="vpn_domain"`) and add `vpn_encryption_domain` (`+0.45`) delta scoring in `TopologyService._score_interface_group`, verifying with unit tests in `tests/unit/test_topology_service.py` covering `vpn_domain` extraction, persistence, and confidence scoring.

## 3. Policy & NAT Rule Evidence and One-Arm Gateway Inference (`find_affected_gateways`)

- [x] 3.1 Implement cached Access Control (`arodonata_rulebase_access_rule`) and NAT (`arodonata_rulebase_nat_rule` `original` and `translated`) rule indexing with `install_on` target resolution in `TopologyService`, awarding `+policy_rule_evidence` (`+0.25`) to cross-interface L3 candidates and verifying with unit tests in `tests/unit/test_topology_service.py`.
- [x] 3.2 Implement `include_policy_inferred: bool = True` in `TopologyService.find_affected_gateways` to discover one-arm (e.g., Cisco ACI service-graph) and incomplete-topology (`not defined` / `network defined by routing` without routes) gateways via explicit installed Access/NAT rules with `match_type="policy_inferred"`, verifying with unit tests in `tests/unit/test_topology_service.py`.

## 4. Policy vs Topology/Routes Reconciliation (`reconcile_gateway_topology`)

- [x] 4.1 Implement `check_policy: bool = False` in `TopologyService.reconcile_gateway_topology` to compare explicit networks in gateway-targeted (`install_on`) Access and NAT rules against the gateway's effective internal topology and route intervals and report `policy_topology_mismatch` discrepancies, verifying with unit tests in `tests/unit/test_topology_service.py`.

## 5. Client Facade, MCP `locate_gateways`, and Enterprise Scale Verification

- [x] 5.1 Wire `include_policy_inferred: bool = True` into `ArodonataClient.find_affected_gateways` and MCP `locate_gateways` (`src/arodonata/client.py`, `src/arodonata/mcp/tools.py`) and `check_policy: bool = False` into `ArodonataClient.reconcile_gateway_topology`, verifying with unit tests in `tests/unit/test_topology_service.py` and `tests/unit/test_mcp_tools.py`.
- [x] 5.2 Extend `tests/unit/test_topology_scale_scenarios.py` so one of the 10 one-arm Cisco ACI service-graph gateways (`corp-aci-onearm-03`) has an installed service policy between two EPG subnets and is discovered with `match_type="policy_inferred"` while the other 9 one-arm gateways are excluded, and run full quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest`, `openspec validate --specs --no-interactive`).
