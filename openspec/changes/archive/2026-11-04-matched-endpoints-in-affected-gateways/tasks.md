# Tasks

## 1. Domain Model & Service Implementation

- [x] 1.1 Add `matched_sources: list[str] = Field(default_factory=list)` and `matched_destinations: list[str] = Field(default_factory=list)` to `AffectedGatewayCandidate` in `src/arodonata/core/models/topology.py` and verify `uv run mypy src/arodonata/core/models` passes.
- [x] 1.2 Update `TopologyService.find_affected_gateways()` in `src/arodonata/core/services/topology_service.py` to populate `matched_sources` and `matched_destinations` on each `AffectedGatewayCandidate` with unique `source_query` and `destination_query` values from that gateway's cross-interface `matched_flows`, strictly preserving the caller's input order from `sources` and `destinations`, and verify `uv run mypy src` passes.

## 2. Unit Tests & Quality Gates

- [x] 2.1 Add unit tests in `tests/unit/test_topology_service.py` with a 4-gateway topology (`GW1`, `GW2`, transit gateway `GW3` with local subnets + upstream/downstream specific/external interfaces, and `GW4` behind `GW3`), asserting relevant gateway selection, exclusion of non-affected gateways (`src_interface == dst_interface` or `external == external`), and exact input-order population of `matched_sources` and `matched_destinations` on each gateway, and verify `uv run pytest tests/unit/test_topology_service.py` passes.
- [x] 2.2 Run all project quality gates (`uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest`, `npx markdownlint-cli "**/*.md" --ignore node_modules --ignore .venv --fix`, and `openspec validate --no-interactive`) and verify all checks pass.
