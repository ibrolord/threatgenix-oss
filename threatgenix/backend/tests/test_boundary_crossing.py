from __future__ import annotations

from uuid import UUID, uuid4


from app.schemas.dfd import TrustBoundaryResponse
from app.services.rules.boundary import crosses_trust_boundary, _find_boundary_for_node

# Fixed UUIDs for deterministic tests
N1 = "00000000-0000-0000-0000-000000000001"
N2 = "00000000-0000-0000-0000-000000000002"
N3 = "00000000-0000-0000-0000-000000000003"
N99 = "00000000-0000-0000-0000-000000000099"


def _make_boundary(name: str, node_ids: list[str]) -> TrustBoundaryResponse:
    return TrustBoundaryResponse(
        id=uuid4(),
        name=name,
        node_ids=[UUID(nid) for nid in node_ids],
    )


class TestCrossesTrustBoundary:
    def test_same_boundary_no_crossing(self):
        """Case 1: source and target in same boundary."""
        b = _make_boundary("Internal", [N1, N2])
        crosses, name = crosses_trust_boundary(N1, N2, [b])
        assert crosses is False
        assert name is None

    def test_different_boundaries_crosses(self):
        """Case 2: source in boundary A, target in boundary B."""
        b_a = _make_boundary("DMZ", [N1])
        b_b = _make_boundary("Internal", [N2])
        crosses, name = crosses_trust_boundary(N1, N2, [b_a, b_b])
        assert crosses is True
        assert name == "Internal"

    def test_source_inside_target_outside(self):
        """Case 3: source in a boundary, target not in any."""
        b = _make_boundary("Internal", [N1])
        crosses, name = crosses_trust_boundary(N1, N2, [b])
        assert crosses is True
        assert name == "Internal"

    def test_source_outside_target_inside(self):
        """Case 3: source not in any boundary, target in one."""
        b = _make_boundary("Internal", [N2])
        crosses, name = crosses_trust_boundary(N1, N2, [b])
        assert crosses is True
        assert name == "Internal"

    def test_both_outside_no_crossing(self):
        """Case 4: neither source nor target in any boundary."""
        b = _make_boundary("Internal", [N3])
        crosses, name = crosses_trust_boundary(N1, N2, [b])
        assert crosses is False
        assert name is None

    def test_empty_boundaries_no_crossing(self):
        """Edge case: empty boundaries list."""
        crosses, name = crosses_trust_boundary(N1, N2, [])
        assert crosses is False
        assert name is None

    def test_node_in_multiple_boundaries_picks_first(self):
        """Edge case: node appears in multiple boundaries, first match wins."""
        b1 = _make_boundary("First", [N1, N2])
        b2 = _make_boundary("Second", [N2, N3])
        # n2 is in both b1 and b2; source outside, target is n2 -> first match = "First"
        crosses, name = crosses_trust_boundary(N99, N2, [b1, b2])
        assert crosses is True
        assert name == "First"

    def test_self_loop_same_boundary(self):
        """Edge case: source == target, same boundary."""
        b = _make_boundary("Internal", [N1])
        crosses, name = crosses_trust_boundary(N1, N1, [b])
        assert crosses is False
        assert name is None

    def test_self_loop_no_boundary(self):
        """Edge case: source == target, not in any boundary."""
        crosses, name = crosses_trust_boundary(N1, N1, [])
        assert crosses is False
        assert name is None


class TestFindBoundaryForNode:
    def test_found(self):
        b = _make_boundary("Zone", [N1, N2])
        result = _find_boundary_for_node(N1, [b])
        assert result is not None
        assert result.name == "Zone"

    def test_not_found(self):
        b = _make_boundary("Zone", [N1])
        result = _find_boundary_for_node(N99, [b])
        assert result is None

    def test_empty_list(self):
        result = _find_boundary_for_node(N1, [])
        assert result is None
