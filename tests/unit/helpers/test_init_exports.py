"""Tests for the arodonata.helpers domain-organized export surface (__init__.py)."""

import arodonata.helpers as helpers_pkg
from arodonata.helpers import (
    UserContext,
    _context,
    add_object,
    assets,
    create_session,
    delete_object,
    discard_session,
    find_object,
    get_access_rules,
    get_gateways,
    get_group_members,
    get_https_rules,
    get_nat_rules,
    get_objects,
    get_threat_rules,
    objects,
    policy,
    publish_session,
    refresh_assets,
    set_object,
    write_session,
)


class TestAllListCompleteness:
    """__all__ should list every re-exported name and nothing extra."""

    def test_all_matches_module_dict(self):
        expected = {
            "UserContext",
            "find_object",
            "get_objects",
            "get_group_members",
            "get_gateways",
            "refresh_assets",
            "create_session",
            "publish_session",
            "discard_session",
            "write_session",
            "add_object",
            "set_object",
            "delete_object",
            "get_access_rules",
            "get_nat_rules",
            "get_https_rules",
            "get_threat_rules",
        }
        assert set(helpers_pkg.__all__) == expected

    def test_every_all_name_is_importable_from_package(self):
        for name in helpers_pkg.__all__:
            assert hasattr(helpers_pkg, name), f"{name} listed in __all__ but not importable"


class TestExportsMapToOriginatingModules:
    """Each re-exported name should be the exact object defined in its domain module."""

    def test_context_export(self):
        assert UserContext is _context.UserContext

    def test_assets_exports(self):
        assert get_gateways is assets.get_gateways
        assert refresh_assets is assets.refresh_assets

    def test_objects_exports(self):
        assert find_object is objects.find_object
        assert get_group_members is objects.get_group_members
        assert get_objects is objects.get_objects

    def test_policy_exports(self):
        assert add_object is policy.add_object
        assert create_session is policy.create_session
        assert delete_object is policy.delete_object
        assert discard_session is policy.discard_session
        assert get_access_rules is policy.get_access_rules
        assert get_https_rules is policy.get_https_rules
        assert get_nat_rules is policy.get_nat_rules
        assert get_threat_rules is policy.get_threat_rules
        assert publish_session is policy.publish_session
        assert set_object is policy.set_object
        assert write_session is policy.write_session
