"""Tests for arodonata.models.rulebases Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arodonata.models import AccessRule, HTTPSRule, NATRule, ThreatRule


class TestAccessRule:
    def test_construction_with_typical_fields(self):
        rule = AccessRule(
            uid="uid-001",
            rule_number=1,
            name="Allow Web Traffic",
            enabled=True,
            sources=["any"],
            destinations=["any"],
            services=["http", "https"],
            action="accept",
            track="Log",
            layer_name="Network",
            mgmt_name="mgmt1",
            domain_name="",
        )
        assert rule.uid == "uid-001"
        assert rule.rule_number == 1
        assert rule.name == "Allow Web Traffic"
        assert rule.enabled is True
        assert rule.sources == ["any"]
        assert rule.action == "accept"
        assert rule.track == "Log"

    def test_domain_name_defaults_to_empty_string(self):
        rule = AccessRule(
            uid="uid-001",
            rule_number=1,
            name="Rule",
            enabled=True,
            sources=["any"],
            destinations=["any"],
            services=["http"],
            action="accept",
            track="Log",
            layer_name="Network",
            mgmt_name="mgmt1",
        )
        assert rule.domain_name == ""

    def test_empty_uid_raises_validation_error(self):
        with pytest.raises(ValidationError):
            AccessRule(
                uid="",
                rule_number=1,
                name="Rule",
                enabled=True,
                sources=["any"],
                destinations=["any"],
                services=["http"],
                action="accept",
                track="Log",
                layer_name="Network",
                mgmt_name="mgmt1",
            )

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            AccessRule(uid="uid-001", rule_number=1, name="Rule")  # type: ignore[call-arg]

    def test_raw_data_default_and_override(self):
        rule = AccessRule(
            uid="uid-001",
            rule_number=1,
            name="Rule",
            enabled=True,
            sources=["any"],
            destinations=["any"],
            services=["http"],
            action="accept",
            track="Log",
            layer_name="Network",
            mgmt_name="mgmt1",
        )
        assert rule.raw_data == {}

        raw_data = {"custom-field": "value"}
        rule2 = AccessRule(
            uid="uid-001",
            rule_number=1,
            name="Rule",
            enabled=True,
            sources=["any"],
            destinations=["any"],
            services=["http"],
            action="accept",
            track="Log",
            layer_name="Network",
            mgmt_name="mgmt1",
            raw_data=raw_data,
        )
        assert rule2.raw_data == raw_data

    def test_extra_unknown_field_ignored(self):
        rule = AccessRule(
            uid="uid-001",
            rule_number=1,
            name="Rule",
            enabled=True,
            sources=["any"],
            destinations=["any"],
            services=["http"],
            action="accept",
            track="Log",
            layer_name="Network",
            mgmt_name="mgmt1",
            some_unknown_field="ignored",
        )
        assert not hasattr(rule, "some_unknown_field")


class TestNATRule:
    def test_construction(self):
        rule = NATRule(
            uid="uid-002",
            rule_number=1,
            name="Hide NAT",
            enabled=True,
            original_source="192.168.1.0",
            original_destination="any",
            original_service="any",
            translated_source="10.0.0.1",
            translated_destination="original",
            translated_service="original",
            layer_name="NAT",
            mgmt_name="mgmt1",
        )
        assert rule.uid == "uid-002"
        assert rule.original_source == "192.168.1.0"
        assert rule.translated_source == "10.0.0.1"
        assert rule.domain_name == ""


class TestHTTPSRule:
    def test_construction(self):
        rule = HTTPSRule(
            uid="uid-003",
            rule_number=1,
            name="Inspect HTTPS",
            enabled=True,
            sources=["any"],
            destinations=["any"],
            track="Inspect",
            layer_name="CVD",
            mgmt_name="mgmt1",
        )
        assert rule.uid == "uid-003"
        assert rule.track == "Inspect"


class TestThreatRule:
    def test_construction(self):
        rule = ThreatRule(
            uid="uid-004",
            rule_number=1,
            name="Block SQL Injection",
            enabled=True,
            track="Alert",
            protections=["SQL Injection"],
            layer_name="Threat",
            mgmt_name="mgmt1",
        )
        assert rule.uid == "uid-004"
        assert rule.track == "Alert"
        assert rule.protections == ["SQL Injection"]

    def test_protections_defaults_required(self):
        with pytest.raises(ValidationError):
            ThreatRule(
                uid="uid-004",
                rule_number=1,
                name="Rule",
                enabled=True,
                track="Alert",
                layer_name="Threat",
                mgmt_name="mgmt1",
            )  # type: ignore[call-arg]
