"""Rulebase models for arodonata v2."""

from pydantic import field_validator

from .common import BaseModelWithRaw


class AccessRule(BaseModelWithRaw):
    """Access control rule from Network layer."""

    uid: str
    rule_number: int
    name: str
    enabled: bool
    sources: list[str]
    destinations: list[str]
    services: list[str]
    action: str
    track: str
    layer_name: str
    mgmt_name: str
    domain_name: str = ""

    @field_validator("uid")
    @classmethod
    def uid_must_not_be_empty(cls, v: str) -> str:
        """Validate that uid is not empty."""
        if not v:
            raise ValueError("uid must not be empty")
        return v


class NATRule(BaseModelWithRaw):
    """NAT rule from NAT layer."""

    uid: str
    rule_number: int
    name: str
    enabled: bool
    original_source: str
    original_destination: str
    original_service: str
    translated_source: str
    translated_destination: str
    translated_service: str
    layer_name: str
    mgmt_name: str
    domain_name: str = ""


class HTTPSRule(BaseModelWithRaw):
    """HTTPS inspection rule from CVD layer."""

    uid: str
    rule_number: int
    name: str
    enabled: bool
    sources: list[str]
    destinations: list[str]
    track: str
    layer_name: str
    mgmt_name: str
    domain_name: str = ""


class ThreatRule(BaseModelWithRaw):
    """Threat prevention rule from Threat layer."""

    uid: str
    rule_number: int
    name: str
    enabled: bool
    track: str
    protections: list[str]
    layer_name: str
    mgmt_name: str
    domain_name: str = ""
