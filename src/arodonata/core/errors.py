"""Exception hierarchy and secret/SID redaction utilities for Arodonata."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, Literal

REDACTED_PLACEHOLDER = "***REDACTED***"

# Patterns matching Check Point SIDs or secret fields in JSON/text payloads and headers
_SID_HEADER_RE = re.compile(r"(?i)(x-chkp-sid\s*[:=]\s*['\"]?)([A-Za-z0-9_\-+/=]{8,})(['\"]?)")
_SID_JSON_RE = re.compile(
    r"""(?i)(['"]?(?:sid|session-id|api-key|api_key|password|secret|token)['"]?\s*:\s*['"])([^'"]+)(['"])"""
)
_BEARER_RE = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)([^\s,'\";]+)")

SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "sid",
        "session_id",
        "session-id",
        "x-chkp-sid",
        "x_chkp_sid",
        "api_key",
        "api-key",
        "api_keys",
        "password",
        "passwd",
        "one_time_password",
        "shared_secret",
        "secret",
        "token",
        "access_token",
        "bearer_token",
        "authorization",
    }
)


def is_sensitive_key(key: str) -> bool:
    """Return True if a key name represents a credential, token, or session identifier."""
    normalized = key.strip().lower().replace("-", "_")
    if normalized.startswith("arodonata."):
        normalized = normalized.removeprefix("arodonata.")
    return normalized in SENSITIVE_FIELD_NAMES or normalized.endswith(("_sid", "_password", "_api_key", "_secret"))


def redact_secret(value: str | None) -> str:
    """Return a constant placeholder for any secret or SID value."""
    if not value:
        return ""
    return REDACTED_PLACEHOLDER


def redact_sid(text: str, known_sids: Iterable[str] | None = None) -> str:
    """Mask Check Point session identifiers and credentials in arbitrary text."""
    if not text:
        return text
    sanitized = _SID_HEADER_RE.sub(rf"\1{REDACTED_PLACEHOLDER}\3", text)
    sanitized = _SID_JSON_RE.sub(rf"\1{REDACTED_PLACEHOLDER}\3", sanitized)
    sanitized = _BEARER_RE.sub(rf"\1{REDACTED_PLACEHOLDER}", sanitized)
    if known_sids:
        for sid in known_sids:
            if sid and len(sid) >= 4 and sid in sanitized:
                sanitized = sanitized.replace(sid, REDACTED_PLACEHOLDER)
    return sanitized


def _sanitize_sequence(seq: Iterable[Any], known_sids: Iterable[str] | None = None) -> list[Any]:
    """Recursively redact items in a list, tuple, or set."""
    items: list[Any] = []
    for item in seq:
        if isinstance(item, dict):
            items.append(sanitize_mapping(item, known_sids=known_sids))
        elif isinstance(item, (list, tuple, set, frozenset)):
            items.append(_sanitize_sequence(item, known_sids=known_sids))
        elif isinstance(item, str):
            items.append(redact_sid(item, known_sids=known_sids))
        else:
            items.append(item)
    return items


def sanitize_mapping(data: dict[str, Any], known_sids: Iterable[str] | None = None) -> dict[str, Any]:
    """Recursively redact sensitive keys and SID strings from a dictionary."""
    result: dict[str, Any] = {}
    for key, val in data.items():
        if is_sensitive_key(key):
            result[key] = REDACTED_PLACEHOLDER if val is not None else None
        elif isinstance(val, dict):
            result[key] = sanitize_mapping(val, known_sids=known_sids)
        elif isinstance(val, (list, tuple, set, frozenset)):
            result[key] = _sanitize_sequence(val, known_sids=known_sids)
        elif isinstance(val, str):
            result[key] = redact_sid(val, known_sids=known_sids)
        else:
            result[key] = val
    return result


class ArodonataError(Exception):
    """Base exception for all Arodonata errors with automatic SID/secret redaction."""

    def __init__(self, message: str = "", *, known_sids: Iterable[str] | None = None) -> None:
        sanitized_message = redact_sid(message, known_sids=known_sids)
        super().__init__(sanitized_message)
        self.message = sanitized_message


class ValidationError(ArodonataError, ValueError):
    """Raised when a command, object type, template, or input parameter fails validation."""


class AmbiguousObjectError(ValidationError):
    """Raised when a cross-domain lookup (domain=None) matches entities in multiple domains."""

    def __init__(
        self,
        mgmt_name: str,
        query: str,
        candidates: list[dict[str, Any]],
        *,
        known_sids: Iterable[str] | None = None,
    ) -> None:
        domains = sorted(
            {
                str(c.get("domain") or c.get("domain_name") or "")
                for c in candidates
                if c.get("domain") or c.get("domain_name")
            }
        )
        ids = [
            str(c.get("object_id") or c.get("service_id") or c.get("asset_id") or c.get("id") or "") for c in candidates
        ]
        preview = ", ".join(i for i in ids if i)[:200]
        super().__init__(
            f"Ambiguous lookup for {query!r} on {mgmt_name!r} matched across multiple domains "
            f"({', '.join(domains)}): {preview}. Specify 'domain' or a 'mgmt:domain:name' composite ID.",
            known_sids=known_sids,
        )
        self.mgmt_name = mgmt_name
        self.query = query
        self.candidates = candidates


class ConfigurationError(ArodonataError):
    """Raised when configuration values are invalid, inconsistent, or unsupported."""


class MissingConfigurationError(ConfigurationError):
    """Raised when required configuration parameters (e.g. target servers) are missing."""


class AuthenticationError(ArodonataError):
    """Raised when authentication with a Check Point management server fails."""


class InvalidCredentialsError(AuthenticationError):
    """Raised when the server explicitly rejects credentials or API keys (non-retryable)."""


class SessionError(ArodonataError):
    """Base exception for Check Point management session lifecycle errors."""


class SessionExpiredError(SessionError):
    """Raised when a Check Point session identifier (SID) has expired or is invalid."""


class DirtySessionError(SessionError):
    """Raised when a shared read session holds unpublished changes or object locks."""


class SessionStateError(SessionError):
    """Raised when an operation violates session isolation or lifecycle constraints."""


class ServerIdentityError(ArodonataError):
    """Base exception for TLS certificate fingerprint verification failures (never retried)."""


class UnknownServerCertificateError(ServerIdentityError):
    """Raised in pinned mode when a server presents an unpinned certificate fingerprint."""


class CertificateMismatchError(ServerIdentityError):
    """Raised when a server presents a certificate differing from its pinned/TOFU fingerprint."""


class TrustStoreError(ServerIdentityError):
    """Raised when the TLS trust store file cannot be read, parsed, or safely written."""


TransportPhase = Literal["connect", "post-send", "read"]


class TransportError(ArodonataError):
    """Raised when low-level HTTP/TCP transport communication fails."""

    def __init__(
        self,
        message: str = "",
        *,
        phase: TransportPhase = "post-send",
        request_sent: bool | None = None,
        known_sids: Iterable[str] | None = None,
    ) -> None:
        super().__init__(message, known_sids=known_sids)
        self.phase: TransportPhase = phase
        self.request_sent: bool = (phase != "connect") if request_sent is None else bool(request_sent)


class ApiTimeoutError(TransportError, TimeoutError):
    """Raised when a socket connect/TLS handshake or HTTP response read times out."""

    def __init__(
        self,
        message: str,
        *,
        phase: TransportPhase = "read",
        request_sent: bool | None = None,
        host: str | None = None,
        port: int | None = None,
        command: str | None = None,
        known_sids: Iterable[str] | None = None,
    ) -> None:
        super().__init__(
            message,
            phase=phase,
            request_sent=request_sent,
            known_sids=known_sids,
        )
        self.host = host
        self.port = port
        self.command = command


class RateLimitTimeoutError(TransportError, TimeoutError):
    """Raised when acquiring a concurrency slot from RateLimiter exceeds rate_limit_slot_timeout."""


class TaskError(ArodonataError):
    """Base exception for asynchronous Check Point server task failures."""


class TaskPollError(TaskError):
    """Raised when consecutive show-task polling failures exceed the tolerance threshold."""


class TaskTimeoutError(TaskError, TimeoutError):
    """Raised when a server task does not reach a terminal state within task_timeout."""


class CacheError(ArodonataError):
    """Base exception for database cache and synchronization errors."""


class LockAcquisitionError(CacheError):
    """Raised when a distributed database lock cannot be acquired within the timeout."""


class DomainNotFoundError(ArodonataError):
    """Raised when a requested Check Point domain does not exist on the target server."""


class AmbiguousLayerName(ArodonataError):
    """Raised when a domainless rulebase query matches layers/packages in multiple domains."""

    def __init__(self, layer_or_package: str, candidates: list[tuple[str, str]]) -> None:
        formatted = ", ".join(f"({domain}, {uid})" for domain, uid in candidates)
        super().__init__(f"Ambiguous layer or package {layer_or_package!r} found in multiple domains: {formatted}")
        self.layer_or_package = layer_or_package
        self.candidates = candidates


class ChangeReportInputError(ArodonataError):
    """Raised when ChangeReport scope bounds or options are invalid."""


class UnsupportedFormat(ArodonataError):
    """Raised when an unsupported report rendering format (e.g. 'pdf') is requested."""
