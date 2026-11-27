"""Check Point Script Repository models and script-body normalization helpers."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from arodonata.core.errors import redact_sid, sanitize_mapping

CpridScriptMode = Literal["inline", "repository", "auto"]
RepositoryScriptEnsureAction = Literal["unchanged", "created", "updated"]

_BASE64_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def normalize_script_body(body: str) -> str:
    """Normalize line endings (`\\r\\n` / `\\r` -> `\\n`) and strip trailing line whitespace."""
    normalized = body.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n")).strip()


def _try_decode_base64_text(
    raw_val: str,
    *,
    min_len: int = 4,
    strict_b64: bool = False,
    strict_utf8: bool = False,
    min_printable_ratio: float = 0.85,
    sample_len: int | None = None,
    require_script_tokens: bool = False,
) -> str:
    """Attempt to decode a Base64-encoded ASCII/UTF-8 string. Returns decoded text if valid, else `raw_val`."""
    cleaned = raw_val.strip()
    if not cleaned:
        return ""
    if "\n" in cleaned or "\r" in cleaned or " " in cleaned or "\t" in cleaned:
        return raw_val
    if "===ARODONATA_" in cleaned or "_vs_error=" in cleaned or " dev " in cleaned or " via " in cleaned:
        return raw_val
    if len(cleaned) < min_len or len(cleaned) % 4 == 1 or not _BASE64_TOKEN_RE.fullmatch(cleaned):
        return raw_val
    try:
        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
        decoded_bytes = base64.b64decode(padded, validate=strict_b64)
        errors_mode = "strict" if strict_utf8 else "replace"
        decoded_str = decoded_bytes.decode("utf-8", errors=errors_mode)
        if not decoded_str:
            return raw_val
        eval_text = decoded_str[:sample_len] if sample_len is not None else decoded_str
        valid_chars = sum(1 for ch in eval_text if (ch.isprintable() and ch != "\ufffd") or ch in ("\n", "\r", "\t"))
        if valid_chars / len(eval_text) < min_printable_ratio:
            return raw_val
        if require_script_tokens and not any(token in decoded_str for token in ("\n", " ", "=", "#", "$", ";")):
            return raw_val
        return decoded_str
    except Exception:
        return raw_val


def decode_base64_task_message(raw_val: str) -> str:
    """Decode a Base64-encoded Check Point task message when plausible UTF-8 text, else return `raw_val`."""
    return _try_decode_base64_text(
        raw_val,
        min_len=4,
        strict_b64=False,
        strict_utf8=False,
        min_printable_ratio=0.85,
        sample_len=120,
        require_script_tokens=False,
    )


def _decode_repository_script_body(raw_body: str) -> str:
    """Decode Base64-encoded `script-body` from Check Point R82 `show-repository-script` if valid, else return `raw_body`."""
    return _try_decode_base64_text(
        raw_body,
        min_len=8,
        strict_b64=True,
        strict_utf8=True,
        min_printable_ratio=0.90,
        sample_len=None,
        require_script_tokens=True,
    )


class RepositoryScript(BaseModel):
    """Check Point Management Script Repository entry (`add/show/set-repository-script`)."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    uid: str = ""
    name: str
    mgmt_name: str = ""
    domain_name: str = ""
    script_body: str = ""
    args: str = ""
    comments: str = ""
    color: str = "black"
    tags: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_cp_dict(
        cls,
        mgmt_name: str,
        domain_name: str,
        data: Mapping[str, Any],
        *,
        fallback_body: str | None = None,
    ) -> RepositoryScript:
        """Build a `RepositoryScript` from a Check Point Management API response payload."""
        raw_dom = data.get("domain")
        if isinstance(raw_dom, Mapping):
            eff_domain = str(raw_dom.get("name") or domain_name)
        elif isinstance(raw_dom, str) and raw_dom.strip():
            eff_domain = raw_dom.strip()
        else:
            eff_domain = domain_name

        raw_body = data.get("script-body")
        raw_b64 = data.get("script-body-base64")
        if isinstance(raw_b64, str) and raw_b64.strip():
            try:
                padded = raw_b64.strip() + "=" * ((4 - len(raw_b64.strip()) % 4) % 4)
                script_body = base64.b64decode(padded, validate=False).decode("utf-8", errors="replace")
            except Exception:
                script_body = fallback_body or ""
        elif isinstance(raw_body, str) and raw_body.strip():
            script_body = _decode_repository_script_body(raw_body)
        elif isinstance(raw_body, str):
            script_body = raw_body
        elif isinstance(data.get("script_body"), str):
            script_body = str(data["script_body"])
        else:
            script_body = fallback_body or ""

        raw_tags = data.get("tags")
        tags: list[str] = []
        if isinstance(raw_tags, list):
            for tag in raw_tags:
                if isinstance(tag, Mapping):
                    t_val = str(tag.get("name") or tag.get("uid") or "").strip()
                else:
                    t_val = str(tag).strip()
                if t_val:
                    tags.append(t_val)
        elif isinstance(raw_tags, str) and raw_tags.strip():
            tags.append(raw_tags.strip())

        return cls(
            uid=str(data.get("uid") or ""),
            name=str(data.get("name") or ""),
            mgmt_name=mgmt_name,
            domain_name=eff_domain,
            script_body=script_body,
            args=str(data.get("args") or ""),
            comments=str(data.get("comments") or ""),
            color=str(data.get("color") or "black"),
            tags=tags,
            raw_data=sanitize_mapping(dict(data)),
        )


class RepositoryScriptStatus(BaseModel):
    """Read-only inspection status of a Check Point Script Repository entry."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    script_ref: str = ""
    exists: bool
    script: RepositoryScript | None = None
    matches_expected: bool | None = None
    error_code: str | None = None
    error: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.error:
            self.error = redact_sid(self.error)


class EnsureRepositoryScriptResult(BaseModel):
    """Result of idempotently ensuring a repository script matches the desired body."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    action: RepositoryScriptEnsureAction
    script: RepositoryScript
    published: bool = False


class ScriptTargetExecutionResult(BaseModel):
    """Per-target execution output decoded from Check Point `run-script` / `show-task`."""

    model_config = ConfigDict(extra="ignore")

    target: str
    target_name: str = ""
    target_uid: str = ""
    task_id: str = ""
    status: str = ""
    success: bool
    stdout: str = ""
    stderr: str = ""
    status_description: str = ""
    revision: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.stdout:
            self.stdout = redact_sid(self.stdout)
        if self.stderr:
            self.stderr = redact_sid(self.stderr)
        if self.status_description:
            self.status_description = redact_sid(self.status_description)


class RepositoryScriptExecutionOutcome(BaseModel):
    """Aggregated outcome of executing a Check Point Script Repository entry via `run-script`."""

    model_config = ConfigDict(extra="ignore")

    mgmt_name: str
    domain_name: str
    script_ref: str
    args: str = ""
    success: bool
    task_ids: list[str] = Field(default_factory=list)
    targets: list[ScriptTargetExecutionResult] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    error_code: str | None = None
    error_message: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.stdout:
            self.stdout = redact_sid(self.stdout)
        if self.stderr:
            self.stderr = redact_sid(self.stderr)
        if self.error_message:
            self.error_message = redact_sid(self.error_message)


__all__ = [
    "CpridScriptMode",
    "EnsureRepositoryScriptResult",
    "RepositoryScript",
    "RepositoryScriptEnsureAction",
    "RepositoryScriptExecutionOutcome",
    "RepositoryScriptStatus",
    "ScriptTargetExecutionResult",
    "decode_base64_task_message",
    "normalize_script_body",
]
