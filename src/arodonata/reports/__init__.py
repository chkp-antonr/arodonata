"""Auditable session change report collection, placement numbering, and rendering (`arodonata.reports`)."""

from arodonata.reports.collector import (
    MAX_UID_LOOKUPS,
    collect_change_report,
    is_bare_uid,
)
from arodonata.reports.models import (
    CURRENT_FORMAT_VERSION,
    ChangeOperation,
    ChangeReport,
    FieldDiff,
    ObjectChangeEntry,
    OwnedSession,
    RangeScope,
    RawResponse,
    RenderedReportBundle,
    RenderOptions,
    ReportFormat,
    ReportScope,
    ReportWarning,
    RuleChangeEntry,
    SessionChangeReport,
    SessionScope,
    WarningCode,
)
from arodonata.reports.placement import apply_session_rule_placement
from arodonata.reports.renderer import (
    SUPPORTED_REPORT_FORMATS,
    build_change_report,
    render_change_report,
    render_safe_inline_markdown_html,
    render_safe_inline_markdown_md,
)

__all__ = [
    "CURRENT_FORMAT_VERSION",
    "ChangeOperation",
    "ChangeReport",
    "FieldDiff",
    "MAX_UID_LOOKUPS",
    "ObjectChangeEntry",
    "OwnedSession",
    "RangeScope",
    "RawResponse",
    "RenderOptions",
    "RenderedReportBundle",
    "ReportFormat",
    "ReportScope",
    "ReportWarning",
    "RuleChangeEntry",
    "SUPPORTED_REPORT_FORMATS",
    "SessionChangeReport",
    "SessionScope",
    "WarningCode",
    "apply_session_rule_placement",
    "build_change_report",
    "collect_change_report",
    "is_bare_uid",
    "render_change_report",
    "render_safe_inline_markdown_html",
    "render_safe_inline_markdown_md",
]
