"""Change report: Check Point show-changes of sessions turned into evidence (HTML, JSON, markdown).

Importing this package loads neither Jinja2 nor MarkupSafe nor the MCP SDK; HTML needs the ``report`` extra.
"""

from .collect import collect_change_report
from .model import (
    FORMAT_VERSION,
    Cell,
    CellItem,
    ChangeReport,
    DomainChanges,
    DomainError,
    FieldChange,
    LayerBlock,
    MgmtChanges,
    NamedRef,
    NumberingInfo,
    ObjectChange,
    PackageBlock,
    RawResponse,
    ReportWarning,
    RequestedScope,
    RulebaseBlock,
    RuleChange,
    RulePlacement,
    SectionHeader,
    SessionChanges,
)
from .render import ChangeReportResult, RenderOptions, ReportFormat, UnsupportedFormat, render_change_report
from .scopes import ChangeReportInputError, OwnedSession, RangeScope, Scope, SessionScope

__all__ = [
    "FORMAT_VERSION",
    "Cell",
    "CellItem",
    "ChangeReport",
    "ChangeReportInputError",
    "ChangeReportResult",
    "DomainChanges",
    "DomainError",
    "FieldChange",
    "LayerBlock",
    "MgmtChanges",
    "NamedRef",
    "NumberingInfo",
    "ObjectChange",
    "OwnedSession",
    "PackageBlock",
    "RangeScope",
    "RawResponse",
    "RenderOptions",
    "ReportFormat",
    "ReportWarning",
    "RequestedScope",
    "RuleChange",
    "RulebaseBlock",
    "RulePlacement",
    "Scope",
    "SectionHeader",
    "SessionChanges",
    "SessionScope",
    "UnsupportedFormat",
    "collect_change_report",
    "render_change_report",
]
