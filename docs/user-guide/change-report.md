# Change Report

## What it is

The change report is evidence of what Check Point policy sessions changed: the rules (with their SmartConsole numbers), the objects and the sections that were added, modified or deleted, grouped by management server > domain > session. Each session shows its name, uid and administrator.

One `ChangeReport` model feeds three formats: HTML (one self-contained file with inline CSS, no scripts and no external resources, meant to be attached to a change ticket), JSON (the `ChangeReport` itself, which can be stored and re-rendered later) and markdown (what the MCP tool returns). It is a library feature: there is no CLI. The MCP server exposes a markdown-only tool, see [MCP Server](../mcp/index.md).

## Install

HTML needs the `report` extra (Jinja2):

```bash
uv sync --extra report
# or, in another project
uv pip install 'arodonata[report]'
```

JSON and markdown need nothing extra. Requesting `html` without the extra raises an `ImportError` that names the extra.

## Quick start

```python
from pathlib import Path

from arodonata.reports.changes import RenderOptions, SessionScope

scope = SessionScope(mgmt_name="sms-1", domain="Domain5", session_uids=["<session uid>"])
options = RenderOptions(title="Change evidence **RITM0012345**", header_fields={"RITM": "RITM0012345"})

result = await client.build_change_report([scope], ["html", "json"], options)
Path("evidence.html").write_bytes(result.html)
```

`client.collect_change_report(scopes)` talks to the management server and returns a `ChangeReport`; `render_change_report(report, formats, options)` turns a report into the requested formats without any Check Point access; `client.build_change_report(scopes, formats, options)` does both. Only the requested formats are built. `ChangeReportResult` carries `report` (always set) and `html`, `json`, `markdown` (`None` unless requested).

The report is read-only: it uses `show-changes`, plus `show-object` for names and read-only rulebase reads for numbering. Nothing is written to the management server. A complete lab script is in [Change Report Evidence](../examples/10-change-report-evidence.md).

## Scopes

A report is built from a list of scopes. Scopes may mix management servers and domains; they are merged into one report and a session that several scopes name appears once.

- `SessionScope(mgmt_name=None, domain="", session_uids=[...], owned_session=None)`: explicit sessions, published or not. Each uid is fetched on its own with one `show-changes to-session=<uid>` request.
- `RangeScope(mgmt_name=None, domain="", from_session=None, to_session=None, from_date=None, to_date=None)`: the published sessions between bounds. `from_session` is exclusive and `to_session` is inclusive, as on the server. `from_date` and `to_date` are inclusive and exact, compared with each session's publish time, and must be timezone-aware.

`mgmt_name=None` means the first configured server (the library never fans out to all servers). `domain=""` is the value for an SMS (a server without domains).

Dates need care because the server accepts only offset-less local-time dates. The library converts your aware datetimes to the server's offset (read from the last published session), widens the server window, and then filters exactly on the publish time. A range given with `from_session` never sends dates to the server (the server refuses the combination), the dates are applied client-side instead. An empty window is an empty range, not an error; a `from_date` in the future returns nothing; a `to_date` close to now is not sent.

## Validation

Bad input fails early and loudly, everything else becomes a warning in the report.

Raised as `pydantic.ValidationError` when a scope is constructed:

- a naive datetime (no timezone)
- an empty `session_uids`
- a range without a lower bound (`from_session` or `from_date`)
- a range with only `to_session` (that is one session, use `SessionScope`) or only `to_date` (it would cover all history)
- `from_date` after `to_date`

Raised as `ChangeReportInputError` when collecting:

- an empty scope list
- an item that is not a `SessionScope` or `RangeScope`
- an unknown `mgmt_name`
- no configured server

Warnings are `ReportWarning` entries (`mgmt`, `domain`, `code`, `message`, `severity` of `info` or `warning`, optional `session_uid`) and are listed in every format:

| Code | Meaning |
|---|---|
| `domain_unavailable` | `show-changes` failed for the domain; the domain shows its error code and message, other domains continue |
| `session_not_found` | a requested session was not returned (unknown uid, another domain, or not visible to this administrator); it is skipped |
| `owned_session_not_used` | the owned session is no longer that unpublished session (published or discarded); numbering came from the cache (info) |
| `owned_session_error` | the owned session's SID could not be used (for example expired); numbering came from the cache |
| `owned_session_conflict` | one session was requested with different owned sessions; the first is used |
| `live_numbering_degraded` | the live read of the rulebase was incomplete, so the numbers are provisional and come from the cache |
| `numbering_failed` | numbering was unavailable (rules are listed as not placed), or the cache snapshot predates a published session (info) |
| `names_unresolved` | some object names could not be resolved and are shown as uids |
| `range_truncated` | a range had more sessions than the cap; the message names the `from_session` to continue from |

## Formats and options

`ReportFormat` is `"html"`, `"json"`, `"markdown"` or `"pdf"`. `pdf` is reserved: requesting it raises `UnsupportedFormat`; an unknown name raises `ValueError`, and passing a bare string instead of a list raises `TypeError`.

`RenderOptions` has `title`, `header_fields` (ordered key/value pairs shown in the header, for example a ticket number), `generated_by`, and the markdown limits `markdown_max_rules` and `markdown_max_objects`. `title` and the `header_fields` keys and values accept limited markdown: `**bold**`, `*italic*`, `` `code` `` and `[text](url)` with http, https or mailto links. Everything else is escaped, so a name cannot inject markup. Every string that comes from Check Point is escaped in all formats.

All times are UTC and labelled `UTC`.

## Owned session

An application that creates its own unpublished session (as the CPCRUD engine does) can pass it so that the pending rules are numbered exactly as SmartConsole shows them:

```python
from pydantic import SecretStr
from arodonata.reports.changes import OwnedSession, SessionScope

owned = OwnedSession(sid=SecretStr(sid), server_ip=server_ip)
scope = SessionScope(domain="Domain5", session_uids=[session_uid], owned_session=owned)
```

The SID is used strictly read-only: `show-session`, `show-packages` and the `show-*-rulebase` reads. It is never used to publish, discard or log out, the application keeps those. The first `show-session` verifies that the SID belongs to one of the scope's unpublished sessions. If the session has since been published or discarded, the report adds an info note (`owned_session_not_used`) and numbers from the cache instead. The SID is never logged, never appears in the report, the raw responses, JSON, HTML or markdown, and `repr()` of an `OwnedSession` masks it.

## Numbering labels

Rule numbers match SmartConsole (`1`, `2.6`, `2.2.1`, including the Global layer prefix). Each session carries one label that says where its numbers come from:

- `Numbering as of this session's publish`, or `Numbering as of publish of <session uid> at <time> UTC`: from the rulebase cache. `(Global packages)` is appended when the packages were numbered with Global layers.
- `Numbering read live in the owned session at <time> UTC`: exact numbers read through an owned session.
- `Provisional numbering: unpublished session; numbers are the last published policy plus in-layer positions`: an unpublished session without an owned session.
- `Numbering unavailable: <error>`: numbering failed; the rules are listed under "Not placed in a package".

Some rows carry a basis suffix in small text: `(before deletion)` for a deleted rule's pre-session number, `(at time of change)` for a rule that is not in the latest snapshot (or the live read), for example because it was moved or deleted later, so it is numbered from the session's own position, and `(provisional)`.

Numbers describe the latest rulebase snapshot, not necessarily the moment the session was published. If a published session is newer than the snapshot (or the same minute with another uid), the library re-reads the cache once; if the snapshot still predates the session, the numbers describe that snapshot and an info warning says so.

## Statuses and colours

- Added rule: green left bar and a `NEW` tag; modified: yellow bar with only the changed cells highlighted; deleted: strikethrough with a red `DELETED` tag, showing the pre-session content.
- Moved rule: the number cell is yellow. It reads `2.6 (was 2.4)` when the old number is known; otherwise the number carries `(moved)` and the rule's details show the old and new position within the section.
- Disabled rule: a first narrow column with a red ✗ and the whole row on light grey, combined with the change colours. A rule created and disabled in one session shows `NEW`, ✗ and grey.
- List cells (source, destination, service, ...): added items green, removed items red and struck through, an unchanged item whose object was itself modified in the same session yellow with a link to the object's detail. Changed scalar cells (action, track, name, ...) are yellow. A negated cell shows a `¬` marker (in markdown it is rendered `not (a, b)`).
- Under each layer's table, every modified rule has a detail table (`field | old | new`, lists `field | - removed | + added`) that the changed cells link to.
- Sections that contain changes appear as header rows with their rule range, for example `FPCR_UAT_Section_4 (2.1-2.2)`.
- Objects are listed per session: added and deleted objects in a short table, modified objects with their changed fields. Changes that are neither rules, sections nor ordinary objects are listed as "Other changes", and internal objects are counted in `Hidden internal changes: N (see JSON)`.

Markdown has no colour: it uses the markers `[+]` added, `[-]` deleted, `[~]` modified and `[x]` disabled, `~~strikethrough~~` for deleted and removed items, `+name` for added items and `name*` for items modified in the session.

## Limitations

- Numbering of unpublished sessions without an owned session. `show-changes` gives a modified rule a `position` only when the session moved it, and that position counts within the rule's section, not within the layer. Wherever the rule is in the rulebase cache (or in the live read through an owned session) its number is used. Otherwise, in a layer without sections the row shows prefix + position; in a layer with sections the row has no number and reads `– (position N in its section)`, under a "Section not known (or before the first section)" header.
- A move is detected by `position` being present, so a move to another section is detected too. The management API refuses to move a rule to another layer; a SmartConsole cut and paste across layers shows as a delete and an add.
- Auto-generated NAT rules are not reported as rules; their changes appear on the object's `nat-settings`.
- Threat Prevention exceptions are out of scope.
- Another administrator's unpublished session may be invisible to the API user; it then yields `session_not_found`.
- Group members and NAT references that `show-changes` returns as bare uids are named from the session's own entries first, then by read-only `show-object`, at most 200 lookups per report. Past the cap, or on a failed lookup, the uid is shown and a `names_unresolved` warning is added.
- Dates: see [Scopes](#scopes) for how aware datetimes are converted to the server's offset and filtered exactly on the publish time.

## Raw responses

`include_raw=True` (on `collect_change_report` and `build_change_report`) keeps one `RawResponse` per `show-changes` request per domain in `report.raw`, failed requests included (`success`, `code`, `message`). `response` is the merged, flattened page set that `api_query` returned (`{"changes": [...], "total": N}`), `None` on failure. HTML shows them in an appendix of `<details>` blocks; markdown never includes them; JSON carries them.

## Markdown truncation

`RenderOptions.markdown_max_rules` limits the number of rule rows (a rule in a shared inline layer counts once per package row), `markdown_max_objects` limits object, section and other-change rows. When a limit is reached the renderer stops that kind of row and appends one of:

```text
…and N more rules, full report via the library
…and N more objects, full report via the library
```

N counts rows. Session headers, warnings and the hidden-internal line are never truncated.

## Stored JSON

The JSON is `report.model_dump_json()`. Reading it back and rendering again needs no Check Point access:

```python
from arodonata.reports.changes import ChangeReport, render_change_report

report = ChangeReport.model_validate_json(path.read_bytes())
result = render_change_report(report, ["html"])
```

`format_version` is stored in the file; a report with a newer version than the installed library supports is refused with an error asking you to upgrade.
