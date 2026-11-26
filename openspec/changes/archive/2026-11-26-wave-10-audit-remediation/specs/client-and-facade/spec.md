# Spec Delta

## ADDED Requirements

### Requirement: SSE Control Field Sanitization Against Frame Injection

**ID**: REQ-CLIENT-019\
**Intent**: Prevent CR/LF/NUL injection and SID leakage in SSE wire `id:` and `event:` headers.\
**Non-goals**: Multiline JSON `data:` payload serialization (`REQ-CLIENT-016`).

`SSEEvent.encode()` SHALL strip CR, LF, and NUL control characters from `id` and `event` header fields and apply SID redaction to `event` before formatting SSE wire frames.

#### Scenario: SCN-CLIENT-019-1 — SSEEvent.encode strips newlines/NUL from id and event and redacts SIDs in event

- **GIVEN** an `SSEEvent` or `to_sse_event(..., event_id=...)` input whose `id` or `event` contains `\r`, `\n`, `\x00`, or an embedded SID pattern
- **WHEN** `encode()` formats the SSE wire frame
- **THEN** the emitted frame SHALL contain zero injected `data:`/`event:` lines and SHALL scrub any SID pattern from both `id:` and `event:` headers
