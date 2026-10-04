# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in arodonata, please report it
privately using [GitHub's private vulnerability reporting](https://github.com/chkp-antonr/arodonata/security/advisories/new)
rather than filing a public issue.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce it
- Any relevant logs, configuration, or code snippets (with credentials and
  customer-identifying details removed)

We'll acknowledge your report and work with you on a fix and coordinated
disclosure timeline.

## Supported Versions

Only the latest released version is actively supported with security fixes.

## Server identity verification

Arodonata verifies the Check Point management servers it connects to by the SHA-256 fingerprint of their certificate, checked after the TLS handshake and before any request is sent (TLS 1.2 or later).
By default (`ARODONATA_TLS_TRUST=tofu`) the first certificate seen at an address is trusted and recorded in a trust store file readable only by its owner, and a different certificate is refused; `pinned` accepts only fingerprints from the store or `ARODONATA_TLS_FINGERPRINTS`.
Trust on first use does not protect the very first connection, so use `pinned` where that matters.
Certificate verification cannot be switched off, and every connection has a connect and a read timeout.
Details: [TLS Verification](docs/configuration/tls-verification.md).
