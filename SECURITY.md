# Security policy

Security fixes target the default branch and the latest supported release. This experimental project currently has no long-term support commitment.

Use GitHub's **Report a vulnerability** control in this repository's Security tab for confidential reports. Do not put credentials, real network details, site geometry or captures in a public issue. If private reporting is unavailable, open an issue requesting a private contact without including vulnerability details.

Include affected revision, impact, prerequisites and a minimal synthetic reproduction. Maintainers will assess the report and coordinate a fix and disclosure. No fixed response-time guarantee is made.

Public CI must never execute untrusted pull requests on an installation-connected runner. Firmware signing keys and approval hashes are supplied independently by the installation. A test key is never suitable for production.

## Deployment transport boundary

Supported device HTTP and MQTT paths can transmit bearer credentials, passwords and sensing data without transport encryption. Signed modules authenticate their content; they do not encrypt telemetry or OTA requests. The activity service can also listen on all IPv4 interfaces. A complete end-to-end TLS deployment profile is not provided by this release.

Keep these endpoints on a trusted, isolated device network. Do not expose them directly to the internet. Remote access needs an authenticated encrypted tunnel or an appropriately configured gateway, with the unencrypted device-side segment still isolated. Network isolation reduces exposure but is not cryptographic transport protection. Review the actual paths and listeners before deploying with real credentials.

## Triage and disclosure

Maintainers record the affected revision, reproduction, impact, prerequisites, severity, remediation decision and verification results. Keep the reporter informed of material changes and explain decisions to close a report without a fix. Coordinate disclosure with actionable mitigation or upgrade instructions, keeping confidential correspondence private.

Prioritize applicable critical findings promptly and track applicable medium-or-higher vulnerabilities from their first public disclosure date. Release notes identify security fixes, affected and fixed versions, upgrade instructions and assigned advisory identifiers when available. Credit reporters using their preferred public attribution, or honor a request for anonymity.
