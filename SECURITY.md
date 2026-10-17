# Security policy

Security fixes target the default branch and the latest supported release. This experimental project currently has no long-term support commitment.

Use GitHub's **Report a vulnerability** control in this repository's Security tab for confidential reports. Do not put credentials, real network details, site geometry or captures in a public issue. If private reporting is unavailable, open an issue requesting a private contact without including vulnerability details.

Include affected revision, impact, prerequisites and a minimal synthetic reproduction. Maintainers will assess the report and coordinate a fix and disclosure. No fixed response-time guarantee is made.

Public CI must never execute untrusted pull requests on an installation-connected runner. Firmware signing keys and approval hashes are supplied independently by the installation. A test key is never suitable for production.
