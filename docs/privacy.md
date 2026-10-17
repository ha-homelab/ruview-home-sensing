# Public publication boundary

Do not submit credentials, receiver MAC addresses, real IP assignments, SSIDs, hostnames, location labels, site plans, purchase records, captures, models trained on private data, operational logs or private repository history.

Examples use neutral zone identifiers and independently fictional data. Do not anonymize a real recording by changing only its labels: timing, geometry, movement and derived observations can still disclose private information.

Public pull requests run on GitHub-hosted runners. They do not need installation secrets, credentials, private network access or production runners. Workflows receive read-only permissions unless a specific trusted publishing or security-reporting job requires more.

Before first publication and each release, inspect the exact source/archive inventory, run the publication-boundary check and secret scan, review all generated archives and metadata, and verify that no private configuration was copied into container layers. The source archive intentionally excludes operational evidence and generated firmware. Scanners supplement human review; an empty report is not proof that arbitrary data is safe.

Report an accidental disclosure privately using the process in SECURITY.md. Rotate exposed credentials and evaluate affected history/artifacts; deleting the newest file alone does not erase previously published material.
