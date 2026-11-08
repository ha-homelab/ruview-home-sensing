# Public publication boundary

Do not submit credentials, receiver MAC addresses, real IP assignments, SSIDs, hostnames, location labels, site plans, purchase records, captures, models trained on private data, operational logs or private repository history.

Examples use neutral zone identifiers and independently fictional data. Do not anonymize a real recording by changing only its labels: timing, geometry, movement and derived observations can still disclose private information.

Public pull requests run on GitHub-hosted runners. They do not need installation secrets, credentials, private network access or production runners. Workflows receive read-only permissions unless a specific trusted publishing or security-reporting job requires more.

Before first publication and each release, inspect the exact source/archive inventory, run the publication-boundary check and secret scan, review all generated archives and metadata, and verify that no private configuration was copied into container layers. The source archive intentionally excludes operational evidence and generated firmware. Scanners supplement human review; an empty report is not proof that arbitrary data is safe.

Use GitHub no-reply identities for both Git authors and committers. Run `python scripts/check-public-history.py` before uploading commits; it checks the complete reachable history without printing email values. A source-content scan does not cover Git author metadata. Public CI repeats this check with full history, and rejects shallow checkouts rather than claiming complete coverage.

Report an accidental disclosure privately using the process in SECURITY.md. Rotate exposed credentials and evaluate affected history/artifacts; deleting the newest file alone does not erase previously published material.


### Recorded historical merge identity incident

The immutable squash merge `1c507290ab8b6f8bbba7f2d9644996a823832c4a`
([PR 31](https://github.com/ha-homelab/ruview-home-sensing/pull/31),
2026-11-08 02:52:04 UTC) has a non-noreply author identity. The shared merge
actuator did not explicitly bind a noreply author address, and GitHub assigned
the reviewer account's non-noreply author identity to this squash merge. This
metadata was already published; this disposition does not remove it or claim
a clean history.

The sole accepted historical finding is that exact commit's **author** role.
The full-history scanner still reports it and counts it separately when deciding
the exit status. No address or actor allowlist is permitted; every other commit
and the committer role remain subject to the original rule. Direct automated
merges must explicitly request the authenticated account's GitHub noreply author
address and fail closed if GitHub rejects the request. Native auto-merge requests
must use a separately qualified GitHub identity route with a verified account
email and account email privacy enabled. The tested bot's generated noreply value
was rejected as an explicit author-email override on that route; the native path
therefore leaves author-email selection to GitHub. Verify both author and
committer identities on the resulting merge, and stop further automation if
either is not a noreply identity. This policy does not waive content,
signature, current-head review, CI, or merge protection requirements.
