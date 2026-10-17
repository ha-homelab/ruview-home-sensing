# Contributing

Open an issue describing the behavior, expected result and a minimal independently fictional reproduction. Keep configuration and captures from real installations private. Use neutral zone IDs in examples.

Changes should include focused regression coverage for meaningful behavior, preserve bounded operations and fail-closed approval checks, and update the relevant documentation. Run the affected local tests and the full required CI checks before review. Hardware-dependent results must identify the tested hardware and method without claiming general accuracy.

Pull requests require review and passing checks. Dependencies and third-party source must have an identified license and immutable revision or hash. Do not add an application implementation already owned by the Home Assistant bridge or evidence-kit projects; add an explicit versioned integration instead.

Before committing, configure this checkout to use your GitHub-provided no-reply email address. Before pushing, run `python scripts/check-public-boundary.py` and `python scripts/check-public-history.py` with a complete local history. The history check rejects personal author or committer email addresses, including identities hidden by a mailmap. CI repeats both checks, but a check after upload cannot undo a disclosure; perform the local checks before publishing.

Contributions are accepted under this repository's MIT license unless clearly identified third-party licensing applies. Preserve copyright notices. Maintainers may request a smaller synthetic reproduction before reviewing private-data-sensitive behavior.
