# Contributing

Open an issue describing the behavior, expected result and a minimal independently fictional reproduction. Keep configuration and captures from real installations private. Use neutral zone IDs in examples.

Changes should include focused regression coverage for meaningful behavior, preserve bounded operations and fail-closed approval checks, and update the relevant documentation. Run the affected local tests and the full required CI checks before review. Hardware-dependent results must identify the tested hardware and method without claiming general accuracy.

Pull requests require review and passing checks. Dependencies and third-party source must have an identified license and immutable revision or hash. Do not add an application implementation already owned by the Home Assistant bridge or evidence-kit projects; add an explicit versioned integration instead.

Contributions are accepted under this repository's MIT license unless clearly identified third-party licensing applies. Preserve copyright notices. Maintainers may request a smaller synthetic reproduction before reviewing private-data-sensitive behavior.
