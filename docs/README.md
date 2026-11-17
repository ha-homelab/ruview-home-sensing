# RuView Home Sensing — documentation index

This index covers the reusable public RuView source: CSI collectors, bounded edge
modules, inference experiments, ESP32-S3 enclosures and the interface and security
contracts around them. Site-specific configuration and operational history belong
in the separate private installation repository.

## Get started

- [Architecture and release boundaries](architecture.md): components, data flow
  and what the public source covers.
- [Reproducible distribution and private consumption](distribution.md): how to
  build and how the archive is consumed privately.
- [Release notes](release-notes.md): current version, fixes and migration notes.

## Configure

- [Pinned collector interface](collector-interface.md): the collector selected by
  `collector/source-lock.json`.
- [External interfaces](interfaces.md): the public surface and its authorization
  boundaries.
- [Command inventory](command-inventory.md): commands, side effects and the
  workflows they belong to.
- [Upstream compatibility review](upstream-sync.md): component drift and selected
  fixes from the original project.

## Reference

- [Cryptography and transport boundaries](security-profile.md).
- [Collector RSA policy](ring-policy.md) and [build tools and reviewed compiler
  diagnostics](build-validation.md).
- [Test coverage and limitations](testing.md).
- [Public publication boundary](privacy.md).

## Development

- [Build-tool vulnerability assessment](build-tool-security-review.md).
- [Dependency security assessment](dependency-applicability.md).
- [Selected Debian runtime findings](debian-runtime-review.md).
- [Static analysis and diagnostic decisions](static-analysis-review.md).

## Evidence

- [Test coverage summary](test-coverage-20261019.json): machine-readable results
  that accompany the testing notes.
- Security review records are under `evidence/`; the dated reviews above
  interpret them.

A recorded review or test result covers the exact source revision it names. It is
not a live status report or a certification of your installation.
