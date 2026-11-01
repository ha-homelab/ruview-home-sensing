# Upstream compatibility review

Reviewed on 2026-11-01 against
[`ruvnet/RuView` main at `5728b90949e60e3f908d996997d453147c1794e0`](https://github.com/ruvnet/RuView/commit/5728b90949e60e3f908d996997d453147c1794e0).
This project imports selected components and applies installation-independent
patches; it is not a copy of the entire upstream product.

## Scope of the difference

- The collector base, `7c8aeacea2ad30972070196eb7d8e7200506b742`, dates from
  October 4. It is 198 upstream repository commits behind the reviewed head.
  The sensing-server subtree has 31 non-merge commits and 35 changed files.
- The firmware base, `e04f269f1a76eb6ed4e8cd33e2ccfeda6fd391a3`, dates from
  August 31. It is 341 repository commits behind. Of the 65 pinned firmware
  inputs, 22 differ at the reviewed head. This is a component comparison, not
  evidence that every difference is a missing fix.
- The WASM-edge module source is also pinned to the August 31 revision, but its
  subtree has no intervening commits. All 82 imported source/license inputs
  match the reviewed head. The native worker consumes that same module source.
- The upstream root license is unchanged across both bases and the reviewed
  head. Existing component and dependency notice requirements still apply.

Repository-wide commit counts include unrelated work. For example, new radio
platforms, MediaTek ingestion, semantic MQTT and training changes do not become
requirements for this integration just because they landed upstream.

## Selected corrections

The collector runtime backport and exact original inputs are recorded in
[`upstream-runtime-fixes.json`](../collector/upstream-runtime-fixes.json).
It withdraws stale latest responses, evicts silent nodes without waiting for a
new packet, checks unauthenticated routable binds, keeps published presence
counts internally consistent, and extends the requested privacy mode to REST,
WebSockets and recordings. See the [collector notes](../collector/README.md)
for consumer-visible behavior and required startup configuration.

The [dependency security policy](../collector/dependency-security.json) locks
Rustls 0.23.46, rustls-webpki 0.103.16, webpki-roots 1.0.10 and quinn-proto
0.11.18, with the supporting package changes required by QUIC. The original
and resulting dependency graphs were resolved with `--locked` for ARM64 and
the collector's `mqtt` feature. The selected normal/build graph includes these
packages; it does not include Wasmtime, Zstandard, ZIP or libz-sys. Their
upstream monorepo updates are therefore not imported into this collector.
The existing patched `ring` remains in place.

The firmware backport bounds the ICMP receive wait to the configured probe
interval in both legacy and optional recovery paths. This addresses the
one-second wait on a missing echo. The existing OTA stack-size correction was
already present and does not need another backport. New upstream configuration
APIs that are not imported here do not justify adding unrelated handlers.

The immutable component bases remain explicit. Advancing the complete collector
would also import approximately 9,638 added and 762 removed lines and a changed
RuField submodule. Selected backports preserve the existing grid expiry, raw
payload mirror, signing, firmware recovery and CSI admission contracts while
the full upstream integration remains a separate, reviewable migration.

## Validation and future reviews

Host regressions exercise the assembled source, including preceding local
patches. The complete CI additionally builds the collector for ARM64, runs its
upstream regression groups and compiles the ESP32-S3 firmware. A source review
or host test alone does not establish successful cross-compilation.

For another review, fetch the upstream head and compare each imported subtree
and file manifest, then subtract fixes already represented by local patches.
Retain exact upstream commit provenance and hashes for backports. Resolve
security updates against the selected target/features; a package appearing in
the monorepo lockfile does not prove it is included in the collector binary.

These are source changes. They do not update deployed images, flash devices,
change model inputs or relax runtime qualification. Existing observations keep
their original source identity and limitations. Probe frequency, presence
classification and fresh API responses do not validate sensing accuracy.
