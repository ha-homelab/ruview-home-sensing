# Native sensing modules

This Rust worker consumes per-receiver CSI, maintains bounded state, and exports
freshness, accounting and diagnostic output. `algorithms.json` declares the module
catalog. Module availability does not establish recognition accuracy.

See [CSI sender profiles](CSI-PROFILES.md) for explicit LLTF/STBC admission,
provenance, raw preservation, first-word masking and downstream feature
boundaries. Default admission remains unchanged.

```sh
python server-modules/prepare.py /tmp/ruview-native
cd /tmp/ruview-native/worker
cargo test --locked --all-targets
cargo build --locked --release
```

Source preparation uses the same pinned upstream module source as firmware and
applies the bounded tailgating patch. HTTP snapshots use a fixed cache and bounded
encoding. UDP admission, sequence accounting and sample ages are explicit; stale
or inconsistent evidence must not be presented as current measurement.

Capture storage uses exclusive ownership, bounded session/byte quotas, durable
metadata and explicit completeness. Interrupted or incomplete capture is not
training evidence. Exported CSI and diagnostics can reveal private activity and
must stay in operator-controlled storage. The service smoke tests cover process
ownership, restart, accounting and capture behavior with synthetic packets.

## Dependency update qualification

The native worker manifest and lock are one manually maintained composition:
`server-modules/Cargo.toml` depends on `../upstream`, which intentionally does not
exist in a plain source checkout. `prepare.py` verifies the exact upstream
revision `e04f269f1a76eb6ed4e8cd33e2ccfeda6fd391a3`, the file hashes in
`firmware/modules/upstream-files.json`, and the three reviewed module patches
before constructing sibling `worker` and `upstream` directories outside the
checkout. Renovate excludes this manifest/lock pair from direct changes; the
other configured dependency managers and GitHub vulnerability alerts stay active.
Do not make the shared updater execute repository preparation code or replace
the verified upstream source with a stub just to regenerate a lock.

For a dependency or security update, review any required direct version change
in `server-modules/Cargo.toml`, then prepare a fresh external workspace with the
existing command and request the affected package explicitly:

```sh
python server-modules/prepare.py /tmp/ruview-native
cd /tmp/ruview-native/worker
cargo update --package AFFECTED_PACKAGE --precise REVIEWED_VERSION
cargo test --manifest-path ../upstream/Cargo.toml --target-dir target --locked --no-default-features --features std --lib sec_tailgating::tests
cargo test --locked --all-targets
cargo build --locked --release
```

Use the pinned Rust 1.96.1 toolchain selected by `rust-toolchain.toml`. Review the
resolved lock and copy the resulting `worker/Cargo.lock` back to
`server-modules/Cargo.lock`; commit it together with any manifest changes. A
transitive security fix requires checking the advisory's fixed range against
the actual resolved package for every affected target/feature combination.
A successful resolver exit alone does not prove remediation. If existing parent
constraints or pinned upstream inputs prevent a fixed resolution, keep the
advisory open and qualify their changes explicitly.

Run the repository's complete existing CI qualification, including the native
worker's service, fleet and capture smoke tests, before merging this composed
source/lock update. This manual boundary does not change the separately pinned
firmware or collector dependency graphs.
