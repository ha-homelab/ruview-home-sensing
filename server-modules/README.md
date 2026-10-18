# Native sensing modules

This Rust worker consumes per-receiver CSI, maintains bounded state, and exports
freshness, accounting and diagnostic output. `algorithms.json` declares the module
catalog. Module availability does not establish recognition accuracy.

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
