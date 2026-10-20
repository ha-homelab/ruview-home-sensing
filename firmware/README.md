# ESP32-S3 firmware source and qualification tools

See [build validation and compiler diagnostics](../docs/build-validation.md)
for the complete firmware build boundary, required tools and the reviewed
warnings retained in the pinned upstream module sources.

This directory builds a patched, pinned RuView firmware and verifies its radio,
module runtime and update protocols. It contains no installed receiver inventory,
network configuration, trusted deployment key, signed deployment module or
hardware acceptance record. Builds and passing host tests do not establish
person detection, coordinates, posture or fall accuracy.

## Build a generic source context

```sh
python3 firmware/fetch-source.py /tmp/ruview-firmware-context
docker buildx build --target artifacts \
  --output type=local,dest=/tmp/ruview-firmware-output \
  /tmp/ruview-firmware-context
```

The upstream source commit and every downloaded file are pinned in
`upstream-files.json`. The source context includes the upstream MIT license.
The Dockerfile pins ESP-IDF, WASM3 and the LED component; vendored Monocypher
retains its license and provenance manifest. The profile expects an ESP32-S3
with 16 MiB flash and 8 MiB octal PSRAM. Confirm the actual board before using a
build. No build command flashes hardware.

**No public verification key is trusted by default.** A generic build keeps
signed uploads mandatory and rejects uploads unless a key is already configured
in NVS. NVS keys retain precedence. To configure a fallback key, supply exactly
32 raw Ed25519 public-key bytes and their independently approved SHA-256:

```sh
python3 firmware/fetch-source.py /private/build-context \
  --wasm-public-key /private/approved-public-key.bin \
  --wasm-public-key-sha256 "$APPROVED_PUBLIC_KEY_SHA256"
```

A digest calculated from an unreviewed candidate is not independent approval.
The signing private key never belongs in the build context. Contexts containing
site configuration or a deployment trust identity, and resulting binaries,
logs and caches, stay private.

## Explicit board profiles

`fleet/build_profile.py` validates exact AP, radio, memory and RGB settings.
`--fleet-plan`, `--fleet-overlay` and `--firmware-version` are supplied together
to the fetcher; build them with `FIRMWARE_PROFILE=fleet-reviewed`. The exported
profile remains a candidate: it cannot authorize a flash or layout change.
The legacy `node2-preferred-ap` profile is retained solely as a protocol
compatibility recipe. It requires a separately approved private overlay mounted
as a BuildKit secret; it is not an installation recommendation or default.

The associated-only capture profile uses LLTF CSI, static internal Wi-Fi TX
buffers, and disabled RGB animation. Changing the RF profile requires new
calibration. AP selection/recovery, HTTP deadlines, module lifecycle telemetry,
boot-bound recovery and packet sequence changes are isolated in numbered
patches. Preserve patch order. Review the real on-device stack, heap, radio and
callback budget; host timings do not measure ESP32 performance.

For password-protected networks, the default station requires WPA2/WPA3 with
AES pairwise and group data ciphers.
Patch `0020` raises the authentication threshold; the separately pinned
`wifi-security/apply.py` patches ESP-IDF 5.4.4 before compilation to reject
WPA1/WEP/TKIP before the WPA key handshake. It checks selected cipher enum
values, not an AP's advertised capability mask. Both input and patched source
hashes are exported in `ruview-wifi-policy.json`. The public Docker recipe
requires `CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY` to stay disabled. A custom
IDF build can explicitly enable this legacy option, but then no AES-only
policy applies. Empty-password open networks remain unencrypted. See the
[security profile](../docs/security-profile.md#wi-fi-association-policy).

## Build and sign module candidates

```sh
python3 firmware/fetch-modules.py /tmp/ruview-modules --profile home-signal-v5
cd /tmp/ruview-modules
cargo test --locked --features std --lib
cargo build --locked --lib --release --target wasm32-unknown-unknown
```

The `home-signal-v2` through `home-signal-v5` names describe source profiles for
bounded/incremental DTW implementations, not installed packages or approvals.
Rust, dependencies and WASM target settings are pinned. Run `sign-module.py
--help` to package a candidate using a private Ed25519 key kept off builders.
Use immutable package names and explicit event maps. See
[module-contract.md](module-contract.md).

## Qualification and restoration

`qualify-module-upload.py` performs a controlled negative-signature test and one
valid upload; uncertain mutations are never automatically retried.
`observe-runtime.py` collects a bounded runtime trial without mutating a device.
Both require an explicitly selected node/version and independently approved
installation identity, site context and qualification package catalog. The
observer also requires an approved collector profile. Use `--help` for exact
arguments. The catalog schema is `ruview.qualification-packages.v1` and contains
`profile`, `name`, `file`, `package_sha256`, `wasm_sha256`, `package_bytes` and
`wasm_bytes` per package. No catalog is loaded implicitly.

`reconcile-modules.py` separately requires a pinned deployment manifest. A
qualification catalog cannot enable restoration. Restoration needs explicit
per-target eligibility, the selected immutable package, and durable attempt
state. Boot-bound and legacy protocols keep their separate bounded attempt
rules. Stopped, mismatched, faulted or ambiguous state requires operator review.
Runtime acceptance does not promote model accuracy or placement validity.

## Verification

Host C tests take an explicitly fetched source directory. The actual WASM3 host
runtime test additionally requires the pinned WASM3 checkout and an explicit
`--wasm` artifact built from reviewed sources. Python tests use synthetic protocol
packages under `tests/fixtures/modules`, never installed signed modules or a
real deployment key. Fleet operations and their independent review boundary are
explained in [fleet/README.md](fleet/README.md).

### Numeric word access in the interpreter

Patch `0021-alias-safe-words.patch` replaces incompatible typed pointer accesses
in WASM3 code emission and constant-slot reuse with fixed-size `memcpy` calls.
It retains the same byte representation, slot widths and index increments;
strict aliasing stays enabled. The patch also removes one unused local from the
LD2410 parser without changing which frames it accepts. The host regression
compiles the actual patched interpreter with optimization and strict-aliasing
diagnostics, exercises both slot widths and emitted code-cell layouts, and
checks synthetic normal/engineering radar reports. Existing runtime tests apply
the same patch. These checks do not establish on-device performance or sensing
accuracy; the full ESP32-S3 build is a separate required CI job.
