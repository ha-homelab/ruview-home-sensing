# CSI collector

`source-lock.json` pins upstream source, lockfile checksums and submodule commits.
`prepare-source.py` verifies a clean checkout and applies the local patches.
The patches expire stale CSI grids, mirror raw samples with bounded queues,
confine recording names, and replace the public default RuField signing key.

The collector builder names Rust `1.96.1-bookworm` and pins its exact amd64
manifest. This matches `RUSTUP_TOOLCHAIN=1.96.1`, the Bookworm cross compiler
and ARM64 OpenSSL sysroot. Compiler or Debian-family migrations need joint
qualification; a moving untagged Rust digest must not select a newer Debian
base while the rest of this profile still targets Bookworm. Digest refreshes
within the named profile remain subject to the complete collector build.

The cross-build toolchain uses the signed Bookworm snapshot dated
`20260630T000000Z`. `install-system-deps.py` gives APT a 12-minute total
budget and a fresh private package cache. If authenticated package fetching
exhausts a transient transport retry or bounded timeout, it may fetch the
same package paths from the official Debian pool. Version selection stays
with the snapshot; SHA-256 and size from that selection must match before
an offline APT install. Signature failures, missing hashes, changed versions
and other archive roots fail closed. The helper is copied into the Docker
build context beside `source/`; CI records its digest with the source inputs.
The pinned runtime/toolchain images, ARM64 OpenSSL hashes and source lock
remain the build authorities.

`upstream-runtime-fixes.json` records selected fixes reviewed against upstream
`5728b90949e60e3f908d996997d453147c1794e0`. The base revision stays pinned so
the local grid, raw-mirror and signing protections retain their reviewed inputs.
This is a source backport, not a full upstream update or a runtime qualification.
The `0.3.5-home-grid.3` build additionally:

- Returns `status: "stale"`, `age_ms` and `source` instead of an old sensing
  classification after ten seconds without an update. Fresh responses gain
  `age_ms`; the existing `status: "no data yet"` response is unchanged.
- Evicts node state silent for sixty seconds on a thirty-second timer, including
  when no new packet arrives. Missing nodes remain unavailable observations.
- Refuses a routable HTTP/WebSocket bind with API authentication disabled unless
  `RUVIEW_ALLOW_UNAUTHENTICATED=1` is explicitly set. Loopback remains permitted.
- Keeps presence and person count consistent with the published debounced node
  classification; this does not validate recognition accuracy.
- Applies `--privacy-mode` to REST JSON, sensing/pose WebSocket streams and
  recordings as well as MQTT. It withholds heart/breathing rates and keypoints;
  unfilterable JSON is withheld, and refined skeletal REST views return HTTP 403.

The `0.3.5-home-grid.4` follow-up (`mqtt-freshness-fixes.json`) also checks the
actual MQTT input path. Only fresh sensing observations enter it: expired,
future/invalid, explicitly offline/unavailable and non-sensing messages are
withheld, never converted into an empty-room reading. Per-node source age is
included in the internal MQTT observation timestamp, so rebroadcasting a frozen
sample cannot renew availability. Source JSON and raw samples are unchanged.
The ten-second freshness limit and thirty-second refresh heartbeat remain.
A persistent one-second maintenance timer attempts availability transitions and
retries pending availability/discovery enqueues even during steady traffic.
Fresh input attempts a changed online state immediately. MQTT enqueue calls are
nonblocking, so a full request queue cannot deadlock the task that drains it.
Rejected state is logged and not credited as delivered; later fresh input can
publish normally. Queue acceptance is not broker acknowledgement, and neither
scheduling nor network delivery has a measured wall-time guarantee. Shutdown
notification remains best effort. A lagged broadcast receiver continues from
retained fresh input instead of terminating the bridge. The build adds source-age,
busy-loop, queue saturation and availability-retry regressions; the original
runtime patch is retained byte-for-byte.

The full collector build runs the upstream regression groups for these paths.
Consumers must treat a stale response or an evicted node as unavailable rather
than an empty room. None of these source changes alters a running installation.

Recording IDs contain at most 128 ASCII letters, digits, `.`, `_` or `-`,
excluding `.` and `..`. New files are created exclusively and with mode 0600
on Unix. The recordings directory and its parents must be operator-controlled;
this does not make an attacker-writable directory safe.

`WDP_RUFIELD_SIGNING_SEED` accepts exactly 64 hexadecimal characters or 32 raw
bytes. Invalid, all-zero or the former public default seed stops startup.
When the variable is absent, the OS random generator creates an ephemeral
Ed25519 identity. Its public key changes after restart: provision a private,
random seed if consumers require a stable identity. There is no fallback to
the public development key or weak random data if OS randomness fails.

The collector also applies a pinned, one-condition policy correction to
`ring` 0.17.14. Upstream rounded the RSA modulus length up to whole bytes
before checking its advertised 2048-bit minimum, accepting 2041–2047 bits.
The local patch compares the actual bit length. Signature algorithms, the
maximum length and exponent validation are unchanged. The registry still
listed 0.17.14 as the latest release on 2026-10-19.

`ring-policy/source.json` authenticates the original crate, changed source
and original workspace manifest/lockfile. Its path override keeps the `ring`
package version unchanged. The build runs both RSA PKCS#1 and
RSA-PSS verification against each actual compiled native `ring` library:
2040/2041/2047-bit keys must fail, 2048-bit keys must pass, and modified
messages must fail. The fixtures contain public keys and signatures only.
The full collector build remains necessary to qualify integration.
The unchanged dependency lifetime-syntax warnings have a
[separate source-specific disposition](../docs/ring-policy.md).

The generated `ruview-dependencies` directory contains the patched source,
five original license notices and `ring-policy-receipt.json`. The main
Dockerfile copies the notices and receipt into the runtime image. If using
`Dockerfile.runtime` with an already built binary, its context must also
contain `ring-licenses/` copied from `ruview-dependencies/licenses/ring/`
and the corresponding receipt. Distribute these files with standalone
collector binaries. An offline preparation additionally requires
`--ring-archive /path/to/ring-0.17.14.crate`; the same digest check applies.

After the ring override, `dependency_security.py` applies the exact lockfile
delta recorded in `dependency-security.json`: Rustls 0.23.46, rustls-webpki
0.103.16, webpki-roots 1.0.10 and quinn-proto 0.11.18, with their required
support packages. The helper checks the patch and both lockfile hashes. This
retains the application manifests and source pin. Wasmtime, Zstandard, ZIP and
libz-sys are absent from the selected ARM64 MQTT normal/build dependency graph;
their unrelated upstream updates are not imported into this backport.
The dependency security receipt is included at `/app/dependency-security-receipt.json`.
Prebuilt-binary contexts for `Dockerfile.runtime` must include that receipt too.

The build also gathers the original license and notice files for every package
in the selected ARM64 Cargo `normal,build` graph. It reads the already fetched,
locked sources without downloading unrelated workspace packages. Registry
archive hashes are checked against `Cargo.lock`, then original notice files are
read from those verified bytes; local crates retain their own or inherited
repository notices. Missing notices fail the build.
For the sixteen locked crates whose published archive omitted license files,
`license-overrides/sources.json` ties recovered original texts to the archive
checksum and the upstream Git revision embedded in that archive. The recovery
is exact-version only and does not change the crate's declared license. For
`anndists`, the original README expressly offers Apache-2.0 but the upstream
commit omits its referenced license file; the bundle preserves that README
and the official Apache-2.0 terms it links.
The bundle includes the project's notices, the selected Rust toolchain's
copyright collection, and the original Debian copyright files for the linked
`libc6` and `libgcc-s1` runtime libraries. Build-only packages and toolchain
notices are included conservatively; this does not mean all their code is linked.

Keep the complete `/app/licenses/collector/` directory beside a distributed
`sensing-server` binary. For `Dockerfile.runtime`, copy this directory from the
qualified image or artifact into the build context as `collector-licenses/`.
`index.json` records the Cargo package versions, declared license expressions,
source manifest hashes and delivered notice hashes. Runtime library notice
hashes are recorded separately in `runtime-libraries/SHA256SUMS`.

```sh
python collector/prepare-source.py /tmp/ruview-collector-source
sh collector/test-grid.sh
node --test collector/ui/tests/*.test.mjs
```

The UI health service retries recoverable failures and distinguishes stale data
from an active connection. Receiver-map colors describe CSI freshness, not a
person's measured location. `ui/home-floor/home-floor.js.in` is a generic template;
geometry and labels are supplied outside this repository. Operator-derived UI
images containing site configuration must remain private.
