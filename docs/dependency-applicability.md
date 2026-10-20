# Dependency security assessment

Review date: 2026-10-19. This is a bounded assessment of the selected source,
build recipes and pinned container images. It is not a clean vulnerability
scan, a complete finding disposition, or a claim about every optional upstream
service. Package-version matches need the affected component and an applicable
call path; absence from a scanner also does not prove safety.

## Firmware SDK correction

The selected ESP32-S3 firmware initializes ESP-NOW after connecting to Wi-Fi.
The `c6_sync_espnow` helper name does not restrict this call to an ESP32-C6.
Consequently,
[GHSA-hqhh-cp47-fv5g](https://github.com/espressif/esp-idf/security/advisories/GHSA-hqhh-cp47-fv5g),
published on 2025-06-24, affects the former ESP-IDF v5.4 build: the vulnerable
receive parser runs before the application's callback. Espressif lists
v5.4.2 and later as patched and no application workaround for v5.4.

[`firmware/Dockerfile`](../firmware/Dockerfile) now selects the official
v5.4.4 image at
`sha256:9ce51d4ace496845678065dc86f8e55fb9c25fc9f01f45597042afa7ed546926`.
Its source revision is
[`296b6eab9445fd720e71aecab961e2d3fbca9944`](https://github.com/espressif/esp-idf/tree/296b6eab9445fd720e71aecab961e2d3fbca9944),
which contains the published correction. The complete ESP32-S3 build passed
in [run 39367804957](https://github.com/ha-homelab/ruview-home-sensing/actions/runs/39367804957);
its [firmware evidence](https://github.com/ha-homelab/ruview-home-sensing/actions/runs/39367804957/artifacts/12239999153)
contains the actual SDK configuration, tool versions, map and ELF. This source
fix does not update already installed devices.

The [22-advisory SDK assessment](evidence/esp-idf-advisory-review.json)
uses this exact ESP32-S3 configuration, linked symbols and maintained callers.
The former ESP-NOW receive issue is fixed by the SDK update. Other rows have
specific version, target or entrypoint exclusions. In particular, the DHCP
server is compiled and linked, but this S3 application starts station mode
only; the upstream AP+STA branch requires both ESP32-C6 and its SoftAP option.
That exclusion does not qualify an optional C6 SoftAP build. The selected
5.4.4 version also meets the WPS advisory's patched-version minimum.

That SDK selects Mbed TLS 3.6.5 at
[`ffb280bb63c78bfec1e1ab55040671768c85c923`](https://github.com/espressif/mbedtls/tree/ffb280bb63c78bfec1e1ab55040671768c85c923).
The [19-row assessment](evidence/firmware-mbedtls-review.json) compares the
later upstream medium/high advisories with the actual configuration, linked
symbols and maintained callers. TLS 1.3, DTLS, PSK modes, ChaCha20 and DHM are
disabled. PKCS7 is configured in the library but no PKCS7 implementation is
linked into this firmware. Certificate writing, private RSA decryption and
long-term MbedTLS ECDSA signing are not maintained caller operations.

The compiled certificate bundle is not selected by the swarm HTTP caller:
that caller does not set a certificate, bundle callback or global CA store.
With insecure TLS disabled, an HTTPS URL fails setup; this assessment does
not claim a working complete firmware HTTPS profile. There is no untrusted
certificate-enrollment path or copying of initialized RNG state. The actual
Wi-Fi build selects the supplicant CCM implementation; its conditional
MbedTLS wrappers also use the one-shot APIs excluded by the multipart CCM
advisory. These are specific applicability decisions, not a blanket approval
of Mbed TLS 3.6.5 or a key-length/TLS qualification.

## Collector Rust dependencies

The [upstream lockfile](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/Cargo.lock)
contains 1,296 packages for the complete workspace. The maintained build
selects `wifi-densepose-sensing-server` with `mqtt`. The successful
[collector build](https://github.com/ha-homelab/ruview-home-sensing/actions/runs/39367804957)
records both exact feature trees in its
[build artifact](https://github.com/ha-homelab/ruview-home-sensing/actions/runs/39367804957/artifacts/12240461264):
355 distinct package/version tuples for ARM64 normal/build dependencies and
402 for the x86-64 normal/build/development test profile. The
[dated Cargo assessment](evidence/cargo-dependency-review.json) covers all 31
package versions matched by 1,262 exact-version OSV queries across the
collector, firmware-module and native-worker locks.

- **jsonwebtoken 9.3.1:**
  [CVE-2026-25537](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc)
  cannot bypass the selected
  [verifier](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/ruview-auth/src/verify.rs):
  it requires `exp`, validates it and deserializes it as `i64`; optional `nbf`
  validation is not enabled.
- **lru 0.12.5:**
  [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html)
  requires panic during key destruction in `pop` followed by reuse. Its only
  selected parent, `midstreamer-temporal-compare 0.2.1`, uses `String` keys and
  `get`/`put`, without `pop`, custom key destruction or panic recovery. It also
  does not call the mutable iterator in
  [RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002.html).
- **quinn-proto 0.11.15:** the August 17
  [connection-ID](https://rustsec.org/advisories/RUSTSEC-2026-0339.html),
  [stream](https://rustsec.org/advisories/RUSTSEC-2026-0341.html) and
  [datagram](https://rustsec.org/advisories/RUSTSEC-2026-0342.html) memory issues
  require an actual QUIC peer. The crate is compiled through the hardware
  dependency, but the
  [hardware transport](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/wifi-densepose-hardware/src/esp32/quic_transport.rs#L453)
  only updates local state; its proposed network call is a comment. All 34
  hardware source files and the selected server were checked for another
  call. The actual aggregator uses ordinary UDP, and the selected `reqwest`
  features exclude HTTP/3. This does not certify the upstream QUIC prototype
  as a working secure transport or repair Quinn for other applications.
- **tar 0.4.45/OpenBLAS:** both actual feature trees exclude `tar`,
  `openblas-build`, `openblas-src` and `ndarray-linalg`. The server and engine
  disable signal defaults, and the selected signal feature set is empty.
  The vulnerable archive extraction path in
  [GHSA-3pv8-6f4r-ffg2](https://github.com/advisories/GHSA-3pv8-6f4r-ffg2)
  is not part of these builds.
- **rand 0.8.5/0.9.2:** both actual feature trees omit `log`, which is required
  for the reentrant-logger trigger in
  [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html).
- **crossbeam-epoch 0.9.18:** this is a firmware host-benchmark/test dependency,
  not a normal WASM dependency. Its selected deque/rayon callers do not format
  `Atomic`/`Shared` pointers; deque debug implementations use constant
  placeholders. The invalid-pointer formatter in
  [RUSTSEC-2026-0204](https://rustsec.org/advisories/RUSTSEC-2026-0204.html)
  is not called. The collector selects corrected 0.9.20.

The four rustls 0.23.45 reports published October 14 remain tracked:
[RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
[RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html),
[RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) and
[RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html).
They are not critical; their 60-day date is December 13. The Brotli feature is
absent, but the other reports are not collectively declared inapplicable or
fixed. Maintenance-only bincode/paste notices also remain. No dependency
monitoring criterion is established merely by a finding being recent.

## Container and build-tool boundaries

The collector runtime image is pinned at
`sha256:29e6b4ce1893687de205324c509976c53911eff1abdfce3663256de3b82866d7`.
An October 19 Trivy scan identified 121 distinct advisory IDs, including
four IDs with a Critical scanner rating. These are raw matches, not 121
confirmed application vulnerabilities. The image contains Debian 12.15,
retains eleven SUID/SGID executables and has no non-root image default.
Local privilege escalation therefore cannot be dismissed just because the
software runs in a container.

The new build replaces `/app/sensing-server`; it retains the base image's
libraries, entrypoint and auxiliary executables. The final binary's native
imports and those retained paths remain part of the assessment.
For example, Debian explicitly documents that
[CVE-2023-45853](https://security-tracker.debian.org/tracker/CVE-2023-45853)
does not affect Bookworm's zlib binary because the vulnerable MiniZip
component is not built from that package. The inspected image contains no
MiniZip component. That specific exclusion does not resolve the other
runtime matches, including the installed Perl and privileged utility
findings.

The three pinned Python Alpine runtime bases each report seven advisory IDs.
Their 293 pip-vendored files were compared byte for byte with the PyPI
`pip-26.2.1-py3-none-any.whl`
(`71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e`).
The old findings have these specific dispositions:

- **msgpack 1.1.2,
  [GHSA-6v7p-g79w-8964](https://github.com/msgpack/msgpack-python/security/advisories/GHSA-6v7p-g79w-8964):**
  the included implementation is the Python fallback; the native
  `_cmsgpack` extension is absent. Moreover, pip's CacheControl calls
  `loads`/`unpackb`, which creates a fresh unpacker, rather than reusing a
  streaming unpacker after a caught error. The reported native use-after-free
  and reuse trigger are therefore absent in this included caller.
- **setuptools 70.3.0, CVE-2025-47273 and CVE-2026-59890:** pip includes only
  the `pkg_resources` subset. The affected `PackageIndex` downloader and
  `FileList` source-distribution builder are absent. The project's separate
  source-distribution build selects setuptools 84.0.0.

The other four matches are newer than 60 days at this review date:
zlib CVE-2026-85091 (published September 3), and urllib3
CVE-2026-97687, CVE-2026-97688 and CVE-2026-97689 (repository advisories
published September 15, before the September 29 CVE records).
They are not Critical-rated and are not excluded merely because of their age.
They remain maintenance candidates: pip's HTTPS downloader can reach remote
responses, while the runtime services use their documented standard-library
HTTP clients. This dated disposition must be revisited before those findings
cross the 60-day boundary: November 2 for zlib and November 14 for urllib3.

The Rust and ESP-IDF build images have separate findings. Linux header
package matches in a build image are not evidence that a vulnerable kernel
is running inside it, but executable build tools and dependencies still need
their own input and invocation review.

The complete old/critical vulnerability criteria remain unqualified while
these concrete dependency and runtime questions remain unresolved.
Neither a green build nor the SDK update alone establishes their closure.
