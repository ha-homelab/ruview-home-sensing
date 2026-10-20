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
which contains the published correction. A successful complete build using
this pin is required to qualify the replacement firmware. This source fix
does not update already installed devices.

That SDK selects Mbed TLS 3.6.5. Its
[later upstream advisories](https://mbed-tls.readthedocs.io/en/latest/security-advisories/)
require a separate configuration and call-path assessment. The ESP-NOW fix
does not establish that every Mbed TLS feature is unaffected. In particular,
the remaining review distinguishes the application's HTTP client from
TLS-server, DTLS, PKCS7, certificate-registration and ECDHE-PSK configurations
rather than treating all of those as active merely because the library
contains them.

## Collector Rust dependencies

The [upstream lockfile](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/Cargo.lock)
contains 1,296 packages for the complete workspace. The maintained build
selects `wifi-densepose-sensing-server` with the `mqtt` feature. A complete
workspace lock is not the same as the selected production dependency graph;
native test dependencies and the ARM64 release graph must also be
distinguished.

The following findings have specific source-based dispositions:

- **jsonwebtoken 9.3.1,
  [CVE-2026-25537 / GHSA-h395-gr6q-cpjc](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc).**
  The affected pattern enables time-claim validation without requiring a
  correctly typed claim. The selected
  [access-token verifier](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/ruview-auth/src/verify.rs)
  requires `exp`, deserializes it as `i64`, and enables expiration validation.
  It does not enable optional `nbf` validation. This excludes the reported
  bypass for that verifier; it does not repair the dependency or approve
  other configurations.
- **lru 0.12.5,
  [RUSTSEC-2026-0253](https://rustsec.org/advisories/RUSTSEC-2026-0253.html).**
  The reported use-after-free requires a key destructor to panic during
  `pop`, recovery from that panic, and subsequent cache use. The locked
  `midstreamer-temporal-compare` 0.2.1 source uses `String` keys and `get`/`put`;
  it has no `pop`, custom key destructor or panic-recovery path. Its cache
  code also does not call the mutable iterator implicated in
  [RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002.html).
  These are call-site exclusions, not a general approval of this lru version.

The following concrete candidates still require qualification:

- **quinn-proto 0.11.15:** the August 17 findings
  [RUSTSEC-2026-0339](https://rustsec.org/advisories/RUSTSEC-2026-0339.html),
  [RUSTSEC-2026-0341](https://rustsec.org/advisories/RUSTSEC-2026-0341.html)
  and [RUSTSEC-2026-0342](https://rustsec.org/advisories/RUSTSEC-2026-0342.html)
  concern peer-triggered memory growth and are corrected in 0.11.17.
  The lockfile has paths through `midstreamer-quic` and optional HTTP/3
  dependencies. Confirming the selected features and actual endpoint
  construction is necessary before either excluding or repairing this
  runtime path. A lockfile-only match is not an exploit demonstration.
- **tar 0.4.45:** the lockfile path is through
  `openblas-build` / `openblas-src` / `ndarray-linalg`, not the application's
  recording export. Both the sensing server and engine disable default
  features on their signal dependency, but the final unified feature graph
  still needs verification before excluding this build-time candidate.
- **crossbeam-epoch 0.9.18 in the firmware module's development graph:**
  [RUSTSEC-2026-0204](https://rustsec.org/advisories/RUSTSEC-2026-0204.html)
  concerns formatting an invalid pointer. It is not a dependency of the
  produced WASM module's normal graph. The affected formatting operation
  still needs separate review for the benchmark/test chain. The collector
  lock selects 0.9.20.

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
CVE-2026-97687, CVE-2026-97688 and CVE-2026-97689 (September 29).
They are not Critical-rated and are not excluded merely because of their age.
They remain maintenance candidates: pip's HTTPS downloader can reach remote
responses, while the runtime services use their documented standard-library
HTTP clients. This dated disposition must be revisited before those findings
cross the 60-day boundary.

The Rust and ESP-IDF build images have separate findings. Linux header
package matches in a build image are not evidence that a vulnerable kernel
is running inside it, but executable build tools and dependencies still need
their own input and invocation review.

The complete old/critical vulnerability criteria remain unqualified while
these concrete dependency and runtime questions remain unresolved.
Neither a green build nor the SDK update alone establishes their closure.
