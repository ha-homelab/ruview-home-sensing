# Build-tool vulnerability assessment

Review date: 2026-10-19. This assessment follows the commands and input surfaces
of the supplied public build recipes. It does not certify arbitrary programs
installed in the builder, a host kernel, modified sources or operator-added
commands. The [grouped evidence](evidence/build-tool-review.json) retains the
reviewed advisory IDs and raw scan digests. Runtime, Cargo and SDK findings
have separate assessments.

## Active download paths repaired

The ESP-IDF 5.4.4 builder is pinned to
`sha256:9ce51d4ace496845678065dc86f8e55fb9c25fc9f01f45597042afa7ed546926`.
Its source tree remains the published SDK revision
`296b6eab9445fd720e71aecab961e2d3fbca9944`. The base image's build clients
needed additional corrections:

- **GnuTLS:** Git HTTPS uses this library. Certificate name-constraint, SAN
  and OCSP issues cannot be dismissed because the repository URL uses HTTPS.
  The build installs Ubuntu `libgnutls30t64` `3.8.3-1.1ubuntu3.6`, whose
  package changelog records those fixes, before fetching source.
- **nghttp2:** the client-session termination issue
  [CVE-2026-27135](https://www.cve.org/CVERecord?id=CVE-2026-27135) is relevant
  to an HTTP/2 client. The build installs Ubuntu `libnghttp2-14`
  `1.59.0-1ubuntu0.4`, which includes the earlier `.3` correction.
- **urllib3:** `idf-component-manager` 2.4.9 downloads with Requests'
  `stream=True`, follows redirects and iterates response content. That
  reaches the decompression paths in
  [CVE-2025-66418](https://www.cve.org/CVERecord?id=CVE-2025-66418),
  [CVE-2025-66471](https://www.cve.org/CVERecord?id=CVE-2025-66471) and
  [CVE-2026-21441](https://www.cve.org/CVERecord?id=CVE-2026-21441).
  The build installs the official **2.8.0** wheel into IDF's Python environment.
  The version also contains the later parser corrections.

[`packages.json`](../firmware/build-security/packages.json) pins both
architecture-specific Debian packages and the wheel by URL and SHA-256.
The source preparer stages and verifies them before Docker runs affected
clients. Installation uses exact filenames; pip runs with no index, no
dependency resolution and required hashes. The metadata came from official
HTTPS repositories; this review does not claim an independent verification
of Ubuntu's InRelease signature.

The build asserts the installed Debian versions and records the actual
`git-remote-https` GnuTLS/nghttp2 linkage. It explicitly enables IDF's normal
offline dependency checks, retains the image's original constraints and
runs `pip check`; it does not disable a constraint to make the upgrade pass.
`BUILD_TRANSPORT.txt` and `BUILD_TRANSPORT_PACKAGES.json` accompany the
firmware output.

The [downloader regression](../firmware/build-security/test_download.py)
calls the real component-manager downloader against loopback HTTP. Ordinary
gzip content must be returned unchanged; six nested content encodings must
be rejected without a completed output file. The old urllib3 1.26.20
accepted the excessive chain; 2.8.0 passed both assertions in the independent
local test. The Docker build repeats that test in IDF's actual Python 3.12
environment before the complete firmware build. A local Python 3.14 result
does not substitute for that target-environment check.

## Remaining builder findings

The exact IDF image scan contained 6,381 package findings, representing 5,862
unique IDs. Selecting all Critical findings and medium-or-higher findings
known before August 20 produced 3,104 IDs. Of these, 2,874 were attributed
to Linux headers and 230 to other packages; none of the latter had a
Critical scanner rating. Header matches do not identify a running kernel.

The 230 remaining IDs were examined by affected operation:

- The default component registry has a fixed ASCII hostname. Metadata joins
  paths without replacing that hostname. The exact Requests 2.33.1 and
  urllib3 2.8.0 redirect probe did not pass raw or percent-encoded Unicode
  Location hosts to `idna.encode`. Thus the long-input IDNA issue does not
  have the proposed redirect path in this build. A custom registry or
  directly configured Unicode source URL needs its own assessment.
- The only selected managed component, `espressif/led_strip` 3.0.1, is a ZIP
  archive. The downloader dispatches it to ZIP extraction, not the vulnerable
  Python/GNU tar hardlink and incremental-restore paths. Decompression
  failures are not caught and resumed on the same failed decompressor.
- Python's cryptography package is not Requests' TLS implementation.
  The firmware build supplies no private signing key and invokes no SECT
  public-key validation, PKCS7 decryption or cryptography certificate-chain
  verification. Its old findings therefore need different calls than this
  build makes.
- The selected pip command installs only verified local wheel bytes. It
  does not consult a malicious package index or accept arbitrary wheel paths
  or entry-point names. The separate system `python3-pip-whl` archive is not
  executed.
- The relevant libc DNS findings affect reverse lookups or deprecated DNS
  debug-printing functions, not the ordinary forward resolver. Other libc
  rows require specific non-Unicode encodings, `wordexp` modes or scanf
  formats absent from these build interfaces.
- No SSH/SFTP, authenticated proxy, SASL, printer, desktop/media decoder,
  database changeset, p11-kit RPC, systemd login service or QEMU network is
  invoked. XML/HTML, Perl archive, compiler diagnostic and filesystem-race
  rows retain their specific absent input conditions in the grouped record.

The Rust builder is pinned to
`sha256:d99f7b31f49909348dc59b51f3c95d1efded1701ffb222f095aaab7de3c4abd8`.
Its corresponding selection contained 2,636 IDs: 2,356 header matches and
280 other IDs. Its 17 reviewed groups cover the actual compiler, fixed
snapshot APT install, two separate public HTTPS curl downloads, hash checks
and extraction commands. In particular, APT 2.6.1 splits clear-signed
metadata into a detached signature and data before invoking gpgv, rather
than entering the reported GnuPG cleartext-armor parser. Curl's identified
authentication/proxy state requirements are absent from those commands.
This base-image scan is not represented as a fresh scan of every package
installed later by the authenticated snapshot.

These decisions do not mark every installed vulnerable package as patched.
Recent noncritical reports, including GnuTLS reports published in October,
remain maintenance inputs. There is no blanket dependency-monitoring or
zero-vulnerability claim. The deadline-based vulnerability criteria also
require the separate runtime and SDK assessments, successful qualification
of the actual repairs and an available project change.
