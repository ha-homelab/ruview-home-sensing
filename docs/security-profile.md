# Cryptography and transport boundaries

This inventory describes the public source, not an installation certification.
No device is flashed or contacted by the regression tests.

## Bridge and Python clients

The compatibility imports use the separately published, SHA-256-pinned
`ruview-home-assistant` **0.1.2** wheel. Version 0.1.0 did not include the
strict TLS implementation; its past qualification must not be attributed to
that earlier wheel. The installed-adapter check verifies the new wheel's
recorded digest, imports and API behavior.

HTTPS uses Python's verified OpenSSL client context with trust-chain and
hostname validation and TLS 1.2 or newer. `RUVIEW_STRICT_TLS=true` additionally
selects OpenSSL security level 3, preserving any stronger policy and the
existing cipher selection. This requires OpenSSL 3 or newer, rejects RSA/DH
keys below 3072 bits and excludes static RSA key exchange. The bridge also
requires HTTPS/WSS service URLs and `MQTT_TLS=true` in that mode. Configure
`MQTT_CA_CERTS`, and optionally `MQTT_CERTFILE` plus `MQTT_KEYFILE`, using the
operator's trust material. Set the appropriate TLS port explicitly.

The activity service now supports these MQTT TLS variables. Its HTTP clients,
the collector observation and coverage tools, the server-module verifier and
the floorplan WSS client use the same TLS policy. The local helper is
standard-library-only so that source fetchers can use it before the bridge is
installed. It calls OpenSSL; it does not implement certificate validation or a
cryptographic primitive.

The server-module verifier refuses redirects before forwarding any bearer
credential. Credential-bearing HTTP clients disable ambient proxies. Public
source downloads can follow HTTPS redirects but refuse a downgrade to HTTP or
URL credentials; the independent source digest remains mandatory.

This strict profile is **not yet a complete project-wide deployment profile**.
Its 3072-bit RSA requirement is stricter than OpenSSF's 2048-bit example:
on 2026-10-19 actual public source endpoints rejected by level 3 included
`raw.githubusercontent.com` and `archive.ubuntu.com`. Do not bypass trust
validation to make them work. Ordinary verified HTTPS remains the default.
The exact smaller-key boundary and all build/runtime clients need separate
qualification before claiming complete key-length coverage.

## Devices, keys and hashes

Device HTTP, ordinary MQTT and the activity HTTP listener retain the deployment
boundary in [SECURITY.md](../SECURITY.md). Signing a module does not encrypt
telemetry, credentials or OTA requests. A strict client connection also does
not encrypt a downstream gateway-to-device segment.

WASM signing uses `cryptography`'s Ed25519 implementation. Firmware verification
uses pinned Monocypher 4.0.3 Ed25519, rather than the original public-key/hash
comparison. An independently approved deployment public key is required;
there is no trusted default signing key.

Python-generated OTA keys and signing seeds use `secrets.token_hex(32)`.
The collector's RuField signer uses `rand::rngs::OsRng` when its explicit
32-byte seed is absent. Invalid configuration or RNG failure stops startup;
the former public development seed is rejected. An unconfigured identity
rotates on restart. See [collector/README.md](../collector/README.md).
The boot-bound recovery patch obtains its 128-bit nonce from `esp_fill_random`
after RF initialization and rejects an all-zero result instead of substituting
a fixed nonce. SHA-256 identifies approved source, configuration and artifacts.
ESP serial flashing and partition-table compatibility also use MD5 as a
protocol checksum, not as a signature or password verifier.

MQTT, Wi-Fi, API and OTA credentials are used to authenticate to other systems;
they are not a database of end-user password verifiers. Keep their provisioning
files and backups private. This fact does not imply that their plaintext
transport is protected.

## Wi-Fi association policy

For password-protected networks, the normal ESP32-S3 firmware now requires
WPA2 or WPA3 association and an AES data cipher for both pairwise and group traffic. Raising the scan threshold
alone would still permit WPA2/TKIP. The separately pinned ESP-IDF 5.4.4
supplicant patch therefore checks the driver's selected protocol and cipher
enum values at `wpa_set_bss`, before the original PMK/cache/nonce processing.
It accepts RSN with CCMP, GCMP or GCMP-256 and rejects WPA1, WEP, TKIP and
unsupported cipher values. An AP advertising mixed capabilities remains usable
when the driver selects RSN and AES for both data cipher roles; a TKIP group
cipher is intentionally rejected even with an AES pairwise cipher.
The public `wpa_sta_connect` and DPP connection paths propagate this failure
before calling `esp_wifi_sta_connect_internal`. The binary radio driver's
implementation is not independently inspected here.

`CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY` defaults to disabled. A separately
configured legacy IDF build can explicitly restore the previous WPA1/TKIP
behavior, at the cost of disabling this policy. The public Docker build
requires the option to remain disabled and exports the exact SDK configuration
and patch digest. An explicitly empty Wi-Fi password still selects an open
network: that offers no link confidentiality and must not be described as
encrypted Wi-Fi. WPA2-PSK does not supply forward secrecy; this change does not
turn a downstream HTTP/MQTT connection into TLS.

The patcher refuses any unreviewed upstream source bytes. The build executes
the real injected C entry guard against the pinned IDF declarations in default,
explicitly disabled and legacy-enabled configurations; the host STA initializer
test also checks all three configurations. These are source/build checks, not
proof of RF association, device performance or deployment acceptance.

## Dependency assessment

The optional inference metadata and its tested requirements both select
NumPy 2.5.4. Build metadata selects setuptools 84.0.0.

A 2026-10-19 advisory query of the 63 explicitly pinned Python package/version
entries found three VTK 9.3.1 GLTF-reader advisories: CVE-2025-57106,
CVE-2025-57107 and CVE-2025-57108. They are fixed upstream in 9.5.1.
The enclosure program does not load GLTF: it constructs CadQuery geometry,
exports STEP/STL, checks its generated STL with trimesh, and supplies
constructed points and triangles directly to VTK for rendering. That path
does not invoke `vtkGLTFDocumentLoader`. This is a path-specific disposition,
not a statement that VTK 9.3.1 can safely load arbitrary files.

That query is not closure of the full dependency graph. The collector,
ESP-IDF/Wi-Fi implementation, native build tools, container operating-system
packages and transitive native libraries require their own dated assessment.
Do not infer vulnerability-free runtime or hardware qualification from the
Python result.

## Reproducing the transport checks

Install the pinned runtime requirements and
`tests/requirements-security.txt`, then run:

```sh
python scripts/test-public-adapter-installed.py
python -m unittest discover -s tests -p 'test_transport*.py' -v
```

The tests perform real in-memory TLS 1.2/1.3 handshakes with generated
certificates, including weak leaf/intermediate/root rejection, hostname and
trust failures. Loopback HTTP tests verify that all five redirect status codes
leave the destination with zero requests. They preserve the verifier's
response bounds and existing activity/module-observation assertions.
