# CSI sender profiles

Default worker admission remains one antenna, 64 complex pairs, 148 bytes,
2.4 GHz, ADR018 PPDU bucket zero and flags `0` or `16`. An optional profile admits
LLTF from a reviewed ESP32-S3 sender when its received Wi-Fi frame carries STBC
metadata. Decoder support does not validate presence, position, pose or falls.

The sender copies flag bit 2 from `rx_ctrl.stbc`, which describes the received
frame. Identical firmware can report different flags when AP transmissions
differ. Patch `0009-associated-lltf-only.patch` selects LLTF and disables HT-LTF
and STBC-HT-LTF for the associated-only ESP32-S3 build. The sender copies the
entire callback buffer without truncation. PPDU bucket zero combines several
PHY types; it does not identify the selected LTF. See the
[pinned sender](https://github.com/ruvnet/RuView/blob/e04f269f1a76eb6ed4e8cd33e2ccfeda6fd391a3/firmware/esp32-csi-node/main/csi_collector.c).

ESP-IDF records imaginary/real pairs. Its documentation distinguishes LTF
selection from STBC metadata and describes a `first_word_invalid` indicator for
the first four bytes. The existing wire format omits that indicator, signal mode,
secondary-channel details and the capture configuration. Byte count and the STBC
bit cannot qualify an arbitrary sender. See
[ESP32-S3 CSI documentation](https://docs.espressif.com/projects/esp-idf/en/v5.4.4/esp32s3/api-guides/wifi.html#wi-fi-channel-state-information).
Review each deployment's retained SDK revision and build configuration rather
than inferring them from a current build recipe.

## Explicit admission

Supply both `--csi-admission-manifest PRIVATE_FILE` and
`--csi-admission-sha256 INDEPENDENTLY_REVIEWED_SHA256`. At most 16 KiB is read and
the file must match its exact hash. No profile is enabled automatically.
This structural example deliberately contains invalid placeholder hashes:

```json
{
  "schema": "ruview.csi-admission.v1",
  "nodes": [{
    "node_id": 7,
    "source_ipv4": "127.0.0.1",
    "profile": "esp32s3-associated-lltf64-mask2-v1",
    "firmware_sha256": "REVIEWED_APPLICATION_SHA256",
    "build_config_sha256": "REVIEWED_BUILD_CONFIG_SHA256",
    "qualification_receipt_sha256": "REVIEWED_PRIVATE_RECEIPT_SHA256"
  }]
}
```

The private qualification receipt must bind the intended device and source
address to the reviewed application/build configuration, LLTF-only selection,
enabled ADR018 tagging, exact nontruncated wire shape and observed capture.
Record how the installed application was identified, including any absence of
a live flash digest. A matching version label is not cryptographic attestation.
Review the artifacts and manifest before supplying its hash. These hashes pin
the operator's decision: the worker does not fetch or independently audit the
referenced artifacts. Source IPv4 binding is not packet authentication. Keep
the source allowlist narrow and the listener on the trusted network.

Only listed, allowed nodes from their exact source IPv4 use the profile. Other
nodes retain default admission. The profile accepts flags `0`, `4`, `16` and
`20` with the same exact length, antenna, frequency and PPDU checks. Extra flags,
multiple LTF buffers, trailing bytes and truncated payloads remain rejected.

## Raw evidence and feature boundaries

Raw bytes, signed I/Q pairs and flags are unchanged in recordings. Profiled
packets and node snapshots carry `admission`, including provenance hashes, the
profile, feature contract and mask. The configuration hash includes the manifest.

The new `lltf64-mask2-v1` contract conservatively zeros wire-pair indices 0 and 1
in derived feature arrays because first-word validity is unavailable. Raw data
is not edited; remaining indices never shift. Arrays and algorithm denominators
stay 64-wide, with two explicitly zero entries. `first_word_invalid` stays null,
not false. Do not mix this contract with `home-raw64-v1` or old calibration.

STBC changes, profile/provenance changes and existing grid discontinuities reset
feature history and algorithm warmup. Sync-valid bit 4 alone does not reset it.
Rapidly alternating STBC traffic may remain in warmup; distinct profiles are not
pooled to manufacture stable evidence.

The existing assumed-activity consumer rejects non-null admission profiles.
The training journal retains profile and manifest identity but marks them
incompatible with its native raw64 contract, even when the STBC bit is clear.
A new consumer needs a reviewed feature contract and fresh binding. Enabling a
decoder does not requalify old recordings, pinned sources, epochs or models.

## Verification

Synthetic tests cover all 256 flag values, source/node isolation, exact shape,
manifest limits/hashes, raw preservation, masking and epoch resets. Keep real
packet fixtures, installation manifests and receipts private. Verify captured
packets offline against the reviewed manifest before a separately authorized
deployment. Synthetic tests alone do not qualify a device.

The optional `csi-profile-check` binary compares default and explicit admission
for at most64 saved UDP payload files, each at most1,044 bytes. It reports hashes,
admission, raw preservation and a 64-entry conservative feature mask. It opens
no sockets and does not create a capture or train a model:

```sh
cargo run --locked --bin csi-profile-check -- \
  7 127.0.0.1 /private/reviewed-manifest.json REVIEWED_MANIFEST_SHA256 \
  /private/saved-udp-payload.bin
```

Use the reviewed source address for saved packets. Keep outputs private.
This checks the decoder against saved evidence; it cannot authenticate the
original transmitter or prove continuity beyond those packets.
