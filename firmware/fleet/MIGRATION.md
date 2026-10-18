# Offline layout migration planning

`plan_migration.py` prepares private, reviewable payloads for one physically
identified board. It imports no serial transport and has no flash, erase,
network, reboot or installation operation. A successful exit means an offline
candidate was prepared; **it never authorizes flashing**. The existing
application-only installer is unchanged and cannot execute this plan.

Use the existing private Python environment with `esptool==5.1.0` and
`esp-idf-nvs-partition-gen==0.3.0`. Inputs require a complete same-device backup
from `backup.py`, verified ESP32-S3 / 16 MiB flash / 8 MiB embedded PSRAM, and a
matched `fleet-reviewed` build. The USB identity and PSRAM boot test are separate
observations; the planner does not turn ROM feature information into a passed
memory test. No current node 1/3 migration or blank-board provisioning is implied
by the synthetic tests.

The current planner and executor require the independently approved private site
context described in [the operator guide](../../docs/private-site-context.md).
Changed tool-source hashes intentionally invalidate old reviewed evidence; never
rewrite hashes in an old receipt to bypass a fresh review.

## Supported preservation policy

Select one explicit source class:

- `blank-full-flash`: the **entire** verified 16 MiB backup must contain erased
  bytes. A blank partition-table sector with other existing data is insufficient.
- `two-ota-preserve-data`: a valid MD5-protected table must contain exactly
  `nvs`, `otadata`, `phy_init`, `ota_0`, `ota_1` and `spiffs`, with their reviewed
  types. `ota_0` must start at `0x20000`. NVS, OTA metadata, PHY and SPIFFS must
  already occupy the target offsets and sizes. Application slot sizes may be
  smaller than the target; no installed legacy board is assumed to match this
  class until its actual backup passes.

The only target is the current six-partition N16R8 layout: 24 KiB NVS at
`0x9000`, 8 KiB OTA metadata at `0xf000`, 4 KiB PHY at `0x11000`, two 2 MiB
application slots at `0x20000` and `0x220000`, and 1920 KiB SPIFFS at `0x420000`.
The partition table is at `0x8000`; the bootloader starts at zero.

Unknown, encrypted, ambiguous or unverified layouts fail closed. A moved or
resized data partition produces a blocked report naming the old and proposed
ranges. This version does not move filesystems, discard calibration or infer that
unrecognized bytes are disposable. Such a board needs a separately reviewed
data migration policy. There is no override flag.

## Bind the build inputs before planning

The build directory must contain these exact regular files:

`esp32-csi-node.bin`, `bootloader.bin`, `partition-table.bin`,
`ota_data_initial.bin`, `flasher_args.json`, `profile.json`,
`sdkconfig.fleet-reviewed`, `build_profile.py`, `sdkconfig`, and `version.txt`.

Create a `bundle.json` alongside them after reviewing their build provenance:

```json
{
  "schema_version": 1,
  "files": {
    "esp32-csi-node.bin": {"bytes": 123, "sha256": "REVIEWED_64_HEX_DIGEST"}
  },
  "source_sha256": {"firmware/Dockerfile": "REVIEWED_64_HEX_DIGEST"}
}
```

The abbreviated example is not a usable manifest. `files` must have every exact
name in `plan_migration.FILES`, with its byte length and SHA-256.
`source_sha256` must equal `plan_migration.source_hashes()` for the reviewed
checkout: upstream source-lock metadata, patch files, public verification key,
Docker/fetch inputs, hardware settings and profile validator. Run imports with
`firmware/fleet` on `PYTHONPATH`; both helpers are offline. Record the manifest's
own SHA-256 independently and supply it on the command line. Do not change it
merely to make a rejected bundle pass.

The manifest is an operator-reviewed binding, not a signed build attestation.
Hashing arbitrary binaries does not prove that they were built from the named
sources. Preserve and review the corresponding the selected private build host build evidence separately,
including ELF/map and build logs. Only the listed flash/profile artifacts are
consumed here. Existing node-2 artifacts without the exact selected board's
`fleet-reviewed` profile are insufficient.

The planner hashes each file, caches its bytes, and validates that same content.
It checks the profile's node ID/MAC, AP/RGB overlay, version, generated hardware
and security configuration, S3 application/bootloader image integrity, exact
partition table, erased initial OTA metadata and consistent flasher offsets.
Flasher command arguments are validated as evidence, never executed.

## Prepare the private candidate

```sh
python firmware/fleet/plan_migration.py \
  --site-context /private/path/reviewed-site \
  --site-context-sha256 "$APPROVED_CONTEXT_SHA256" \
  --installation-identity /private/path/installation-identity.json \
  --installation-identity-sha256 "$APPROVED_IDENTITY_SHA256" \
  --backup /PRIVATE/node01-before-UNIQUE \
  --node 1 \
  --build-manifest /PUBLIC/node01-artifacts/bundle.json \
  --bundle-sha256 REVIEWED_MANIFEST_SHA256 \
  --source-layout two-ota-preserve-data \
  --output /PRIVATE/node01-layout-plan-UNIQUE
```

For a truly blank board, use `--source-layout blank-full-flash` and
`--network-settings /PRIVATE/network.json`. That mode requires explicit private
`ssid`, `password`, `target_ip` and integer `target_port`. Existing network
settings cannot be replaced by that argument.

NVS is regenerated with the existing CRC-validating parser and pinned generator.
All prior logical values, including opaque calibration and Wi-Fi values, must
remain equal. Conflicting node IDs, keys or verification policy stop the plan.
An existing per-device OTA key is preserved; otherwise a new random 256-bit key
is generated locally. The deployment Ed25519 **public** key is sufficient;
the signing private key is never accessed. Unique credential allocation across
the fleet still needs operator verification; the tool does not read other units'
private keys.

The new output directory is 0700 and its files are 0600. `plan.json` records the
full-backup and bundle digests, exact sector-padded payload hashes, before hashes,
all unchanged ranges, logical NVS preservation, AP policy and intended `ota_0`
boot. `payloads/` includes the prepared NVS and therefore contains secrets.
`ota-key.private.txt` also remains private. Never copy the output directory to
the selected private build host, Git or an issue. The JSON reports changed NVS key names without their values.
Existing output directories are refused. Failed inputs leave `blocked.json`
without exception payloads or credentials; partial output remains private.

## Remaining installation gates

The output status remains `requires_boot_selection_and_install_review`, with
both authorization flags false. Erased OTA metadata is bound exactly, but the
pinned bootloader's first-slot selection has not been independently proved by
this tool. `bootloader_selection_verified`, runtime and restore qualification
remain false. The inactive slot is not populated or qualified. Automatic
bootloader rollback is disabled in this profile.

The separate `install_migration.py` now implements this narrow write path with
offline and fake-transport tests only; no physical migration has been performed
by those tests. It rechecks current identity/security and complete flash against
the backup, reserves one durable attempt before the only `write_flash` call,
disables esptool's whole-image retries, and verifies every written sector and
unchanged range before any first boot. It never requests a reset, even after a
verified write. A full-chip erase or copying another unit's backup is not an
acceptable shortcut.

## Reviewed executor inputs

The [boot-rule source review](BOOT-RULE.md) establishes only the first attempted
partition for exact IDF source/configuration and the reviewed table. Collect the
three named source files from the actual immutable builder's `$IDF_PATH`, retaining
their relative paths, together with its actual `git rev-parse HEAD`, artifact
hashes and successful build result. A tag, copied reference source or hashes
alone do not establish that an executable was built from those sources.

The exported `boot-build-evidence.json` must have exactly these fields:
`schema_version: 1`, `idf_commit`, `idf_image`, `idf_sources_sha256`,
`bootloader_sources_unmodified: true`, `build_exit_code: 0`, and
`artifacts_sha256`. The source map must equal `boot_rule.IDF_SOURCES`; the artifact
map must bind `bootloader.bin`, `partition-table.bin`, `ota_data_initial.bin`
and `sdkconfig` from the matched build bundle. Unsupported selection overrides
or build provenance stop installation. This is coordinator-reviewed evidence,
not cryptographic build attestation. There is no automatic evidence generator
that fills in a successful exit or source revision.

Create a separate private mode-0600 reviewed wrapper only after reviewing the
physical unit, build provenance and power-loss recovery. Required exact fields:

- `schema_version: 1`, `action: "layout_migration_usb"`,
  `coordinator_approved: true`, `build_provenance_reviewed: true`, and
  `power_loss_recovery_reviewed: true`.
- `node_id`, `expected_mac`, `backup_directory`, `backup_sha256`,
  `candidate_file` and `candidate_sha256`. The original candidate remains
  unauthorized; its physical inventory binding must already be verified.
- `build_manifest`, `bundle_sha256`, `idf_source_directory`,
  `boot_build_evidence` and `boot_build_evidence_sha256`.
- `tool_sha256`, exactly the current `install_migration.tool_hashes()` map.

These are schema descriptions, not a prepared or authorized board plan. Review
and pin the actual wrapper hash as part of the per-unit operation. First run the
offline check; it neither enumerates nor opens USB ports:

```sh
python firmware/fleet/install_migration.py check \
  --site-context /private/path/reviewed-site \
  --site-context-sha256 "$APPROVED_CONTEXT_SHA256" \
  --installation-identity /private/path/installation-identity.json \
  --installation-identity-sha256 "$APPROVED_IDENTITY_SHA256" \
  --reviewed-plan /PRIVATE/node01-reviewed-migration.json \
  --output /PRIVATE/node01-migration-check-UNIQUE
```

Only the separate installation action opens the explicitly observed port:

```sh
python firmware/fleet/install_migration.py install \
  --site-context /private/path/reviewed-site \
  --site-context-sha256 "$APPROVED_CONTEXT_SHA256" \
  --installation-identity /private/path/installation-identity.json \
  --installation-identity-sha256 "$APPROVED_IDENTITY_SHA256" \
  --reviewed-plan /PRIVATE/node01-reviewed-migration.json \
  --port /dev/cu.usbserial-EXACT_OBSERVED_PORT \
  --output /PRIVATE/node01-migration-write-UNIQUE
```

All files stay private; no NVS/key values appear in the result. The executor
rehashes cached input payloads and reconstructs exact sector coverage independently
of the candidate's offsets. Old NVS/calibration values must remain logically equal;
new board settings are restricted to the original provisioner's allowed keys.
The five ranges are passed once in ascending offset order with flash headers
preserved. This is **not atomic**: interruption may require reviewed USB recovery.

The marker `migration-attempt-<candidate-sha256>.json` is exclusively created
beside the canonical original candidate and fsynced together with its directory
before the write. It remains after success or uncertainty. Copying, relocating
or reformatting a review wrapper cannot rearm the same candidate. Never delete
the marker, relocate/duplicate the candidate or create a new candidate to retry
an uncertain write without a separately reviewed recovery operation.
Device MD5 readbacks verify all changed padded sectors and the entire unchanged
complement against locally SHA-256-pinned bytes, before a separate explicit boot.
No automatic recovery, erase, retry, OTA operation or reboot is implemented.
After a verified result, coordinate a separate power cycle/boot-log observation;
until then the selected board remains in ROM/stub. Physical boot, sensing and
restoration qualification remain false.

After installation, verify PSRAM, unique ID, DHCP reservation, selected AP, dark
RGB, authenticated OTA and an inactive-slot update. Installed-position transport
and module restoration require their own evidence. The seven allocated future
addresses do not establish MAC reservations, room placements or qualification.

Offline tests:

```sh
python -m unittest discover -s firmware/fleet/tests -v
python -O -m unittest discover -s firmware/fleet/tests -v
```
