# Explicit fleet preparation and recovery

These tools prepare and inspect one explicitly identified receiver. They load
no inventory, network setting or trust key from repository defaults. Commands
that use a site require an independently approved site-context SHA-256 and
installation-identity SHA-256. The identity policy binds fleet size, receiver
IDs, version eligibility and the Ed25519 verification key. Candidate files
cannot approve themselves.

Use Python with the pinned dependencies in `requirements-synology.txt` in a
separate virtual environment; the filename is retained for compatibility.
Run each command with `--help` for the current required arguments.

- `backup.py` lists ports, identifies an explicitly selected board, and can
  preserve physical flash privately. USB inspection can reset the selected
  board into ROM and run a RAM stub.
- `prepare.py` verifies a private backup and an exact firmware artifact, then
  creates a candidate plan/NVS image. It never flashes.
- `build_profile.py` validates exact hardware/radio/RGB settings, without device
  or signing-private-key access. A build profile grants no flash permission.
- `install.py` executes an explicitly reviewed application-only operation.
- `direct_usb.py` provides bounded inspection and application/NVS updates when
  a full backup is not selected. It preserves existing network settings and
  valid keys; no implicit rotation or rebinding is allowed.
- `plan_migration.py` and `install_migration.py` separate a layout proposal from
  its independently reviewed execution. See [MIGRATION.md](MIGRATION.md).

Choose the physical USB port and match the observed station MAC to the approved
inventory. Do not probe unrelated serial ports. Verify real flash/PSRAM size,
partition table, current boot selection, image identity and both OTA slot
capacities. Never infer offsets from an old example. No executor erases the
whole chip, writes eFuses or automatically retries an uncertain write.

Outputs must be outside Git: directories mode 0700, files mode 0600. Full flash,
NVS, generated binaries, serial logs and network configuration can disclose
secrets. Keep them and installation trust decisions private. Preserve attempt
state before a write; an interruption does not authorize another attempt.

After a reviewed update, verify boot/OTA status, node identity, RF association,
CSI continuity, runtime memory and exact module behavior on the actual device.
A workbench test does not calibrate a final placement. Runtime stability does
not establish fall detection, posture, measured coordinates or sensing accuracy.
