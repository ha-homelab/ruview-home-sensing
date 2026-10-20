# Command inventory

This is the source-archive command reference. The main workflows, side effects,
formats and failure meanings are described in [interfaces](interfaces.md).
The lists below are the union of accepted arguments across each command's
subcommands. Run `python PATH --help` and then `python PATH SUBCOMMAND --help`
for required combinations, defaults, choices and type constraints. For modules
under `inference`, `radar`, `wisp_pilot` or `assumed_activity`, use `python -m`
and replace `/` with `.` (omit `/__main__.py` and `.py`).

`--help` is supplied by argparse. Configuration and artifact approval options
provided by shared helpers are listed separately below; they must not be
inferred from candidate inputs. Commands never imply permission to access
a device merely because they appear in this inventory.

## `assumed_activity/service.py`

Read-only source polling and expiring HTTP/MQTT activity envelopes.

Arguments: no configuration arguments.

[Parser and implementation](../assumed_activity/service.py).

## `collector/prepare-source.py`

Fetch pinned public collector sources and apply the reviewed local grid fix.

Arguments: `--offline`, `source`.

[Parser and implementation](../collector/prepare-source.py).

## `collector/ui/export-floor-config.py`

Export approved geometry and receiver anchors as a private UI configuration.

Arguments: `--model-sha256`, `--output`, `--profile`, `--profile-sha256`, `--site-context`, `--site-context-sha256`, `--source-revision`, `model`.

[Parser and implementation](../collector/ui/export-floor-config.py).

## `firmware/fetch-modules.py`

Fetch pinned RuView WASM module sources and the locked home build inputs.

Arguments: `--profile`, `--source-only`, `output`.

[Parser and implementation](../firmware/fetch-modules.py).

## `firmware/fetch-source.py`

Fetch the exact public RuView firmware sources, verifying pinned SHA-256s.

Arguments: `--firmware-version`, `--fleet-overlay`, `--fleet-plan`, `--preferred-ap-overlay`, `--preferred-ap-overlay-sha256`, `--wasm-public-key`, `--wasm-public-key-sha256`, `output`.

[Parser and implementation](../firmware/fetch-source.py).

## `firmware/fleet/backup.py`

Inspect or back up one explicitly selected USB receiver; never write flash.

Arguments: `--allow-reset`, `--expected-mac`, `--installation-identity`, `--installation-identity-sha256`, `--node`, `--output`, `--partition-offset`, `--port`, `--site-context`, `--site-context-sha256`, `action`.

[Parser and implementation](../firmware/fleet/backup.py).

## `firmware/fleet/build_profile.py`

Private per-board build inputs and sdkconfig checks; no device or key access.

Subcommands: `check-preferred`, `configure`, `configure-preferred`, `prepare`, `verify`, `verify-preferred`.

Arguments: `--output`, `--overlay`, `--plan`, `--version`, `directory`, `expected_sha256`, `overlay`, `project`, `sdkconfig`.

[Parser and implementation](../firmware/fleet/build_profile.py).

## `firmware/fleet/direct_usb.py`

Explicitly inspected, reviewed, single app/NVS USB write; no full backup.

Subcommands: `inspect`, `install`, `prepare`.

Arguments: `--allow-reset`, `--current-version`, `--expected-mac`, `--firmware`, `--inspection`, `--installation-identity`, `--installation-identity-sha256`, `--node`, `--output`, `--port`, `--pre-usb-status`, `--reviewed-plan`, `--sha256`, `--site-context`, `--site-context-sha256`, `--version`.

[Parser and implementation](../firmware/fleet/direct_usb.py).

## `firmware/fleet/install.py`

One reviewed application-only USB write, after exact private backup checks.

Arguments: `--installation-identity`, `--installation-identity-sha256`, `--output`, `--port`, `--reviewed-plan`, `--site-context`, `--site-context-sha256`.

[Parser and implementation](../firmware/fleet/install.py).

## `firmware/fleet/install_migration.py`

One reviewed five-range migration; no erase-all, retry or automatic reset.

Arguments: `--installation-identity`, `--installation-identity-sha256`, `--output`, `--port`, `--reviewed-plan`, `--site-context`, `--site-context-sha256`, `action`.

[Parser and implementation](../firmware/fleet/install_migration.py).

## `firmware/fleet/plan_migration.py`

Offline, private layout/NVS planning. No serial or installation capability.

Arguments: `--backup`, `--build-manifest`, `--bundle-sha256`, `--installation-identity`, `--installation-identity-sha256`, `--network-settings`, `--node`, `--output`, `--site-context`, `--site-context-sha256`, `--source-layout`.

[Parser and implementation](../firmware/fleet/plan_migration.py).

## `firmware/fleet/prepare.py`

Create a private per-board candidate plan and NVS image; never flash it.

Arguments: `--backup`, `--existing-ota-key`, `--firmware`, `--installation-identity`, `--installation-identity-sha256`, `--network-settings`, `--node`, `--output`, `--preferred-bssid`, `--sha256`, `--site-context`, `--site-context-sha256`, `--version`.

[Parser and implementation](../firmware/fleet/prepare.py).

## `firmware/observe-runtime.py`

Read-only single-receiver runtime trial; passing never qualifies recognition accuracy.

Arguments: `--duration`, `--expect-partition`, `--expected-version`, `--mode`, `--module-id`, `--node`, `--output`.

[Parser and implementation](../firmware/observe-runtime.py).

## `firmware/ota-update.py`

Update an inventoried receiver over private-LAN HTTP with a private OTA key.

Arguments: `--expect-current`, `--firmware`, `--installation-identity`, `--installation-identity-sha256`, `--key-file`, `--node`, `--sha256`, `--site-context`, `--site-context-sha256`, `--version`.

[Parser and implementation](../firmware/ota-update.py).

## `firmware/provision-ota-key.py`

Prepare NVS with an OTA key offline, preserving every logical stored value.

Arguments: `--input-nvs`, `--key-file`, `--output-nvs`.

[Parser and implementation](../firmware/provision-ota-key.py).

## `firmware/qualify-module-upload.py`

Controlled single-receiver signed upload; never retry an uncertain mutation automatically.

Arguments: `--expect-partition`, `--expected-version`, `--node`, `--output`.

[Parser and implementation](../firmware/qualify-module-upload.py).

## `firmware/reconcile-modules.py`

Restore a qualified module once per manually armed generation.

Arguments: `--directory`, `--manifest-sha256`, `--state-directory`.

[Parser and implementation](../firmware/reconcile-modules.py).

## `firmware/sign-module.py`

Build an Ed25519-signed RVF v1 container for the patched RuView firmware.

Arguments: `--budget-us`, `--capabilities`, `--name`, `--private-key`, `output`, `wasm`.

[Parser and implementation](../firmware/sign-module.py).

## `firmware/validate-module-contract.py`

Validate local module metadata and event maps without running or uploading WASM.

Arguments: `--catalog`, `--manifest`, `--package-directory`.

[Parser and implementation](../firmware/validate-module-contract.py).

## `firmware/wisp-pilot/prepare.py`

Package pinned Wisp source and the local pilot recipe without network or flashing.

Arguments: `--output`, `--source`.

[Parser and implementation](../firmware/wisp-pilot/prepare.py).

## `inference/__main__.py`

Offline commands. Writes new private output files; never opens a device/camera.

Subcommands: `index-session`, `pair`, `pair-session`, `predict-candidate`, `train`, `verify-capture`, `verify-session`.

Arguments: `--between-probe-allowance-ns`, `--capture-manifest`, `--capture-report`, `--classification`, `--clock-after`, `--clock-assumption-reference`, `--clock-before`, `--closing-snapshot`, `--eval-session`, `--expected-coordinate-frame`, `--feature-contract`, `--frames`, `--label-clock-offset-ms`, `--labels`, `--manifest`, `--manifest-output`, `--max-clock-step-ns`, `--max-gap-ms`, `--max-label-uncertainty-ms`, `--max-label-uncertainty-ns`, `--max-receipt-gap-ns`, `--min-frames`, `--model`, `--node-id`, `--opening`, `--opening-snapshot`, `--output`, `--paired`, `--profiles`, `--provenance-reference`, `--reference-directory`, `--reference-export`, `--report-output`, `--ridge`, `--task`, `--terminal`, `--window-ms`.

[Parser and implementation](../inference/__main__.py).

## `inference/fall_detection.py`

Offline temporal fall candidates from declared metric body observations.

Arguments: `--input`, `--output`.

[Parser and implementation](../inference/fall_detection.py).

## `inference/fall_evaluation.py`

Score held-out fall events without converting heuristic flags into ground truth.

Arguments: `--input`, `--output`.

[Parser and implementation](../inference/fall_evaluation.py).

## `inference/qualification.py`

Reproducible held-out evaluation and offline review; never a deployment permit.

Arguments: `--expected-coordinate-frame`, `--model`, `--output`, `--paired`, `--protocol`, `--report`, `--review`, `command`.

[Parser and implementation](../inference/qualification.py).

## `inference/reference_session.py`

Private human observations and explicit review; no capture, model or HA calls.

Subcommands: `export`, `init`, `mark`, `review`.

Arguments: `--accept-reference-truth`, `--capture-opening`, `--event`, `--evidence`, `--expected-coordinate-frame`, `--node-ids`, `--observation`, `--operator`, `--output`, `--points`, `--profiles`, `--reason`, `--reviewer`, `--timing-policy`, `--trial-id`, `directory`.

[Parser and implementation](../inference/reference_session.py).

## `inference/stream.py`

Bounded offline replay diagnostics. No network, HA publication or promotion.

Arguments: `--capture-report`, `--config`, `--emit-research-candidates`, `--expected-coordinate-frame`, `--input`, `--manifest`, `--max-seconds`, `--opening`, `--output`, `--terminal`.

[Parser and implementation](../inference/stream.py).

## `inference/zone_annotations.py`

Import independently reviewed whole-interval zone observations; no live calls.

Arguments: `--annotations`, `--definition`, `--expected-coordinate-frame`, `--geometry`, `--output`, `--pair-report`, `--paired`, `--reference-directory`, `--reference-export`, `command`.

[Parser and implementation](../inference/zone_annotations.py).

## `inference/zone_model.py`

Actual offline ridge zone baseline; fitted artifacts remain private candidates.

Subcommands: `evaluate`, `predict`, `train`.

Arguments: `--context`, `--expected-coordinate-frame`, `--model`, `--model-output`, `--output`, `--plan`, `--policy`, `--records`, `--regularization`, `--report-output`, `--window`.

[Parser and implementation](../inference/zone_model.py).

## `inference/zones.py`

Offline two-zone readiness and score admission; no recorder or fitted model.

Subcommands: `decision`, `readiness`.

Arguments: `--expected-coordinate-frame`, `--model-artifact`, `--model-review`, `--observation`, `--output`, `--plan`, `--policy`, `--records`.

[Parser and implementation](../inference/zones.py).

## `mechanical/enclosure/model.py`

Parametric RuView enclosure. Millimetres; +X antenna, -X USB, +Z lid.

Arguments: `--output`, `--profile`.

[Parser and implementation](../mechanical/enclosure/model.py).

## `mechanical/enclosure/provision_native.py`

Extract pinned Ubuntu CAD libraries into job scratch without system writes.

Arguments: `--github-env`, `--output`.

[Parser and implementation](../mechanical/enclosure/provision_native.py).

## `radar/__main__.py`

Offline configuration inspection. Never opens a configured UART endpoint.

Subcommands: `validate-config`.

Arguments: `--expected-coordinate-frame`, `--format`, `--require-complete`, `path`.

[Parser and implementation](../radar/__main__.py).

## `scripts/build-release.py`

Build a deterministic source/tool release from an exact committed Git tree.

Arguments: `--output`, `--revision`, `--source`.

[Parser and implementation](../scripts/build-release.py).

## `scripts/check-public-boundary.py`

Reject private deployment material in a public source tree or source archive.

Arguments: `--archive`, `--strip-components`.

[Parser and implementation](../scripts/check-public-boundary.py).

## `scripts/check-public-history.py`

Check reachable commit identities before publishing this repository.

Arguments: `--revision`.

[Parser and implementation](../scripts/check-public-history.py).

## `scripts/mac-worker-proxy.py`

Forward explicitly allowed peers to a loopback-only worker or activity service.

Arguments: `--allow-peer`, `--bind-address`, `--mode`.

[Parser and implementation](../scripts/mac-worker-proxy.py).

## `scripts/measure-reference-clock.py`

Read-only, explicitly targeted clock probes. No automatic clock correction.

Arguments: `--deadline-seconds`, `--host`, `--hostname`, `--interval-ms`, `--max-clock-step-ms`, `--no-proxyjump`, `--output`, `--sample-timeout-ms`, `--samples`, `--ssh-config`, `--startup-timeout-ms`.

[Parser and implementation](../scripts/measure-reference-clock.py).

## `scripts/observe-collector.py`

Passively record accepted CSI freshness; never send measurements to RuView.

Arguments: `--collector-profile`, `--collector-profile-sha256`, `--duration`, `--max-age-ms`, `--nodes`, `--output`.

`--nodes` is required: provide every receiver whose freshness must qualify.
IDs must be unique integers from 1 through 255. No installation-specific receiver
subset is assumed, and an absent requested receiver prevents a passing report.

[Parser and implementation](../scripts/observe-collector.py).

## `scripts/observe-server-modules.py`

Read-only bounded recovery observation, run through stdin in the HA bridge.

Arguments: `--accept-gzip`, `--deadline-seconds`, `--expected-selected-count`, `--nodes`, `--samples`.

[Parser and implementation](../scripts/observe-server-modules.py).

## `scripts/prepare-site-inputs.py`

Export verified private data for Terraform; the approval pin stays separate.

Arguments: `--deployment-profile`, `--deployment-profile-sha256`, `--installation-identity`, `--installation-identity-sha256`, `--output`, `--site-context`, `--site-context-sha256`.

[Parser and implementation](../scripts/prepare-site-inputs.py).

## `scripts/prepare-ui-build.py`

Prepare a private, deterministic UI build context; never build or deploy it.

Arguments: `--base-image`, `--model-sha256`, `--output`, `--profile`, `--profile-sha256`, `--site-context`, `--site-context-sha256`, `--source-revision`, `model`.

[Parser and implementation](../scripts/prepare-ui-build.py).

## `scripts/provision-secret.py`

Provision the runtime Secret without credentials entering Terraform state.

Arguments: `--context`.

[Parser and implementation](../scripts/provision-secret.py).

## `scripts/record-coverage-producer.py`

Record bounded private RuView snapshots under an existing local HA session.

Arguments: `--consumer-metadata`, `--duration`, `--expected-image`, `--nodes`, `--output-directory`, `--package-directory`, `--site-context`, `--site-context-sha256`, `--url`.

[Parser and implementation](../scripts/record-coverage-producer.py).

## `scripts/reserve-dhcp.py`

Reserve verified RuView station MACs; default is a read-only plan.

Arguments: `--apply`, `--backup-dir`, `--installation-identity`, `--installation-identity-sha256`, `--router-profile`, `--router-profile-sha256`, `--site-context`, `--site-context-sha256`.

[Parser and implementation](../scripts/reserve-dhcp.py).

## `scripts/sample-server-modules.py`

Fixed-length, read-only sampled diagnostic execution; never continuity proof.

Arguments: `--deadline-seconds`, `--expected-catalog-sha256`, `--expected-clock-id`, `--expected-config-sha256`, `--expected-worker-run-id`.

[Parser and implementation](../scripts/sample-server-modules.py).

## `scripts/sync-floorplan.py`

Merge RuView receiver markers using HA's authenticated, revision-checked API.

Arguments: `--apply`, `--backup-dir`, `--site-context`, `--site-context-sha256`, `--update-owned`.

[Parser and implementation](../scripts/sync-floorplan.py).

## `scripts/verify-server-modules.py`

Read-only live verification; run through stdin inside the HA bridge container.

Arguments: `--expected-selected-count`, `--nodes`, `--samples`.

[Parser and implementation](../scripts/verify-server-modules.py).

## `server-modules/package-runtime.py`

Package a trusted, natively compiled Linux worker and exact runtime closure.

Arguments: `binary`, `destination`.

[Parser and implementation](../server-modules/package-runtime.py).

## `server-modules/prepare.py`

Prepare a public, pinned native worker build outside this checkout.

Arguments: `--offline`, `--source`, `destination`.

[Parser and implementation](../server-modules/prepare.py).

## `wisp_pilot/__main__.py`

An explicit, private, bounded Wisp transport pilot.

Subcommands: `capture`, `replay`, `validate-config`.

Arguments: `--config`, `--config-sha256`, `--input`, `--output`, `--seconds`.

[Parser and implementation](../wisp_pilot/__main__.py).

## Shared approvals and non-argparse entrypoints

Firmware upload/observation/reconciliation commands also add their common
`--site-context`, `--site-context-sha256`, `--installation-identity` and
`--installation-identity-sha256` pairs. Qualification commands require
`--package-catalog`, `--package-catalog-sha256`, `--package-profile` and
`--package-directory`; runtime observation additionally takes
`--collector-profile` and `--collector-profile-sha256`. Read the exact
subcommand help before preparing a reviewed operation.

`server-modules/build.sh PREPARED_SOURCE CARGO_CACHE NEW_OUTPUT_DIRECTORY`
builds and tests an already prepared native worker with offline dependencies.
The output directory must not exist. `CARGO_BUILD_JOBS` selects 1–4 workers;
`RUVIEW_BUILDER_IMAGE` selects a previously provisioned immutable local Docker
image ID. The driver writes build/test logs, provenance and the runtime package
to the new output directory, then reports that path. It does not fetch a
missing image or populate the cache. Its artifact and runtime interfaces are
in [native modules](../server-modules/README.md).
`collector/test-grid.sh` is a test runner, not a receiver command.
`mechanical/enclosure/render.py` is the CAD rendering companion described in
[enclosure documentation](../mechanical/enclosure/README.md).
`tools/check_workflows.py` and `tools/check_history_event.py` are CI validators:
they read the repository/workflow event, print diagnostics and exit nonzero
on a rejected policy/history. They do not deploy software.

`bridge.py` starts the separately installed Home Assistant bridge; configure
that distribution using its own reference. `ruview-activity` is equivalent to
`python -m assumed_activity`, not direct execution of its relative-import
`service.py` file. The installed-wheel reference includes only the four console
entrypoints; other tools require the source archive and sibling files.
