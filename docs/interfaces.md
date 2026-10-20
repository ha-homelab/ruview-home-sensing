# External interfaces

This reference describes the public source distribution. It does not authorize
access to a receiver, approve a recording, or establish sensing accuracy.
Examples and fixtures are synthetic. Keep installation files, credentials,
captures and generated configuration outside the checkout.

The source archive includes firmware, native-worker, CAD and operator tools.
The wheel includes the Python packages and four console commands described
below. See [distribution](distribution.md) for installation and artifact
verification. Internal helper functions are not a stable ABI; pin the source
version when embedding Python or Rust code.

## Command conventions

The argument-parsed Python commands below accept `--help` without starting their
operation. Required arguments, choices and defaults are shown by the command's help. For a module,
use `python -m MODULE --help`; for an archive tool, use
`python path/to/tool.py --help`. Do not run a command without `--help` merely to
discover its options: some commands deliberately open a network connection,
write an artifact, or update an explicitly selected device.

JSON uses UTF-8; JSONL contains one JSON object per nonempty line. Hashes are
lowercase hexadecimal SHA-256 unless explicitly described otherwise. A
`--*-sha256` approval is supplied independently of the candidate it approves.
An output file or directory is not an approval. Reject an unexpected schema
version; retain original input bytes when a manifest binds their hash.

Successful one-shot commands normally exit zero; argument errors exit 2.
Validation commands can return a nonzero result while writing a useful failure
report. Other failures may raise a Python exception; callers must inspect both
the exit status and the report rather than treating file existence as success.
Service commands run until stopped. Do not parse human diagnostic messages as a
stable machine protocol.

## Python console commands

### `ruview-inference` / `python -m inference`

All these operations are offline. New evidence/model outputs are private files,
not permission to publish results or deploy a model.

- `pair`: `--frames` native CSI JSONL, `--labels` independent label JSONL,
  `--profiles` per-node profiles and `--label-clock-offset-ms` produce
  `--output` paired-window JSONL. `--window-ms` defaults to 1000,
  `--max-gap-ms` to 250, `--min-frames` to 8 and
  `--max-label-uncertainty-ms` to 100. Supply all four of
  `--capture-manifest`, `--capture-report`, `--opening-snapshot` and
  `--closing-snapshot` to verify original v1 capture evidence. Omitting that
  group explicitly leaves unverified research evidence.
- `verify-capture`: `--manifest`, `--frames`, `--opening-snapshot`,
  `--closing-snapshot` produce the v1 verification report at `--output`.
  Exit 1 means the recording is not complete, even though a report exists.
- `index-session`: original v2 `--frames`, `--opening`, `--terminal`,
  `--provenance-reference`, `--classification`,
  `--max-clock-step-ns` and `--max-receipt-gap-ns` produce
  `--manifest-output` and `--report-output`. Classification is `synthetic` or
  `household_recording`; it is a declaration, not an inferred property.
  This command cannot close an active recording or manufacture a terminal.
- `verify-session`: `--frames`, `--opening`, `--terminal` and `--manifest`
  recompute closure evidence into `--report-output`. Exit 1 means closure was
  not verified.
- `pair-session`: v2 `--frames`, `--opening`, `--terminal`, `--manifest`,
  `--capture-report`, `--profiles`, `--reference-directory`,
  `--reference-export`, `--clock-before`, `--clock-after` and
  `--clock-assumption-reference` produce paired `--output` and
  `--report-output`. Explicit `--between-probe-allowance-ns` and
  `--max-label-uncertainty-ns` bound alignment uncertainty. Window/gap/minimum
  defaults match `pair`.
- `train`: `--paired`, `--task` (`posture`, `image_pose_2d`, `house_xy_m`),
  repeatable `--eval-session` and `--output` fit a ridge candidate.
  `--ridge` defaults to 1.0; `--node-id` selects one receiver.
  Held-out sessions must remain separate from training.
- `predict-candidate`: `--model`, `--paired` and `--output` write offline
  candidate predictions; optional `--node-id` must match the model.

Pairing, training and prediction accept `--feature-contract`:
`native1x64-amplitude-mean-std-abs-slope-v1` is the default;
`native1x64-exclude-wire-pairs-0-1-amplitude-stats-v1` explicitly excludes the
first two wire pairs. Stored windows and models must agree. Neither choice
changes the original recording or invents firmware validity metadata.
`--expected-coordinate-frame` is required when consuming coordinates in a
declared installation frame; it is independently reviewed, not copied blindly
from a candidate.

Additional offline commands use the module name with `python -m`:

- `inference.reference_session`: `DIRECTORY init`, `DIRECTORY mark`,
  `DIRECTORY review` and `DIRECTORY export` manage original human-reference sessions.
  Their help describes
  private `directory`, capture/profile/point/timing inputs, observation events,
  reviewer evidence and export paths. Review is explicit; export binds original
  bytes and does not replace the CSI capture's own evidence.
- `inference.qualification`: `evaluate` consumes `--model`, `--paired` and
  `--protocol`, writing `--output`; `review` additionally consumes the previous
  `--report` and an independent `--review`.
  The result is an offline evaluation decision, not deployment authorization.
- `inference.zones`, `inference.zone_annotations` and `inference.zone_model`
  validate plans/interval annotations, fit candidates and evaluate/predict
  zone results. Use the explicit plan, records, policy, model and output paths
  displayed by their help; coordinate-frame checks remain mandatory where used.
- `inference.fall_detection --input … --output …` replays metric-body
  observations into temporal candidates.
  `inference.fall_evaluation --input … --output …` scores independently
  labelled held-out events. Neither result establishes a medical capability.
- `inference.stream --config … --input … --output …` runs a bounded offline
  replay. `--manifest`, `--capture-report`, `--opening` and `--terminal`
  provide original v2 evidence where required. `--emit-research-candidates`
  enables a separate research field, never a qualified observation;
  `--max-seconds` bounds execution.

For schema details and the embedding interface see [data contracts](#data-contracts-and-python-embedding)
and the generated Python reference below.

### `ruview-radar` / `python -m radar`

`validate-config PATH --expected-coordinate-frame FRAME` reads a regular JSON
file of at most 65536 bytes without opening a UART. `--format text|json`
defaults to text. Output identifies structural errors, pending declarations and
the original SHA-256. Exit 2 means unreadable/structurally invalid input;
`--require-complete` additionally exits 3 for incomplete declarations.
Exit zero still does not establish hardware or survey acceptance.

The [configuration](../radar/configuration.template.json) and
[fleet](../radar/fleet.template.json) templates show the accepted single/fleet
forms. Decoded slots are temporary report slots, not persistent person IDs.

### `ruview-wisp` / `python -m wisp_pilot`

- `validate-config --config FILE --config-sha256 HASH` verifies an explicitly
  pinned `wisp.pilot-config.v1` and prints JSON with `valid`, receiver count and
  `network_io:false`.
- `capture` takes the same configuration plus `--output DIRECTORY` and
  `--seconds N`. It sends subscriptions only to configured receivers and
  records bounded raw datagrams plus provenance and summary. Zero means complete;
  exit 2 means incomplete or failed. Captures remain private.
- `replay --input DIRECTORY --output DIRECTORY` verifies the original
  capture and reproduces decoded records/quality summaries. It performs no
  receiver operation and prints `verified` and record count.

Configuration has exactly `schema`, `bind_ip`, `source_port` (47010), `streams`
(3), `receivers` (1–16 unique `{ip,mac}` pairs), `max_records` (1–1000000) and
`max_bytes` (1024–1073741824). Addresses are explicit unicast IPv4; MACs are
lowercase nonzero unicast identifiers. No discovery supplies these values.

The v1 UDP format is documented in the pinned
[Wisp protocol](https://github.com/albert-canfield/wisp/blob/56813ac91a0fe696dae20e1fec468d33fc1e60ed/docs/PROTOCOL.md).
The local decoder accepts only raw-CSI/link-report packets, at most 4096 bytes,
384 CSI bytes, 20 links and 16 pairs; unknown versions, flags, lengths and
duplicate/self links fail. A subscription is `WSUB`, version byte 1, stream byte
1/2/3; its lease must be renewed. RSSI/noise are signed dBm, timestamps retain
their device origin, and IQ bytes retain imaginary/real order. Upstream motion
flags are assertions, not independently established physical observations.
See the [separate firmware recipe](../firmware/wisp-pilot/README.md).

### `ruview-activity` / `python -m assumed_activity`

This service has no positional/options configuration; `--help` exits before
starting it. It consumes:

- `ASSUMED_ACTIVITY_CONFIG`, `ASSUMED_ACTIVITY_RECEIVERS`,
  `ASSUMED_ACTIVITY_RUNTIME`: configuration paths, defaulting respectively to
  `/config/assumed-activity.json`, `/config/assumed-activity-receivers.json`,
  `/config/assumed-activity-runtime.json`.
- The corresponding `*_SHA256` variables: independently approved raw hashes.
  All three documents are authenticated before credentials are read.
- `ASSUMED_ACTIVITY_COORDINATE_FRAME`: reviewed expected frame when geometry
  is used.
- `ASSUMED_ACTIVITY_BIND_ADDRESS` (IPv4, default `0.0.0.0`) and
  `ASSUMED_ACTIVITY_HTTP_PORT` (default 5017).
- `RUVIEW_URL`, `RUVIEW_MODULES_URL`: collector/native-worker origins.
  Their defaults target the cluster services; set explicit origins elsewhere.
- `RUVIEW_API_TOKEN`, `RUVIEW_MQTT_HOST`, `RUVIEW_MQTT_PORT` (default 1883),
  `MQTT_USERNAME`, `MQTT_PASSWORD`: transport configuration and credentials.

HTTP returns JSON with `Cache-Control: no-store`:
`GET /health` returns 200 for recent completed polling or 503 when stalled;
MQTT state is a separate field. `GET /v1/activity` returns the current activity
envelope, including unavailable/stale decisions. `GET /internal/diagnostics`
is restricted to loopback peers and returns bounded counters and recent poll
history, not a public status feed. Other GET paths return 404.

MQTT output uses `ruview/home/assumed_activity/{state,attributes,availability}`
and discovery topic `homeassistant/sensor/ruview_assumed_zone_activity/config`.
These are stable protocol topic strings, not installation labels.
The [runtime](../assumed_activity/tests/fixtures/assumed-activity.config.json)
example is synthetic. Stale inputs withdraw prior hypotheses; repeated polling
does not create a new observation. SIGINT/SIGTERM request shutdown.
Default HTTP/MQTT transports do not supply encryption; isolate them and follow
the [privacy boundary](privacy.md).

## Native worker and capture API

The prepared `ruview-server-modules` executable requires at least one
`--allow-source PRIVATE_IP_OR_CIDR` (up to 16). `--nodes` is a comma-separated
list of 1–10 unique IDs in 1–16 (default `1,2,3`). The UDP and HTTP bind defaults
are `0.0.0.0:5015` and `0.0.0.0:5016`; override them with `--listen-udp` and
`--listen-http`. The service is intended for a controlled private network;
source admission is not cryptographic authentication.

The admitted CSI datagram is exactly 148 bytes, little-endian:
offset 0 magic `0xc5110001` (u32), 4 node (u8), 5 antenna count (1),
6 subcarrier count (u16, 64), 8 frequency MHz (u32, 2412–2472 in steps of 5),
12 sequence (u32), 16 RSSI and 17 noise (signed bytes), 18 PPDU (0), 19 flags
(0 or `0x10`), followed by 128 signed IQ bytes. The sync-valid flag does not
establish a verified device clock. Unsupported source, node, length or grid
is rejected and counted.

`GET /health` returns 200 with `status:"ok"` or 503 with
`status:"processor_unresponsive"`. `GET /v1/latest` and `/v1/events` both return
the bounded current snapshot, not an unbounded event stream.
`ruview.server-modules.v1` includes worker/clock/configuration identity,
`recognition_validated:false`, freshness and catalog limits, per-node state,
events, fleet diagnostics and counters. Timestamp nanoseconds and occurrence
IDs may be decimal strings; preserve them without float conversion.
Age is recomputed on every response. Expired events do not become current when
read. Unsupported paths/methods return 404, unacceptable content encoding 406,
and an oversized snapshot 503. The server supports bounded gzip negotiation.
It closes each HTTP connection; requests have a 2048-byte header limit and
750 ms read/write deadlines.

`--record-jsonl PATH` writes bounded diagnostic records to a new private file.
`--record-seconds` defaults to 600 (1–3600);
`--record-max-bytes` defaults to 100000000 (1024–1000000000).
Diagnostic recording is distinct from a complete original capture.

Original capture requires both `--capture-directory DIRECTORY` and
`--capture-admin-socket SOCKET`. Control is local over an owned Unix socket:

```text
ruview-server-modules capture-control SOCKET JSON
ruview-server-modules capture-export DIRECTORY SESSION opening|terminal|raw
```

Control JSON uses `schema:"ruview.capture.control.v2"`, `op` and a canonical
lowercase UUID `session_id`. `start` additionally requires sorted unique
`node_ids` from the configured set, `duration_ms` (1–3600000) and `max_bytes`
(1024–104857600). `status` and `stop` accept only the common three fields.
Unknown/duplicate fields fail. Requests/replies are bounded to 4096/16384 bytes;
at most eight sessions and 256 MiB total are retained. Export writes the
original selected bytes to stdout, not a reconstructed recording.
Opening/raw/terminal records bind the session, run, clock and configuration.
Incomplete writes, overflow, missing receivers and interrupted draining remain
explicit failures. See [native source/build instructions](../server-modules/README.md).

## Collector and browser UI

The collector packages pinned upstream software plus local grid, mirror and
security patches. Its inherited API is broader than the three native-worker endpoints.
Use the exact revision in [source-lock.json](../collector/source-lock.json):
[upstream API reference and status semantics](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/docs/adr/ADR-043-sensing-server-ui-api-completion.md),
[training API](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/docs/adr/ADR-186-training-progress-api.md)
and [full collector interface inventory](collector-interface.md).
Do not substitute the upstream archive/v1 API for this Rust server.

The local consumer reads `GET /api/v1/sensing/latest` and `/ws/sensing`;
their receiver/freshness fields are kept distinct from native module output.
The local patches expire stale grids and optionally mirror original CSI with
bounded queues. The UI accepts reviewed geometry generated by
`collector/ui/export-floor-config.py`; colors indicate sample freshness, not
measured positions. Generated geometry and credentials are not public assets.

## Data contracts and Python embedding

Python classes/functions and their signatures/docstrings can be inspected
without reading implementation code:

```sh
python -m pydoc inference.pipeline
python -m pydoc inference.capture_session
python -m pydoc inference.reference_session
python -m pydoc inference.reference_alignment
python -m pydoc inference.model
python -m pydoc inference.stream
python -m pydoc assumed_activity.core
python -m pydoc radar.config
python -m pydoc radar.ld2450
python -m pydoc wisp_pilot.protocol
```

- `WindowBuilder` consumes per-receiver CSI frames through `push(frame)`,
  emitting a window when duration/count/gap requirements are met; `None`
  means no complete window yet. It never combines receivers. Profiles bind
  receiver/grid/feature identities.
- `verify_session(manifest, frames, opening, terminal)` checks original v2
  closure and returns a verification report; `verified_session` provides a
  verified read scope. `ruview.capture.opening.v2`,
  `ruview.csi.frame.v2` and `ruview.capture.terminal.v2` are distinct records.
  Do not mix the older v1 capture/snapshot evidence with a v2 session.
- Reference-session exports bind original event bytes, explicit human review,
  capture identity and coordinate frame. Alignment takes bracketing clock
  measurements and a declared uncertainty allowance; wall-clock resemblance
  alone is insufficient.
- Model candidates bind task, node, feature contract, training/held-out session
  identities and coefficients. `ruview.native_csi.ridge_candidate.v1` and
  `ruview.native_csi.ridge_prefix_excluded_candidate.v1` are distinct schemas.
- `ReplayRunner` consumes declared offline events under bounded configuration
  and emits `ruview.offline_stream_diagnostic.v1`. Unknown versions, stale
  samples or mismatched lineage do not become qualified observations.
- `radar.ld2450.decode_report(bytes)` returns a tuple of `Target` objects
  (`slot`, `x_mm`, `y_mm`, `speed_cm_s`, `distance_resolution_mm`). A report is
  exactly 30 bytes with header `aa ff 03 00` and footer `55 cc`; three 8-byte
  slots use signed magnitude, not two's-complement, for coordinates/speed.
  `StreamDecoder` accepts bounded chunks and caller-supplied clocks. Projection
  requires a complete reviewed profile; the library opens no serial device.
- `wisp_pilot.protocol.parse_packet(bytes)` returns decoded raw/link dictionaries;
  invalid input raises `ProtocolError`. `subscribe_packet(streams)` returns
  subscription bytes. Transport/replay uses these functions without inferring
  a qualified detection from upstream flags.
- The top-level `bridge` and `module_observations` are compatibility imports of
  the separately versioned
  [ruview-home-assistant](https://github.com/ha-homelab/ruview-home-assistant)
  package. Use that package's documented interface; they do not introduce a
  second broker or publication implementation.

## Source-archive operator and build tools

The [command inventory](command-inventory.md) lists each shipped command with
its purpose and accepted parameters. Common approval objects are:

- Site context `ruview.private-site-context.v1`: approved file inventory/hash
  binding for private input files.
- Installation identity `ruview.installation-identity.v2`: explicit policy,
  allowed receiver IDs/versions, restore image hash and WASM verification key.
- Collector profile `ruview.collector-profile.v1`: exact HTTP origin and
  WebSocket URL.
- Module manifest: exact package bytes/hash plus algorithm/event mappings,
  separate from the qualification package catalog.

These objects are not interchangeable. Device-write commands also require
their specific reviewed plan and artifact identity. Read the
[firmware interface](../firmware/README.md),
[module event contract](../firmware/module-contract.md) and
[fleet operation/migration contracts](../firmware/fleet/README.md) before use.
Those references describe inputs, side effects, output evidence and retry
restrictions; `--help` alone is not deployment acceptance.

`scripts/mac-worker-proxy.py` forwards only allowlisted peers and paths to a
loopback worker. Worker mode exposes `/health` and `/v1/latest` and forwards
admitted CSI UDP to the local worker; activity mode exposes `/health` and
`/v1/activity` without a UDP listener. It does not relay arbitrary HTTP methods
or destinations.

CAD `mechanical/enclosure/model.py --profile … --output …` creates the selected
parametric shape and metadata. Units, profile dimensions, output formats and
rendering commands are in the [CAD reference](../mechanical/enclosure/README.md).
No physical fit is implied. `scripts/build-release.py` produces the source
archive described in [distribution](distribution.md); validators report
rejection and exit nonzero rather than silently publishing unsafe inputs.
