# Pinned collector interface

This documents the collector selected by `collector/source-lock.json` at
upstream revision `7c8aeacea2ad30972070196eb7d8e7200506b742`, including inherited
features. It is not the interface of the separate native worker. Local patches
change freshness, raw mirroring and security boundaries, not the route names below. The collector
includes experimental/model-management endpoints; their presence does not
establish model accuracy or authorize their use on an installation.

## Startup and transport

Run the prepared sensing-server binary with `--help` for its complete generated
option reference. Main listener options are `--http-port` (8080), `--ws-port`
(8765), `--udp-port` (5005), `--bind-addr` and `--udp-bind` (loopback by
default). A routable UDP bind requires `--udp-allow` IP/CIDR values, or the
explicit insecure-LAN option. UDP reports are not authenticated.

`--source auto|wifi|esp32|simulate` selects input; `--tick-ms` defaults to 100.
`--ui-path` selects static assets; `--data-dir` selects private persistent state.
`--allowed-host` and `SENSING_ALLOWED_HOSTS` configure accepted HTTP Host values.
Do not disable Host validation for an unprotected listener.

Other option families support model import/export (`--model`, `--load-rvf`,
`--save-rvf`, `--export-rvf`, `--convert-model`, `--convert-out`, `--progressive`),
training (`--train`, `--dataset`, `--dataset-type`, `--epochs`,
`--checkpoint-dir`, `--pretrain`, `--pretrain-epochs`), embeddings/index
(`--embed`, `--build-index`), `--node-positions`, `--calibrate`, `--benchmark`,
discovery (`--no-mdns`, `--installation-id`, `--installation-name`) and the
registry (`--edge-registry-url`, `--edge-registry-ttl-secs`, `--no-edge-registry`).
Use explicit private paths for recordings, models and generated state.
MQTT options are included in the binary's generated help.

HTTP responses are generally JSON; `/` and `/ui/*` provide browser content.
WebSocket routes upgrade the connection and stream JSON. REST compatibility
handlers may return HTTP 200 with `success:false` or an `error` object; clients
must check the payload as well as transport status. There is no guarantee of
stable field sets between unpinned upstream revisions.

`RUVIEW_API_TOKEN` and optional OAuth configuration enable the inherited
authentication layer. An unset token is not an access-control policy. Native
clients can supply `Authorization: Bearer …`; browser clients obtain a
single-use ticket from `POST /api/v1/ws-ticket` and append `?ticket=…` to an
upgrade URL. The reply contains `ticket` and `expires_in_secs`; exhaustion
returns 503. Tokens, cookies and tickets must not be logged or published.
Health/browser sign-in routes have their own access semantics. See the pinned
[authentication and transport documentation](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/wifi-densepose-sensing-server/SECURITY.md).
This reference does not claim that optional OAuth, MQTT or upstream model
operations have been independently deployment-qualified here.

## Inputs and outputs by route family

- Health routes return liveness/readiness, versions, counters and metrics.
  `/api/v1/info` describes build/source/features; a feature being advertised
  does not establish its accuracy. `/api/v1/status` aliases readiness.
- Sensing/vendor `latest` routes return current reports or an unavailable
  result, not a historical dataset. `/api/v1/nodes` returns per-node state;
  `:id/sync` uses that node identifier and returns synchronization diagnostics.
  Mesh routes report topology/metrics.
- `/api/v1/rf/vendors` lists supported vendor descriptors.
  `POST /api/v1/rf/vendors/:vendor/events` takes the selected vendor's JSON
  event representation; the response reports accepted/rejected ingestion.
  The [vendor protocol references](https://github.com/ruvnet/RuView/tree/7c8aeacea2ad30972070196eb7d8e7200506b742/docs/adr)
  define device-specific CSI/radar formats. They are not interchangeable with
  the 148-byte native-worker packet.
- Pose/vital routes return estimates, availability and diagnostic context.
  `/api/v1/pose/current?view=raw|both|refined` selects representation. A refined
  or combined view without suitable canonical input returns 409. Retain
  source and validity metadata; do not promote estimates to measured positions.
- Model-list and active-model routes return metadata (`models`/`active`).
  `POST /api/v1/models/load` takes `id` (or `model_id`) and changes active state;
  unload takes no model identifier. Delete takes the model `{id}` in the URL path.
  LoRA activation takes `profile` (or `name`); list returns `profiles`.
  The singular `/api/v1/model/*` family exposes container/layer/segment/SONA
  metadata, and SONA activation takes a profile selection. A success reply
  from a compatibility handler does not prove training quality.
- Recording start accepts a JSON object with optional `id`; stop closes the
  current recording; list returns `recordings`; delete takes `{id}` in the URL
  path. Use a unique 1–128-character ASCII identifier containing only letters,
  digits, `_`, `-` or `.`, except the complete names `.` and `..`, never a path.
  An existing file or symlink is rejected
  rather than overwritten; new recordings use private file permissions.
  The recording directory
  is `data/recordings` relative to the server's working directory; `--data-dir`
  does not relocate it. Keep that working directory private. These inherited
  recordings are distinct from this project's
  bounded v2 native capture with opening/terminal evidence.
- Training start takes `dataset_ids` and a `config` object with `epochs`,
  `batch_size`, `learning_rate`, `weight_decay`, `early_stopping_patience`,
  `warmup_epochs` and optional pretrained/LoRA selection.
  Defaults are 100, 8, 0.001, 0.0001, 20 and 5 respectively.
  Pretraining takes `dataset_ids`, `epochs` (50) and `lr` (0.001).
  Stop/status and `/ws/train/progress` expose the current job lifecycle.
  LoRA and adaptive training have their own model/dataset inputs; use the
  pinned [training API reference](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/docs/adr/ADR-186-training-progress-api.md)
  and generated server help. Training outputs remain model candidates.
- Calibration start takes a JSON `binding_digest` and sorted unique
  `source_node_ids`, with optional query `source_node_id`.
  The status response supplies current boot/session/binding identifiers.
  Stop/cancel/reset and bootstrap operations must match those identifiers;
  do not replay a request from another boot. Bootstrap refinement additionally
  uses explicit empty-scene confirmation. The pose calibration routes are
  aliases, not separate calibration state.
- `GET /api/v1/config/dedup-factor` returns the factor;
  POST takes `{"value": NUMBER}` (clamped to 1–10).
  `POST /api/v1/config/ground-truth` takes `{"count": POSITIVE_INTEGER}` and
  derives/persists a factor from current data. These operations change state;
  they do not create independently reviewed ground truth.
- `/oauth/start`, `/oauth/callback`, `/oauth/logout` and `/oauth/status` are
  browser sign-in/callback/session operations, not sensing inputs.
- `/api/field` returns recent RuField events plus signer metadata;
  `/ws/field` streams events admitted by the privacy policy. There are at most
  64 recent events and a bounded broadcast queue. Set an independently
  provisioned `WDP_RUFIELD_SIGNING_SEED` when identity must survive a restart.
  It must encode exactly 32 raw bytes or 64 hexadecimal characters; invalid,
  zero and known public fixture keys fail startup. Without it, the patched
  server generates an ephemeral OS-random key. Neither an ephemeral nor a
  persistent signature independently establishes sensing accuracy.

The pinned [API behavior reference](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/docs/adr/ADR-043-sensing-server-ui-api-completion.md)
provides compatibility response examples. The route inventory below includes
the main router plus its training and RuField subrouters. A configured mode
can expose a subset; listing a route is not enabling it.

## Local raw-mirror extension

`RUVIEW_RAW_CSI_MIRROR` is an explicit private/loopback destination socket address
with a nonzero port. `RUVIEW_RAW_CSI_MIRROR_NODE_IDS` supplies 1–16 unique
nonzero node IDs. Without a destination, mirroring is disabled; invalid
configuration is rejected with a warning rather than changing primary
ingestion. Eligible original datagram bytes are forwarded unchanged.
Counters distinguish eligible, sent and dropped packets. Forwarding does not
make an incomplete capture suitable for training.

## Exact route inventory

The following methods/paths are registered by the pinned main, training and
RuField routers. Path variables select an existing identity; they are not
filesystem paths. The native worker and activity service use the separate
interfaces in [interfaces.md](interfaces.md).

- `GET /ws/sensing`
- `GET /health`
- `GET /`
- `GET /health/health`
- `GET /health/live`
- `GET /health/ready`
- `GET /health/version`
- `GET /health/metrics`
- `GET /api/v1/info`
- `GET /api/v1/status`
- `GET /api/v1/metrics`
- `GET /api/v1/sensing/latest`
- `GET /api/v1/radar/latest`
- `GET /api/v1/csi/mediatek/latest`
- `GET /api/v1/csi/qualcomm/latest`
- `GET /api/v1/csi/realtek/latest`
- `GET /api/v1/rf/vendors`
- `GET /api/v1/rf/vendors/latest`
- `GET /api/v1/rf/vendors/:vendor/latest`
- `POST /api/v1/rf/vendors/:vendor/events`
- `GET /api/v1/nodes`
- `GET /api/v1/nodes/:id/sync`
- `GET /api/v1/mesh`
- `GET /api/v1/mesh/metrics`
- `GET /api/v1/vital-signs`
- `GET /api/v1/edge-vitals`
- `GET /api/v1/edge/registry`
- `GET /api/v1/wasm-events`
- `GET /api/v1/model/info`
- `GET /api/v1/model/layers`
- `GET /api/v1/model/segments`
- `GET /api/v1/model/sona/profiles`
- `POST /api/v1/model/sona/activate`
- `GET /api/v1/pose/current`
- `GET /api/v1/pose/physics/metrics`
- `GET /api/v1/pose/stats`
- `GET /api/v1/pose/zones/summary`
- `GET /api/v1/pose/activities`
- `POST /api/v1/pose/calibrate`
- `GET /api/v1/pose/calibration/status`
- `GET /api/v1/stream/status`
- `POST /api/v1/ws-ticket`
- `GET /oauth/start`
- `GET /oauth/callback`
- `GET /oauth/logout`
- `GET /oauth/status`
- `GET /api/v1/stream/pose`
- `GET /ws/introspection`
- `GET /api/v1/introspection/snapshot`
- `GET /api/v1/models`
- `GET /api/v1/models/active`
- `POST /api/v1/models/load`
- `POST /api/v1/models/unload`
- `DELETE /api/v1/models/{id}`
- `GET /api/v1/models/lora/profiles`
- `POST /api/v1/models/lora/activate`
- `GET /api/v1/recording/list`
- `POST /api/v1/recording/start`
- `POST /api/v1/recording/stop`
- `DELETE /api/v1/recording/{id}`
- `POST /api/v1/adaptive/train`
- `GET /api/v1/adaptive/status`
- `POST /api/v1/adaptive/unload`
- `POST /api/v1/calibration/start`
- `POST /api/v1/calibration/stop`
- `POST /api/v1/calibration/bootstrap/promote`
- `POST /api/v1/calibration/bootstrap/refine`
- `POST /api/v1/calibration/cancel`
- `GET /api/v1/calibration/status`
- `POST /api/v1/calibration/reset`
- `GET /api/v1/config/dedup-factor`
- `POST /api/v1/config/dedup-factor`
- `POST /api/v1/config/ground-truth`
- `POST /api/v1/train/start`
- `POST /api/v1/train/stop`
- `GET /api/v1/train/status`
- `POST /api/v1/train/pretrain`
- `POST /api/v1/train/lora`
- `GET /ws/train/progress`
- `GET /api/field`
- `GET /ws/field`
