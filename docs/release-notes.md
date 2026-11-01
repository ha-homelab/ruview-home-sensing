# Release notes

## 0.4.1-beta.2

This candidate distributes the source changes merged after beta.1, including
the [upstream compatibility corrections](upstream-sync.md). Source/tool archive
and wheel must both come from the exact reviewed release commit, with package
version `0.4.1b2`; existing releases retain their original bytes.

### Collector and firmware corrections

The collector withdraws stale latest responses, evicts silent nodes on a timer,
keeps presence/count output consistent and applies requested privacy filtering
to REST, WebSockets and recordings. A routable HTTP/WebSocket bind now requires
authentication or explicit `RUVIEW_ALLOW_UNAUTHENTICATED` opt-in. Consumers must
treat stale or missing samples as unavailable, not as an empty room.

The MQTT bridge rejects expired, future-dated, untimed and explicitly offline
samples. Availability follows the original sample time instead of repeated
delivery of a frozen observation. Publisher maintenance uses a persistent
timer so continuous input cannot postpone availability and heartbeat checks.
Lagged input receivers continue from retained fresh messages. Nonblocking MQTT
enqueues prevent a full request queue from deadlocking its own event loop;
failed availability and discovery batches remain pending for maintenance.
Fresh input immediately attempts an online transition, and one-second
maintenance attempts stale transitions. Queue acceptance is not a broker
acknowledgement or a wall-time delivery guarantee.

Selected TLS/QUIC dependencies are updated to the reviewed upstream versions.
The local ring policy, immutable source bases and raw mirror protections remain
in place. Source preparation verifies the exact dependency lockfile delta and
includes its receipt in the image. Firmware self-ping receive waits now follow
the configured probe interval in both legacy and optional recovery paths.
CI verifies the delivered dependency receipt against the committed policy and
records its digest together with the patch and secured lockfile identities.

The dependency updates include fixes for the following published advisories;
affected runtime paths depend on enabled features and configuration:

- `quinn-proto` 0.11.18: [RUSTSEC-2026-0338](https://rustsec.org/advisories/RUSTSEC-2026-0338.html),
  [0339](https://rustsec.org/advisories/RUSTSEC-2026-0339.html),
  [0340](https://rustsec.org/advisories/RUSTSEC-2026-0340.html),
  [0341](https://rustsec.org/advisories/RUSTSEC-2026-0341.html) and
  [0342](https://rustsec.org/advisories/RUSTSEC-2026-0342.html).
- `rustls` 0.23.46: [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
  [0347](https://rustsec.org/advisories/RUSTSEC-2026-0347.html),
  [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) and
  [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html).
- `rustls-webpki` 0.103.16, `webpki-roots` 1.0.10 and `webpki-root-certs` 1.0.10:
  [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html),
  [0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html) and
  [0383](https://rustsec.org/advisories/RUSTSEC-2026-0383.html)
  (CVE-2026-111943).

### Explicit experimental contracts

The source distribution includes bounded shadow feature capture and trainable
sensor-model tools. Primary API telemetry can mix host and firmware producers;
these tools do not establish a qualified CSI, pose or fall-recognition model.
The native worker's optional reviewed LLTF admission profile preserves received
IQ bytes and has a distinct derived-feature contract. Raw64 consumers continue
to fail closed for incompatible frames. No admission profile or model is
automatically enabled by this release.

The incompatible upstream first-word flag/payload representation and new
STBC/HE capture behavior are not adopted. They need a coordinated wire/feature
contract migration and installation-specific qualification.

### Distribution and validation

The Home Assistant bridge remains pinned to `0.1.3b1` and its existing wheel
digest. Python requirements and the beta.1 container-image pins are unchanged.
The source archive carries all sibling files required by firmware, collector
and operator tools; the wheel provides Python libraries and four entrypoints.
Before publication, require full source CI, installed-wheel checks, repeatable
archive/wheel builds and publication-boundary scans.
Installed-wheel validation imports the shadow journal, join and model modules
as well as the four console entrypoints from outside the source checkout.

Software delivery does not deploy containers, flash firmware, tune thresholds,
promote a model or satisfy the separate live STBC runtime gate.

## 0.4.1-beta.1

Versions the already reviewed Python 3.15 Alpine runtime images and their
architecture-specific manifest pins from #18, plus the updated setuptools
packaging backend. The Home Assistant bridge dependency and its immutable wheel
digest remain unchanged. This metadata change introduces no new inference,
firmware or deployment behavior.

The source/tool archive and wheel must be built from the final reviewed commit,
with package metadata `0.4.1b1`. Publish them under a new prerelease identity;
never replace the existing 0.4.0 artifacts. Before publication, require the full
source CI, installed-wheel entrypoint checks, archive reproducibility and
publication-boundary scans. Container checks qualify the runtime images;
source tests alone do not establish Python 3.15 container compatibility.

The package retains Python 3.11+ support, with Python 3.12+ for the inference
extra. Physical installation, sensing accuracy and enclosure fit still require
independent acceptance.

## 0.4.0

The software release retains the runtime implementation and exact dependency
pins of `0.4.0-rc.3`. Package metadata now uses `0.4.0`; installation instructions
refer to the final wheel. The source/tool archive and Python wheel are rebuilt
from the reviewed release commit and receive their own immutable checksums.

The migration requirements and evidence limits described below remain in force.
In particular, collector observation requires an explicit receiver scope, and
the separate Home Assistant bridge remains pinned to its qualified `0.1.3b1`
wheel digest. This is not a firmware deployment or a claim of calibrated
coordinates, recognition accuracy, fall-detection reliability or enclosure fit.

## 0.4.0-rc.3

Changes since `0.4.0-rc.2` address delayed observations and make collector
qualification scope explicit. This remains an opt-in software candidate.

### Preserve observation age through publication

The bridge dependency is now [v0.1.3-beta.1](https://github.com/ha-homelab/ruview-home-assistant/releases/tag/v0.1.3-beta.1),
packaged as `ruview-home-assistant 0.1.3b1` from public source
`e8ab8fabdd7b3f5bcccf1878c852927d78c4f388`. Both dependency manifests pin its wheel
to SHA-256 `7a410f23d8d291a9ccffa577ca6b377ffd36f4a3c1bba5df1c686f61937c4c73`,
verified against the published release manifest and downloaded bytes.

The separately packaged Home Assistant bridge now accounts for time spent on
module work, discovery and MQTT publication. CSI, inference and snapshot ages
retain their original observation time; slow work cannot renew expired
observations. Primary and fall availability fail closed when the supporting
observation expires, and an independent fall lease can expire while primary
observations remain fresh.

This project continues to import the public bridge through compatibility
facades. Its installed-adapter regression checks the exact wheel digest,
delayed publication, fresh and expired observations, independent fall expiry
and unchanged input samples with network access forbidden. It reproduces the
stale-online behavior in the previous `0.1.2` dependency. Existing RC2 files
and their source identity remain unchanged.

### Require an explicit collector receiver scope

`scripts/observe-collector.py` now requires `--nodes`. Previously its implicit
receiver subset could omit another installed receiver and still produce a
passing report. Supply every receiver whose freshness must qualify, together
with the independently pinned collector profile. IDs must be unique integers
from 1 through 255; invalid or missing scopes fail before credentials are read
or network requests are made. A missing requested receiver prevents success.

Existing invocations that omitted `--nodes` must add their reviewed receiver
list. The report shape, accepted-CSI age checks and sampling coverage rules are
unchanged. The collector observer and coverage recorder now use the shared
no-redirect transport implementation, preserving its TLS and proxy policy.

The base package retains Python 3.11 support; the inference extra and full
development environment require Python 3.12+ for the pinned NumPy version.

The supported outputs remain a deterministic source/tool archive with a
per-file manifest and a Python wheel. Consumers must approve the immutable
source revision and pin the published asset digests before use. Installation
identities, geometry, observations and signing material remain separate.

This release does not establish calibrated coordinates, posture accuracy,
confirmed fall-detection performance or physical enclosure fit. Those require
independent reference data and acceptance for the intended installation.
