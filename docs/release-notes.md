# Release notes

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
