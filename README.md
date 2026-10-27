# RuView Home Sensing

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15634/badge)](https://www.bestpractices.dev/projects/15634)

The badge links to the current OpenSSF assessment, supporting evidence and remaining criteria.

Reusable CSI sensing tools, bounded edge modules, inference experiments and printable ESP32-S3 enclosures.

This repository contains generic software and independently fictional examples. Installation configuration, receiver identities, site geometry, captures, model weights, signing material and operational history belong in separately protected storage.

## Components

- **[Collector](collector/README.md):** pinned RuView source, fresh CSI grid handling, bounded raw-CSI mirroring and a configurable receiver-map UI.
- **[Native modules](server-modules/README.md):** Rust workers with bounded capture, per-receiver state, freshness and fault reporting.
- **[Activity engine](assumed_activity/README.md):** conservative activity hypotheses with temporal confirmation and stale-data withdrawal.
- **[Inference tools](inference/README.md):** aligned recording, reference sessions, model evaluation and explicit evidence gates for coordinates, posture and possible falls.
- **[Firmware](firmware/README.md):** reproducible source preparation, OTA mechanisms, signed-module validation and lifecycle qualification.
- **[LD2450](radar/README.md)** and **[Wisp pilot](firmware/wisp-pilot/README.md):** optional inputs with explicit coordinate and time contracts.
- **[Enclosures](mechanical/enclosure/README.md):** parametric CAD for nominal 50/80/100 mm antenna pigtails. Physical fit remains unverified.

Home Assistant publication is implemented once in [ruview-home-assistant](https://github.com/ha-homelab/ruview-home-assistant). The tiny compatibility modules here import that separately versioned package. [sensing-evidence-kit](https://github.com/ha-homelab/sensing-evidence-kit) owns consumer-side recording and labelling; it does not replace producer-side CSI alignment.

## Evidence limits

Software tests establish the contracts they exercise. They do not establish recognition accuracy in a building. CSI activity is a hypothesis, not a measured person count or coordinate. Posture, position and fall outputs require suitable independent reference data, evaluation and explicitly approved artifacts. This project is experimental and is not a medical or emergency-response system.

## Software release

The **0.4.1-beta.1** candidate versions the reviewed Python 3.15 container-image
refresh and updated packaging backend. Its Python package version is `0.4.1b1`.
See the [candidate notes](docs/release-notes.md#041-beta1) for scope and checks;
no inference models, firmware payloads or installation state change.

The **0.4.0** software release follows the reviewed `0.4.0-rc.3` candidate. See the
[release notes](docs/release-notes.md) for the bridge freshness correction and
explicit collector-scope migration, and [distribution instructions](docs/distribution.md)
for verified source and wheel consumption. The release keeps the candidate's
runtime and dependency pins. Software release status does not establish
installation acceptance, update devices or promote experimental inference outputs.

## Development

The base package requires Python 3.11+. Inference and the complete development setup below require Python 3.12+ because the pinned NumPy release requires it. Select a compatible interpreter before creating the virtual environment. CI uses pinned dependencies and GitHub-hosted Linux runners. Native module builds pin Rust and upstream sources; CAD uses its separate locked environment.

CI reuses the shared [venus-os-ci-toolkit](https://github.com/victron-venus/venus-os-ci-toolkit/tree/21a366f200f0371a10a6de7ad6ca263af230b842) at an immutable revision. Checks cover the public-data boundary, Python and UI tests, firmware and native modules, containers, CAD and distribution integrity. Branch protection requires both `Public CI gate` and the separate `CodeQL` analysis result; a successful report upload alone does not satisfy the security requirement. Self-hosted runners are not used by this repository.

Maintainers opt into bot review with `auto-approve` and automatic merging with `automerge`. The shared metadata-only workflows run on GitHub-hosted runners. They require a trusted author, a current independent approval, successful checks and a branch containing the current default branch before merging. The reviewer has repository write access without a ruleset bypass. The two required branch checks remain enforced. Removing `automerge` prevents subsequent automatic merge decisions. Approval recovery is available from the default branch with an explicit PR number and exact head SHA. Automatic merging admits the maintainer and dependency bots; the reviewer account approves maintainer changes, but its own PRs need a manual merge with an explicit GitHub noreply author email until its account email privacy is verified. This keeps unverified merge-author metadata out of public history.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes --only-binary=:all: -r requirements.txt
python -m pip install -r inference/requirements.txt
python -m unittest discover -s tests -v
python -m unittest discover -s assumed_activity/tests -v
python -m unittest discover -s inference/tests -v
python -m unittest discover -s radar/tests -v
python -m unittest discover -s wisp_pilot/tests -v
node --test collector/ui/tests/*.test.mjs
python scripts/check-public-boundary.py
```

See [external interfaces](docs/interfaces.md), [test coverage and limitations](docs/testing.md), [architecture and release boundaries](docs/architecture.md), [privacy](docs/privacy.md), [contributing](CONTRIBUTING.md), [security reporting](SECURITY.md) and [third-party notices](NOTICE).

## License

Original code, documentation and CAD are available under the [MIT license](LICENSE). Third-party components retain their own licenses and notices; see [NOTICE](NOTICE). No upstream model weights or household recordings are distributed here.
