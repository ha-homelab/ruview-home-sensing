# Test coverage and limitations

Tests use synthetic inputs, temporary files and loopback services. They exercise
software behavior; they do not establish sensing accuracy, a clinical use,
physical fit, RF behavior or acceptance of a particular installed device.
The [public CI workflow](../.github/workflows/ci.yml) is the executable inventory
of required jobs. It requires the public-data gate, both runtime containers,
Python/UI/native/firmware checks, CAD and distribution/security checks.

## Functional test map

- Configuration and authorization inputs: `tests/test_site_context.py`,
  `test_installation_identity.py`, `test_evidence_context.py`,
  `test_collector_profile.py`, `test_module_manifest.py` and
  `test_qualification_*.py` exercise independently pinned identities,
  malformed/changed JSON, unsafe files and wrong receiver/package selection.
- Capture and evidence: `tests/test_coverage_producer.py`,
  `test_reference_clock.py`, `test_runtime_observation.py`,
  `test_sampled_diagnostic_runtime.py` and `test_observer_coverage.py` exercise
  bounded recording, identity changes, clock probes, process deadlines and
  recovery accounting. These tests distinguish a diagnostic sample from
  continuous capture evidence.
- Inference: `inference/tests/` covers raw-frame validation, window gaps,
  per-node feature selection, capture closure, reference sessions/alignment,
  training/holdout separation, model/coordinate mismatch, zone fitting,
  replay expiry and metric fall-candidate/evaluation rules. Candidate outputs
  remain experimental even when these tests pass.
- Activity service: `assumed_activity/tests/` covers source polling,
  partial/stale/contradictory evidence, temporal confirmation, expiration,
  persistence after restart, HTTP/MQTT output and bounded diagnostics.
  `test_cli.py` additionally proves that help and invalid options never start
  the service, and that the normal invocation still calls the runtime.
- Optional inputs: `radar/tests/` exercises framing, signed units, chunked
  decoding, coordinate transforms and invalid configuration.
  `wisp_pilot/tests/` exercises raw/link protocol bounds, malformed packets,
  strict configuration, actual loopback capture and replay tamper detection.
- Provisioning and recovery: `firmware/fleet/tests/` covers backup/plan
  boundaries, explicit device identity, reviewed application/NVS/migration
  writes, rejected retries and unsafe paths. `firmware/wisp-pilot/tests/`
  covers pinned source preparation, archive hashes, dirty source and exclusive
  output. Serial operations are simulated; these tests do not flash hardware.
- Firmware C behavior: CI runs the actual patched source through host tests for
  RF selection, preferred AP, runtime diagnostics, OTA deadlines, HTTP results,
  boot-bound recovery, self-ping and CSI sequence admission. The WASM3 test
  executes actual built v2–v5 modules with AddressSanitizer, varied frame widths,
  input values, allocation failure, restart and concurrent lifecycle calls.
  Host scheduling/memory is not an ESP32 stack/timing measurement.
- Native worker: `server-modules/tests/` covers preparation/package/runtime
  contracts. CI additionally runs the actual Rust tests and built process
  smoke tests for packet admission, freshness, event accounting, fleet state,
  capture ownership, interruption, storage limits and export.
- Collector and UI: `collector/test-grid.sh` exercises the modified grid and
  mirror behavior. `collector/ui/tests/` covers health recovery and node-state
  rendering. This is not a browser test of every inherited upstream page or
  every collector API; those remain part of the documented external surface.
- Packaging and public boundaries: release-archive tests check deterministic
  member bytes and reject unsafe members. The installed-wheel test imports the
  real noneditable wheel and loads its four entrypoints. Publication checks
  scan actual archive/wheel bytes and Git history identities. CAD CI validates
  generated mesh/solid constraints for the documented profiles, without a
  physical printer or board-fit test.

## Run the software suites

Use a dedicated environment, as described in the root README. Install the
transport-security test requirements; the optional fleet tests additionally
require the pinned esptool and NVS generator:

```sh
python -m pip install -r tests/requirements-security.txt
python -m pip install esptool==5.1.0 esp-idf-nvs-partition-gen==0.3.0
python -m unittest discover -s tests -v
python -m unittest discover -s assumed_activity/tests -v
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python -m unittest discover -s inference/tests -v
python -m unittest discover -s radar/tests -v
python -m unittest discover -s wisp_pilot/tests -v
python -m unittest discover -s firmware/fleet/tests -v
python -m unittest discover -s firmware/wisp-pilot/tests -v
python -m unittest discover -s server-modules/tests -v
python -m unittest discover -s tools/tests -v
node --test collector/ui/tests/*.test.mjs
```

Use the CI commands for the pinned source fetch, actual Rust/WASM/C tests and
native process smoke tests. A Python preparation test is not a substitute for
executing the built native program. Likewise, container import checks do not
prove a complete end-to-end deployed installation.

## Measuring Python branches

Coverage is evidence with a defined denominator, not a replacement for the
functional test map. Install Coverage.py in the test environment, then create a
temporary configuration outside the source tree:

```ini
[run]
branch = true
source = .
omit =
    */tests/*
    */test_*.py
[report]
include_namespace_packages = true
```

Run each Python suite above with
`python -m coverage run --rcfile=/path/to/coverage.ini --append -m unittest discover …`
from the source root, then
`python -m coverage report --rcfile=/path/to/coverage.ini`.
Start with an empty coverage data file for each measurement and retain the
exact source revision, tool version and suite results. Including namespace
packages makes unexecuted source tools visible instead of omitting them.
Subprocess execution without coverage instrumentation is undercounted; do not
silently exclude such files to improve the number.

A local 2026-10-19 run of the nine Python suites above, including the CLI
regressions, completed 1,024 tests successfully on Python 3.14.7
with Coverage.py 7.16.2. The 97-file source inventory counted 10,048 of 12,347
statements (81.38%) and 2,657 of 3,590 branches (74.01%), with no excluded
lines. It includes root compatibility modules and unexecuted CAD/source
preparation tools. The [measurement manifest](test-coverage-20261019.json) binds
this snapshot to public base revision `b2bdbeb8c6122bf7fc184d591ecaca85f6e64a53`
plus the hashes of its four changed files. It predates the subsequent integrated
transport-security code and additional tests. This is a dated source measurement,
not a coverage threshold or a result for later revisions; rerun the commands
after implementation changes.

The measurement does not instrument Rust, C, JavaScript, downloaded upstream
source or native dependencies. Most Python branches being covered does not
establish a repository-wide percentage. The OpenSSF Passing `test_most`
suggestion concerns branches, input fields and functionality; it is distinct
from a fixed percentage requirement at a higher badge level. No complete
cross-language percentage is claimed here. Expand evidence for inherited
collector features and real firmware branches before describing all of the
produced software as covered.
