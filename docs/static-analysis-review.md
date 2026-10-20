# Static analysis and diagnostic decisions

The project runs Ruff and CodeQL in public CI. A successful job is not a claim
that every diagnostic is a vulnerability or that every possible defect is found.
Diagnostics must be fixed or reviewed against their actual behavior. This
document records the decisions for the Python diagnostics and collector
compiler warnings reviewed on 2026-10-19; it does not disable any query or
exclude any source path.

## Corrected diagnostics

- `tests/test_mac_worker_proxy.py` and
  `inference/tests/test_capture_session.py`: subprocess programs are explicit
  multiline strings, so a command list cannot be mistaken for a missing comma
  between adjacent string literals. The bounded-processing and FIFO rejection
  regressions remain executable.
- `tests/test_module_upload.py`: the fake device receives its firmware version
  through its constructor. The recovery fixture no longer overwrites a parent
  initializer's version after construction.
- `mechanical/enclosure/tests/test_native_runtime.py`: the required package set
  uses `assertLessEqual`, which reports both sets on failure.
- `inference/tests/test_reference_alignment.py`: absence of the required window
  raises `AssertionError` explicitly; it cannot fall through with `None`.
- Expected process-exit and deliberately disconnected-client exceptions in the
  test servers now have explanations at the handlers.
- `scripts` is an explicit Python package. Its shared helpers retain their
  package-relative imports and their existing standalone-script fallback.
  CodeQL previously reported unresolved relative imports when extracting these
  files as unparented modules. Both invocation forms remain supported.
- `server-modules/tests/capture_service_smoke.py` explicitly marks the outcome
  failed when an exception is recorded, including an interruption after the
  successful assertions. Cleanup cannot turn an interrupted run into a pass.

## Deliberate constructs retained

### Interruption and cleanup handling

The `BaseException` handlers in `scripts/coverage_producer.py`,
`server-modules/tests/fleet_service_smoke.py` and
`server-modules/tests/capture_service_smoke.py` are outer evidence/cleanup
boundaries. They also need to record interruption by `KeyboardInterrupt` or
`SystemExit`, stop owned processes, and save an incomplete result. Restricting
these boundaries to `Exception` would omit that evidence.

The coverage producer records `capture_interrupted`; the fleet smoke check
propagates its failure after saving completion; the capture smoke check sets
`passed=False` and fails its final check. Worker-process cleanup failures are
retained alongside the original failure. These handlers are not general-purpose
retries and do not continue a successful measurement after an interruption.

### Test oracles and clock injection

`NoCredentials.__getitem__` in the activity configuration tests deliberately
raises `AssertionError` if code reads credentials before validating approval.
A `KeyError` would describe an absent dictionary key rather than the security
ordering failure under test. This deliberately hostile test double is not a
production mapping.

The cleanup assertion after `assertRaisesRegex` in
`inference/tests/test_evidence.py` is reachable: unittest consumes the expected
exception, then the test verifies that the temporary directory was removed.
Retaining that assertion checks cleanup on failure, not just on normal return.

The `lambda: time.monotonic()` supplied to `SourceReads` intentionally resolves
the clock at call time. Activity tests replace the clock after constructing a
service. Binding `time.monotonic` at construction instead changes that injection
behavior. No untrusted expression is evaluated by the lambda.

### Deferred evidence imports

`inference.evidence` and `inference.capture_session` defer their mutual imports
until the validation/context function is invoked. Importing either module
finishes before the function accesses the other module. These imports reuse the
same identity, boundary and evidence validators rather than creating a second
validation implementation that could drift.

The inference suite exercises both closed-capture validation and pairing to
verified recordings, including tampered data and failure cleanup. The cycle is
retained as a bounded internal dependency, not an assertion that arbitrary
import-time cycles are safe.

## Collector compiler warnings retained

The first complete collector build emitted nine distinct Rust warnings,
repeated across its Linux native-test and ARM64 release compilation steps.
The subsequent build also compiled library security tests and exposed one
additional unused import, making ten distinct diagnostics in that run.
These decisions concern the pinned upstream revision
[`7c8aeacea2ad30972070196eb7d8e7200506b742`](https://github.com/ruvnet/RuView/tree/7c8aeacea2ad30972070196eb7d8e7200506b742).
They do not describe a warning-free build or qualify the entire upstream
workspace.

- In
  [`wlanapi_native.rs`](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/wifi-densepose-wifiscan/src/adapter/wlanapi_native.rs),
  `Instant` and `BssidId` are used by the `#[cfg(windows)]` scanner.
  `freq_khz_to_channel`, `freq_khz_to_band` and `phy_type_to_radio` are
  used by that scanner and the module's unit tests. The Linux production
  implementation of `scan_native` returns `WifiScanError::Unsupported`;
  it does not invoke the Windows FFI or fabricate observations. The two
  unused-import and three dead-function warnings result from these
  declarations remaining outside the platform gate. This finding concerns
  this WLAN module, not every subprocess-based scanner in the application.
- In
  [`matter/bridge.rs`](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/wifi-densepose-sensing-server/src/matter/bridge.rs),
  one diagnostic covers the unused `MatterClusterMapping` and
  `DEVICE_TYPE_BRIDGED_NODE` imports. The tree builder obtains the actual
  mapping and device type from `matter_mapping`; a Rust name import does
  not perform runtime registration. The separate unnecessary-`mut` warning
  concerns an `Endpoint` constructed once and then moved into `children`.
  The reviewed path does not modify that local endpoint before the move.
- In
  [`matter/commissioning.rs`](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/wifi-densepose-sensing-server/src/matter/commissioning.rs),
  `VENDOR_ATTR_PERSON_COUNT as _` is an unused import despite its
  “re-export-only guard” comment. It neither re-exports a public API nor
  supplies a value to pairing-code construction. The pairing calculation
  uses its explicit validated input fields; this warning does not indicate
  a missing runtime initialization.
- In
  [`main.rs`](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/wifi-densepose-sensing-server/src/main.rs),
  the initial `None` assigned to `engine_bridge_multistatic_cfg` is
  overwritten before it is read. The preceding `multistatic_fuser` field
  initializer unconditionally assigns `Some(MultistaticConfig { ... })`
  using the same parsed guard configuration; the later `engine_bridge`
  initializer consumes it. Optional node-position processing does not
  bypass that assignment. A failed earlier initializer does not continue
  construction with `None`. The diagnostic concerns the redundant initial
  value, not a discarded configured guard.
- In the `#[cfg(test)]` module of
  [`mqtt/config.rs`](https://github.com/ruvnet/RuView/blob/7c8aeacea2ad30972070196eb7d8e7200506b742/v2/crates/wifi-densepose-sensing-server/src/mqtt/config.rs),
  the outer `use clap::Parser` is redundant: the only parsing helper imports
  the same trait inside its own function, where both `#[derive(Parser)]`
  and `W::parse_from` use it. The diagnostic is exposed by compiling library
  tests; it does not remove parsing or validation from the production CLI.

These are retained, source-reviewed diagnostics. No compiler warning flag is
suppressed. A change to platform gates, endpoint construction, pairing inputs
or state-initializer order requires a new review. This assessment does not
establish Matter interoperability, sensing accuracy or hardware acceptance.

## Reassessment

Changes to these handlers, test oracles, import paths or clock injection require
rechecking the associated decision and tests. Newly reported diagnostics are
not covered merely because their query name appears here. The current CodeQL
result and the exact source commit remain the evidence for each CI run.
