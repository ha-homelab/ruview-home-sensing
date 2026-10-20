# Static analysis and diagnostic decisions

The project runs Ruff and CodeQL in public CI. A successful job is not a claim
that every diagnostic is a vulnerability or that every possible defect is found.
Diagnostics must be fixed or reviewed against their actual behavior. This
document records the decisions for the Python diagnostics reviewed on
2026-10-19; it does not disable any query or exclude any source path.

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

## Reassessment

Changes to these handlers, test oracles, import paths or clock injection require
rechecking the associated decision and tests. Newly reported diagnostics are
not covered merely because their query name appears here. The current CodeQL
result and the exact source commit remain the evidence for each CI run.
