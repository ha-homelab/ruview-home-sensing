# Build tools and reviewed compiler diagnostics

The firmware build recipe is [`firmware/Dockerfile`](../firmware/Dockerfile).
It compiles and links the ESP32-S3 application, bootloader and partition image;
it does not flash a board. Its output contains the ELF, map, binary images,
configuration, managed-component lock, compiler command database,
`BUILD_TOOLS.txt` and the IDF tool manifest. A successful host C harness or WASM
build is not evidence that this complete firmware build succeeded. Use the
separate **ESP32-S3 firmware build** CI result for that claim.

The default build has no operator Wi-Fi settings or provisioned signing key.
Successful compilation does not establish radio behavior, stack margin,
physical sensing accuracy, deployment acceptance or a safe provisioning policy.

## Required build tools

The recipe pins the official ESP-IDF v5.4.4 container by digest
`sha256:9ce51d4ace496845678065dc86f8e55fb9c25fc9f01f45597042afa7ed546926`.
[Espressif documents this image](https://docs.espressif.com/projects/esp-idf/en/v5.4.4/esp32s3/api-guides/tools/idf-docker-image.html)
as an automated application/library build environment with Python, CMake, Ninja
and its cross compilers. The build uses two compiler workers.

The [IDF v5.4.4 tool manifest](https://github.com/espressif/esp-idf/blob/v5.4.4/tools/tools.json)
identifies the Xtensa GCC toolchain as GPL-3.0 with the GCC exception, CMake as
BSD-3-Clause and Ninja as Apache-2.0. IDF's Python build scripts use its
[Apache-2.0 license](https://github.com/espressif/esp-idf/blob/v5.4.4/LICENSE).
The actual container's tool manifest and executed tool versions are exported
alongside the firmware, rather than inferred only from its tag. The recipe
uses the FLOSS Docker Engine/BuildKit interfaces; Docker Desktop is not required.
It does not require a proprietary IDE, programmer application or cloud build
service.

This update fixes the SDK-side ESP-NOW receive vulnerability described in
[GHSA-hqhh-cp47-fv5g](https://github.com/espressif/esp-idf/security/advisories/GHSA-hqhh-cp47-fv5g),
published on 2025-06-24. The selected ESP32-S3 application calls
`c6_sync_espnow_init()` after Wi-Fi connection and registers an ESP-NOW receive
callback; the affected protocol is therefore used, despite the helper's `c6`
name. Espressif identifies v5.4.2 and later as patched and states that v5.4
has no application-level workaround. The
[v5.4.4 release](https://github.com/espressif/esp-idf/releases/tag/v5.4.4)
retains the 5.4 API series. The pin update requires a new complete firmware
build; earlier builds do not qualify its output. This is a specific security
fix, not a claim that every optional SDK feature or build-image package has
been audited.

The other produced software uses Rust/Cargo 1.96.1
([MIT or Apache-2.0](https://github.com/rust-lang/rust/tree/1.96.1)),
CPython and setuptools for the Python wheel, and the pinned CadQuery/trimesh
Python workflow for CAD. See the checked-in toolchain and requirements pins,
[`mechanical/enclosure/model.py`](../mechanical/enclosure/model.py) and CI
commands for each output. This is a build-tool statement: it does not
relicense linked Espressif radio libraries, external firmware or hardware.
Their separate redistribution terms still apply.

## C host adapter

`firmware/tests/freertos_host.h` models a FreeRTOS task handle as a nullable
pointer, independently of the native `pthread_t` representation. The earlier
integer-handle model caused pointer/integer conversion warnings on Linux for
`vTaskDelete(NULL)` and resetting the worker handle. The native thread identity
is now stored separately; failed creation frees its temporary start record and
clears the handle. This changes the test adapter, not the device scheduler.

`test_runtime.py` treats integer/pointer conversions, incompatible pointer
types, implicit function declarations, return-type errors and format
diagnostics as errors. Its actual WASM3/AddressSanitizer run covers creation
failure, environment failure/self-delete, a retry, concurrent lifecycle calls
and the selected module's restart contract. Synthetic host stack reporting
does not establish device stack headroom.

## Pinned Rust module diagnostics

Review date: 2026-10-19. A release WASM build with Rust 1.96.1 reports eight
unused-import diagnostics and sixteen dead-code diagnostics in the pinned
upstream module source. They remain visible. No `allow` attribute, warning
filter or source rewrite was added to hide them. The immutable v2–v5 source
patches and previously distributed module identities are retained.

All paths below are relative to the
[pinned upstream module source](https://github.com/ruvnet/RuView/tree/e04f269f1a76eb6ed4e8cd33e2ccfeda6fd391a3/v2/crates/wifi-densepose-wasm-edge/src).
The home patches modify `gesture.rs` and `lib.rs`, not these files.

The eight unused imports are `sqrtf` in `sec_perimeter_breach.rs`,
`sec_weapon_detect.rs`, `sec_panic_motion.rs`, `ret_customer_flow.rs` and
`ind_forklift_proximity.rs`; and `fabsf` in `sec_tailgating.rs`,
`ret_dwell_heatmap.rs` and `ret_shelf_engagement.rs`. No call resolves through
these imports. Keeping the imports does not invoke an omitted calculation;
the diagnostic is accepted for this exact upstream snapshot.

The sixteen dead-code diagnostics have these dispositions:

- `sec_weapon_detect.rs`: `VAR_WINDOW` and the `amp_window`/`phase_window`
  fields are remnants of a rolling-window design. The actual implementation
  uses bounded per-subcarrier Welford statistics in `run_*` fields. The unused
  arrays are initialized, never read and consume storage; they do not provide
  an additional window or detection capability.
- `sec_panic_motion.rs`: `MAX_SC` is unused because this module consumes scalar
  motion/presence inputs and its own `WINDOW`-sized energy history.
- `bld_meeting_room.rs`: `MEETING_MIN_FRAMES` does not enforce the comment's
  five-minute definition. The actual transition checks `state_frames >= 60`
  in PreMeeting and a current count of at least two people. It does not prove
  sustained multi-person occupancy for five minutes. This prototype output
  must not be described as a validated genuine-meeting classifier.
- `ret_queue_length.rs`: `RATE_HISTORY` does not size a history buffer. Actual
  rate computation uses window counters and EMA state, with `SERVICE_WINDOW`
  determining when rates are updated.
- `ret_customer_flow.rs`: `FRAME_RATE` is unused; direction uses successive
  phase changes rather than a physically calibrated velocity. `NUM_GROUPS`
  is also unused; the implementation explicitly splits the bounded
  subcarrier slice into low and high halves.
- `ind_livestock_monitor.rs`: `STILLNESS_COOLDOWN` is unused. The implemented
  alert latches through `stillness_alerted` until movement/presence reset,
  rather than periodically alerting after the unused cooldown.
- `lrn_meta_adapt.rs`: `DEFAULT_STEP_FRAC` is unused because each
  `TunableParam` supplies its own bounded step size.
- `spt_pagerank_influence.rs`: `ALPHA` is not an active EMA control. Current
  output uses the fixed PageRank iterations and compares current/previous
  rank; no additional temporal EMA smoothing is claimed.
- `tmp_pattern_sequence.rs`: `THRESH_STILL` is unused. With presence and a
  single person, readings at or below `THRESH_LOW` map to `Still`; the other
  branches are explicit. No extra 0.05 boundary is enforced.
- `tmp_goap_autonomy.rs`: `Goal.priority` is redundant metadata. The actual
  `goal_priorities` array is initialized with the same six values and can be
  changed by `set_goal_priority`; selection reads that array. The unused
  field does not disable priority selection.
- `aut_psycho_symbolic.rs`: private `CmpOp::Neq` is never constructed by the
  static rule table. The other three operations are used. There is no
  external enum deserializer that could require this otherwise unused branch.
- `exo_hyperbolic_space.rs`: `initialized` is assigned but not read. The
  constructor initializes references, projection and EMA state directly;
  the processing path does not rely on an omitted lazy initialization.
- `exo_happiness_score.rs`: `STEP_INTERVAL_LEN` is not a live interval-buffer
  size; the implemented proxy uses `WelfordStats` over input variance.
  `BASELINE_GAIT_SPEED` is not used for calibration; the live score divides by
  `MAX_GAIT_SPEED`. These are unvalidated movement proxies, not measurements
  of happiness, clinical condition or physical gait speed.

These are narrow dispositions of enabled compiler diagnostics, including the
documented prototype limitations. They are not an audit of every algorithm.
New compiler diagnostics, full firmware diagnostics and static-extractor
limitations require their own review. In particular, this document does not
claim that strict warnings cover every language or every optional upstream
feature.
