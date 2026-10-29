# Shadow telemetry journal

`python -m assumed_activity.training_journal` records read-only observations at
a new shadow evaluation boundary. It fixes the loss of full per-node features
in a projection which retained only `nodes`: the sensing API exposes signal
metrics under **`node_features`**. This journal includes `motion_band_power`,
`variance`, other finite numeric feature fields and selected diagnostic values.
These are primary API telemetry fields with no per-feature producer provenance
in the journal. Their values may come from host CSI processing or firmware
`motion_energy`; collecting the full array does not make them qualified CSI
features. The `nodes` diagnostics and native-worker grid are separate context,
not proof of the primary values' radio origin. In particular, a diagnostic
`subcarrier_count=0` may describe a vitals envelope.

It does not change or replay the production producer, publish to Home Assistant,
label occupancy, or qualify a model. Independent source annotations and a
separate train/evaluation contract remain necessary.

```sh
python -m assumed_activity.training_journal \
  --sensing-url "$SENSING_ENDPOINT" \
  --worker-url "$WORKER_ENDPOINT" \
  --node 1 --node 2 --node 3 \
  --token-file /private/collector-token \
  --output /private/new-shadow-run \
  --deadline "$FIXED_UTC_DEADLINE"
```

The output directory must not exist. No existing recording is modified or
resumed, and no source API receives a write. The collector token is sent only to
the explicitly selected sensing URL; worker and receiver requests never receive
it. Redirects and ambient proxies are disabled. Response bodies, rows, file
counts, outstanding reads and byte totals are bounded. Never publish generated
journals: worker identities, radio identity proofs and signal data are private.

Defaults are one-second cadence, 0.8-second source phase budget, a 512 MiB total
cap, 8 MiB part target and a 1 GiB free-space floor. Pass explicit limits suited
to the host. A delayed poll records its actual receipt interval; it does not
fabricate samples to fill the gap. Each endpoint has at most one outstanding
request. Expired results are discarded rather than reused. Both UTC and
monotonic deadlines prevent a backward clock correction extending the run.
Use an external service deadline as a final process boundary for abnormal I/O.

Every observation records run/configuration identity, UTC and monotonic receipt
time, clock epochs, actual intervals, read outcomes, per-node source age and
feature availability. Missing/nonfinite metrics remain missing and make the
required-feature row unavailable. The worker projection retains its independent
freshness, raw grid, sequence, epoch and discontinuity facts. A primary feature
row may exist even when the native worker rejects its radio profile.
`native_profile_compatible` is a profile-only diagnostic (null for missing
profile), not native evidence eligibility or model qualification.

Optional `--receiver-config` and `--receiver-sha256` use the existing independently
pinned receiver-proof policy. If omitted, `receiver_proof` is null, never an
invented approval. Those proofs relate to this shadow observation and do not
retroactively validate older records. Source endpoints are represented by
hashes in metadata; credentials are never recorded.

`metadata.json` binds the configuration and collector source hash. Rotated
`observations-*.jsonl` parts are flushed and fsynced before their SHA-256 hashes
are included in `status.json`. `terminal.json` preserves the exit reason and all
closed-part hashes. Active-part rows are provisional until closure. A STOP file
inside this new run directory, SIGINT or SIGTERM closes the current part. Byte
or free-space stops are incomplete observations, not successful full-duration
captures. A crash without a terminal receipt requires recovery/verification and
must not be labeled clean closure.

On Linux, metadata records a bounded canonical boot UUID and `CLOCK_MONOTONIC`.
Unsupported or invalid boot identity remains null. This permits a proven
same-kernel join to separately verified reference events; it is not a guessed
UTC clock calibration. See the [verified primary-telemetry join](shadow-join.md).
