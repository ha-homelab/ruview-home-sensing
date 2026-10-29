# Trainable shadow sensor-state models

`shadow_model.py` provides a dependency-free logistic model, portable JSON artifact, pinned loader, prediction and frozen evaluation. It predicts whether a declared independent sensor output is active. It does **not** predict verified occupancy, body pose, person count, metric coordinates or falls, and cannot authorize Home Assistant publication.

The existing adaptive anomaly detector does not need to be restarted or changed. Collect and evaluate shadow inputs separately. Keep household source mappings, radio identifiers, model artifacts, examples and recordings outside this public repository.

## Input and provenance

Each normalized JSONL example has this shape. Names below are synthetic placeholders; the adapter must supply actual verified identities and reference coverage.

```json
{
  "schema": "ruview.shadow-motion-example.v1",
  "example_id": "capture-a:sample-123",
  "interval_start_utc": "2026-01-01T00:01:00+00:00",
  "interval_end_utc": "2026-01-01T00:01:01+00:00",
  "observed_at_utc": "2026-01-01T00:01:01+00:00",
  "feature_contract": {
    "name": "example-rssi-only",
    "version": 1,
    "features": ["node_a_rssi"],
    "identity": {"source_config_sha256": "EXTERNALLY_VERIFIED_DIGEST", "radio_profile": "EXPLICIT_PROFILE"}
  },
  "features": {"node_a_rssi": -54.0},
  "quality": {"eligible": true, "reasons": []},
  "maintenance_excluded": false,
  "references": [{
    "source_group": "independent-source-a",
    "kind": "motion",
    "independent": true,
    "derived_from_ruview": false,
    "available": true,
    "state": "off",
    "observed_at_utc": "2026-01-01T00:01:01+00:00"
  }]
}
```

Features are ordered by the contract and must all be finite measured values. Missing values are not filled with zeros. RSSI-only legacy inputs and newer full-feature journal inputs require different contracts. Changing nodes, firmware/radio profile, channel, antenna, feature extraction or cadence requires a new identity and evaluation; inference abstains when the contract differs.

The adapter is responsible for verifying capture hashes, clocks, actual source identities, profile continuity and reference lineage. A declaration such as `independent: true` is not independent evidence. Preserve its source evidence separately. `observed_at_utc` on a reference describes the time at which the source state is known under a continuously healthy subscription or a successful direct sample. It is **not** necessarily HA `last_changed`; a long unchanged OFF state may still be current. Do not refresh this timestamp through a disconnected or unavailable interval. Close the observation interval with a real subsequent receipt before supplying a historical projected state. Exclude clock discontinuities, reconnect settling and maintenance windows in the adapter.

The selected physical source groups are OR-combined only after every group is known and available. All OFF is a negative example of **sensor output activity**, not absence of people. Matching aliases within one group produce one label; conflicting aliases, derived RuView labels, stale timestamps and unknown states are rejected. RF hold times and ONVIF latching remain properties of the target. Per-room claims require separately reviewed spatial mapping; a model of one source's output does not establish whole-house coverage.

## Fixed fit and validation policy

```json
{
  "schema": "ruview.shadow-motion-policy.v1",
  "feature_contract": {"name": "example-rssi-only", "version": 1, "features": ["node_a_rssi"], "identity": {"source_config_sha256": "EXTERNALLY_VERIFIED_DIGEST", "radio_profile": "EXPLICIT_PROFILE"}},
  "reference_groups": ["independent-source-a"],
  "validation_start_utc": "2026-01-01T01:00:00+00:00",
  "final_holdout_start_utc": "2026-01-01T16:00:00+00:00",
  "split_gap_seconds": 30,
  "reference_max_age_seconds": 10,
  "min_train_per_class": 10,
  "min_validation_per_class": 5,
  "threshold": 0.5,
  "epochs": 400,
  "learning_rate": 0.1,
  "l2": 0.01,
  "minimum_logloss_improvement": 0.0
}
```

Choose and retain the policy before inspecting validation outcomes. The fit partition ends before the declared purge gap; validation starts at the fixed boundary. Final-holdout features and labels are never consumed by fitting or development evaluation. Duplicate identities and overlapping intervals are rejected. Standardization, positive prior and coefficients are fitted on training rows only. The threshold is fixed by policy, never selected using validation results.

Training needs the declared minimum observations in both classes. If validation has too few observations in either class, the fitted candidate is still saved, but reports `pending_validation`, `validation_sufficient: false` and `passes_shadow_baseline: false`. Accumulate later observations at the original boundary; do not move the boundary or lower class minima after seeing the result.

Validation compares log loss, Brier score, balanced accuracy, class recalls and confusion counts with the constant training-prior baseline. The simple development gate requires better log loss and no decrease in balanced accuracy. It permits shadow investigation only, not production promotion. Observed positive/negative runs and transition counts are also reported: repeated adjacent sensor states are correlated samples, not independent trials. Chronological validation within one capture is exploratory and cannot replace independent sessions or household recognition qualification.

## Train, load and evaluate

```sh
python3 -m assumed_activity.shadow_model train \
  --examples /private/examples.jsonl --policy /private/policy.json \
  --output /private/new-model.json --report /private/new-report.json

python3 -m assumed_activity.shadow_model predict \
  --model /private/new-model.json --expected-sha256 MODEL_FILE_SHA256 \
  --examples /private/live-examples.jsonl --output /private/new-predictions.json

python3 -m assumed_activity.shadow_model evaluate \
  --model /private/new-model.json --expected-sha256 MODEL_FILE_SHA256 \
  --examples /private/evaluation.jsonl \
  --start-utc 2026-01-02T00:00:00Z --end-utc 2026-01-02T01:00:00Z \
  --output /private/new-evaluation.json
```

Outputs must be new paths and are created mode 0600. The train command prints the model file SHA-256. Preserve that digest independently; the internal payload digest detects corruption but is not a signature or source approval. The pinned loader reads and verifies the same bytes once. API callers can use `train(examples, policy)`, `load_model(path, expected_sha256)`, `predict(artifact, examples)` and `evaluate(artifact, examples, start_utc, end_utc)`.

Predictions contain `probability_reference_active`, a fixed-threshold prediction, model digest, and explicit availability/abstention reason. All outputs retain `mode: shadow` and `publish_to_ha: false`. Frozen evaluation cannot overlap the fitting partition or purge gap. Do not run final-holdout evaluation early; once its outcomes inform another candidate, it is no longer an untouched holdout for that candidate.

## Repeated development cycles

`shadow_cycle.py` adds a small repeatable wrapper, not a new inference service. Supply a fixed cycle policy with `schema: ruview.shadow-cycle-policy.v1`, `capture_start_utc`, `final_holdout_start_utc`, `cycle_seconds` (default 900), `validation_seconds` (default 1800), and `fit_policy` containing the feature contract, reference groups and model hyperparameters above. The wrapper supplies the model policy schema and time boundaries itself.

Each invocation rounds the supplied time down to the latest completed cycle boundary anchored at capture start. The last declared validation-duration interval is reserved for that candidate; earlier examples fit the model with the fixed purge gap. Only complete development examples before the frozen final holdout can enter either partition. Boundaries depend on time, never the observed class counts or scores.

```sh
python3 -m assumed_activity.shadow_cycle \
  --examples /private/development-examples.jsonl \
  --policy /private/frozen-cycle-policy.json \
  --as-of-utc 2026-01-01T02:15:00Z \
  --output-directory /private/new-cycle-directory \
  --previous-model /private/previous-model.json \
  --previous-sha256 PREVIOUS_MODEL_FILE_SHA256
```

Omit both previous-model options for the first candidate. A new directory contains the frozen cycle/model policies, candidate and evaluation when available, an unchanged previous-model copy when supplied, and a final manifest with file hashes. Existing directories are rejected. A retry should inspect the existing manifest rather than replace it.

The manifest reports `fit_pending` when training class support is insufficient, `eval_pending` when later validation or prior-model comparison is insufficient, `passes` for the declared exploratory comparison, and `no_improvement` otherwise. A valid candidate is retained even if validation is pending or worse than baseline. Compatible prior models are evaluated over the same later interval and reference policy; a candidate must improve their log loss without lowering balanced accuracy to pass that comparison. No prior artifact is changed and no deployment pointer is updated.

Rolling development intentionally permits an earlier candidate's validation data to enter later training. Those data have been consumed for development and must not be described as independent final validation. The fixed final holdout remains excluded from every cycle. Even `passes` is a sensor-state proxy result and leaves `model_update_allowed: false` and `publish_to_ha: false`; actual deployment requires a separately reviewed experiment and applicability contract.
