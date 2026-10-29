# Join complete features to verified proxy references

`python -m assumed_activity.shadow_join` joins a verified `shadow_legacy` export
to the most recent earlier full-feature observation from `training_journal`.
It preserves the reference examples' five-second cadence and copies their
independent binary targets unchanged. It does not interpret OFF as an empty
room and does not reconstruct spectral features in the old capture.

```sh
python -m assumed_activity.shadow_join \
  --references "$VERIFIED_REFERENCE_EXPORT" \
  --reference-root "$ORIGINAL_REFERENCE_CAPTURE" \
  --journal "$FULL_FEATURE_JOURNAL" \
  --config "$REVIEWED_JOIN_BINDING" \
  --output "$NEW_PRIVATE_EXPORT"
```

The configuration schema is `ruview.shadow-join-config.v1`. Bind these fields
to observed, independently retained input identity; do not fill missing values
with guessed IDs:

- `reference_feature_contract_sha256`: canonical JSON SHA-256 of the original
  RSSI feature contract, computed with `shadow_join.sha`.
- `journal_metadata_sha256`: byte SHA-256 of the journal's `metadata.json`.
- `expected_boot_id`: the same nonzero canonical Linux boot UUID present in the
  reference capture metadata and full-feature journal. A missing or different
  UUID fails closed. `training_journal` also declares `CLOCK_MONOTONIC`.
- `expected_clock_epoch`: the admitted journal clock epoch, normally zero.
- `node_ids` and `feature_keys`: explicit ordered inputs. Typical full-feature
  keys are `motion_band_power`, `variance`, `spectral_power` and `mean_rssi`.
  Every selected value must exist and be finite for every required node.
- `expected_profiles`: a dictionary keyed by string node ID, containing the
  exact result of `shadow_join.profile_identity(node)` for each admitted
  observation. This binds collector radio diagnostics and worker run/config/
  clock/grid identity. Unknown native profiles may remain explicitly null;
  they are not qualified native evidence.
- `max_lag_seconds`: positive and at most 1.5; default 1.5.
- `max_clock_disagreement_ms`: from zero through 500; default 100. UTC receipt
  difference must agree with the shared monotonic difference within this bound.

The adapter rechecks the reference export's examples hash, each retained source
prefix and capture metadata hash. It also rechecks the journal metadata hash,
configuration identity, run/row order and complete-prefix hashes. An unfinished
active line is excluded; a closed part must match its complete hash. The journal
is streamed, and verification completes before any output is written. Generated
examples, original and joined contracts, prefix receipts, targets and receiver
identities are private data.

Only an earlier observation may join. Gaps, unavailable nodes, missing values,
profile changes and clock-epoch changes are exclusions. The adapter never falls
back to an older apparently healthy sample across a newer invalid observation.
Normal `bounded_history_renewal` node epochs are permitted; other node epoch
changes require a new reviewed segment/binding. Epochs and discontinuities are
preserved in each example's lineage. A profile change never silently changes a
model's feature contract.

The output has a distinct `full_node_features_same_boot_shadow_join` contract,
with original reference and full-journal lineage. Its feature interval begins at
the earlier feature observation and ends at the existing reference boundary.
Active prefixes remain explicitly provisional; their receipt is useful for
bounded shadow fitting, but does not replace final terminal/hash validation.
The downstream trainer still enforces the chronological split and untouched
holdout. No joined data, model or profile is automatically published to HA.
