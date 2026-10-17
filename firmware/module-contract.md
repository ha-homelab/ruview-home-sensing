# Module event contracts

`validate-module-contract.py` checks an explicitly selected manifest against
actual RVF bytes and the static pinned upstream catalog. It verifies container
bounds, payload hash, name, capability mask, execution budget, source revision
and event-map completeness. It does not verify an Ed25519 signature, execute
WASM, prove emitted behavior, or qualify recognition accuracy.

```sh
python3 firmware/validate-module-contract.py \
  --manifest /private/proposed-modules.json \
  --package-directory /private/signed-modules
```

Every package must supply an explicit `event_map`. Source identities are
`(algorithm, event_id)` pairs, because different algorithms may reuse a numeric
ID. `wire_event_id` is an integer in 0..255 and must be unique within a package.
Every declared source event needs one mapping. `wire_event_ids` must match the
mapping; optional `package_event_ids` belong to the `$package` namespace.
Truncation or modulo conversion is never a valid mapping.

A matching map is a declaration. The tool does not infer acceptance from a
known binary name or hash, and it does not generate a remapping wrapper. An
independently approved deployment manifest must bind each immutable name to
its exact binary before restoration can be enabled.

The wire packet contains node, slot, byte event ID and value. A slot is not a
stable package identity; packets lack a package hash, boot identifier, sequence
and source timestamp. Bind decoding to fresh runtime evidence and the approved
installation manifest. Cached last-event polling does not prove a new event.

The runtime has four module slots, a 128 KiB binary limit, and a bounded event
buffer per callback. Callback time budgets are checked after return; they do
not preempt an infinite guest loop. Check real device memory and timing for
combined modules. Library catalog availability does not mean every algorithm
is compiled into an installed WASM package. Person coordinates, body pose and
fall detection need their own calibrated models and independent validation.
