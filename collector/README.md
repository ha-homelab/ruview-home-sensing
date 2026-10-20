# CSI collector

`source-lock.json` pins upstream source, lockfile checksums and submodule commits.
`prepare-source.py` verifies a clean checkout and applies the local patches.
The patches expire stale CSI grids, mirror raw samples with bounded queues,
confine recording names, and replace the public default RuField signing key.

Recording IDs contain at most 128 ASCII letters, digits, `.`, `_` or `-`,
excluding `.` and `..`. New files are created exclusively and with mode 0600
on Unix. The recordings directory and its parents must be operator-controlled;
this does not make an attacker-writable directory safe.

`WDP_RUFIELD_SIGNING_SEED` accepts exactly 64 hexadecimal characters or 32 raw
bytes. Invalid, all-zero or the former public default seed stops startup.
When the variable is absent, the OS random generator creates an ephemeral
Ed25519 identity. Its public key changes after restart: provision a private,
random seed if consumers require a stable identity. There is no fallback to
the public development key or weak random data if OS randomness fails.

```sh
python collector/prepare-source.py /tmp/ruview-collector-source
sh collector/test-grid.sh
node --test collector/ui/tests/*.test.mjs
```

The UI health service retries recoverable failures and distinguishes stale data
from an active connection. Receiver-map colors describe CSI freshness, not a
person's measured location. `ui/home-floor/home-floor.js.in` is a generic template;
geometry and labels are supplied outside this repository. Operator-derived UI
images containing site configuration must remain private.
