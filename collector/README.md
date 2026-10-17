# CSI collector

`source-lock.json` pins upstream source, lockfile checksums and submodule commits.
`prepare-source.py` verifies a clean checkout and applies the local patches.
The patches expire stale CSI grids and mirror raw samples with bounded queues.

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
