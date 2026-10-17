# Reference capture and inference

These tools support CSI capture, independent reference sessions, clock alignment,
zone annotation, model fitting and held-out evaluation. Coordinates and posture
need independently measured reference data; a schematic placement is not a
measurement. Possible-fall events are experimental outputs and require suitable
reference and evaluation before any accuracy claim.

```sh
python -m pip install -r inference/requirements.txt
python -m inference --help
python -m unittest discover -s inference/tests -v
```

Use an explicit coordinate frame, units and orientation. Record timestamp origin,
clock offset/uncertainty, receiver identity and sample completeness. Reject
mismatched capture/reference identity, stale data, invalid numeric values and
unapproved artifacts. Split evaluation by independent recording/session where
appropriate; do not treat repeated samples from one recording as independent
validation.

Model files and recordings are supplied by each installation and are not included
in this repository. No qualified posture, person-coordinate or fall-detection
model is distributed. A software test result cannot substitute for ground truth.
