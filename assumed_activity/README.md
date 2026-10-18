# Activity hypotheses

The activity service combines configured receiver evidence with temporal
confirmation. Its output is an activity hypothesis. It does not infer a verified
person count, pose, or measured coordinate.

Configuration is explicit. Network operations have deadlines, source snapshots
must agree, and stale observations withdraw prior hypotheses. State persistence
is bounded and must not revive expired evidence after restart. Receiver labels
and geometry are supplied by the installation and stay private.

```sh
python -m unittest discover -s assumed_activity/tests -v
python -m assumed_activity --help
```
