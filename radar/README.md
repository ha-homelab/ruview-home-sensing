# LD2450 input

The optional LD2450 adapter decodes bounded radar target frames and applies an
explicitly configured coordinate transform. `configuration.template.json` and
`fleet.template.json` are fictional templates, not deployment configuration.

```sh
python -m radar --help
python -m unittest discover -s radar/tests -v
```

Check the exact module's electrical interface before wiring. Radar measurements
must retain their source, time and frame; do not relabel them as CSI-derived
measurements. Installation coordinates and target recordings remain private.
