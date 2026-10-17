# Independent fictional installation

These fixtures are written for offline tests, not transformed copies of an
installed site. They use the private test range `10.77.0.0/24`, locally
administered synthetic MAC addresses and three invented laboratory markers.
No operator command uses them as a default.

The four rectangles have centres `(1, 3)`, `(7, 3)`, `(4, 6)` and `(4, 3)`.
Receivers are at `(1, 1)`, `(7, 1)` and `(4, 5)`. With kernel radius 4, the
hand-derived inverse-weight denominators are `(20, 56, 29)`, `(56, 20, 29)`,
`(50, 50, 17)` and `(29, 29, 20)`. Tests check these numbers, reversed polygon
winding, boundary points, overlapping zones and the lack of occupancy claims.

The activity fixture duplicated under `assumed_activity/tests/fixtures` describes
the same fictional geometry. Its frozen output keeps the existing synthetic
time series, while hashes and weights are calculated from these explicit inputs.

`installation-identity.json` is a fixed, separate test approval. Mutating a
candidate inventory must not regenerate that approval. Invalid identities,
extra receivers, missing pins and altered context files must still fail closed.
The module tests retain the real public signed package hashes and the existing
device, capability, flash-attempt and restore restrictions.

The fleet settings golden uses this separately fixed fictional deployment
profile. Its raw-CSI mirror uses the TEST-NET sentinel `192.0.2.1:5015` from
the provider-free Terraform test, while allowed hosts come from this example
profile. Positions and target identities also use only this fictional
installation. The fleet suite checks the complete generated settings, targets
and positions against that golden. Original installation replays are preserved
privately outside Git; these fixtures do not approve a real deployment.
