#!/bin/sh
set -eu
collector_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
rustc --edition 2021 --test "$collector_dir/src/grid_gate.rs" -o "$test_dir/grid-tests"
"$test_dir/grid-tests"
rustc --edition 2021 --test "$collector_dir/src/raw_csi_mirror.rs" -o "$test_dir/mirror-tests"
"$test_dir/mirror-tests"
rustc --edition 2021 --test "$collector_dir/src/security_boundaries.rs" -o "$test_dir/security-tests"
"$test_dir/security-tests"
