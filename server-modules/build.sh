#!/usr/bin/env bash
# Use a native Linux builder whose immutable image ID has been recorded.
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo "Usage: build.sh PREPARED_SOURCE CARGO_CACHE NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
source_directory=$(cd "$1" && pwd)
cargo_cache=$(cd "$2" && pwd)
output_directory=$3
jobs=${CARGO_BUILD_JOBS:-4}
case "$jobs" in 1|2|3|4) ;; *) echo "One to four compilation jobs required" >&2; exit 2 ;; esac
if [ -e "$output_directory" ]; then
  echo "Output directory must be new; preserve earlier evidence" >&2
  exit 2
fi
mkdir -p "$output_directory"
output_directory=$(cd "$output_directory" && pwd)
builder=${RUVIEW_BUILDER_IMAGE:-sha256:702459bcb555314df1b5ae98665c731214ff3b2c2809a1ee34fa626e3dca2ac6}
if [[ ! "$builder" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "RUVIEW_BUILDER_IMAGE must be an immutable local image ID" >&2
  exit 2
fi
docker image inspect "$builder" --format '{{.Id}}' > "$output_directory/builder-image.txt"
docker image inspect "$builder" > "$output_directory/builder-inspect.json"
docker run --rm --network=none --cpus="$jobs" \
  -e CARGO_HOME=/cargo -e CARGO_BUILD_JOBS="$jobs" -e RUST_TEST_THREADS=1 \
  -v "$source_directory:/src" -v "$cargo_cache:/cargo" -v "$output_directory:/out" \
  -w /src/worker "$builder" bash -euc '
    date -u +%Y-%m-%dT%H:%M:%SZ > /out/started-at.txt
    rustc --version --verbose > /out/rustc.txt
    cargo --version > /out/cargo.txt
    python3 -m unittest discover -s tests -v > /out/preparation-tests.log 2>&1
    python3 -O -m unittest discover -s tests -v >> /out/preparation-tests.log 2>&1
    cargo test --manifest-path ../upstream/Cargo.toml --target-dir target --locked --offline --no-default-features --features std --lib sec_tailgating::tests > /out/tailgating-native-tests.log 2>&1
    cargo test --locked --offline --all-targets > /out/tests.log 2>&1
    cargo build --locked --offline --release > /out/build.log 2>&1
    python3 tests/service_smoke.py target/release/ruview-server-modules /out/service-smoke
    python3 tests/fleet_service_smoke.py target/release/ruview-server-modules /out/fleet-service-smoke
    python3 tests/capture_service_smoke.py target/release/ruview-server-modules /out/capture-service-smoke --uid 10001
    python3 package-runtime.py target/release/ruview-server-modules /out/runtime
    cp Cargo.lock provenance.json /out/
    date -u +%Y-%m-%dT%H:%M:%SZ > /out/finished-at.txt
  ' > "$output_directory/build-driver.log" 2>&1
echo "Verified build output: $output_directory"
