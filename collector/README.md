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

The collector also applies a pinned, one-condition policy correction to
`ring` 0.17.14. Upstream rounded the RSA modulus length up to whole bytes
before checking its advertised 2048-bit minimum, accepting 2041–2047 bits.
The local patch compares the actual bit length. Signature algorithms, the
maximum length and exponent validation are unchanged. The registry still
listed 0.17.14 as the latest release on 2026-10-19.

`ring-policy/source.json` authenticates the original crate, changed source
and original workspace manifest/lockfile. Preparation adds a path override
without changing any package version. The build runs both RSA PKCS#1 and
RSA-PSS verification against each actual compiled native `ring` library:
2040/2041/2047-bit keys must fail, 2048-bit keys must pass, and modified
messages must fail. The fixtures contain public keys and signatures only.
The full collector build remains necessary to qualify integration.
The unchanged dependency lifetime-syntax warnings have a
[separate source-specific disposition](../docs/ring-policy.md).

The generated `ruview-dependencies` directory contains the patched source,
five original license notices and `ring-policy-receipt.json`. The main
Dockerfile copies the notices and receipt into the runtime image. If using
`Dockerfile.runtime` with an already built binary, its context must also
contain `ring-licenses/` copied from `ruview-dependencies/licenses/ring/`
and the corresponding receipt. Distribute these files with standalone
collector binaries. An offline preparation additionally requires
`--ring-archive /path/to/ring-0.17.14.crate`; the same digest check applies.

The build also gathers the original license and notice files for every package
in the selected ARM64 Cargo `normal,build` graph. It reads the already fetched,
locked sources without downloading unrelated workspace packages. Registry
archive hashes are checked against `Cargo.lock`, then original notice files are
read from those verified bytes; local crates retain their own or inherited
repository notices. Missing notices fail the build.
For the sixteen locked crates whose published archive omitted license files,
`license-overrides/sources.json` ties recovered original texts to the archive
checksum and the upstream Git revision embedded in that archive. The recovery
is exact-version only and does not change the crate's declared license. For
`anndists`, the original README expressly offers Apache-2.0 but the upstream
commit omits its referenced license file; the bundle preserves that README
and the official Apache-2.0 terms it links.
The bundle includes the project's notices, the selected Rust toolchain's
copyright collection, and the original Debian copyright files for the linked
`libc6` and `libgcc-s1` runtime libraries. Build-only packages and toolchain
notices are included conservatively; this does not mean all their code is linked.

Keep the complete `/app/licenses/collector/` directory beside a distributed
`sensing-server` binary. For `Dockerfile.runtime`, copy this directory from the
qualified image or artifact into the build context as `collector-licenses/`.
`index.json` records the Cargo package versions, declared license expressions,
source manifest hashes and delivered notice hashes. Runtime library notice
hashes are recorded separately in `runtime-libraries/SHA256SUMS`.

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
