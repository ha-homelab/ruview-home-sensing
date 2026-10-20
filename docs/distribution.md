# Reproducible distribution and private consumption

The source/tool archive is the supported distribution for firmware, native workers, CAD preparation and operator tools that require sibling files. A wheel additionally provides the Python libraries and `ruview-inference`, `ruview-radar`, `ruview-wisp` and `ruview-activity` entrypoints. The wheel is not a firmware source bundle.

## Build the exact reviewed source

```sh
python scripts/build-release.py --revision "$REVIEWED_COMMIT" --output ruview-home-sensing-tools.tar.gz
python -m pip wheel --no-deps --wheel-dir dist .
python scripts/test-installed-wheel.py dist/ruview_home_sensing-0.4.0rc2-py3-none-any.whl
```

`REVIEWED_COMMIT` must be an exact 40-character Git commit. The archive builder reads committed blobs only, rejects links/submodules, records SHA-256, size and mode for every file, and writes fixed archive timestamps and ownership. Local untracked inputs and Git history are never included. Run the repository publication gate against both source and generated artifacts before upload. Build the wheel from a clean checkout; set `SOURCE_DATE_EPOCH` consistently when comparing reproducibility.

The archive includes `RELEASE-MANIFEST.json` with the public repository, exact revision and file inventory. A consumer independently reviews and pins the archive digest, then validates the manifest and all member bytes before extraction or execution. A tag or manifest downloaded alongside an unpinned archive is not independent approval. Reject unexpected members, links, traversal paths, oversized files and modified extracted caches.

Install the existing public bridge from its separately pinned distribution. This repository contains compatibility imports, not a second bridge implementation. The current dependency is the digest-pinned v0.1.2 release, including its verified TLS context. The installed-adapter check verifies the wheel identity and compatibility imports; future upgrades need the same integration checks.

## Installation data stays outside the distribution

A consumer keeps its Terraform root, release lock, signed-module approvals, coordinate data, identities, device credentials and observations separately. It invokes tools from the verified release instead of copying them back into its source tree. Generated UI contexts, device firmware, measurements and deployment receipts are private derived artifacts and are not public release inputs.

Installation identity v2 requires an independently pinned `policy` object containing `fleet_size`, `receiver_ids`, `receiver_versions`, `restore_image_sha256` and `wasm_public_key_hex`. Every receiver has an explicit firmware allowlist. Candidate inventory does not supply policy defaults. Generic protocol bounds and strict private-file permissions remain enforced independently of the policy.

The coverage producer takes `--package-directory` explicitly and verifies package bytes against its independently approved module manifest. Public archives contain no production-signed module defaults. The UI preparer likewise requires explicit pinned model, profile and site-context inputs and writes its private build context outside the checkout.

A release provides software mechanisms and synthetic test evidence. It does not establish calibrated coordinates, pose accuracy, reliable fall detection or physical enclosure fit for a particular installation.

## Release status and shared CI

CI reuses the pinned shared Python setup and security workflow while the project validates its own runtime, firmware, CAD and distribution contracts on GitHub-hosted runners. The full shared release-promotion engine is not installed. There is no automatic stable publication or promotion.

The initial source candidate is a prerelease: its tools archive and wheel are bound to one reviewed immutable commit and their published SHA-256 inventory. A stable release requires a separate reviewed decision and artifact acceptance. Adopting shared signing, SBOM and promotion automation later must preserve the exact source-archive contract, public-data gate and hosted-runner boundary.

## Version notes

Each published version includes human-readable release notes covering user-visible changes, compatibility or migration requirements, known limitations and applicable security fixes. Include assigned CVE/GHSA or equivalent identifiers for fixed vulnerabilities when available. Link the notes to the immutable source revision and the published artifact inventory. Release notes do not imply stable promotion or physical-device acceptance.
