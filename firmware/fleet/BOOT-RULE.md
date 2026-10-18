# First-attempt boot selection: ESP-IDF 5.4

The immutable firmware builder is
`espressif/idf:v5.4@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb`.
Its cached metadata names the `v5.4` clone tag, but that alone does not prove the
actual build's Git revision. The primary upstream annotated tag resolves through
`8e27ea72c6688b79348b123ff40d556cfe16c8c3` to commit
`67c1de1eebe095d554d281952fde63c16ee2dca0`. The executor requires that actual
builder revision, exported source bytes, successful build evidence and exact
bootloader/table/sdkconfig hashes; it does not infer them from a tag.

Primary sources, retained unchanged under `boot-rule-reference/` with their
Apache-2.0 license, are inspection data and are never compiled by fleet tooling:

- [bootloader_common_loader.c](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/components/bootloader_support/src/bootloader_common_loader.c),
  SHA-256 `b036254d126187fcfcc4a630e6b21658afeaa93e30456576ab62e856a9204c24`.
- [bootloader_utility.c](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/components/bootloader_support/src/bootloader_utility.c),
  SHA-256 `5ae38992cce9e7a9f919a9923bf6acbbf6f74a24d4f4c13ce3cf6c488cbe8401`.
- [bootloader_start.c](https://github.com/espressif/esp-idf/blob/67c1de1eebe095d554d281952fde63c16ee2dca0/components/bootloader/subproject/main/bootloader_start.c),
  SHA-256 `02825e360f143711c497b539ad734eab9b38e067f9c0accd9147f8bbe466a7c1`.

The reviewed branch is narrow. Both erased OTA selection entries have sequence
`UINT32_MAX`, so `bootloader_common_ota_select_invalid` rejects them. With
anti-rollback disabled and no factory application, the utility chooses index 0.
The exact six-partition table maps that to `ota_0` at `0x20000`; image loading
first tries that partition. Factory-reset, test-application and validation-skip
overrides are excluded by the executor, alongside the planner's existing security
and rollback configuration restrictions.

This proves the first attempted partition under the reviewed source/configuration,
not physical boot success. If image verification/loading fails, the bootloader
can try other partitions. On successful loading from initial erased metadata,
`set_actual_ota_seq` writes an actual sequence and valid state to OTA data.
Therefore full write/complement verification happens **before** the separate
explicit first boot. Later OTA metadata and NVS changes cannot be compared to
the pre-boot image as if they were unchanged.

The inactive application is not prepared or qualified, and automatic bootloader
rollback remains disabled. Retained reference files are not evidence that a
particular executable used them: review the actual builder source and artifact
receipt before creating the private executor wrapper. Tests use synthetic flash
and mocked image inspection; no installed-board qualification follows.
