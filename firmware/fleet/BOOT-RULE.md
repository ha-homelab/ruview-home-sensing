# First-attempt boot selection: ESP-IDF 5.4.4

The immutable firmware builder is
`espressif/idf:v5.4.4@sha256:9ce51d4ace496845678065dc86f8e55fb9c25fc9f01f45597042afa7ed546926`.
The upstream `v5.4.4` tag resolves to commit
`296b6eab9445fd720e71aecab961e2d3fbca9944`. The executor requires that actual
builder revision, exported source bytes, successful build evidence and exact
bootloader/table/sdkconfig hashes; it does not infer them from a tag.

The 2026-10-19 source review compared the three files below with the previous
5.4 reference. The bootloader utility and OTA selection logic are unchanged.
The other changes add explicit headers and correct RTC retained-memory
alignment and target-specific placement. They do not change the reviewed
no-factory, erased-OTA-data first-attempt rule. A receipt from the previous
builder cannot be reused for this version.

Primary sources, retained unchanged under `boot-rule-reference/` with their
Apache-2.0 license, are inspection data and are never compiled by fleet tooling:

- [bootloader_common_loader.c](https://github.com/espressif/esp-idf/blob/296b6eab9445fd720e71aecab961e2d3fbca9944/components/bootloader_support/src/bootloader_common_loader.c),
  SHA-256 `24e78c681997257648a66673d78f923e8b91c087c6f8f7edddd9a78ec56c1981`.
- [bootloader_utility.c](https://github.com/espressif/esp-idf/blob/296b6eab9445fd720e71aecab961e2d3fbca9944/components/bootloader_support/src/bootloader_utility.c),
  SHA-256 `5ae38992cce9e7a9f919a9923bf6acbbf6f74a24d4f4c13ce3cf6c488cbe8401`.
- [bootloader_start.c](https://github.com/espressif/esp-idf/blob/296b6eab9445fd720e71aecab961e2d3fbca9944/components/bootloader/subproject/main/bootloader_start.c),
  SHA-256 `b9be53d67dd3b319f8bba3474e605e6cf867e11515240e79cd7282e4a7c7a08f`.

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
