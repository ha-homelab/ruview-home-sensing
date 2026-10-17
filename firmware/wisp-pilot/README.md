# Wisp ESP32-S3 pilot build recipe

This recipe prepares a **separate spare-board pilot**. It does not replace the
existing RuView receivers, alter their OTA route, or install a Home Assistant
integration. The accompanying [pilot guide](../../docs/wisp-pilot.md) describes
the recording boundary and the evidence still needed before integration.

The source pin is Wisp **0.1.20**, commit
`56813ac91a0fe696dae20e1fec468d33fc1e60ed`. Its
[firmware workflow](https://github.com/albert-canfield/wisp/blob/56813ac91a0fe696dae20e1fec468d33fc1e60ed/.github/workflows/firmware.yml)
uses ESPHome **2026.9.1**. Pinning these inputs supports repeatable preparation;
it does not make Python's transitive dependencies or produced firmware
bit-reproducible. Save the resolved environment and build logs with each artifact.

## Prepare outside Git

Create a private, empty directory outside all checkouts and enter it. The
commands below only fetch source and prepare the build; they never contact a
receiver. The script path refers to this repository's preparation helper.

```sh
umask 077
git init source
git -C source remote add origin https://github.com/albert-canfield/wisp.git
git -C source fetch --depth 1 origin 56813ac91a0fe696dae20e1fec468d33fc1e60ed
git -C source checkout --detach FETCH_HEAD
test "$(git -C source rev-parse HEAD)" = 56813ac91a0fe696dae20e1fec468d33fc1e60ed
test -z "$(git -C source status --porcelain)"
python3 /path/to/ruview-home-sensing/firmware/wisp-pilot/prepare.py \
  --source source --output pilot-inputs.tar
mkdir build
tar -xf pilot-inputs.tar -C build
cd build
python3.13 -m venv .venv
.venv/bin/python -m pip install 'esphome==2026.9.1'
.venv/bin/python -m pip freeze > resolved-environment.txt
```

The helper performs no network or device operations. It refuses a source at
another commit or with tracked/untracked changes. It packages only the pinned
component, its license, the local template and a manifest with every input's
SHA-256. It rejects symlinks and unexpected archive paths, fixes archive metadata
for deterministic output, and atomically creates a new mode-`0600` archive.
The output parent must already be private and outside any Git checkout; existing
files are never overwritten. The supplied path must not traverse symlinks
(on macOS, use the resolved `/private/tmp/...` rather than `/tmp/...`).

Review and create `secrets.yaml` with mode `0600` in the same private directory.
It must contain `wifi_ssid`, `wifi_password`, `wifi_bssid`, `api_encryption_key`, `ota_password`
and an integer `grid_channel`. Use independently selected credentials and the
reviewed channel shared by the pilot receivers. For a US deployment select
**1, 6 or 11** with an AP serving that channel; the component accepts additional
values, so operator review still matters. The API key is a base64-encoded
32-byte key; the OTA password is a separate strong secret. Never commit this
file, resolved configuration, credentials, build output or captures.

```sh
.venv/bin/esphome config node-esp32s3.yaml > validated-config.log 2>&1
ESPHOME_DEFAULT_COMPILE_PROCESS_LIMIT=2 \
  .venv/bin/esphome compile node-esp32s3.yaml > build.log 2>&1
```

Keep logs private even if the tool normally masks secrets. Record the template
digest, source commit and clean-tree check, resolved environment, resulting
factory/OTA artifact hashes and board identity before any later upload. A
successful configuration check is not a successful compile; a successful
compile is not evidence of RF behavior or hardware compatibility.

## Intentional differences from upstream defaults

The template uses only the local, verified Wisp component; it does not import
the upstream `base.yaml`, dashboard adoption package or mutable `main` branch.
It has no public update manifest, HTTP OTA, web server or fallback hotspot. It
keeps encrypted ESPHome API and password-protected ESPHome OTA available for
later deliberate operation. Neither has to connect for the UDP pilot to run;
the no-client reboot timer is disabled. ESPHome API encryption does **not**
authenticate Wisp's UDP reports, so the pilot network must remain trusted.

The selected grid channel and intended AP BSSID are explicit in the WiFi
configuration. The same channel is supplied to the Wisp component. Wisp and
ESPHome have their own reconnection logic, so configuration alone is not proof
of the actual association: check the reported channel, BSSID and RSSI after
every placement change and mark a mismatched association invalid for comparison.
A separate pilot SSID/AP avoids changing the radio
conditions of the existing RuView comparison.

Raw CSI starts off on every boot. Turn on **Pilot raw CSI stream** through the
encrypted API only for an explicitly scheduled raw capture, then turn it off.
Link reports are available without that switch. Experimental breathing and FTM
are not enabled. They are not substitutes for pose or fall validation.

The S3 recipe retains upstream's conservative **4 MB flash layout without
PSRAM**, including on an N16R8 board. It does not claim to use the board's full
16 MB flash or 8 MB PSRAM. Confirm chip model, flash capacity, supply stability
and the LED pin on each spare before flashing. GPIO48 drives the documented
S3 board's WS2812; this template commands that LED off after startup, excludes
the status animation and provides no identify strobe. It cannot guarantee the
power-on behavior of another board's LED circuit.

## First installation and later OTA

The first Wisp installation on a spare requires the correctly identified USB
device and a factory image. **Do not send this image to RuView's signed OTA
endpoint.** The two applications have different update contracts and state.
No flash command is run by this recipe, and no existing board is selected by
serial-port guessing. Keep the native-USB/COM distinction in the
[pinned upstream setup guide](https://github.com/albert-canfield/wisp/blob/56813ac91a0fe696dae20e1fec468d33fc1e60ed/docs/SETUP.md)
in mind when locating logs.

After a separately performed first installation, ESPHome OTA can update that
pilot receiver using its private password and the matching OTA image. A device
must run the new image for at least **60 seconds** before power interruption
so ESPHome can confirm it. Check boot completion, LED off, stable power, channel,
station MAC and an actual UDP recording before considering the board accepted.
Changing firmware also requires a new recording provenance entry. Do not
silently combine pre-update and post-update evidence.

The upstream Wisp component is MIT licensed by Albert Canfield. Its checked-out
`LICENSE` must accompany redistributed source or substantial copied portions.
This repository fetches the component rather than vendoring it. Consult the
[ESPHome local-component documentation](https://esphome.io/components/external_components/),
[API encryption documentation](https://esphome.io/components/api/) and
[ESPHome OTA documentation](https://esphome.io/components/ota/esphome/) for the
configuration mechanisms; the reviewed version above remains the build pin.

## Software verification

The preparation helper has offline regressions for source pinning, dirty source,
archive traversal/symlinks, missing component/license, manifest hashes,
determinism and exclusive output. Run them without ESPHome or hardware:

```sh
python -m unittest discover -s firmware/wisp-pilot/tests -v
```

Build and runtime evidence are deployment-specific. Record fresh artifact hashes,
resolved tool versions, board identity and actual observations privately. Public
unit tests only establish software behavior under synthetic inputs.
