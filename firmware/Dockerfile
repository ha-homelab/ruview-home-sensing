ARG IDF_IMAGE=espressif/idf:v5.4@sha256:f1e9f69dc052b9afc7801ca884e0ef40c17e014bb05ce73d9c09d29290bd17fb
FROM ${IDF_IMAGE} AS build
SHELL ["/bin/bash", "-c"]
WORKDIR /project
COPY source/ ./
COPY fleet-build/ /fleet-build/
ARG FIRMWARE_PROFILE=home-s3-n16r8
ARG PREFERRED_AP_SHA256
# The secret is required only in the legacy profile, before any source fetch.
RUN --mount=type=secret,id=preferred_ap,target=/run/secrets/preferred_ap,mode=0400 \
    case "$FIRMWARE_PROFILE" in \
      home-s3-n16r8|fleet-reviewed) ;; \
      node2-preferred-ap) python3 /fleet-build/build_profile.py check-preferred /run/secrets/preferred_ap "$PREFERRED_AP_SHA256" || exit 1 ;; \
      *) echo 'Unknown firmware profile' >&2; exit 1 ;; \
    esac && \
    git init components/wasm3/wasm3-src && \
    git -C components/wasm3/wasm3-src remote add origin https://github.com/wasm3/wasm3.git && \
    git -C components/wasm3/wasm3-src fetch --depth 1 origin 6b8bcb1e07bf26ebef09a7211b0a37a446eafd52 && \
    git -C components/wasm3/wasm3-src checkout --detach FETCH_HEAD
COPY sdkconfig.home-s3-n16r8 ./
COPY vendor/monocypher/ components/monocypher/
COPY patches/ /patches/
COPY home_wasm_pubkey.h main/
RUN git apply /patches/*.patch && \
    if [ "$FIRMWARE_PROFILE" = fleet-reviewed ]; then \
      python3 /fleet-build/build_profile.py configure /fleet-build /project; \
    else printf "0.8.8.8\n" > version.txt; fi
# Pin the only managed component needed on a display-less board.
RUN printf 'dependencies:\n  espressif/led_strip: "3.0.1"\n' > main/idf_component.yml
RUN --mount=type=secret,id=preferred_ap,target=/run/secrets/preferred_ap,mode=0400 \
    if [ "$FIRMWARE_PROFILE" = node2-preferred-ap ]; then \
      python3 /fleet-build/build_profile.py configure-preferred /run/secrets/preferred_ap "$PREFERRED_AP_SHA256" /project || exit 1; \
    fi && \
    . /opt/esp/idf/export.sh && \
    defaults='sdkconfig.defaults;sdkconfig.defaults.devkitc;sdkconfig.home-s3-n16r8' && \
    case "$FIRMWARE_PROFILE" in \
      home-s3-n16r8) ;; \
      node2-preferred-ap) defaults="$defaults;sdkconfig.home-node2-preferred-ap" ;; \
      fleet-reviewed) defaults="$defaults;sdkconfig.fleet-reviewed" ;; \
      *) echo 'Unknown firmware profile' >&2; exit 1 ;; \
    esac && \
    idf.py -D SDKCONFIG_DEFAULTS="$defaults" set-target esp32s3 && \
    grep -q '^CONFIG_WASM_ENABLE=y$' sdkconfig && \
    grep -q '^CONFIG_ESP_WIFI_STATIC_TX_BUFFER=y$' sdkconfig && \
    grep -q '^CONFIG_ESP_WIFI_TX_BUFFER_TYPE=0$' sdkconfig && \
    grep -q '^CONFIG_HOME_CSI_ASSOCIATED_ONLY=y$' sdkconfig && \
    if [ "$FIRMWARE_PROFILE" = node2-preferred-ap ]; then \
      python3 /fleet-build/build_profile.py verify-preferred /run/secrets/preferred_ap "$PREFERRED_AP_SHA256" /project/sdkconfig; \
    elif [ "$FIRMWARE_PROFILE" = fleet-reviewed ]; then \
      python3 /fleet-build/build_profile.py verify /fleet-build /project/sdkconfig; \
    else \
      ! grep -q '^CONFIG_HOME_WIFI_PREFERRED_AP_ENABLE=y$' sdkconfig; \
    fi && \
    if [ "$FIRMWARE_PROFILE" != fleet-reviewed ]; then \
      ! grep -q '^CONFIG_HOME_RUNTIME_RECOVERY_V1=y$' sdkconfig; \
    fi && \
    python3 -c 'import json; c=json.load(open("build/compile_commands.json")); assert any(x["file"].endswith("/main/wasm_runtime.c") and "-DWASM3_AVAILABLE=1" in x["command"] for x in c), "WASM3 must be linked into the real runtime"' && \
    cmake --build build --parallel 2 && \
    mkdir /out && cp build/esp32-csi-node.bin build/esp32-csi-node.elf build/esp32-csi-node.map build/bootloader/bootloader.bin build/partition_table/partition-table.bin build/ota_data_initial.bin build/flasher_args.json sdkconfig dependencies.lock /out/ && \
    cp build/compile_commands.json /out/ && \
    cp /opt/esp/idf/tools/tools.json /out/IDF_TOOLS.json && \
    (git -C /opt/esp/idf rev-parse HEAD && \
     idf.py --version && xtensa-esp-elf-gcc --version && \
     cmake --version && ninja --version && python --version) > /out/BUILD_TOOLS.txt && \
    if [ "$FIRMWARE_PROFILE" = fleet-reviewed ]; then \
      cp /fleet-build/profile.json /fleet-build/sdkconfig.fleet-reviewed /fleet-build/build_profile.py version.txt /out/ && \
      (cd /out && sha256sum profile.json sdkconfig.fleet-reviewed build_profile.py version.txt sdkconfig > BUILD_PROFILE_SHA256SUMS.txt); \
    fi && \
    mkdir -p /out/licenses && \
    cp /project/licenses/RuView-LICENSE /out/licenses/RuView-LICENSE && \
    cp /project/components/monocypher/LICENCE.md /out/licenses/Monocypher-LICENCE.md && \
    cp /project/components/wasm3/wasm3-src/LICENSE /out/licenses/WASM3-LICENSE && \
    cp /opt/esp/idf/LICENSE /out/licenses/ESP-IDF-LICENSE && \
    (cd /out && sha256sum ./*.bin ./*.elf ./*.map > SHA256SUMS.txt) && \
    rm -f /project/sdkconfig.home-node2-preferred-ap
FROM scratch AS artifacts
COPY --from=build /out/ /
