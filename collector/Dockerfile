# Read the unchanged ARM64 runtime files without executing that architecture.
FROM --platform=linux/arm64 docker.io/ruvnet/wifi-densepose@sha256:29e6b4ce1893687de205324c509976c53911eff1abdfce3663256de3b82866d7 AS runtime-base

# Cross-build on amd64 for arm64. Keep the Bookworm cross sysroot compatible
# with the exact original runtime image rather than the build host's Ubuntu.
FROM --platform=linux/amd64 docker.io/library/rust@sha256:d99f7b31f49909348dc59b51f3c95d1efded1701ffb222f095aaab7de3c4abd8 AS toolchain
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260630T000000Z bookworm main' > /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu g++-aarch64-linux-gnu pkg-config cmake python3 \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add --toolchain 1.96.1 aarch64-unknown-linux-gnu
ENV RUSTUP_TOOLCHAIN=1.96.1 \
    CARGO_BUILD_JOBS=4 \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
RUN mkdir -p /tmp/openssl-arm64 /opt/ruview/openssl-arm64 \
 && cd /tmp/openssl-arm64 \
 && curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 -o libssl-dev.deb https://snapshot.debian.org/archive/debian/20260630T000000Z/pool/main/o/openssl/libssl-dev_3.0.20-1~deb12u1_arm64.deb \
 && curl --fail --location --retry 3 --connect-timeout 15 --max-time 120 -o libssl3.deb https://snapshot.debian.org/archive/debian/20260630T000000Z/pool/main/o/openssl/libssl3_3.0.20-1~deb12u1_arm64.deb \
 && printf '%s\n' '4b80f806af6d297bd9a9771e322c35f040fc473d3afc9cb438412aa17bebcca0  libssl-dev.deb' 'ddee5dde4e755bbefc894ee5776440f30ba6681443124b339140694eac643b6a  libssl3.deb' | sha256sum --check \
 && for package in *.deb; do dpkg-deb --extract "$package" /opt/ruview/openssl-arm64; done \
 && sha256sum *.deb > /opt/ruview/openssl-arm64/packages.sha256 \
 && dpkg-deb --field libssl-dev*.deb Version > /opt/ruview/openssl-arm64/version \
 && rm -rf /tmp/openssl-arm64
# Target-specific pkg-config isolation; native test compilation keeps its
# ordinary amd64 library search path. The cross compiler selects arm64 headers.
ENV PKG_CONFIG_ALLOW_CROSS_aarch64_unknown_linux_gnu=1 \
    PKG_CONFIG_LIBDIR_aarch64_unknown_linux_gnu=/opt/ruview/openssl-arm64/usr/lib/aarch64-linux-gnu/pkgconfig \
    PKG_CONFIG_SYSROOT_DIR_aarch64_unknown_linux_gnu=/opt/ruview/openssl-arm64 \
    CFLAGS_aarch64_unknown_linux_gnu=-I/opt/ruview/openssl-arm64/usr/include/aarch64-linux-gnu

FROM toolchain AS build
WORKDIR /source/v2
COPY source/ /source/
RUN cargo tree --locked -p wifi-densepose-sensing-server --features mqtt --target aarch64-unknown-linux-gnu --edges normal,build --prefix none --format '{p} features=[{f}]' \
 && cargo tree --locked -p wifi-densepose-sensing-server --features mqtt --target x86_64-unknown-linux-gnu --edges normal,build,dev --prefix none --format '{p} features=[{f}]'
RUN cargo test --locked -j 4 -p wifi-densepose-sensing-server --bin sensing-server --features mqtt grid_gate:: \
 && cargo test --locked -j 4 -p wifi-densepose-sensing-server --bin sensing-server --features mqtt raw_csi_mirror:: \
 && cargo test --locked -j 4 -p wifi-densepose-sensing-server --bin sensing-server --features mqtt bootstrap_vital_publication_tests:: \
 && cargo test --locked -j 4 -p wifi-densepose-sensing-server --bin sensing-server --features mqtt calibration_expiry_tests:: \
 && cargo test --locked -j 4 -p wifi-densepose-sensing-server --lib --features mqtt security_boundaries:: \
 && cargo test --locked -j 4 -p wifi-densepose-sensing-server --lib --features mqtt rufield_surface:: \
 && python3 /source/ruview-dependencies/test_ring_policy.py target/debug/deps \
 && cargo build --locked -j 4 --release --target aarch64-unknown-linux-gnu -p wifi-densepose-sensing-server --bin sensing-server --features mqtt \
 && aarch64-linux-gnu-readelf -h target/aarch64-unknown-linux-gnu/release/sensing-server \
 && aarch64-linux-gnu-strip target/aarch64-unknown-linux-gnu/release/sensing-server \
 && python3 /source/ruview-dependencies/bundle_licenses.py --workspace /source/v2 \
      --output /source/ruview-dependencies/binary-licenses \
      --project-notices /source/ruview-dependencies/project-notices
COPY --from=runtime-base /usr/share/doc/libc6/copyright /source/ruview-dependencies/binary-licenses/runtime-libraries/libc6-copyright
COPY --from=runtime-base /usr/share/doc/gcc-12-base/copyright /source/ruview-dependencies/binary-licenses/runtime-libraries/libgcc-s1-copyright
RUN cd /source/ruview-dependencies/binary-licenses/runtime-libraries \
 && sha256sum libc6-copyright libgcc-s1-copyright > SHA256SUMS

# Reuse the original UI, entrypoint, libraries and auxiliary binaries verbatim.
FROM runtime-base
COPY --from=build /source/v2/target/aarch64-unknown-linux-gnu/release/sensing-server /app/sensing-server
COPY --from=build /source/ruview-dependencies/licenses/ring/ /app/licenses/ring/
COPY --from=build /source/ruview-dependencies/ring-policy-receipt.json /app/ring-policy-receipt.json
COPY --from=build /source/ruview-dependencies/binary-licenses/ /app/licenses/collector/
LABEL org.opencontainers.image.revision="7c8aeacea2ad30972070196eb7d8e7200506b742" \
      org.opencontainers.image.version="0.3.5-home-grid.2" \
      io.ha-homelab.ruview.patch="collector/patches/0001-expire-csi-grid.patch,collector/patches/0002-raw-csi-mirror.patch,collector/patches/0003-security-boundaries.patch"
