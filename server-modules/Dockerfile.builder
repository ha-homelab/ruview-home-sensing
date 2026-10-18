# Supply an immutable official rust:1.96.1-bookworm manifest digest.
# Record the resulting architecture-specific image ID before running build.sh.
ARG RUST_IMAGE
FROM ${RUST_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 binutils \
    && dpkg-query -W > /builder-packages.txt \
    && rm -rf /var/lib/apt/lists/*
