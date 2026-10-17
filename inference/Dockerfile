FROM --platform=linux/amd64 python:3.13-alpine@sha256:ba27df8b6499cc3756cff167690f3fcb5321faa1703b3a914df5f4fdadb32f05

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONNOUSERSITE=1 \
    OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

WORKDIR /app
COPY inference/requirements-image.txt /app/inference/requirements-image.txt
RUN python -m pip --isolated install --no-cache-dir --no-compile \
    --disable-pip-version-check --index-url https://pypi.org/simple \
    --require-hashes --only-binary=:all: --no-deps \
    -r /app/inference/requirements-image.txt

# Explicit public code/fixture copies; no repository config, recordings or keys.
COPY inference/*.py /app/inference/
COPY inference/tests/*.py /app/inference/tests/
COPY scripts/reference_clock.py /app/scripts/reference_clock.py
COPY server-modules/tests/fixtures/capture-v2.synthetic.json /app/server-modules/tests/fixtures/capture-v2.synthetic.json

# Cache both tested Python modes during the build, never at runtime.
# Private build contexts may contain mode-0700 directories; this is public code.
RUN umask 022 && python -m compileall -q -f -j 2 -o 0 -o 1 \
    --invalidation-mode checked-hash \
    /usr/local/lib/python3.13 /app \
    && chmod -R a+rX /app

USER 10001:10001
ENTRYPOINT ["python"]
CMD ["-m", "inference", "--help"]
