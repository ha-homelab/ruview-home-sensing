# Pin per-architecture manifests: a legacy builder can reuse an amd64 cache
# entry when two FROM stages share the same multi-architecture index digest.
ARG DEPENDENCY_PLATFORM=linux/amd64
ARG DEPENDENCY_IMAGE=python:3.15-alpine@sha256:a943ed02f4e22d024d2b4fc5083619497dfb9bc1c64c193861f3bc6d3074f5b1
FROM --platform=${DEPENDENCY_PLATFORM} ${DEPENDENCY_IMAGE} AS dependencies
WORKDIR /app
COPY requirements.txt requirements-public.txt ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
    --platform any --target /dependencies -r requirements.txt

FROM --platform=linux/arm64 python:3.15-alpine@sha256:4e2ab0675612ba77cc94ed8d3522d1c7c1ec5c521bc4db61c6e3d00a011841f9
WORKDIR /app
COPY --from=dependencies /dependencies/ /opt/python-dependencies/
COPY bridge.py module_observations.py ruview_http.py ./
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/python-dependencies
ENTRYPOINT ["python", "/app/bridge.py"]
