# Pin per-architecture manifests: a legacy builder can reuse an amd64 cache
# entry when two FROM stages share the same multi-architecture index digest.
ARG DEPENDENCY_PLATFORM=linux/amd64
ARG DEPENDENCY_IMAGE=python:3.15-alpine@sha256:c480059ce7dd8fc98f30e2a56cc3b54e559c3b3b66cc498a92f641237a47f288
FROM --platform=${DEPENDENCY_PLATFORM} ${DEPENDENCY_IMAGE} AS dependencies
WORKDIR /app
COPY requirements.txt requirements-public.txt ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
    --platform any --target /dependencies -r requirements.txt

FROM --platform=linux/arm64 python:3.15-alpine@sha256:41c8bc4eafe6c381073ddde4ed64d49a3e10675363e850938276d7276f54f318
WORKDIR /app
COPY --from=dependencies /dependencies/ /opt/python-dependencies/
COPY bridge.py module_observations.py ruview_http.py ./
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/python-dependencies
ENTRYPOINT ["python", "/app/bridge.py"]
