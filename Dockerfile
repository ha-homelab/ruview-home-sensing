# Pin per-architecture manifests: a legacy builder can reuse an amd64 cache
# entry when two FROM stages share the same multi-architecture index digest.
ARG DEPENDENCY_PLATFORM=linux/amd64
ARG DEPENDENCY_IMAGE=python:3.14-alpine@sha256:7f2ec713f0436c59df2362d973b6a05af9e87ba78f0e94f5245c302984a7a1fd
FROM --platform=${DEPENDENCY_PLATFORM} ${DEPENDENCY_IMAGE} AS dependencies
WORKDIR /app
COPY requirements.txt requirements-public.txt ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
    --platform any --target /dependencies -r requirements.txt

FROM --platform=linux/arm64 python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72
WORKDIR /app
COPY --from=dependencies /dependencies/ /opt/python-dependencies/
COPY bridge.py module_observations.py ruview_http.py ./
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/python-dependencies
ENTRYPOINT ["python", "/app/bridge.py"]
