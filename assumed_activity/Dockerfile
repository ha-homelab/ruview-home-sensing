# Install only architecture-independent wheels on the chosen native builder.
ARG DEPENDENCY_PLATFORM=linux/amd64
ARG DEPENDENCY_IMAGE=python:3.13-alpine@sha256:ba27df8b6499cc3756cff167690f3fcb5321faa1703b3a914df5f4fdadb32f05
FROM --platform=${DEPENDENCY_PLATFORM} ${DEPENDENCY_IMAGE} AS dependencies
WORKDIR /app
COPY requirements.txt requirements-public.txt /app/
COPY assumed_activity/requirements.txt /app/assumed_activity/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
    --platform any --target /dependencies -r /app/assumed_activity/requirements.txt

FROM --platform=linux/amd64 python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72
WORKDIR /app
COPY --from=dependencies /dependencies/ /usr/local/lib/python3.13/site-packages/
COPY ruview_http.py ./
COPY assumed_activity/ /app/assumed_activity/
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 5017
ENTRYPOINT ["python", "-m", "assumed_activity"]
