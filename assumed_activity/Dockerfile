# Install only architecture-independent wheels on the chosen native builder.
ARG DEPENDENCY_PLATFORM=linux/amd64
ARG DEPENDENCY_IMAGE=python:3.15-alpine@sha256:a943ed02f4e22d024d2b4fc5083619497dfb9bc1c64c193861f3bc6d3074f5b1
FROM --platform=${DEPENDENCY_PLATFORM} ${DEPENDENCY_IMAGE} AS dependencies
WORKDIR /app
COPY requirements.txt requirements-public.txt /app/
COPY assumed_activity/requirements.txt /app/assumed_activity/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
    --platform any --target /dependencies -r /app/assumed_activity/requirements.txt

FROM --platform=linux/amd64 python:3.15-alpine@sha256:0f9552bb28711333da16915ec146f5e6bb44a7fdac9ced15dc17c2e0206346dd
WORKDIR /app
COPY --from=dependencies /dependencies/ /opt/python-dependencies/
COPY ruview_http.py ./
COPY scripts/transport_security.py /app/scripts/transport_security.py
COPY assumed_activity/ /app/assumed_activity/
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/python-dependencies
EXPOSE 5017
ENTRYPOINT ["python", "-m", "assumed_activity"]
