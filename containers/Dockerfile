# Build from the repository root. The Linux-specific closure is hash-locked.
FROM openpolicyagent/opa@sha256:a6ccb6e0cc91b2d1807b1b65a844b189249b9ab33d126e0bca30c0cf43b0ae07 AS policy-engine
FROM python@sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 FLWR_TELEMETRY_ENABLED=0 \
    HOME=/runtime TMPDIR=/runtime/tmp PYTHONPATH=/app/src
WORKDIR /app
COPY containers/requirements-linux.lock /app/containers/requirements-linux.lock
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: \
      -r /app/containers/requirements-linux.lock \
    && groupadd --gid 10001 pcfl \
    && useradd --uid 10001 --gid pcfl --no-create-home --home-dir /runtime pcfl \
    && mkdir -p /runtime/tmp /runtime/data /runtime/certs /runtime/keys /runtime/flower \
    && chown -R 10001:10001 /runtime
COPY src/ /app/src/
COPY --from=policy-engine /opa /usr/local/bin/opa
COPY policies/rego/pcfl.rego policies/rego/data.json policies/rego/api_authz.rego policies/rego/log_mask.rego /app/policies/rego/
COPY pyproject.toml /app/pyproject.toml
COPY containers/entrypoint.py /app/containers/entrypoint.py
COPY containers/build-source.json /app/containers/build-source.json
USER 10001:10001
# ECS copies this image-owned directory into the per-task ephemeral bind volume.
VOLUME ["/runtime"]
ENTRYPOINT ["python", "/app/containers/entrypoint.py"]
CMD ["--help"]
