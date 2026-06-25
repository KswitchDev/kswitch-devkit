# syntax=docker/dockerfile:1.7

ARG KSWITCH_BASE_IMAGE=ghcr.io/maxcope-alt/kswitch:v1.36-pg
ARG PYTHON_BASE=python:3.12-slim@sha256:5072b08ad74609c5329ab4085a96dfa873de565fb4751a4cfcd7dcc427661df0

FROM ${KSWITCH_BASE_IMAGE} AS source

FROM ${PYTHON_BASE} AS runtime

ARG KSWITCH_VERSION=v1.36-pg
ARG GIT_SHA=unknown

LABEL org.opencontainers.image.title="KSwitch Developer Edition Runtime" \
      org.opencontainers.image.description="Minimal local runtime for the free KSwitch Developer Edition devkit" \
      org.opencontainers.image.vendor="KSwitch" \
      org.opencontainers.image.version="${KSWITCH_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KSWITCH_GIT_SHA=${GIT_SHA} \
    KSWITCH_EDITION=developer \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        libpq5 \
        openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1001 -s /bin/false kswitch \
    && mkdir -p \
        /opt/kswitch/scripts/licence \
        /opt/kswitch/config \
        /opt/kswitch/observability

WORKDIR /opt/kswitch

COPY --from=source /opt/venv /opt/venv
COPY --from=source /opt/kswitch/VERSION /opt/kswitch/VERSION
COPY --from=source /opt/kswitch/gunicorn.conf.py /opt/kswitch/gunicorn.conf.py
COPY --from=source /opt/kswitch/entrypoint.sh /opt/kswitch/entrypoint.sh
COPY --from=source /opt/kswitch/app /opt/kswitch/app
COPY --from=source /opt/kswitch/fleet/__init__.py /opt/kswitch/fleet/__init__.py
COPY --from=source /opt/kswitch/fleet/deployment /opt/kswitch/fleet/deployment
COPY --from=source /opt/kswitch/fleet/inventory_ingest /opt/kswitch/fleet/inventory_ingest
COPY --from=source /opt/kswitch/fleet/scanner_sync_egress /opt/kswitch/fleet/scanner_sync_egress
COPY --from=source /opt/kswitch/fleet/shared /opt/kswitch/fleet/shared
COPY --from=source /opt/kswitch/schema /opt/kswitch/schema
COPY --from=source /opt/kswitch/config/otel /opt/kswitch/config/otel
COPY --from=source /opt/kswitch/observability/detections /opt/kswitch/observability/detections
COPY --from=source /opt/kswitch/scripts/init_runtime_bootstrap.py /opt/kswitch/scripts/init_runtime_bootstrap.py
COPY --from=source /opt/kswitch/scripts/run_runtime_ops.py /opt/kswitch/scripts/run_runtime_ops.py
COPY --from=source /opt/kswitch/scripts/run_inventory_ingest.py /opt/kswitch/scripts/run_inventory_ingest.py
COPY --from=source /opt/kswitch/scripts/run_scanner_sync_egress.py /opt/kswitch/scripts/run_scanner_sync_egress.py
COPY --from=source /opt/kswitch/scripts/ep094_jwt_materializer.py /opt/kswitch/scripts/ep094_jwt_materializer.py
COPY --from=source /opt/kswitch/scripts/licence/check_runtime_boot.py /opt/kswitch/scripts/licence/check_runtime_boot.py

# Bake the free local entitlement into the public image. The full platform image
# keeps the normal fail-closed licence verifier; only this derivative swaps the
# loader.
COPY devkit/developer-edition/licence_loader.py /opt/kswitch/app/licence/loader.py
COPY devkit/images/kswitch-developer/check_runtime_boot.py /opt/kswitch/scripts/licence/check_runtime_boot.py

RUN python -m compileall -q -b /opt/kswitch/app /opt/kswitch/fleet \
    && find /opt/kswitch/app /opt/kswitch/fleet -type f -name '*.py' -delete \
    && find /opt/kswitch/app /opt/kswitch/fleet -type d -name '__pycache__' -prune -exec rm -rf {} + \
    && chmod 0555 /opt/kswitch/entrypoint.sh \
    && chown -R kswitch:kswitch /opt/kswitch

USER kswitch

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD if [ -n "$TLS_CERT_FILE" ] && [ -n "$TLS_KEY_FILE" ]; then \
          python -c "import ssl, urllib.request; ctx=ssl._create_unverified_context(); urllib.request.urlopen('https://127.0.0.1:5001/api/v1/health/ready', context=ctx, timeout=5).close()" || exit 1; \
        else \
          python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5001/api/v1/health/ready', timeout=5).close()" || exit 1; \
        fi

ENTRYPOINT ["/opt/kswitch/entrypoint.sh"]
