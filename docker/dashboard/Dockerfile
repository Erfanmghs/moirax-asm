# syntax=docker/dockerfile:1
# Dashboard console. Nested docker CLI comes from the official cli image
# (no curl|tar). The process starts as root only to join docker.sock GID,
# then setpriv drops to RECON_HOST_UID/GID.

FROM docker:27.5.1-cli AS docker-cli

FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY dashboard/ ./dashboard/
COPY pipeline/ ./pipeline/
COPY recon.sh ./
COPY docker/dashboard/entrypoint.sh /entrypoint.sh
COPY tools.yaml tools.lock views.yaml wordlists.yaml search_engines.yaml dorks.yaml scheduler.json scope.yaml targets.yaml ./
RUN chmod 0755 /app/recon.sh /entrypoint.sh \
    && chmod 0755 /usr/local/bin/docker

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]
