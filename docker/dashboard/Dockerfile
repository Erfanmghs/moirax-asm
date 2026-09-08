FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz \
      | tar -xz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /var/lib/apt/lists/* \
    && pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0

COPY dashboard/ ./dashboard/
COPY pipeline/ ./pipeline/
COPY recon.sh ./
COPY tools.yaml tools.lock views.yaml wordlists.yaml search_engines.yaml dorks.yaml scheduler.json scope.yaml ./
RUN chmod +x /app/recon.sh

ENV PYTHONPATH=/app
EXPOSE 8080

CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]

