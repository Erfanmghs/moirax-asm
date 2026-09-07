FROM python:3.12-slim

WORKDIR /app

# section 9.1 dashboard service: FastAPI backend + SPA, binds 127.0.0.1:8080 via
# compose mapping; the backend is the ONLY docker.sock client.
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0

COPY dashboard/ ./dashboard/
COPY pipeline/ ./pipeline/
COPY tools.yaml tools.lock views.yaml wordlists.yaml search_engines.yaml dorks.yaml scheduler.json scope.yaml ./

ENV PYTHONPATH=/app
EXPOSE 8080

CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]
