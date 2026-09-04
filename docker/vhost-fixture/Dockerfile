# TEST FIXTURE (B2 acceptance smoke) — pinned base per §2.2
FROM python:3.12.11-alpine3.21
COPY server.py /usr/local/bin/vhost-fixture-server.py
RUN chmod 755 /usr/local/bin/vhost-fixture-server.py
USER nobody
ENTRYPOINT ["python3", "-u", "/usr/local/bin/vhost-fixture-server.py"]
