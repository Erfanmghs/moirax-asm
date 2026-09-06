# TEST FIXTURE (E2E): multi-port vhost+DNS server (host network at runtime).
FROM python:3.12-slim

RUN mkdir -p /etc/fixture /app && \
    openssl req -x509 -newkey rsa:2048 -keyout /etc/fixture/key.pem \
      -out /etc/fixture/cert.pem -days 3650 -nodes \
      -subj "/CN=fixture-target.test" \
      -addext "subjectAltName=DNS:fixture-target.test,DNS:*.fixture-target.test"

WORKDIR /app
COPY server.py dnsserver.py /app/

# 53/udp DNS, 80 vhost HTTP, 8080 alt HTTP, 8443 HTTPS, 2222 SSH banner,
# 6379 RESP banner, 9200 elastic JSON (host-network mode publishes these
# directly on the runner host).
EXPOSE 53/udp 80 8080 8443 2222 6379 9200

CMD ["python3", "server.py"]
