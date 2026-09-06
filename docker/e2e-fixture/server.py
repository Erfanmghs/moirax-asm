#!/usr/bin/env python3
"""TEST FIXTURE (E2E): multi-port web/TCP server with vhosts + nested subdomains.

Zone (all *.fixture-target.test -> 172.17.0.1, served by dnsserver.py):
  apex  fixture-target.test            -> APEX-E2E
  flat  www / app / dev / api / mail   -> <NAME>-E2E-ROOT   (SecLists top-5000 labels)
  nested dev.app (L3), k8s.dev (L3), api.dev.app (L4), git.staging.app (L4),
         mail.api.dev.app (L5)         -> <NAME>-E2E-NESTED (dotted fixture wordlist)

Listeners (host network): 53/udp DNS, 80 vhost HTTP (unknown Host -> 404),
8080 alt HTTP, 8443 HTTPS (self-signed cert generated at build), 2222 SSH-style
banner, 6379 RESP error banner, 9200 elastic-style JSON. Designed to be
discovered by the REAL pipeline: dnsx brute (flat + nested), ffuf vhost
probes, httpx alive probes, naabu port sweep.
"""

from __future__ import annotations

import json
import ssl
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IP = "172.17.0.1"

FLAT = ("www", "app", "dev", "api", "mail")
NESTED = ("dev.app", "k8s.dev", "api.dev.app", "git.staging.app", "mail.api.dev.app")
ZONE = ("fixture-target.test",) + tuple(f"{n}.fixture-target.test" for n in FLAT + NESTED)


def _body(marker: str) -> bytes:
    pad = marker.encode() + b"\n"
    return pad + (b"z" * (9014 - len(pad)))


BODIES = {
    "fixture-target.test": _body("APEX-E2E"),
    **{f"{n}.fixture-target.test": _body("-".join(n.upper().split(".")) + "-E2E") for n in FLAT + NESTED},
}


def _host_header(handler: BaseHTTPRequestHandler) -> str:
    raw = handler.headers.get("Host") or ""
    return raw.split("@")[-1].split(":")[0].strip().lower().rstrip(".")


class VhostHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _serve(self) -> None:
        host = _host_header(self)
        body = BODIES.get(host)
        if body is None:
            self.send_response(404)
            miss = b"miss\n"
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(miss)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(miss)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_HEAD = _serve


class PlainHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _serve(self) -> None:
        body = _body("HTTP-ALT-E2E")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_HEAD = _serve


class ElasticHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _serve(self) -> None:
        body = json.dumps({"cluster_name": "fixture-e2e", "tagline": "e2e-test-node"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_HEAD = _serve


def _banner_server(port: int, banner: bytes) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)

    def loop() -> None:
        while True:
            try:
                conn, _addr = srv.accept()
            except OSError:
                return
            try:
                conn.sendall(banner)
                while True:
                    if not conn.recv(4096):
                        break
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()


def main() -> None:
    from dnsserver import start_dns_daemon

    start_dns_daemon("0.0.0.0", 53, zone=ZONE, answer_ip=IP)

    servers = [
        threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 80), VhostHandler).serve_forever, daemon=True),
        threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 8080), PlainHandler).serve_forever, daemon=True),
        threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 9200), ElasticHandler).serve_forever, daemon=True),
    ]
    for t in servers:
        t.start()

    _banner_server(2222, b"SSH-2.0-FixtureE2E_1.0\r\n")
    _banner_server(6379, b"-ERR unknown command 'FIXTURE'\r\n")

    https = ThreadingHTTPServer(("0.0.0.0", 8443), VhostHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/etc/fixture/cert.pem", "/etc/fixture/key.pem")
    https.socket = ctx.wrap_socket(https.socket, server_side=True)
    threading.Thread(target=https.serve_forever, daemon=True).start()

    print("e2e-fixture: all listeners up (53/udp, 80, 2222, 6379, 8080, 8443, 9200)", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
