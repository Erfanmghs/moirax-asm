#!/usr/bin/env python3
"""TEST FIXTURE (B2 acceptance smoke): local wildcard vhost HTTP server.

P1.1: exact stall names accept TCP and never write an HTTP response.
R4.1: vhost answers restricted to an allowlist of five prefixed names under app
(mail, webmail, vpn, dev, staging) -> 200 size 9014; all other prefixes -> 404;
mixed-case -> 404. Stall rules unchanged (httpx UA + bare app -> stall; www always 200).
"""

from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STALL_ALWAYS = frozenset({"fixture-target.test"})
STALL_UNLESS_FFUF = frozenset({"app.fixture-target.test"})
ALIVE_EXACT = frozenset({"www.fixture-target.test"})
VHOST_ALLOW = frozenset(
    {
        "mail.app.fixture-target.test",
        "webmail.app.fixture-target.test",
        "vpn.app.fixture-target.test",
        "dev.app.fixture-target.test",
        "staging.app.fixture-target.test",
    }
)
VHOST_BODY = b"VHOST-HIT\n" + (b"y" * (9014 - len(b"VHOST-HIT\n")))


def _host_header(handler: BaseHTTPRequestHandler) -> str:
    raw = handler.headers.get("Host") or ""
    return raw.split("@")[-1].split(":")[0].strip()


def _is_ffuf(handler: BaseHTTPRequestHandler) -> bool:
    ua = handler.headers.get("User-Agent") or ""
    low = ua.lower()
    return "fuzz faster" in low or "ffuf" in low


def _should_stall(host: str, handler: BaseHTTPRequestHandler) -> bool:
    key = host.lower().rstrip(".")
    if key in STALL_ALWAYS:
        return True
    if key in STALL_UNLESS_FFUF:
        return not _is_ffuf(handler)
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _serve(self) -> None:
        host = _host_header(self)
        if _should_stall(host, self):
            while True:
                time.sleep(3600)
        key = host.lower().rstrip(".")
        first = host.split(".")[0] if host else ""
        if key in ALIVE_EXACT:
            body = b"WWW-ALIVE-FIXTURE\n"
        elif key in STALL_UNLESS_FFUF:
            body = b"APP-ALIVE-FIXTURE\n"
        elif any(ch.isupper() for ch in first):
            self.send_response(404)
            miss = b"calib\n"
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(miss)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(miss)
            return
        elif key in VHOST_ALLOW:
            body = VHOST_BODY
        else:
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

    def do_GET(self) -> None:
        self._serve()

    def do_HEAD(self) -> None:
        self._serve()

    def do_POST(self) -> None:
        self._serve()

    def do_PUT(self) -> None:
        self._serve()

    def do_OPTIONS(self) -> None:
        self._serve()


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
