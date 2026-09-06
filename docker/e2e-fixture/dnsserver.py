#!/usr/bin/env python3
"""TEST FIXTURE (E2E): minimal authoritative UDP DNS responder (stdlib only).

Answers A queries for the seeded zone names ONLY (everything else -> NXDOMAIN)
so dnsx brute-force discovery stays HONEST: a name resolves iff the fixture
zone defines it. Every answer points at 172.17.0.1 (the docker bridge gateway
= the host-network fixture itself).
"""

from __future__ import annotations

import socket
import struct
import threading

_QTYPE_A = 1
_CLASS_IN = 1


def _encode_name(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _read_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        length = payload[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            ptr = struct.unpack("!H", payload[offset:offset + 2])[0] & 0x3FFF
            tail, _ = _read_name(payload, ptr)
            labels.append(tail)
            offset += 2
            break
        labels.append(payload[offset + 1:offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    return ".".join(x for x in labels if x), offset


def start_dns_daemon(bind: str, port: int, zone: tuple[str, ...], answer_ip: str) -> None:
    zone_set = {n.lower().rstrip(".") for n in zone}
    answer_bytes = socket.inet_aton(answer_ip)

    def handle(payload: bytes, addr: tuple[str, int], sock: socket.socket) -> None:
        if len(payload) < 12:
            return
        query_id = payload[:2]
        qdcount = struct.unpack("!H", payload[4:6])[0]
        if qdcount < 1:
            return
        try:
            qname, offset = _read_name(payload, 12)
        except (IndexError, UnicodeDecodeError):
            return
        if offset + 4 > len(payload):
            return
        qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])

        flags = 0x8180  # QR=1, RD=1, RA=1, RCODE=0
        answers = b""
        ancount = 0
        if qtype == _QTYPE_A and qclass == _CLASS_IN and qname in zone_set:
            ancount = 1
            answers = struct.pack("!HHIHI", 0xC00C, _QTYPE_A, _CLASS_IN, 300, 4) + answer_bytes
        elif qtype == _QTYPE_A and qclass == _CLASS_IN:
            flags |= 0x0003  # NXDOMAIN — honest miss
        header = query_id + struct.pack("!HHHHH", flags, qdcount, ancount, 0, 0)
        question = _encode_name(qname) + struct.pack("!HH", qtype, qclass)
        try:
            sock.sendto(header + question + answers, addr)
        except OSError:
            pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))

    def loop() -> None:
        while True:
            try:
                payload, addr = sock.recvfrom(4096)
            except OSError:
                continue
            threading.Thread(target=handle, args=(payload, addr, sock), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
