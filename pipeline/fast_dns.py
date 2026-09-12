"""Native UDP DNS probes -- stdlib only, no container start.

dnsx-probe and dnsx-canary used to pay a full `docker run --rm` per
resolver (or every canary window). On a 250-IP fleet that is hundreds of
cold starts before the first brute packet. This module answers the same
health question with one UDP datagram per (name, resolver) so the
orchestrator is faster than the tool it would have wrapped.

Honesty: every skip of docker is logged by the caller. Fail-closed: a
timeout or malformed packet is a miss, never a silent healthy.
"""

from __future__ import annotations

import random
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable


def encode_qname(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").lower().split("."):
        raw = label.encode("ascii", errors="strict")
        if not raw or len(raw) > 63:
            raise ValueError("illegal DNS label")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_query(name: str, qtype: int = 1) -> bytes:
    txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_qname(name) + struct.pack("!HH", qtype, 1)
    return header + question


def _skip_name(buf: bytes, offset: int) -> int:
    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def response_has_a(buf: bytes) -> bool:
    if len(buf) < 12:
        return False
    _txid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    if (flags & 0x8000) == 0:
        return False
    rcode = flags & 0xF
    if rcode not in (0, 3):  # NOERROR or NXDOMAIN still means the resolver spoke
        return False
    offset = 12
    for _ in range(qd):
        offset = _skip_name(buf, offset)
        offset += 4
        if offset > len(buf):
            return False
    for _ in range(an):
        offset = _skip_name(buf, offset)
        if offset + 10 > len(buf):
            return False
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[offset : offset + 10])
        offset += 10
        if offset + rdlen > len(buf):
            return False
        if rtype == 1 and rdlen == 4:
            return True
        offset += rdlen
    return rcode == 0 and an > 0


def query_a(name: str, resolver_ip: str, timeout_sec: float = 1.5, port: int = 53) -> bool:
    """Return True when the resolver answers this name (A or a spoken rcode)."""
    try:
        payload = build_query(name)
    except ValueError:
        return False
    family = socket.AF_INET6 if ":" in resolver_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(max(0.2, float(timeout_sec)))
        sock.sendto(payload, (resolver_ip, int(port)))
        data, _addr = sock.recvfrom(2048)
    except (OSError, TimeoutError, ValueError):
        return False
    finally:
        sock.close()
    try:
        return response_has_a(data)
    except (struct.error, ValueError, IndexError):
        return False


def probe_resolver(
    resolver_ip: str,
    domains: Iterable[str],
    timeout_sec: float = 1.5,
) -> float:
    names = [str(d).strip().rstrip(".") for d in domains if str(d).strip()]
    if not names:
        return 0.0
    hits = 0
    for name in names:
        if query_a(name, resolver_ip, timeout_sec=timeout_sec):
            hits += 1
    return hits / len(names)


def probe_resolvers(
    resolvers: list[str],
    domains: list[str],
    timeout_sec: float = 1.5,
    workers: int = 32,
) -> dict[str, float]:
    if not resolvers:
        return {}
    n = max(1, min(int(workers), len(resolvers)))
    health: dict[str, float] = {}

    def one(ip: str) -> tuple[str, float]:
        return ip, probe_resolver(ip, domains, timeout_sec=timeout_sec)

    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(one, ip) for ip in resolvers]
        for fut in as_completed(futs):
            ip, ratio = fut.result()
            health[ip] = ratio
    return health


def canary_ok(
    sentinels: list[str],
    resolvers: list[str],
    timeout_sec: float = 1.5,
    resolver_sample: int = 3,
) -> bool:
    """True when at least one sentinel gets an A via a sampled resolver."""
    names = [s.strip().rstrip(".") for s in sentinels if str(s).strip()]
    pool = [r.strip() for r in resolvers if str(r).strip()]
    if not names or not pool:
        return False
    sample = pool[: max(1, min(int(resolver_sample), len(pool)))]
    for resolver in sample:
        for name in names:
            if query_a(name, resolver, timeout_sec=timeout_sec):
                return True
    return False
