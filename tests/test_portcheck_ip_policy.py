"""REM8 (TEST 3) bidirectional regression proof: port-check IP scan eligibility.

Defect (OLD): port-check rejected EVERY IP via gate.enforce() when the scope
carries host includes but no CIDR includes — run 20260905T100243Z (run #8):
dnsr data.json held 2 resolved hosts sharing 2 public IPs (example.com,
www.example.com -> 104.20.23.154, 172.66.147.243) yet port-check produced
unique_ips_checked=0: every IP was rejected with reason "no IP includes".
The one-naabu-per-IP machinery TEST 3 must prove was unreachable dead code,
while merge.py's as-frozen ruling (lines: reason in ("no IP includes",
"IP not in included CIDRs") -> in_scope_ips) accepted the very same IPs.

Fix (NEW): _ip_scan_verdict mirrors merge.py's ruling at port-check.

Safety rails stay shut (bidirectional contract):
  REJECTED (OLD class must stay rejected):
    10.1.2.3    RFC1918 not listed in includes
    127.0.0.1   loopback
    169.254.1.1 link-local
    192.0.2.5   explicitly excluded CIDR (TEST-NET-1 listed in excludes)
  ACCEPTED (NEW class):
    93.184.216.34  public IP, host-includes-only scope ("no IP includes")
    198.51.100.7   public IP outside listed CIDRs ("IP not in included
                   CIDRs" — scope with a CIDR include that misses it)
"""

from __future__ import annotations

import unittest

from pipeline.modules.port_check import _ip_scan_verdict
from pipeline.scope import ScopeGate


class _FakePolicyParams:
    def require(self, key: str):
        table = {
            "rfc1918_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "loopback_cidrs": ["127.0.0.0/8"],
            "link_local_cidrs": ["169.254.0.0/16"],
            "cloud_wildcard_suffixes": [],
        }
        try:
            return table[key]
        except KeyError:
            raise KeyError(key)


def _gate(includes: list[str], excludes: list[str]) -> ScopeGate:
    return ScopeGate(_FakePolicyParams(), {"includes": includes, "excludes": excludes})


class TestIpScanVerdict(unittest.TestCase):
    def test_public_ip_eligible_on_host_only_scope(self) -> None:
        gate = _gate(["example.com", "*.example.com"], ["out.example.com"])
        eligible, reason = _ip_scan_verdict(gate, "93.184.216.34")
        self.assertTrue(eligible)
        self.assertIsNone(reason)

    def test_ip_outside_listed_cidr_still_eligible_per_merge_ruling(self) -> None:
        gate = _gate(["203.0.113.0/24"], [])
        eligible, _ = _ip_scan_verdict(gate, "198.51.100.7")
        self.assertTrue(eligible)

    def test_rfc1918_stays_rejected(self) -> None:
        gate = _gate(["example.com"], [])
        eligible, reason = _ip_scan_verdict(gate, "10.1.2.3")
        self.assertFalse(eligible)
        self.assertEqual(reason, "RFC1918 not listed in includes")

    def test_loopback_stays_rejected(self) -> None:
        gate = _gate(["example.com"], [])
        eligible, reason = _ip_scan_verdict(gate, "127.0.0.1")
        self.assertFalse(eligible)
        self.assertEqual(reason, "loopback not listed in includes")

    def test_link_local_stays_rejected(self) -> None:
        gate = _gate(["example.com"], [])
        eligible, reason = _ip_scan_verdict(gate, "169.254.1.1")
        self.assertFalse(eligible)
        self.assertEqual(reason, "link-local not listed in includes")

    def test_excluded_cidr_stays_rejected(self) -> None:
        gate = _gate(["example.com"], ["192.0.2.0/24"])
        eligible, reason = _ip_scan_verdict(gate, "192.0.2.5")
        self.assertFalse(eligible)
        self.assertEqual(reason, "excluded CIDR/IP")


if __name__ == "__main__":
    unittest.main()
