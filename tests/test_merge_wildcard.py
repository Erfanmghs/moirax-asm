"""Regression: wildcard / catch-all quarantine must fire, but CONSERVATIVELY.

dns-resolve now emits the catch-all IPs in ``wildcard_ips``. MERGE quarantines
only names that resolve EXCLUSIVELY to those IPs. A host that also holds a
genuine (non-wildcard) IP, or a set of hosts that legitimately share a normal
IP (shared hosting / CDN), must stay in ``assets`` -- we never hide a real
IP-bearing host (the inverse of the 'wrongly-dead' bug).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.merge import merge_branches
from pipeline.params import Params
from pipeline.scope import ScopeGate

_ROOT = Path(__file__).resolve().parents[1]


class TestMergeWildcardQuarantine(unittest.TestCase):
    def _run(self, active_doc):
        params = Params(_ROOT)
        target = "example.com"
        target_dir = Path(tempfile.mkdtemp()) / target
        (target_dir / "00_assets").mkdir(parents=True)
        (target_dir / "logs").mkdir(parents=True, exist_ok=True)
        gate = ScopeGate(params, {"includes": ["example.com", "*.example.com"], "excludes": []})
        merge_branches(params, gate, target_dir, target, [], [active_doc])
        doc = json.loads((target_dir / str(params.require("assets_relpath"))).read_text(encoding="utf-8"))
        assets = {a["host"] for a in doc["assets"]}
        quarantine = {q["host"] for q in doc.get("quarantine", [])}
        return assets, quarantine

    def test_conservative_wildcard_quarantine(self):
        active_doc = {
            "module": "dns-resolve",
            "wildcard_ips": ["9.9.9.9"],
            "resolved": [
                # pure catch-all noise: resolves ONLY to the wildcard IP
                {"host": "noise1.example.com", "ips": ["9.9.9.9"], "resolution_status": "resolved"},
                {"host": "noise2.example.com", "ips": ["9.9.9.9"], "resolution_status": "resolved"},
                # REAL host: has the wildcard IP AND a genuine distinct IP -> keep
                {"host": "real.example.com", "ips": ["9.9.9.9", "1.2.3.4"], "resolution_status": "resolved"},
                # legit shared hosting on a NON-wildcard IP -> keep both
                {"host": "shared1.example.com", "ips": ["8.8.8.8"], "resolution_status": "resolved"},
                {"host": "shared2.example.com", "ips": ["8.8.8.8"], "resolution_status": "resolved"},
            ],
        }
        assets, quarantine = self._run(active_doc)

        # pure-wildcard names are quarantined out of canonical assets
        self.assertEqual(quarantine, {"noise1.example.com", "noise2.example.com"})
        self.assertNotIn("noise1.example.com", assets)

        # real / shared-IP hosts are NEVER quarantined
        self.assertIn("real.example.com", assets)
        self.assertIn("shared1.example.com", assets)
        self.assertIn("shared2.example.com", assets)
        self.assertFalse(assets & quarantine)

    def test_no_wildcard_ip_means_no_quarantine(self):
        # Without a catch-all IP, nothing is quarantined even on a shared IP.
        active_doc = {
            "module": "dns-resolve",
            "wildcard_ips": [],
            "resolved": [
                {"host": "a.example.com", "ips": ["8.8.8.8"], "resolution_status": "resolved"},
                {"host": "b.example.com", "ips": ["8.8.8.8"], "resolution_status": "resolved"},
            ],
        }
        assets, quarantine = self._run(active_doc)
        self.assertEqual(quarantine, set())
        self.assertEqual(assets, {"a.example.com", "b.example.com"})


if __name__ == "__main__":
    unittest.main()
