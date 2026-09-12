"""Regression: MERGE must never write an IP-bearing, in-scope host as dead.

A host that resolves to an in-scope IP is a live asset (its ports get scanned,
it can seed nested vhost). HTTP reachability is a separate signal (http_status).
This locks the fix for the 'resolved host shown DEAD' data-quality bug.
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


class TestMergeAlive(unittest.TestCase):
    def test_ip_bearing_host_is_alive_even_when_probe_said_dead(self):
        params = Params(_ROOT)
        target = "example.com"
        target_dir = Path(tempfile.mkdtemp()) / target
        (target_dir / "00_assets").mkdir(parents=True)
        (target_dir / "logs").mkdir(parents=True, exist_ok=True)
        gate = ScopeGate(params, {"includes": ["example.com", "*.example.com"], "excludes": []})
        active_doc = {
            "module": "dns-resolve",
            "resolved": [
                # resolved with IP but HTTP probe reported not-alive
                {"host": "a.example.com", "ips": ["1.2.3.4"], "alive": False, "resolution_status": "resolved"},
                # resolved with IP but never probed (httpx disabled)
                {"host": "b.example.com", "ips": ["5.6.7.8"], "alive": None, "resolution_status": "resolved"},
                # genuinely dead: never resolved, no IP
                {"host": "dead.example.com", "ips": [], "alive": False, "resolution_status": "unresolved"},
            ],
        }
        merge_branches(params, gate, target_dir, target, [], [active_doc])
        doc = json.loads((target_dir / str(params.require("assets_relpath"))).read_text(encoding="utf-8"))
        by_host = {a["host"]: a for a in doc["assets"]}

        self.assertTrue(by_host["a.example.com"]["alive"], "IP-bearing host must be alive despite probe alive=False")
        self.assertTrue(by_host["b.example.com"]["alive"], "IP-bearing host must be alive despite alive=None")
        self.assertFalse(by_host["dead.example.com"]["alive"], "a host with no IP is genuinely dead")


if __name__ == "__main__":
    unittest.main()
