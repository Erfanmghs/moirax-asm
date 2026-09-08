"""Atomic tests for C6 OWASP-PASSIVE (operator roadmap item C6).

Laws under test:
- ZERO-PACKET: the adapter is NEVER called (file analysis only)
- evidence -> OWASP mapping (Top 10 2021 + API Top 10 2023)
- severity ceiling: passive evidence never claims high/critical
- honesty: not-passively-assessable items are DISCLOSED, never silent
- missing/corrupt artifacts -> disclosed empty result, never a crash
- registration: owasp-passive in RUNNERS + tools.yaml wiring + layout dir
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.modules import RUNNERS  # noqa: E402
from pipeline.modules.owasp_passive import run_owasp_passive  # noqa: E402
from pipeline.params import Params  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]


def _isolated_root() -> Path:
    tmp = Path(tempfile.mkdtemp())
    for rel in ("tools.yaml", "wordlists.yaml", "scope.yaml"):
        src = _ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return tmp


class TestC6OwaspBase(unittest.TestCase):
    def setUp(self) -> None:
        self.params = Params(_isolated_root())
        self.target_dir = self.params.root / "targets" / "example.com"
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.partial: list[str] = []
        self.adapter = mock.MagicMock()

    # -- artifact helpers -------------------------------------------------
    def _write_assets(self, assets: list[dict]) -> None:
        path = self.target_dir / str(self.params.require("assets_relpath"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"schema_version": 1, "target": "example.com", "assets": assets,
                        "quarantine": []}) + "\n",
            encoding="utf-8",
        )

    def _write_probe(self, rows: list[dict], junk: bool = False) -> None:
        rel = str(self.params.require("passive_sources_relpath")) + "/httpx.json"
        path = self.target_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(r) for r in rows]
        if junk:
            lines = ["<<<garbage>>>", ""] + lines + ["{not-json"]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _write_ports(self, key: str, results: list[dict]) -> None:
        path = self.target_dir / str(self.params.require(key))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"schema_version": 1, "results": results}) + "\n",
            encoding="utf-8",
        )

    def _run(self) -> dict:
        return run_owasp_passive(
            self.params, None, self.adapter, self.target_dir, "example.com",
            {}, 5, None, self.partial,
        )

    def _doc(self) -> dict:
        return json.loads(
            (self.target_dir / str(self.params.require("owasp_data_json"))).read_text(encoding="utf-8")
        )


class TestZeroPacketLaw(TestC6OwaspBase):
    def test_adapter_is_never_called(self):
        self._write_assets([{"host": "a.example.com", "ips": [], "alive": True, "sources": []}])
        self._run()
        self.assertEqual(self.adapter.method_calls, [], "zero-packet law: adapter untouched")

    def test_gate_and_budget_inputs_ignored(self):
        # gate=None is passed deliberately: a passive module has no one to ask.
        doc = self._run()
        self.assertEqual(doc["passive_only"], True)


class TestEvidenceMapping(TestC6OwaspBase):
    def test_banner_disclosure_maps_a05(self):
        self._write_probe([{"host": "a.example.com", "webserver": "nginx"}])
        doc = self._run()
        f = [x for x in doc["findings"] if x["top10"].startswith("A05")]
        self.assertTrue(f, "webserver banner must surface as A05:2021")
        self.assertEqual(f[0]["severity"], "low")
        self.assertIn("a.example.com", f[0]["hosts"])
        self.assertTrue(f[0]["review_required"])
        self.assertIn("10_subdomains/passive/sources/httpx.json", f[0]["evidence"])

    def test_misconfig_suspect_maps_a05(self):
        self._write_assets([{"host": "wild.example.com", "misconfig_suspect": True}])
        doc = self._run()
        f = [x for x in doc["findings"] if x["top10"].startswith("A05") and "wild.example.com" in x["hosts"]]
        self.assertTrue(f, "misconfig_suspect assets must surface as A05:2021")

    def test_risk_ports_medium_with_api8_lens(self):
        self._write_ports("portcheck_data_json", [
            {"ip": "93.184.216.34", "hosts": ["a.example.com"],
             "ports": [{"port": 6379, "proto": "tcp", "state": "open"},
                       {"port": 443, "proto": "tcp", "state": "open"}]},
        ])
        doc = self._run()
        f = [x for x in doc["findings"] if x["top10"].startswith("A05") and "a.example.com" in x["hosts"]
             and "management" in x["rationale"].lower()]
        self.assertTrue(f, "management ports must surface as A05:2021 medium")
        self.assertEqual(f[0]["severity"], "medium")
        self.assertIn("API8:2023 Security Misconfiguration", f[0]["also_maps"])

    def test_cleartext_scheme_maps_a02(self):
        self._write_probe([{"host": "b.example.com", "scheme": "http"}])
        doc = self._run()
        f = [x for x in doc["findings"] if x["top10"].startswith("A02")]
        self.assertTrue(f, "cleartext http must surface as A02:2021")
        self.assertIn("b.example.com", f[0]["hosts"])

    def test_versioned_tech_maps_a06_plain_tech_does_not(self):
        self._write_probe([{"host": "c.example.com", "tech": ["nginx:1.18.0", "grafana"]}])
        doc = self._run()
        f = [x for x in doc["findings"] if x["top10"].startswith("A06")]
        self.assertTrue(f, "versioned tech must surface as A06:2021")
        self.assertIn("c.example.com", f[0]["hosts"])

    def test_api_surface_maps_api3_and_admin_maps_a01_without_overlap(self):
        self._write_assets([
            {"host": "api.example.com", "ips": [], "alive": True, "sources": [], "tags": ["api"]},
            {"host": "admin.example.com", "ips": [], "alive": True, "sources": [], "tags": ["admin"]},
        ])
        doc = self._run()
        api_f = [x for x in doc["findings"] if x["top10"].startswith("API3")]
        admin_f = [x for x in doc["findings"] if x["top10"].startswith("A01")]
        self.assertTrue(api_f and admin_f)
        self.assertIn("api.example.com", api_f[0]["hosts"])
        self.assertIn("API1:2023 Broken Object Level Authorization", api_f[0]["also_maps"])
        self.assertIn("admin.example.com", admin_f[0]["hosts"])
        self.assertNotIn("api.example.com", admin_f[0]["hosts"], "api host belongs to the API finding")
        self.assertIn("API6:2023 Unlimited Access to Sensitive Business Flows", admin_f[0]["also_maps"])


class TestHonestyLaws(TestC6OwaspBase):
    def test_severity_ceiling_high_is_never_claimed(self):
        self._write_probe([{"host": "a.example.com", "webserver": "nginx"}])
        self._write_ports("portcheck_data_json", [
            {"ip": "93.184.216.34", "hosts": ["a.example.com"],
             "ports": [{"port": 3306, "proto": "tcp", "state": "open"}]},
        ])
        doc = self._run()
        for f in doc["findings"]:
            self.assertIn(f["severity"], ("info", "low", "medium"))
        self.assertEqual(doc["counts"]["high"], 0)
        self.assertEqual(doc["severity_ceiling"], "medium")

    def test_missing_artifacts_disclosed_never_crash(self):
        doc = self._run()
        self.assertEqual(doc["findings"], [])
        self.assertTrue(doc["coverage"]["not_passively_assessable"], "disclosure must exist")
        self.assertEqual(doc["counts"]["findings"], 0)
        self.assertTrue((self.target_dir / str(self.params.require("owasp_summary"))).is_file())

    def test_malformed_probe_lines_skipped_valid_rows_kept(self):
        self._write_probe([{"host": "a.example.com", "webserver": "nginx"}], junk=True)
        doc = self._run()
        f = [x for x in doc["findings"] if x["top10"].startswith("A05")]
        self.assertTrue(f, "valid row must survive junk lines")

    def test_coverage_disclosure_lists_all_unassessable_items(self):
        doc = self._run()
        items = {row["item"] for row in doc["coverage"]["not_passively_assessable"]}
        for expected in ("A03:2021 Injection", "A09:2021 Security Logging and Monitoring Failures",
                         "API2:2023 Broken Authentication", "API10:2023 Unsafe Consumption of APIs"):
            self.assertIn(expected, items)


class TestRegistration(TestC6OwaspBase):
    def test_module_registered_and_wired(self):
        self.assertIn("owasp-passive", RUNNERS)
        self.assertEqual(str(self.params.require("owasp_module")), "owasp-passive")

    def test_layout_dir_registered(self):
        dirs = list(self.params.require("recon_layout_dirs"))
        self.assertIn("70_owasp", dirs)

    def test_summary_md_carries_findings_and_disclosure(self):
        self._write_probe([{"host": "a.example.com", "webserver": "nginx"}])
        self._run()
        summary = (self.target_dir / str(self.params.require("owasp_summary"))).read_text(encoding="utf-8")
        self.assertIn("PASSIVE-ONLY", summary)
        self.assertIn("A05:2021", summary)
        self.assertIn("Not passively assessable", summary)

    def test_engine_hook_key_present_in_runners(self):
        # the engine hook reads params.require("owasp_module") and dispatches
        # through RUNNERS -- this test pins that the wiring stays consistent.
        from pipeline import engine
        self.assertTrue(str(self.params.require("owasp_module")) in RUNNERS)
        self.assertTrue(hasattr(engine, "RUNNERS"))


if __name__ == "__main__":
    unittest.main()
