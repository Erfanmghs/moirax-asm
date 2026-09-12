"""B7 REPORTING unit proof (spec section 10) -- deterministic, no network."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.params import Params
from pipeline.reporting import (
    CSV_CLASSES,
    collect,
    generate_all,
    scope_digest,
    verify_bundle,
)

_ROOT = Path(__file__).resolve().parents[1]


def _params() -> Params:
    return Params(_ROOT)


def _vehicle_dir() -> tuple[Params, Path]:
    """Synthetic canonical layout mirroring section 6.3 module outputs."""
    tmp = Path(tempfile.mkdtemp()) / "example.com"
    (tmp / "00_assets").mkdir(parents=True)
    (tmp / "10_subdomains" / "passive").mkdir(parents=True)
    (tmp / "30_ports" / "naabu-full").mkdir(parents=True)
    (tmp / "00_assets" / "assets.json").write_text(json.dumps({
        "schema_version": 1,
        "assets": [
            {"host": "dev.example.com", "ips": ["1.1.1.1"], "alive": True, "length": 1234, "sources": ["subfinder", "crtsh"], "tags": ["dev"]},
            # Resolves to an in-scope IP but the HTTP probe did not answer:
            # still a LIVE asset (must never be counted/reported as dead).
            {"host": "api.example.com", "ips": ["2.2.2.2"], "alive": False, "sources": ["subfinder"], "tags": []},
            {"host": "www.example.com", "ips": ["3.3.3.3"], "alive": True, "length": 88, "sources": ["crtsh"], "tags": []},
        ],
    }), encoding="utf-8")
    (tmp / "10_subdomains" / "passive" / "data.json").write_text(json.dumps({
        "schema_version": 1, "module": "passive-recon",
        "candidates": [], "counts": {"candidates": 3, "alive": 2},
        "passive_ips": [{"ip": "9.9.9.9", "sources": ["crtsh"]}],
    }), encoding="utf-8")
    (tmp / "30_ports" / "naabu-full" / "data.json").write_text(json.dumps({
        "schema_version": 1, "module": "port-sweep",
        "scans": [{"host": "dev.example.com", "ip": "1.1.1.1", "ports": [{"port": 443, "proto": "tcp", "state": "open"}]}],
        "services": [{"ip": "1.1.1.1", "port": 443, "proto": "tcp", "service": "https"}],
        "counts": {"unique_ips_scanned": 1},
    }), encoding="utf-8")
    (tmp / "diff.json").write_text(json.dumps({"added": {"hosts": [{"host": "dev.example.com"}]}}, ), encoding="utf-8")
    return _params(), tmp


class TestPrecisionContract(unittest.TestCase):
    """section 10.2: every format FROM canonical data.json; embeds stamp + scope digest."""

    def test_scope_digest_stable(self):
        p1 = scope_digest(_params())
        p2 = scope_digest(_params())
        self.assertEqual(p1, p2)
        self.assertEqual(len(p1), 64)

    def test_collect_from_canonical_only(self):
        params, td = _vehicle_dir()
        bundle = collect(params, td, "20260101T000000Z")
        self.assertEqual(bundle["counts"]["hosts"], 3)
        # All 3 resolve to an in-scope IP => all 3 are live assets, even though
        # api.example.com's HTTP probe reported alive=False (HTTP-down != dead).
        self.assertEqual(bundle["counts"]["alive_hosts"], 3)
        self.assertEqual(bundle["counts"]["module_docs"], 2)
        self.assertEqual(bundle["scope_digest"], scope_digest(params))
        self.assertEqual(bundle["run_timestamp"], "20260101T000000Z")

    def test_ip_bearing_host_is_never_dead_but_no_ip_is(self):
        """Regression: a resolved (IP-bearing) host is a live asset even when
        the HTTP probe said alive=False; only a host with NO IP is dead."""
        tmp = Path(tempfile.mkdtemp()) / "example.com"
        (tmp / "00_assets").mkdir(parents=True)
        (tmp / "00_assets" / "assets.json").write_text(json.dumps({
            "schema_version": 1,
            "assets": [
                {"host": "ip-http-down.example.com", "ips": ["5.5.5.5"], "alive": False, "sources": ["dnsx"]},
                {"host": "ip-no-probe.example.com", "ips": ["6.6.6.6"], "alive": None, "sources": ["dnsx"]},
                {"host": "dead.example.com", "ips": [], "alive": False, "sources": ["ffuf-3"]},
            ],
        }), encoding="utf-8")
        params = _params()
        bundle = collect(params, tmp, "20260101T000000Z")
        self.assertEqual(bundle["counts"]["hosts"], 3)
        self.assertEqual(bundle["counts"]["alive_hosts"], 2, "both IP-bearing hosts are alive; only the no-IP host is dead")
        generate_all(params, tmp, "20260101T000000Z")
        export = json.loads((tmp / "90_report" / "export.json").read_text(encoding="utf-8"))
        alive_by_host = {h["host"]: h["alive"] for h in export["hosts"]}
        self.assertTrue(alive_by_host["ip-http-down.example.com"], "IP-bearing, HTTP-down host must export alive")
        self.assertTrue(alive_by_host["ip-no-probe.example.com"], "IP-bearing, unprobed host must export alive")
        self.assertFalse(alive_by_host["dead.example.com"], "a host with no IP is genuinely dead")
        csv_text = (tmp / "90_report" / "export.csv").read_text(encoding="utf-8")
        self.assertIn("hosts,ip-http-down.example.com,5.5.5.5,True", csv_text)

    def test_all_formats_agree_on_counts(self):
        """Companion B7 acceptance: counts equal across md/html/csv/json/pdf."""
        params, td = _vehicle_dir()
        result = generate_all(params, td, "20260101T000000Z")
        report_dir = td / "90_report"
        md = (report_dir / "report.md").read_text(encoding="utf-8")
        html = (report_dir / "report.html").read_text(encoding="utf-8")
        csv_text = (report_dir / "export.csv").read_text(encoding="utf-8")
        export = json.loads((report_dir / "export.json").read_text(encoding="utf-8"))
        pdf_bytes = (report_dir / "report.pdf").read_bytes()
        self.assertIn("hosts: 3 (alive: 3)", md)
        self.assertIn("run timestamp: 20260101T000000Z", md)
        self.assertIn(bundle_scope(params), md)
        self.assertIn("hosts: 3", html)
        self.assertIn("run timestamp: 20260101T000000Z", html)
        self.assertIn(bundle_scope(params), html)
        host_csv_rows = [l for l in csv_text.splitlines() if l.startswith("hosts,")]
        self.assertEqual(len(host_csv_rows), 3, "csv flat rows == hosts count")
        self.assertEqual(export["counts"]["hosts"], 3)
        self.assertEqual(pdf_bytes[:5], b"%PDF-", "real PDF rendered")
        self.assertIn(b"hosts: 3", _pdf_text(pdf_bytes), "pdf carries the same counts")
        for name in ("report_md", "report_html", "export_csv", "export_json", "report_pdf"):
            self.assertIn(name, result["files"])

    def test_csv_classes_complete(self):
        params, td = _vehicle_dir()
        generate_all(params, td, "20260101T000000Z")
        csv_text = (td / "90_report" / "export.csv").read_text(encoding="utf-8")
        # classes WITH rows in the fixture must appear; empty classes emit no rows
        for cls in ("hosts", "ports", "services", "passive_ips"):
            self.assertIn(cls + ",", csv_text)
        self.assertNotIn("vhosts,", csv_text, "zero-row class emits zero rows (precision)")

    def test_theme_in_html(self):
        params, td = _vehicle_dir()
        generate_all(params, td, "20260101T000000Z")
        html = (td / "90_report" / "report.html").read_text(encoding="utf-8")
        self.assertIn("#070b12", html, "dashboard dark palette embedded")
        self.assertIn("#0a0e14", html, "legacy palette token kept for theme contract")
        self.assertIn("badge", html)
        self.assertIn("<th>length</th>", html)
        self.assertIn("1234", html)
        self.assertIn('id="f-q"', html)
        self.assertIn("Attack Surface Management", html)
        csv_text = (td / "90_report" / "export.csv").read_text(encoding="utf-8")
        self.assertIn("length", csv_text.splitlines()[0])

    def test_diff_badge_new_host(self):
        params, td = _vehicle_dir()
        generate_all(params, td, "20260101T000000Z")
        html = (td / "90_report" / "report.html").read_text(encoding="utf-8")
        self.assertIn('"is_new": true', html, "diff badge for added host is in the report payload")
        self.assertIn("<th>Port</th>", html)
        self.assertIn("<th>Product</th>", html)
        self.assertIn("<th>Version</th>", html)
        self.assertNotIn("<th>ips</th>", html)


class TestReportDropsCatchall(unittest.TestCase):
    def test_wildcard_only_host_omitted_from_bundle(self):
        tmp = Path(tempfile.mkdtemp()) / "example.com"
        (tmp / "00_assets").mkdir(parents=True)
        (tmp / "20_dns" / "dnsx").mkdir(parents=True)
        (tmp / "00_assets" / "assets.json").write_text(json.dumps({
            "schema_version": 1,
            "assets": [
                {"host": "example.com", "ips": ["9.9.9.9"], "alive": True, "sources": ["dnsx"]},
                {"host": "app2.example.com", "ips": ["9.9.9.9"], "alive": True, "sources": ["dnsx"]},
            ],
        }), encoding="utf-8")
        (tmp / "20_dns" / "dnsx" / "data.json").write_text(json.dumps({
            "schema_version": 1,
            "module": "dns-resolve",
            "wildcard_ips": ["9.9.9.9"],
            "resolved": [],
        }), encoding="utf-8")
        params = _params()
        bundle = collect(params, tmp, "20260101T000000Z")
        hosts = {h["host"] for h in bundle["hosts"]}
        self.assertIn("example.com", hosts)
        self.assertNotIn("app2.example.com", hosts)
        self.assertEqual(bundle["counts"]["hosts"], 1)


class TestTamperCheck(unittest.TestCase):
    """Companion B7 acceptance: a tampered data.json fails the digest check."""

    def test_verify_ok_when_untouched(self):
        params, td = _vehicle_dir()
        generate_all(params, td, "20260101T000000Z")
        ok, reason = verify_bundle(params, td)
        self.assertTrue(ok, reason)

    def test_tampered_data_json_fails(self):
        params, td = _vehicle_dir()
        generate_all(params, td, "20260101T000000Z")
        path = td / "10_subdomains" / "passive" / "data.json"
        doc = json.loads(path.read_text(encoding="utf-8"))
        doc["counts"]["candidates"] = 999
        path.write_text(json.dumps(doc), encoding="utf-8")
        ok, reason = verify_bundle(params, td)
        self.assertFalse(ok, "tampered data.json MUST fail the digest check")
        self.assertIn("tampered", reason)

    def test_scope_change_fails(self):
        params, td = _vehicle_dir()
        generate_all(params, td, "20260101T000000Z")
        ok, _ = verify_bundle(params, td)
        self.assertTrue(ok)
        manifest_path = td / "90_report" / "report_manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["scope_digest"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        ok, reason = verify_bundle(params, td)
        self.assertFalse(ok)
        self.assertIn("scope", reason)

    def test_verify_without_report(self):
        params, td = _vehicle_dir()
        ok, reason = verify_bundle(params, td)
        self.assertFalse(ok)
        self.assertIn("no manifest", reason)


class TestWiring(unittest.TestCase):
    def test_engine_generates_on_run_end(self):
        text = (_ROOT / "pipeline" / "engine.py").read_text(encoding="utf-8")
        self.assertIn("generate_all(params, target_dir, stamp)", text)
        self.assertIn("report: generated=", text, "never-silent ledger line")
        # REM24 (run #36 evidence): anomaly-terminated runs get reports too (section 10.1)
        terminal_block = text.split("terminal = {")[1].split("}")[0]
        for status_param in ("run_status_completed", "run_status_partial", "run_status_failed", "run_status_anomaly", "run_status_stopped"):
            self.assertIn(status_param, terminal_block, f"{status_param} must be a report-generating terminal status")

    def test_dashboard_on_demand_endpoints(self):
        text = (_ROOT / "dashboard" / "app.py").read_text(encoding="utf-8")
        self.assertIn("/api/report/{target}", text)
        self.assertIn("report_generate", text)


def bundle_scope(params: Params) -> str:
    return scope_digest(params)


def _pdf_text(raw: bytes) -> bytes:
    """Decompress the first FlateDecode content stream (ASCII85-wrapped) so the
    text layer can be asserted -- the precision check reads REAL rendered text."""
    import base64
    import re
    import zlib

    match = re.search(rb"stream\r?\n(.*?)endstream", raw, re.DOTALL)
    assert match, "pdf has no content stream"
    decoded = base64.a85decode(match.group(1).strip(), adobe=True)
    return zlib.decompress(decoded)


if __name__ == "__main__":
    unittest.main()
