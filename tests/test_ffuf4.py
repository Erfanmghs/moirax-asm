"""FFUF-4: vhost enum on HTTP-like ports after PORT-SWEEP."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pipeline.modules.ffuf4 as ffuf4_module
from pipeline.modules import RUNNERS
from pipeline.modules.ffuf4 import http_vhost_jobs, run_ffuf4
from pipeline.params import Params


class _Gate:
    includes = ["*.example.com"]

    def enforce(self, target_dir: Path, host: str) -> bool:
        return str(host).endswith(".example.com") or host == "example.com"

    def validate_candidate(self, host: str):
        return True, None

    def log_rejection(self, *args, **kwargs) -> None:
        return None


class _Params:
    def __init__(self, root: Path, **overrides) -> None:
        self.root = root
        self.settings = {
            "portsweep_data_json": "30_ports/naabu-full/data.json",
            "portcheck_data_json": "30_ports/naabu-light/data.json",
            "ffuf4_data_json": "15_vhosts/ffuf-4/data.json",
            "ffuf4_summary": "15_vhosts/ffuf-4/summary.md",
            "ffuf_vhost_wordlist_rel": "wordlists/effective-FFUF-2-test.txt",
            "ffuf4_max_jobs": 200,
            "vhost_http_ports": "80,8080,3000",
            "vhost_https_ports": "443,8443",
            "max_total_requests": 5000000,
            "recon_container_mount": "/recon",
            "run_log": "logs/run.log",
            "schema_version": 1,
            "assets_relpath": "00_assets/assets.json",
            "assets_summary_relpath": "00_assets/summary.md",
            "out_of_scope_log": "logs/out_of_scope.log",
            "merge_wildcard_reason": "wildcard",
            "merge_catchall_reason": "catchall",
        }
        self.settings.update(overrides)

    def require(self, key: str):
        if key in self.settings:
            return self.settings[key]
        raise KeyError(f"unnamed parameter {key!r}")


class _Result:
    exit_code = 0
    stdout = ""
    stderr = ""


class _ProbeSpyAdapter:
    def __init__(self, hits_by_call: list[list[dict]] | None = None, vhost_on: bool = True) -> None:
        self.calls: list[dict] = []
        self._hits = hits_by_call or []
        self._n = 0
        self._vhost_on = vhost_on

    def enabled(self, name: str) -> bool:
        return bool(self._vhost_on) if name == "ffuf-vhost" else True

    def invoke(self, name, module, extra=None, **kwargs):
        self.calls.append({"tool": name, "module": module, "extra": dict(extra or {})})
        hits = self._hits[self._n] if self._n < len(self._hits) else []
        self._n += 1
        res = _Result()
        res.stdout = json.dumps(
            [
                {
                    "input": {"FUZZ": h["fuzz"]},
                    "host": h["host"],
                    "url": h["url"],
                    "status": h.get("status", 200),
                    "length": h.get("length", 17),
                }
                for h in hits
            ]
        )
        return res


def _patch_wordlist(root: Path, labels: list[str]):
    wl = root / "effective-FFUF-2-test.txt"
    wl.write_text("\n".join(labels) + "\n", encoding="utf-8")

    def fake_materialize(params, task):
        return wl

    def fake_copy(params, target_dir, src, rel):
        dst = target_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return dst

    return fake_materialize, fake_copy


def _write_sweep(root: Path, scans: list[dict], services: list[dict] | None = None) -> None:
    path = root / "30_ports/naabu-full/data.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "module": "port-sweep",
                "scans": scans,
                "services": services or [],
            }
        ),
        encoding="utf-8",
    )


class TestFfuf4Jobs(unittest.TestCase):
    def test_http_like_ports_only(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        _write_sweep(
            tmp,
            [
                {
                    "ip": "1.2.3.4",
                    "hosts": ["www.example.com"],
                    "ports": [
                        {"port": 22, "proto": "tcp", "state": "open"},
                        {"port": 80, "proto": "tcp", "state": "open"},
                        {"port": 443, "proto": "tcp", "state": "open"},
                        {"port": 8080, "proto": "tcp", "state": "open"},
                        {"port": 9999, "proto": "tcp", "state": "open"},
                    ],
                }
            ],
            services=[{"ip": "1.2.3.4", "port": 3000, "service": "http"}],
        )
        # 3000 not in open_ports -- hinted service only counts if the port is open
        jobs = http_vhost_jobs(_Params(tmp), tmp, "example.com")
        triples = {(j["ip"], j["port"], j["scheme"]) for j in jobs}
        self.assertEqual(
            triples,
            {
                ("1.2.3.4", 80, "http"),
                ("1.2.3.4", 443, "https"),
                ("1.2.3.4", 8080, "http"),
            },
        )

    def test_nmap_http_hint_adds_unlisted_open_port(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        _write_sweep(
            tmp,
            [
                {
                    "ip": "1.2.3.4",
                    "hosts": ["www.example.com"],
                    "ports": [{"port": 8888, "proto": "tcp", "state": "open"}],
                }
            ],
            services=[{"ip": "1.2.3.4", "port": 8888, "service": "http-proxy"}],
        )
        jobs = http_vhost_jobs(_Params(tmp), tmp, "example.com")
        self.assertEqual(jobs[0]["port"], 8888)
        self.assertEqual(jobs[0]["scheme"], "http")


class TestFfuf4Run(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._saved = (
            ffuf4_module.materialize_effective,
            ffuf4_module.copy_into_target,
        )
        fake_m, fake_c = _patch_wordlist(self.root, ["dev", "mail"])
        ffuf4_module.materialize_effective = fake_m
        ffuf4_module.copy_into_target = fake_c

    def tearDown(self) -> None:
        ffuf4_module.materialize_effective, ffuf4_module.copy_into_target = self._saved
        self._tmp.cleanup()

    def _run(self, adapter, **overrides):
        params = _Params(self.root, **overrides)
        partial: list[str] = []
        payload = run_ffuf4(
            params,
            _Gate(),
            adapter,
            self.root,
            "example.com",
            {"target_domain": "example.com"},
            1,
            None,
            partial,
        )
        return payload, partial

    def test_binds_ffuf_to_ip_port_not_hostname(self) -> None:
        _write_sweep(
            self.root,
            [
                {
                    "ip": "1.2.3.4",
                    "hosts": ["www.example.com"],
                    "ports": [{"port": 8080, "proto": "tcp", "state": "open"}],
                }
            ],
        )
        adapter = _ProbeSpyAdapter(
            [
                [
                    {
                        "fuzz": "dev",
                        "host": "dev.example.com",
                        "url": "http://1.2.3.4:8080/",
                        "status": 200,
                        "length": 42,
                    }
                ]
            ]
        )
        payload, _ = self._run(adapter)
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(adapter.calls[0]["module"], "ffuf-4")
        self.assertEqual(adapter.calls[0]["extra"]["ffuf_url"], "http://1.2.3.4:8080")
        self.assertEqual(adapter.calls[0]["extra"]["ffuf_host_header"], "Host: FUZZ.example.com")
        self.assertEqual(payload["module"], "ffuf-4")
        self.assertEqual(len(payload["vhosts"]), 1)
        row = payload["vhosts"][0]
        self.assertEqual(row["vhost"], "dev.example.com")
        self.assertEqual(row["port"], 8080)
        self.assertTrue(row["misconfig_suspect"])
        data = json.loads((self.root / "15_vhosts/ffuf-4/data.json").read_text(encoding="utf-8"))
        self.assertEqual(data["module"], "ffuf-4")
        assets = json.loads((self.root / "00_assets/assets.json").read_text(encoding="utf-8"))
        hosts = {a["host"] for a in assets["assets"]}
        self.assertIn("dev.example.com", hosts)

    def test_skip_when_vhost_tool_off(self) -> None:
        _write_sweep(
            self.root,
            [{"ip": "1.2.3.4", "hosts": ["www.example.com"], "ports": [{"port": 80}]}],
        )
        adapter = _ProbeSpyAdapter(vhost_on=False)
        payload, _ = self._run(adapter)
        self.assertEqual(adapter.calls, [])
        self.assertEqual(payload["skipped"], "ffuf-vhost disabled")

    def test_job_cap_disclosed(self) -> None:
        _write_sweep(
            self.root,
            [
                {
                    "ip": "1.2.3.4",
                    "hosts": ["www.example.com"],
                    "ports": [{"port": 80}, {"port": 8080}, {"port": 3000}],
                }
            ],
        )
        adapter = _ProbeSpyAdapter()
        payload, partial = self._run(adapter, ffuf4_max_jobs=1)
        self.assertEqual(len(adapter.calls), 1)
        self.assertIn("ffuf4_job_cap", partial)
        self.assertIn("ffuf-4 job cap", (self.root / "logs/run.log").read_text(encoding="utf-8"))


class TestFfuf4Wiring(unittest.TestCase):
    def test_registered_not_in_active_branch(self) -> None:
        self.assertIn("ffuf-4", RUNNERS)
        params = Params(Path(__file__).resolve().parents[1])
        self.assertEqual(str(params.require("ffuf4_module")), "ffuf-4")
        self.assertNotIn("ffuf-4", params.require("active_branch_modules"))
        self.assertIn("ffuf-4", params.require("pipeline_modules"))
        self.assertIn("15_vhosts/ffuf-4", params.require("recon_layout_dirs"))


if __name__ == "__main__":
    unittest.main()
