"""FFUF-3 (spec v1.9 §8, Option-1 item 1) unit proof — B3 first sub-step.

No docker, no network. Mirrors the pure-function harness style of
tests/test_ffuf_label.py and tests/test_dns_freshness.py:

  1. flag rule      : a NON-FILTERED answer on a DNS-dead name lands flagged
                      (misconfig_suspect=true, dns_status="dead", alive=null);
                      a filtered/autocalib artifact (label NOT in the job
                      wordlist — REM4-R1 calibration-drop discipline) is
                      counted as suppressed and NEVER flagged.
  2. probe binding  : -u is bound to the alive in-scope base with
                      "Host: FUZZ.<dead-name>"; the dead name is never
                      resolved directly (no dnsx invoke happens).
  3. base-host set  : FFUF-1 records UNION DNSR-3 unresolved, with both input
                      counts logged BEFORE any probe; resolved names are not
                      probed.
  4. skip path      : no alive base -> explicit log line, zero probes,
                      never silent.
  5. output         : data.json at 15_vhosts/ffuf-3/ with module "ffuf-3" and
                      exactly the spec root keys; bases[] carry host/ip/alive.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pipeline.modules.ffuf3 as ffuf3_module
from pipeline.modules.ffuf3 import _alive_bases, run_ffuf3


class _Gate:
    def enforce(self, target_dir: Path, host: str) -> bool:
        return True


class _Params:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.settings = {
            "ffuf_data_json": "10_subdomains/ffuf/data.json",
            "dnsr_data_json": "20_dns/dnsx/data.json",
            "ffuf3_data_json": "15_vhosts/ffuf-3/data.json",
            "ffuf3_summary": "15_vhosts/ffuf-3/summary.md",
            "ffuf_vhost_wordlist_rel": "wordlists/effective-FFUF-2-test.txt",
            "max_total_requests": 5000000,
            "recon_container_mount": "/recon",
            "run_log": "logs/run.log",
            "schema_version": 1,
        }

    def require(self, key: str):
        if key in self.settings:
            return self.settings[key]
        raise KeyError(f"unnamed parameter {key!r}")


class _Result:
    exit_code = 0
    stdout = ""
    stderr = ""


class _ProbeSpyAdapter:
    """Records ffuf-3 invokes; returns one canned ffuf JSON payload per job."""

    def __init__(self, hits_by_call: list[list[dict]] | None = None) -> None:
        self.calls: list[dict] = []
        self._hits = hits_by_call or []
        self._n = 0

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


def _write_ffuf_doc(root: Path, hosts: list[dict]) -> None:
    p = root / "10_subdomains/ffuf/data.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"schema_version": 1, "module": "ffuf", "hosts": hosts, "vhosts": []}), encoding="utf-8")


def _write_dnsr_doc(root: Path, resolved: list[dict]) -> None:
    p = root / "20_dns/dnsx/data.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "module": "dns-resolve",
                "resolved": resolved,
                "candidates": {"brute": 0, "perms": 0, "valid": 0},
                "wildcard_suspects": [],
            }
        ),
        encoding="utf-8",
    )


ALIVE_BASE_HOST = "app.example.test"
ALIVE_BASE_ROW = {
    "host": ALIVE_BASE_HOST,
    "ips": ["93.184.216.34"],
    "resolution_status": "resolved",
    "resolution_reason": None,
}
DEAD_NAME = "dead.example.test"
DEAD_ROW = {
    "host": DEAD_NAME,
    "ips": [],
    "resolution_status": "unresolved",
    "resolution_reason": "no A/AAAA",
}


def _patch_wordlist(monkey_root: Path, labels: list[str]):
    """Patch materialize_effective/copy_into_target with a fixed label list."""
    wl = monkey_root / "effective-FFUF-2-test.txt"
    wl.write_text("\n".join(labels) + "\n", encoding="utf-8")

    def fake_materialize(params, task):
        return wl

    def fake_copy(params, target_dir, src, rel):
        dst = target_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        return dst

    return fake_materialize, fake_copy


class TestFfuf3(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self._saved = (
            ffuf3_module.materialize_effective,
            ffuf3_module.copy_into_target,
        )
        fake_m, fake_c = _patch_wordlist(
            self.root, ["dev", "mail", "staging", "vpn", "webmail"]
        )
        ffuf3_module.materialize_effective = fake_m
        ffuf3_module.copy_into_target = fake_c

    def tearDown(self) -> None:
        ffuf3_module.materialize_effective, ffuf3_module.copy_into_target = self._saved
        self._tmp.cleanup()

    def _run(self, adapter, target="example.test"):
        params = _Params(self.root)
        partial: list[str] = []
        payload = run_ffuf3(
            params,
            _Gate(),
            adapter,
            self.root,
            target,
            {"target_domain": target},
            1,
            None,
            partial,
        )
        return payload, partial

    def test_flag_rule_row_and_suppression(self):
        _write_ffuf_doc(
            self.root,
            [
                {"fqdn": ALIVE_BASE_HOST, "alive": True, "http_status": 200},
                {"fqdn": DEAD_NAME, "alive": False},
            ],
        )
        _write_dnsr_doc(self.root, [ALIVE_BASE_ROW, DEAD_ROW])
        hits = [
            # genuine non-filtered answer: label recovered from Host, in wordlist
            {"fuzz": "dev", "host": f"dev.{DEAD_NAME}", "url": f"http://dev.{DEAD_NAME}/", "status": 200, "length": 17},
            # autocalib artifact: FUZZ token NOT in the job wordlist -> suppressed
            {"fuzz": "XnRbiBeJ", "host": f"XnRbiBeJ.{DEAD_NAME}", "url": f"http://XnRbiBeJ.{DEAD_NAME}/", "status": 403, "length": 0},
        ]
        adapter = _ProbeSpyAdapter([hits])
        payload, _ = self._run(adapter)

        self.assertEqual(len(adapter.calls), 1)
        call = adapter.calls[0]
        self.assertEqual(call["module"], "ffuf-3")
        self.assertEqual(call["extra"]["ffuf_url"], f"http://{ALIVE_BASE_HOST}")
        self.assertEqual(call["extra"]["ffuf_host_header"], f"Host: FUZZ.{DEAD_NAME}")

        self.assertEqual(len(payload["vhosts"]), 1)
        row = payload["vhosts"][0]
        self.assertEqual(row["base_host"], DEAD_NAME)
        self.assertEqual(row["vhost"], f"dev.{DEAD_NAME}")
        self.assertIsNone(row["alive"])  # asset-promotion ruling: never promoted
        self.assertEqual(row["http_status"], 200)
        self.assertEqual(row["length"], 17)
        self.assertTrue(row["misconfig_suspect"])
        self.assertEqual(row["dns_status"], "dead")
        self.assertEqual(payload["suppressed"], 1)
        self.assertEqual(
            set(payload.keys()), {"schema_version", "module", "vhosts", "bases", "suppressed"}
        )
        self.assertEqual(payload["module"], "ffuf-3")
        self.assertEqual(payload["bases"], [{"host": ALIVE_BASE_HOST, "ip": "93.184.216.34", "alive": True}])

        data = json.loads((self.root / "15_vhosts/ffuf-3/data.json").read_text(encoding="utf-8"))
        self.assertEqual(data["module"], "ffuf-3")

    def test_base_set_union_counts_and_dead_only_probing(self):
        _write_ffuf_doc(
            self.root,
            [
                {"fqdn": ALIVE_BASE_HOST, "alive": True},
                {"fqdn": DEAD_NAME, "alive": False},
                {"fqdn": "perm-only.example.test", "alive": None},
            ],
        )
        _write_dnsr_doc(
            self.root,
            [
                ALIVE_BASE_ROW,
                DEAD_ROW,
                {"host": "dnsr-unresolved.example.test", "ips": [], "resolution_status": "unresolved", "resolution_reason": "no A/AAAA"},
            ],
        )
        adapter = _ProbeSpyAdapter([[], []])
        payload, _ = self._run(adapter)

        # union = {app, dead, perm-only, dnsr-unresolved}; dead = {dead, dnsr-unresolved}
        probed = [c["extra"]["ffuf_host_header"] for c in adapter.calls]
        self.assertEqual(
            probed,
            [f"Host: FUZZ.dead.example.test", "Host: FUZZ.dnsr-unresolved.example.test"],
        )
        self.assertEqual(payload["suppressed"], 0)
        summary = (self.root / "15_vhosts/ffuf-3/summary.md").read_text(encoding="utf-8")
        self.assertIn("ffuf1_records=3", summary)
        self.assertIn("dnsr_unresolved=2", summary)
        self.assertIn("union=4", summary)
        self.assertIn("dead_probed=2", summary)

    def test_no_alive_base_skips_never_silent(self):
        _write_ffuf_doc(self.root, [{"fqdn": DEAD_NAME, "alive": False}])
        _write_dnsr_doc(self.root, [DEAD_ROW])
        adapter = _ProbeSpyAdapter()
        payload, _ = self._run(adapter)

        self.assertEqual(adapter.calls, [])  # zero probes
        self.assertEqual(payload["vhosts"], [])
        self.assertEqual(payload["bases"], [])
        run_log = (self.root / "logs/run.log").read_text(encoding="utf-8")
        self.assertIn("ffuf-3 skipped: no alive in-scope base", run_log)

    def test_alive_bases_prefers_apex(self):
        ffuf_doc = {
            "hosts": [
                {"fqdn": "www.example.test", "alive": True},
                {"fqdn": "example.test", "alive": True},
            ]
        }
        dnsr_doc = {
            "resolved": [
                {"host": "example.test", "ips": ["1.1.1.1"], "resolution_status": "resolved"},
                {"host": "www.example.test", "ips": ["2.2.2.2"], "resolution_status": "resolved"},
            ]
        }
        bases = _alive_bases(ffuf_doc, dnsr_doc, _Gate(), Path("."), "example.test")
        self.assertEqual([b["host"] for b in bases], ["example.test", "www.example.test"])
        self.assertEqual(bases[0]["ip"], "1.1.1.1")

    def test_alive_base_requires_resolved_ip_and_alive(self):
        ffuf_doc = {
            "hosts": [
                {"fqdn": "a.example.test", "alive": True},    # no resolved IP
                {"fqdn": "b.example.test", "alive": False},   # resolved but not alive
                {"fqdn": "c.example.test", "alive": True},    # qualifies
            ]
        }
        dnsr_doc = {
            "resolved": [
                {"host": "a.example.test", "ips": [], "resolution_status": "unresolved"},
                {"host": "b.example.test", "ips": ["4.4.4.4"], "resolution_status": "resolved"},
                {"host": "c.example.test", "ips": ["5.5.5.5"], "resolution_status": "resolved"},
            ]
        }
        bases = _alive_bases(ffuf_doc, dnsr_doc, _Gate(), Path("."), "example.test")
        self.assertEqual([b["host"] for b in bases], ["c.example.test"])


if __name__ == "__main__":
    unittest.main()
