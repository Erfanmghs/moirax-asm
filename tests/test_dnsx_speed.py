"""False QPS collapse, catch-all skip, live RESULTS extract."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pipeline.adapter import InvokeResult
from pipeline.history import extract_live_classes
from pipeline.load_balance import LoadBalancer, _canary_answers
from pipeline.live_status import live_status
from pipeline.params import Params
from pipeline.recon_depth import dnsx_job_qps, dnsx_parent_worker_count, recursion_parents

_ROOT = Path(__file__).resolve().parents[1]


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def time(self) -> float:
        return self.t

    def sleep(self, sec: float) -> None:
        self.t += float(sec)


class _CanaryAdapter:
    def __init__(self, stdout: str, exit_code: int = 0) -> None:
        self.stdout = stdout
        self.exit_code = exit_code
        self.clock = _Clock()
        self.breaker = type(
            "B",
            (),
            {
                "force_pause": lambda *a, **k: None,
                "apply_limit": lambda *a, **k: a[-1] if a else 1,
            },
        )()

    def invoke(self, *args, **kwargs):
        self.clock.t += 20.0
        return InvokeResult(
            tool="dnsx-canary",
            argv=[],
            docker_cmd=[],
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr="",
            duration_sec=20.0,
            used_fallback=False,
            data_json=None,
        )


class TestSplitQps(unittest.TestCase):
    def test_workers_at_cap(self):
        params = Params(_ROOT)
        params.settings["dnsx_parallel_parents"] = 4
        params.settings["dnsx_max_qps"] = 5000
        self.assertEqual(dnsx_parent_worker_count(params, 20, 5000), 4)
        self.assertEqual(dnsx_parent_worker_count(params, 20, 1), 1)
        self.assertEqual(dnsx_job_qps(5000, 4), 1250)


class TestCanaryAnswersNotThrottle(unittest.TestCase):
    def test_answers_keep_qps_even_if_container_was_slow(self):
        params = Params(_ROOT)
        tmp = Path(tempfile.mkdtemp())
        adapter = _CanaryAdapter('{"host":"example.com","a":["93.184.216.34"]}\n')
        lb = LoadBalancer(params, adapter, tmp, "example.com", clock=adapter.clock)
        lb.state.qps = 1000
        lb.state.baseline_latency = 1.3
        extra = {
            "dnsx_canary_hosts": "/recon/canary.txt",
            "dnsx_resolvers": "/recon/resolvers.txt",
        }
        self.assertTrue(lb._canary("/recon/resolvers.txt", "logs/raw/dnsx-canary", extra))
        self.assertEqual(lb.state.qps, 1000)
        self.assertTrue(_canary_answers(adapter.invoke()))


class TestWildcardParents(unittest.TestCase):
    def test_skips_any_matching_wildcard_ip(self):
        resolved = {
            "api.example.com": {"ips": ["1.2.3.4"]},
            "cdn.example.com": {"ips": ["9.9.9.9", "8.8.8.8"]},
        }
        parents = recursion_parents(resolved, "example.com", 2, {"9.9.9.9"}, 100)
        self.assertEqual(parents, ["api.example.com"])


class TestLiveExtract(unittest.TestCase):
    def test_dnsx_ndjson_becomes_hosts(self):
        params = Params(_ROOT)
        tmp = Path(tempfile.mkdtemp())
        dnsx = tmp / "20_dns" / "dnsx"
        dnsx.mkdir(parents=True)
        (dnsx / "brute_l1_example.com_chunk_0.json").write_text(
            '{"host":"www.example.com","a":["93.184.216.34"]}\n',
            encoding="utf-8",
        )
        maps = extract_live_classes(params, tmp)
        self.assertIn("www.example.com", maps["hosts"])
        self.assertEqual(maps["hosts"]["www.example.com"]["ips"], ["93.184.216.34"])

    def test_catchall_ip_is_not_a_live_host(self):
        params = Params(_ROOT)
        tmp = Path(tempfile.mkdtemp()) / "example.com"
        dnsx = tmp / "20_dns" / "dnsx"
        dnsx.mkdir(parents=True)
        (tmp / str(params.require("dnsr_data_json"))).parent.mkdir(parents=True, exist_ok=True)
        (tmp / str(params.require("dnsr_data_json"))).write_text(
            '{"wildcard_ips":["9.9.9.9"],"resolved":[]}',
            encoding="utf-8",
        )
        (dnsx / "brute_l1_example.com_chunk_0.json").write_text(
            '{"host":"app2.example.com","a":["9.9.9.9"]}\n'
            '{"host":"api.example.com","a":["1.2.3.4"]}\n',
            encoding="utf-8",
        )
        maps = extract_live_classes(params, tmp)
        self.assertNotIn("app2.example.com", maps["hosts"])
        self.assertIn("api.example.com", maps["hosts"])


class TestLiveStatusLog(unittest.TestCase):
    def test_throttle_becomes_issue(self):
        params = Params(_ROOT)
        tmp = Path(tempfile.mkdtemp())
        (tmp / "logs").mkdir(parents=True)
        (tmp / "logs" / "run.log").write_text(
            "2026-09-11T17:35:52Z\tbreaker\tdns-resolve\tthrottle\terrors=0/1\tthrottle_factor=0.015625\treason=latency drift\n"
            "cmd=dnsx -d bus.snapp.ir -rl 1 -a -resp -json\n",
            encoding="utf-8",
        )
        (tmp / "state.json").write_text(
            '{"run":{"status":"running"},"breaker":{"paused":{}}}',
            encoding="utf-8",
        )
        doc = live_status(params, tmp)
        codes = {i["code"] for i in doc["issues"]}
        self.assertIn("throttle", codes)
        self.assertIn("qps_collapse", codes)


class TestScanRowHealth(unittest.TestCase):
    def test_row_carries_live_and_issues(self):
        from unittest.mock import patch

        from dashboard.service import scan_target_row

        params = Params(_ROOT)
        tmp = Path(tempfile.mkdtemp())
        (tmp / "logs").mkdir(parents=True)
        (tmp / "logs" / "run.log").write_text(
            "breaker\tdns-resolve\tthrottle\tthrottle_factor=0.01\treason=latency drift\n"
            "cmd=dnsx -d bus.example.com -rl 1 -a\n",
            encoding="utf-8",
        )
        (tmp / "state.json").write_text(
            '{"run":{"status":"stopped","reason":"operator stop"},"breaker":{"paused":{}},"modules":{}}',
            encoding="utf-8",
        )
        dnsx = tmp / "20_dns" / "dnsx"
        dnsx.mkdir(parents=True)
        (dnsx / "brute_l1_example.com_chunk_0.json").write_text(
            '{"host":"www.example.com","a":["1.2.3.4"]}\n',
            encoding="utf-8",
        )
        with patch("pipeline.factory.target_root", return_value=tmp):
            row = scan_target_row(params, "example.com")
        self.assertTrue(any(i.get("code") == "throttle" for i in row.get("issues") or []))
        self.assertGreaterEqual(int((row.get("live") or {}).get("host_hits") or 0), 1)


class TestLiveResultsRows(unittest.TestCase):
    def test_dnsx_json_fills_results_without_assets(self):
        from unittest.mock import patch

        from dashboard.service import results_rows_for

        params = Params(_ROOT)
        tmp = Path(tempfile.mkdtemp())
        dnsx = tmp / "20_dns" / "dnsx"
        dnsx.mkdir(parents=True)
        (dnsx / "brute_l1_example.com_chunk_0.json").write_text(
            '{"host":"api.example.com","a":["1.2.3.4"]}\n',
            encoding="utf-8",
        )
        with patch("dashboard.service._target_dir", return_value=tmp):
            rows = results_rows_for(params, "example.com")
        hosts = {r.get("host") for r in rows}
        self.assertIn("api.example.com", hosts)


if __name__ == "__main__":
    unittest.main()
