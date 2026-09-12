"""B4 PORT-SWEEP unit proof (spec section 8 order-4 post-MERGE) -- deterministic, no network."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pipeline.adapter import Adapter, Completed, ScriptedRunner
from pipeline.breaker import CircuitBreaker, FakeClock
from pipeline.ceiling import ResourceCeiling
from pipeline.modules.port_sweep import (
    _count_ports,
    _mine_sentinels,
    _parse_nmap_xml,
    run_port_sweep,
)
from pipeline.params import Params
from pipeline.scope import ScopeGate

_ROOT = Path(__file__).resolve().parents[1]

_NAABU_ROW = '{{"ip":"{ip}","port":{port},"protocol":"tcp"}}\n'


def _params(overrides: dict | None = None) -> Params:
    params = Params(_ROOT)
    for key, value in (overrides or {}).items():
        params.settings[key] = value
    return params


def _gate(params: Params) -> ScopeGate:
    document = {
        "engagement": {"name": "unit", "authorization_date": "2026-01-01"},
        "includes": ["example.com", "*.example.com", "93.184.215.0/24"],
        "excludes": ["out.example.com"],
    }
    return ScopeGate(params, document)


def _adapter(params: Params, gate: ScopeGate, outcomes: dict[str, list[Completed]] | None = None,
             clock: FakeClock | None = None, target_dir: Path | None = None) -> tuple[Adapter, FakeClock]:
    clock = clock or FakeClock()
    breaker = CircuitBreaker(params, clock=clock, target_dir=Path(tempfile.mkdtemp()), target="example.com")
    ceiling = ResourceCeiling(params)
    patcher = mock.patch("pipeline.adapter.docker_prefix", return_value=["docker"])
    patcher.start()
    adapter = Adapter(params, target_dir or Path(tempfile.mkdtemp()), breaker, ceiling,
                      clock=clock, runner=ScriptedRunner(outcomes))
    adapter._test_patcher = patcher
    return adapter, clock


def _target_dir(params: Params, assets: list[dict], history: list[tuple[str, dict]] | None = None) -> Path:
    td = Path(tempfile.mkdtemp())
    (td / "00_assets").mkdir(parents=True, exist_ok=True)
    (td / "logs").mkdir(parents=True, exist_ok=True)
    (td / "00_assets" / "assets.json").write_text(
        json.dumps({"schema_version": 1, "module": "merge", "assets": assets}), encoding="utf-8"
    )
    for stamp, doc in history or []:
        path = td / "history" / stamp / str(params.require("portsweep_data_json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc), encoding="utf-8")
    return td


def _run(params: Params, gate: ScopeGate, adapter: Adapter, td: Path, partial: list[str] | None = None):
    partial = partial if partial is not None else []
    payload = run_port_sweep(
        params, gate, adapter, td, "example.com", {"target_domain": "example.com"},
        2, None, partial,
    )
    return payload, partial


def _sweep_doc(**overrides) -> dict:
    base = {
        "schema_version": 1,
        "module": "port-sweep",
        "skipped": None,
        "pace": {"duration_hours": 24, "effective_pps": 10, "window_breached": False},
        "completed_at": "2026-09-05T00:00:00Z",
    }
    base.update(overrides)
    return base


class PortSweepTest(unittest.TestCase):
    def test_ip_dedup_one_invocation_two_hosts(self):
        # RULE 2: two hostnames sharing one IP -> exactly ONE scan invocation,
        # results attributed back to EVERY hostname sharing the IP.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        outcomes = {"naabu-full": [Completed(0, _NAABU_ROW.format(ip="93.184.215.14", port=443), "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [
            {"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]},
            {"host": "api.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]},
        ])
        payload, partial = _run(params, gate, adapter, td)
        self.assertIsNone(payload["skipped"])
        self.assertEqual(payload["unique_ips_scanned"], 1)
        self.assertEqual(payload["duplicates_skipped"], 1)
        self.assertEqual(len(payload["scans"]), 1)
        self.assertEqual(sorted(payload["scans"][0]["hosts"]), ["api.example.com", "www.example.com"])
        log = (td / "logs" / "run.log").read_text()
        self.assertEqual(log.count("naabu-invoke"), 1)

    def test_resolution_guarantee_resolves_and_excludes(self):
        # RULE 1: no-IP hosts -> ONE batched dnsx pass; resolved host joins the
        # scan, still-unresolvable host carries explicit unresolved + reason.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        dnsx_rows = (
            '{"host":"fresh.example.com","a":["93.184.215.20"]}\n'
            '{"host":"dead.example.com","a":[]}\n'
        )
        outcomes = {
            "dnsx-list": [Completed(0, dnsx_rows, "")],
            "naabu-full": [Completed(0, _NAABU_ROW.format(ip="93.184.215.20", port=80), "")],
        }
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [
            {"host": "fresh.example.com", "ips": [], "alive": True, "sources": ["psv6"]},
            {"host": "dead.example.com", "ips": [], "alive": True, "sources": ["psv6"]},
        ])
        (td / "20_dns").mkdir(parents=True, exist_ok=True)
        (td / "20_dns" / "resolvers.txt").write_text("194.242.2.2\n", encoding="utf-8")
        payload, _partial = _run(params, gate, adapter, td)
        g = payload["resolution_guarantee"]
        self.assertEqual(g["hosts"], 2)
        self.assertEqual(g["resolved"], 1)
        self.assertEqual([u["host"] for u in g["unresolved"]], ["dead.example.com"])
        self.assertEqual(g["unresolved"][0]["resolution_status"], "unresolved")
        self.assertTrue(g["unresolved"][0]["reason"])
        self.assertEqual(payload["unique_ips_scanned"], 1)
        log = (td / "logs" / "run.log").read_text()
        self.assertIn("resolution-guarantee hosts=2 resolved=1 unresolved=1", log)
        self.assertIn("skip-unresolved\tdead.example.com", log)

    def test_ip_rejected_hosts_never_enter_guarantee(self):
        # A host whose ONLY IPs were scope-rejected is resolved-but-unscannable
        # (explicit ledger line) -- it must NOT be re-resolved as "no IP".
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        adapter, _clock = _adapter(params, gate, {"naabu-full": [Completed(0, _NAABU_ROW.format(ip="93.184.215.14", port=443), "")]})
        td = _target_dir(params, [
            {"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]},
            {"host": "boot.example.com", "ips": ["10.0.0.5"], "alive": True, "sources": ["dnsr"]},
        ])
        payload, _partial = _run(params, gate, adapter, td)
        log = (td / "logs" / "run.log").read_text()
        self.assertIn("skip-ip-rejected\tboot.example.com", log)
        self.assertEqual(payload["resolution_guarantee"]["hosts"], 0)
        self.assertNotIn("10.0.0.5", payload["scans"] and [s["ip"] for s in payload["scans"]] or [])

    def test_pacing_formula_full_profile(self):
        # effective_pps = unique_ips x 65535 / (duration x 3600), capped.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        rows = "".join(_NAABU_ROW.format(ip="93.184.215.14", port=80) + _NAABU_ROW.format(ip="93.184.215.20", port=443) for _ in range(1))
        outcomes = {"naabu-full": [Completed(0, rows, ""), Completed(0, rows, "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [
            {"host": "a.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]},
            {"host": "b.example.com", "ips": ["93.184.215.20"], "alive": True, "sources": ["dnsr"]},
        ])
        payload, _partial = _run(params, gate, adapter, td)
        expected = max(1, int(min(2 * 65535 / 3600.0, 1000.0)))
        self.assertEqual(payload["pace"]["effective_pps"], expected)  # 36
        self.assertFalse(payload["pace"]["window_breached"])

    def test_window_breach_partials_with_remaining_list(self):
        # required_pps > cap -> window_breached + remaining-IP list + PARTIAL
        # marker; never silently abandoned.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1, "portsweep_full_rate_cap": 1})
        gate = _gate(params)
        adapter, _clock = _adapter(params, gate, {"naabu-full": []})
        assets = [
            {"host": f"h{i}.example.com", "ips": [f"93.184.215.{i}"], "alive": True, "sources": ["dnsr"]}
            for i in range(2)
        ]
        td = _target_dir(params, assets)
        payload, partial = _run(params, gate, adapter, td)
        self.assertTrue(payload["pace"]["window_breached"])
        self.assertEqual(len(payload["remaining_ips"]), 2)
        self.assertIn("portsweep_window_breached", partial)

    def test_no_overlap_previous_in_progress(self):
        # A previous completed sweep still inside its duration window -> the
        # new sweep is SKIPPED (skipped: previous_in_progress), zero scans.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 24})
        gate = _gate(params)
        adapter, _clock = _adapter(params, gate, {"naabu-full": [Completed(0, "", "")]})
        td = _target_dir(
            params,
            [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}],
            history=[("2026-09-05T23:00:00Z", _sweep_doc())],  # 1h before FakeClock(0)=epoch? see below
        )
        # FakeClock starts at 0.0 epoch; make the previous sweep "recent" by
        # stamping it far in the future relative to epoch 0.
        payload, partial = _run(params, gate, adapter, td)
        self.assertEqual(payload["skipped"], "previous_in_progress")
        self.assertEqual(payload["unique_ips_scanned"], 0)
        self.assertNotIn("portsweep_window_breached", partial)
        log = (td / "logs" / "run.log").read_text()
        self.assertIn("skipped: previous_in_progress", log)
        self.assertEqual(adapter.runner.calls, [])

    def test_profile_routing(self):
        # light -> naabu (top-N PORT-CHECK behavior); custom -> naabu-sweep
        # with the named range; custom without a range -> never-silent skip.
        for profile, tool, extra in (
            ("light", "naabu", {}),
            ("custom", "naabu-sweep", {"portsweep_custom_ports": "80,443,8080"}),
        ):
            params = _params({"portsweep_profile": profile, "portsweep_duration_hours": 1, **extra})
            gate = _gate(params)
            outcomes = {tool: [Completed(0, _NAABU_ROW.format(ip="93.184.215.14", port=443), "")]}
            adapter, _clock = _adapter(params, gate, outcomes)
            td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
            payload, _partial = _run(params, gate, adapter, td)
            self.assertEqual(payload["pace"]["profile"], profile, profile)
            # invocation routed to the profile's registered tool spec
            log = (td / "logs" / "run.log").read_text()
            self.assertIn(f"tool={tool}", log, profile)
        # custom without a range: explicit skip, zero scans
        params = _params({"portsweep_profile": "custom", "portsweep_duration_hours": 1})
        gate = _gate(params)
        adapter, _clock = _adapter(params, gate, {})
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        payload, partial = _run(params, gate, adapter, td)
        self.assertEqual(payload["skipped"], "profile_unusable:custom")
        self.assertIn("portsweep:profile-unusable:custom", partial)

    def test_filtered_suspect_after_reprobe(self):
        # FILTERING INTELLIGENCE: alive host, full profile, zero open ports ->
        # ONE slower re-probe; still empty -> filtered_suspect=true.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        outcomes = {"naabu-full": [Completed(0, "", ""), Completed(0, "", "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        payload, _partial = _run(params, gate, adapter, td)
        self.assertTrue(payload["scans"][0]["filtered_suspect"])
        log = (td / "logs" / "run.log").read_text()
        self.assertIn("filtered-reprobe", log)
        self.assertEqual(log.count("naabu-invoke"), 1)
        self.assertEqual(log.count("re-probe-invoke"), 1)

    def test_anomalous_open_suspect(self):
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        rows = "".join(_NAABU_ROW.format(ip="93.184.215.14", port=p) for p in range(1, 1002))
        outcomes = {"naabu-full": [Completed(0, rows, "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        payload, _partial = _run(params, gate, adapter, td)
        self.assertTrue(payload["scans"][0]["anomalous_open_suspect"])
        self.assertFalse(payload["scans"][0]["filtered_suspect"])

    def test_nmap_toggle_off_zero_containers(self):
        # Acceptance: toggle OFF -> zero nmap invocations ever.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        outcomes = {"naabu-full": [Completed(0, _NAABU_ROW.format(ip="93.184.215.14", port=443), "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        payload, _partial = _run(params, gate, adapter, td)
        self.assertEqual(payload["services"], [])
        calls = [" ".join(c) for c in adapter.runner.calls]
        self.assertFalse(any("nmap" in c for c in calls), calls)

    def test_nmap_services_parse_and_invoke(self):
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1, "portsweep_nmap_sv": True})
        gate = _gate(params)
        xml = (
            "<nmaprun><host><ports>"
            '<port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https" product="nginx" version="1.25.3" extrainfo="Ubuntu"/></port>'
            "</ports></host></nmaprun>"
        )
        outcomes = {
            "naabu-full": [Completed(0, _NAABU_ROW.format(ip="93.184.215.14", port=443), "")],
            "nmap-sv": [Completed(0, xml, "")],
        }
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        payload, _partial = _run(params, gate, adapter, td)
        self.assertEqual(
            payload["services"],
            [{
                "ip": "93.184.215.14",
                "port": 443,
                "proto": "tcp",
                "name": "https",
                "product": "nginx",
                "version": "1.25.3",
                "extrainfo": "Ubuntu",
            }],
        )

    def test_out_of_scope_ip_rejected(self):
        # Private ranges stay REJECTED even when attributed to an in-scope
        # host (REM8 ruling only relaxes public host-IPs) -- ledger + exclusion.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        adapter, _clock = _adapter(params, gate, {"naabu-full": []})
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["10.0.0.5"], "alive": True, "sources": ["dnsr"]}])
        payload, _partial = _run(params, gate, adapter, td)
        self.assertEqual(payload["unique_ips_scanned"], 0)
        oos = (td / "logs" / "out_of_scope.log").read_text()
        self.assertIn("10.0.0.5", oos)
        log = (td / "logs" / "run.log").read_text()
        self.assertIn("skip-ip-rejected\twww.example.com", log)

    def test_exact_schema_keys(self):
        params = _params({"portsweep_profile": "light", "portsweep_duration_hours": 1})
        gate = _gate(params)
        outcomes = {"naabu": [Completed(0, _NAABU_ROW.format(ip="93.184.215.14", port=443), "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        payload, _partial = _run(params, gate, adapter, td)
        for key in ("schema_version", "module", "scans", "services", "pace", "unique_ips_scanned", "duplicates_skipped"):
            self.assertIn(key, payload)
        scan = payload["scans"][0]
        for key in ("ip", "hosts", "profile", "ports", "filtered_suspect", "anomalous_open_suspect"):
            self.assertIn(key, scan)
        self.assertEqual(scan["ports"][0], {"port": 443, "proto": "tcp", "state": "open"})
        for key in ("duration_hours", "effective_pps", "window_breached"):
            self.assertIn(key, payload["pace"])

    def test_target_set_materialized_before_scan(self):
        # RULE 3: the exact server list exists on disk + is logged BEFORE the
        # first naabu invocation line in run.log.
        params = _params({"portsweep_profile": "full", "portsweep_duration_hours": 1})
        gate = _gate(params)
        outcomes = {"naabu-full": [Completed(0, _NAABU_ROW.format(ip="93.184.215.14", port=443), "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        _run(params, gate, adapter, td)
        ts = (td / "30_ports" / "naabu-full" / "target-set.txt").read_text()
        self.assertIn("93.184.215.14\twww.example.com\tdnsr", ts)
        log = (td / "logs" / "run.log").read_text()
        self.assertLess(log.index("target-set unique_ips=1"), log.index("naabu-invoke"))

    def test_psv8_cidr_ips_scan_only_entries(self):
        params = _params({"portsweep_profile": "custom", "portsweep_custom_ports": "443", "portsweep_duration_hours": 1})
        gate = _gate(params)
        outcomes = {"naabu-sweep": [Completed(0, _NAABU_ROW.format(ip="93.184.215.30", port=443), "")]}
        adapter, _clock = _adapter(params, gate, outcomes)
        td = _target_dir(params, [{"host": "www.example.com", "ips": ["93.184.215.14"], "alive": True, "sources": ["dnsr"]}])
        src = td / "10_subdomains" / "passive" / "sources"
        src.mkdir(parents=True, exist_ok=True)
        (src / "cidr-ips.txt").write_text("93.184.215.30\nnot-an-ip\n", encoding="utf-8")
        payload, _partial = _run(params, gate, adapter, td)
        ips = [s["ip"] for s in payload["scans"]]
        self.assertIn("93.184.215.30", ips)
        self.assertEqual(ips.count("93.184.215.30"), 1)
        log = (td / "logs" / "run.log").read_text()
        self.assertIn("psv8-ip\t93.184.215.30", log)

    def test_canary_halving_and_pause(self):
        from pipeline.port_pace import PortPacer

        params = _params()
        td = Path(tempfile.mkdtemp())
        (td / "logs").mkdir(parents=True, exist_ok=True)
        breaker = CircuitBreaker(params, clock=FakeClock(), target_dir=Path(tempfile.mkdtemp()), target="example.com")
        clock = FakeClock()
        pacer = PortPacer(params, breaker, clock, td)
        sentinels = [("93.184.215.14", 443), ("93.184.215.14", 80), ("93.184.215.20", 22)]
        with mock.patch("pipeline.port_pace._tcp_open", side_effect=[False, False, False, False, False, False]):
            self.assertTrue(pacer.tick(sentinels, 1000.0))  # window 1: halved, not paused
            self.assertEqual(pacer.state.bad_windows, 1)
            clock.advance(30)  # next canary window (canary_interval_sec)
            self.assertFalse(pacer.tick(sentinels, 1000.0))  # window 2: pause
        self.assertTrue(pacer.state.paused)
        self.assertIn("port-sweep", breaker.paused_module_names())

    def test_sentinel_mining_from_history(self):
        params = _params()
        td = _target_dir(params, [], history=[("2026-01-01T00:00:00Z", {
            "schema_version": 1, "module": "port-sweep", "skipped": None,
            "scans": [
                {"ip": "93.184.215.14", "hosts": ["www.example.com"], "ports": [{"port": 443, "proto": "tcp", "state": "open"}, {"port": 80, "proto": "tcp", "state": "open"}]},
                {"ip": "93.184.215.20", "hosts": [], "ports": [{"port": 22, "proto": "tcp", "state": "open"}]},
            ],
        })])
        sentinels = _mine_sentinels(params, td)
        self.assertEqual(len(sentinels), 3)
        self.assertIn(("93.184.215.14", 443), sentinels)

    def test_count_ports(self):
        self.assertEqual(_count_ports("80,443,8080"), 3)
        self.assertEqual(_count_ports("1-100,443"), 101)
        self.assertEqual(_count_ports(""), 0)


if __name__ == "__main__":
    unittest.main()
