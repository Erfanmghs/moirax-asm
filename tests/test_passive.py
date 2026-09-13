"""B3 PASSIVE CHAIN unit proof (spec section 8 PSV-0..PSV-8) -- deterministic, no network."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from unittest import mock

from pipeline.adapter import Adapter, Completed, ScriptedRunner
from pipeline.breaker import CircuitBreaker, FakeClock
from pipeline.ceiling import ResourceCeiling
from pipeline.modules.passive_recon import (
    _Candidates,
    _crtsh_names,
    _hosts_from_lines,
    _psv8_ip,
    dork_forge,
    run_passive_recon,
)
from pipeline.params import Params
from pipeline.search_forge import (
    SearchForge,
    extract_http_status,
    hosts_from_engine_body,
    load_dorks_registry,
    load_registry,
    split_headers_body,
)
from pipeline.scope import ScopeGate

_ROOT = Path(__file__).resolve().parents[1]


def _params() -> Params:
    return Params(_ROOT)


def _gate(params: Params, extra_includes: list[str] | None = None) -> ScopeGate:
    document = {
        "engagement": {"name": "unit", "authorization_date": "2026-01-01"},
        "includes": ["example.com", "*.example.com"] + (extra_includes or []),
        "excludes": ["out.example.com"],
    }
    return ScopeGate(params, document)


def _adapter(params: Params, gate: ScopeGate, outcomes: dict[str, list[Completed]] | None = None,
             clock: FakeClock | None = None,
             target_dir: Path | None = None) -> tuple[Adapter, FakeClock]:
    clock = clock or FakeClock()
    breaker = CircuitBreaker(params, clock=clock, target_dir=Path(tempfile.mkdtemp()), target="example.com")
    ceiling = ResourceCeiling(params)
    # this sandbox has no docker binary: docker_prefix is patched; the
    # ScriptedRunner never executes docker anyway (deterministic, no network)
    patcher = mock.patch("pipeline.adapter.docker_prefix", return_value=["docker"])
    patcher.start()
    adapter = Adapter(params, target_dir or Path(tempfile.mkdtemp()), breaker, ceiling,
                      clock=clock, runner=ScriptedRunner(outcomes))
    adapter._test_patcher = patcher
    return adapter, clock


def _http(status: int, body: str) -> Completed:
    return Completed(0, f"HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\n\r\n{body}", "")


class SearchForgeTest(unittest.TestCase):
    def test_registry_loads_and_keyless_engine_available(self):
        params = _params()
        forge = SearchForge(params, load_registry(params), FakeClock(), lambda msg: None)
        names = [e["name"] for e in forge.engines]
        self.assertIn("duckduckgo", names)  # keyless -> available without .env
        for name in ("google-cse", "serper", "brave", "serpapi", "yandex-xml"):
            self.assertNotIn(name, names)  # no keys in unit env -> disclosed skip

    def test_post_fetch_cmd_includes_endpoint_url(self):
        params = _params()
        forge = SearchForge(params, load_registry(params), FakeClock(), lambda msg: None)
        engine = next(e for e in forge.engines if e["name"] == "duckduckgo")
        cmd, _key = forge.fetch_cmd(engine, "site:*.example.com")
        self.assertIn("https://html.duckduckgo.com/html/", cmd)
        self.assertIn("--data", cmd)
        self.assertIn("curl", cmd)

    def test_dork_forge_templates_dedupes(self):
        params = _params()
        registry = load_dorks_registry(params)
        with tempfile.TemporaryDirectory() as tmp:
            params.root = Path(tmp)
            dorks, rel = dork_forge(params, Path(tmp), "example.com", registry)
        self.assertIn("site:*.example.com", dorks)
        self.assertIn("site:*.example.com -site:www.example.com", dorks)
        self.assertEqual(len(dorks), len(set(dorks)))
        self.assertTrue(rel.endswith("dorks/forge/search-dorks.txt"))

    def test_key_rotation_alternates_per_request(self):
        params = _params()
        registry = {
            "settings": {"cooldown_backoff_base_sec": 1, "isolate_window_sec": 60,
                         "isolate_error_ratio": 0.2, "dork_cache_ttl_sec": 100},
            "engines": {"serper": {"kind": "json", "endpoint": "https://x", "method": "POST",
                                   "key_env": "SERPER_API_KEY", "enabled": True,
                                   "rate_per_min": 600, "priority": 1, "headers": []}},
        }
        import os

        os.environ["SERPER_API_KEY"] = "k1,k2"
        try:
            forge = SearchForge(params, registry, FakeClock(), lambda msg: None)
            engine = forge.engines[0]
            first = forge.next_key(engine)
            second = forge.next_key(engine)
            third = forge.next_key(engine)
            self.assertEqual([first, second, third], ["k1", "k2", "k1"])
        finally:
            del os.environ["SERPER_API_KEY"]

    def test_empty_env_file_does_not_shadow_process_env(self):
        """Placeholder KEY= lines in .env must not hide os.environ keys."""
        import os
        from pipeline.search_forge import env_keys

        params = _params()
        with tempfile.TemporaryDirectory() as tmp:
            params.root = Path(tmp)
            (Path(tmp) / ".env").write_text("SERPER_API_KEY=\n", encoding="utf-8")
            os.environ["SERPER_API_KEY"] = "k1,k2"
            try:
                self.assertEqual(env_keys(params, "SERPER_API_KEY"), ["k1", "k2"])
            finally:
                del os.environ["SERPER_API_KEY"]

    def test_429_marks_cooldown_and_reroutes(self):
        params = _params()
        registry = {
            "settings": {"cooldown_backoff_base_sec": 2, "cooldown_backoff_max_sec": 300,
                         "isolate_window_sec": 60, "isolate_error_ratio": 0.2,
                         "dork_cache_ttl_sec": 100, "http_user_agent": "ua"},
            "engines": {
                "bad": {"kind": "html", "endpoint": "https://bad", "method": "GET",
                        "keyless": True, "enabled": True, "rate_per_min": 600, "priority": 1,
                        "headers": []},
                "good": {"kind": "html", "endpoint": "https://good", "method": "GET",
                         "keyless": True, "enabled": True, "rate_per_min": 600, "priority": 2,
                         "headers": []},
            },
        }
        notes: list[str] = []
        clock = FakeClock()
        forge = SearchForge(params, registry, clock, notes.append)
        bad = forge.engines[0]
        forge.record(bad, ok=False, status_code=429)
        self.assertEqual(bad["status"], "cooldown")
        self.assertIn("COOLDOWN", " ".join(notes))
        self.assertEqual(forge.pick()["name"], "good")  # traffic instantly re-routed
        clock.sleep(3600)  # past the backoff window
        self.assertEqual(forge.pick()["name"], "bad")  # cooldown engine re-probed
        self.assertEqual(forge.stats["cooldown"], 1)

    def test_error_ratio_isolates_engine(self):
        params = _params()
        registry = {
            "settings": {"cooldown_backoff_base_sec": 1, "isolate_window_sec": 60,
                         "isolate_error_ratio": 0.2, "dork_cache_ttl_sec": 100},
            "engines": {"e": {"kind": "html", "endpoint": "https://e", "method": "GET",
                              "keyless": True, "enabled": True, "rate_per_min": 600,
                              "priority": 1, "headers": []}},
        }
        notes: list[str] = []
        clock = FakeClock()
        forge = SearchForge(params, registry, clock, notes.append)
        engine = forge.engines[0]
        for status in (500, 502, 503):
            forge.record(engine, ok=False, status_code=status)
        self.assertEqual(engine["status"], "isolated")
        self.assertIn("ISOLATED", " ".join(notes))
        self.assertIsNone(forge.pick())
        self.assertEqual(forge.stats["isolated"], 1)

    def test_ttl_cache(self):
        params = _params()
        registry = {
            "settings": {"cooldown_backoff_base_sec": 1, "isolate_window_sec": 60,
                         "isolate_error_ratio": 0.2, "dork_cache_ttl_sec": 100},
            "engines": {},
        }
        clock = FakeClock()
        forge = SearchForge(params, registry, clock, lambda msg: None)
        forge.cache_put("site:*.example.com", ["a.example.com"])
        self.assertEqual(forge.cache_get("site:*.example.com"), ["a.example.com"])
        clock.sleep(200)
        self.assertIsNone(forge.cache_get("site:*.example.com"))

    def test_engine_body_parsers(self):
        html = '<a href="/l/?uddg=https%3A%2F%2Fwww.example.com%2Fx">r</a>'
        self.assertEqual(hosts_from_engine_body("html", html), ["www.example.com"])
        js = '{"organic": [{"link": "https://api.example.com/v"}]}'
        self.assertEqual(hosts_from_engine_body("json", js), ["api.example.com"])
        xml = "<result><url>https://mail.example.com/</url></result>"
        self.assertEqual(hosts_from_engine_body("xml", xml), ["mail.example.com"])
        self.assertEqual(extract_http_status("HTTP/2 429\r\n\r\nx"), 429)
        headers, body = split_headers_body("HTTP/1.1 200 OK\r\nA: b\r\n\r\npayload")
        self.assertIn("200 OK", headers)
        self.assertEqual(body, "payload")


class CandidatesTest(unittest.TestCase):
    def test_scope_prefilter_and_attribution(self):
        params = _params()
        gate = _gate(params)
        with tempfile.TemporaryDirectory() as tmp:
            target_dir = Path(tmp)
            cands = _Candidates(gate, target_dir, params)
            self.assertTrue(cands.add("www.example.com", "subfinder"))
            self.assertTrue(cands.add("www.example.com", "crtsh", tags=["dev"]))
            self.assertFalse(cands.add("out.example.com", "subfinder"))  # excluded -> logged
            self.assertFalse(cands.add("evil.com", "subfinder"))  # out of scope -> logged
            out_log = target_dir / str(params.require("out_of_scope_log"))
            self.assertTrue(out_log.is_file())
            rows = cands.rows()
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row["host"], "www.example.com")
            self.assertEqual(row["sources"], ["crtsh", "subfinder"])
            self.assertEqual(row["tags"], ["dev"])
            self.assertNotIn("alive", row)  # alive stays null until PSV-6

    def test_crtsh_name_parsing_splits_embedded_newlines(self):
        body = json.dumps([
            {"name_value": "*.example.com\nwww.example.com"},
            {"name_value": "dev.example.com"},
        ])
        names = _crtsh_names(body)
        self.assertEqual(sorted(set(names)), ["dev.example.com", "example.com", "www.example.com"])

    def test_hosts_from_lines_handles_urls_and_wildcards(self):
        hosts = _hosts_from_lines(
            "https://www.example.com/a?q=1\n*.example.com\nevil.com\nwww.example.com"
        )
        self.assertEqual(hosts, ["www.example.com", "example.com", "evil.com"])


class SubStepsTest(unittest.TestCase):
    def test_psv8_pure_domain_skips_never_silent(self):
        params = _params()
        gate = _gate(params)
        adapter, _clock = _adapter(params, gate)
        with tempfile.TemporaryDirectory() as tmp:
            target_dir = Path(tmp)
            notes: list[str] = []
            skips: list[str] = []
            meta = _psv8_ip(params, gate, adapter, target_dir, "example.com", {}, 1,
                            _Candidates(gate, target_dir, params), {}, skips,
                            notes.append, lambda: 100.0, lambda cap=None: 60.0)
            self.assertEqual(meta["state"], "skipped")
            self.assertTrue(any("psv-8" in s for s in skips))

    def test_psv8_ignores_fixture_cidr_for_public_apex(self):
        params = _params()
        gate = _gate(params, extra_includes=["172.17.0.1/32"])
        adapter, _clock = _adapter(params, gate)
        with tempfile.TemporaryDirectory() as tmp:
            target_dir = Path(tmp)
            notes: list[str] = []
            skips: list[str] = []
            meta = _psv8_ip(params, gate, adapter, target_dir, "example.com", {}, 1,
                            _Candidates(gate, target_dir, params), {}, skips,
                            notes.append, lambda: 100.0, lambda cap=None: 60.0)
            self.assertEqual(meta["state"], "skipped")
            self.assertTrue(any("fixture CIDR" in n for n in notes))

    def test_psv8_cidr_activates_and_stores_ips_as_is(self):
        params = _params()
        gate = _gate(params, extra_includes=["192.0.2.0/24"])
        censys_body = json.dumps(
            {"result": {"hits": [{"ip": "192.0.2.10", "dns": {"names": ["host.example.com"]}},
                                 {"ip": "192.0.2.11"}]}}
        )
        outcomes = {"curl-fetch": [_http(200, censys_body)]}
        adapter, _clock = _adapter(params, gate, outcomes)
        with tempfile.TemporaryDirectory() as tmp:
            target_dir = Path(tmp)
            (target_dir / "10_subdomains" / "passive" / "sources").mkdir(parents=True)
            notes: list[str] = []
            skips: list[str] = []
            cands = _Candidates(gate, target_dir, params)
            source_files: dict[str, int] = {}
            import os

            os.environ["CENSYS_API_ID"] = "id"
            os.environ["CENSYS_API_SECRET"] = "secret"
            try:
                meta = _psv8_ip(params, gate, adapter, target_dir, "example.com", {}, 1,
                                cands, source_files, skips, notes.append, lambda: 100.0,
                                lambda cap=None: 60.0)
            finally:
                del os.environ["CENSYS_API_ID"], os.environ["CENSYS_API_SECRET"]
            self.assertEqual(meta["state"], "ok")
            ips_file = target_dir / "10_subdomains" / "passive" / "sources" / "cidr-ips.txt"
            self.assertIn("192.0.2.10", ips_file.read_text(encoding="utf-8"))
            self.assertIn("192.0.2.11", ips_file.read_text(encoding="utf-8"))
            rows = cands.rows()
            host_rows = [r for r in rows if r["host"] == "host.example.com"]
            self.assertEqual(len(host_rows), 1)  # hostname scope-gated into candidates
            self.assertEqual(host_rows[0]["sources"], ["censys-cidr"])
            self.assertEqual(meta["ips"], 2)  # stored AS-IS, never hostname-gated


class OrchestratorTest(unittest.TestCase):
    def _run(self, outcomes: dict[str, list[Completed]], extra_includes: list[str] | None = None,
             target: str = "example.com"):
        """Deterministic vehicle: the SEARCH-FORGE registry is replaced with an
        EMPTY engine pool so PSV-1 performs zero HTTP (dorks marked
        rerun-next-run, disclosed) and the scripted outcomes queue is consumed
        exactly by PSV-2/PSV-3/PSV-4 in a fixed order."""
        params = _params()
        tmp = Path(tempfile.mkdtemp())
        empty_registry = tmp / "search_engines_empty.yaml"
        empty_registry.write_text(
            "schema_version: 1\n"
            "settings:\n"
            "  cooldown_backoff_base_sec: 1\n"
            "  isolate_window_sec: 60\n"
            "  isolate_error_ratio: 0.2\n"
            "  dork_cache_ttl_sec: 100\n"
            "engines: []\n",
            encoding="utf-8",
        )
        params.settings["search_engines_registry"] = str(empty_registry)
        params.settings["dorks_forge_output"] = str(tmp / "dorks" / "forge" / "search-dorks.txt")
        gate = _gate(params, extra_includes)
        target_dir = tmp / "target"
        (target_dir / "10_subdomains" / "passive" / "sources").mkdir(parents=True)
        (target_dir / "logs").mkdir()
        adapter, _clock = _adapter(params, gate, outcomes, target_dir=target_dir)
        partial: list[str] = []
        payload = run_passive_recon(
            params, gate, adapter, target_dir, target, {"target_domain": target}, 1,
            900.0, partial,
        )
        return payload, target_dir, partial

    def test_end_to_end_schema_and_source_files(self):
        crtsh_body = json.dumps([
            {"name_value": "www.example.com\ndev.example.com"},
            {"name_value": "mail.example.com"},
        ])
        httpx_body = json.dumps({"host": "www.example.com", "status_code": 200}) + "\n"
        gau_body = "https://www.example.com/a\nhttps://api.example.com/b\n"
        outcomes = {
            "curl-fetch": [
                _http(200, crtsh_body),   # psv-2 wildcard query
                _http(200, crtsh_body),   # psv-2 bare query
            ],
            "subfinder": [Completed(0, "www.example.com\nsub.example.com\n", "")],
            "amass": [Completed(0, "mail.example.com\n", "")],
            "assetfinder": [Completed(0, "www.example.com\nassets.example.com\n", "")],
            "assetfinder-related": [Completed(0, "www.example.com\nrelated.org\n", "")],
            "findomain": [Completed(0, "", "")],
            "assetfinder-resolved": [Completed(0, "www.example.com\nassets.example.com\n", "")],
            "waybackurls": [Completed(0, gau_body, "")],
            "gau": [Completed(0, gau_body, "")],
            "httpx-passive": [Completed(0, httpx_body, "")],
        }
        payload, target_dir, partial = self._run(outcomes)
        # exact section 8 output schema
        self.assertEqual(payload["module"], "passive-recon")
        self.assertIn("candidates", payload)
        self.assertIn("passive_ips", payload)
        self.assertIn("search_forge", payload)
        self.assertIn("recursion", payload)
        self.assertIn("counts", payload)
        for key in ("engines_used", "cooldown", "isolated"):
            self.assertIn(key, payload["search_forge"])
        for key in ("depth_used", "seeds_total"):
            self.assertIn(key, payload["recursion"])
        for key in ("candidates", "alive"):
            self.assertIn(key, payload["counts"])
        # candidates carry per-source attribution + keyword TAGS never drop
        hosts = {row["host"]: row for row in payload["candidates"]}
        self.assertIn("www.example.com", hosts)
        self.assertIn("dev.example.com", hosts)  # keyword-tagged name NOT filtered
        self.assertIn("dev", hosts["dev.example.com"]["tags"])
        self.assertIn("related.org", open(
            target_dir / "10_subdomains/passive/sources/assetfinder-related.txt"
        ).read())  # full harvest kept as evidence
        self.assertNotIn("related.org", hosts)  # ...but never enumerated into candidates
        self.assertIn("api.example.com", hosts)  # archives union gated into candidates
        # PSV-6 alive tagging from httpx output
        self.assertEqual(hosts["www.example.com"]["alive"], True)
        # per-source files populated (section 8 output contract)
        sources_dir = target_dir / "10_subdomains" / "passive" / "sources"
        for name in ("crtsh.txt", "subfinder.txt", "amass.txt", "assetfinder.txt",
                     "assetfinder-related.txt", "assetfinder-resolved.txt", "archives.txt"):
            self.assertTrue((sources_dir / name).is_file(), name)
        # PSV-7 skip never silent (no GITHUB_TOKEN in unit env)
        summary = (target_dir / "10_subdomains" / "passive" / "summary.md").read_text(encoding="utf-8")
        self.assertIn("psv-7", summary)
        # data.json on disk matches payload
        on_disk = json.loads((target_dir / "10_subdomains" / "passive" / "data.json").read_text())
        self.assertEqual(on_disk["counts"]["candidates"], payload["counts"]["candidates"])
        self.assertNotIn("passive_recursion_seeds_cap", partial)

    def test_recursion_stops_at_zero_new_hosts_naturally(self):
        crtsh_body = json.dumps([{"name_value": "www.example.com"}])
        outcomes = {
            "curl-fetch": [_http(200, crtsh_body), _http(200, crtsh_body)],
            "subfinder": [Completed(0, "www.example.com\n", ""),
                          Completed(0, "www.example.com\n", "")],
            "assetfinder": [Completed(0, "www.example.com\n", ""),
                            Completed(0, "www.example.com\n", "")],
            "assetfinder-related": [Completed(0, "", "")],
            "amass": [Completed(0, "", "")],
            "findomain": [Completed(0, "", "")],
            "assetfinder-resolved": [Completed(0, "www.example.com\n", "")],
            "waybackurls": [Completed(0, "", "")],
            "gau": [Completed(0, "", "")],
            "httpx-passive": [Completed(0, "", "")],
        }
        payload, _target_dir, partial = self._run(outcomes)
        self.assertEqual(payload["recursion"]["depth_used"], 1)
        self.assertEqual(partial, [])


if __name__ == "__main__":
    unittest.main()
