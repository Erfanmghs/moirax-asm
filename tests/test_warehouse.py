"""Per-target warehouse: physical isolation, SCD-2 facts, arbitrary-pair diffs."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from pipeline.factory import ensure_layout
from pipeline.history import FACT_CLASSES, empty_maps
from pipeline.params import Params
from pipeline.warehouse import (
    WarehouseError,
    compare_runs,
    enrich_assets,
    facts_as_assets,
    host_timeline,
    ingest_maps,
    maps_for_run,
    open_bound,
    rebuild_from_history,
    status,
    warehouse_path,
)

_ROOT = Path(__file__).resolve().parents[1]


def _params() -> Params:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "tools.yaml").write_text((_ROOT / "tools.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    return Params(tmp)


def _maps(hosts: list[dict]) -> dict:
    out = empty_maps()
    for row in hosts:
        out["hosts"][str(row["host"])] = row
    return out


class TestPhysicalIsolation(unittest.TestCase):
    def test_two_targets_never_share_rows_or_files(self):
        params = _params()
        a = ensure_layout(params, "alpha.example")
        b = ensure_layout(params, "beta.example")
        ingest_maps(
            params, a, "alpha.example", "20260101T000000Z", "completed", {"assets": 1},
            _maps([{"host": "only-alpha.example", "alive": True}]),
        )
        ingest_maps(
            params, b, "beta.example", "20260101T000000Z", "completed", {"assets": 1},
            _maps([{"host": "only-beta.example", "alive": True}]),
        )
        path_a = warehouse_path(params, a)
        path_b = warehouse_path(params, b)
        self.assertNotEqual(path_a.resolve(), path_b.resolve())
        self.assertTrue(path_a.is_file())
        self.assertTrue(path_b.is_file())
        hosts_a = maps_for_run(params, a, "alpha.example", "20260101T000000Z")["hosts"]
        hosts_b = maps_for_run(params, b, "beta.example", "20260101T000000Z")["hosts"]
        self.assertIn("only-alpha.example", hosts_a)
        self.assertNotIn("only-beta.example", hosts_a)
        self.assertIn("only-beta.example", hosts_b)
        self.assertNotIn("only-alpha.example", hosts_b)
        st_a = status(params, a, "alpha.example")
        st_b = status(params, b, "beta.example")
        self.assertEqual(st_a["bound_target"], "alpha.example")
        self.assertEqual(st_b["bound_target"], "beta.example")
        self.assertEqual(st_a["facts"]["hosts"], 1)
        self.assertEqual(st_b["facts"]["hosts"], 1)

    def test_copied_db_into_other_target_is_refused(self):
        params = _params()
        a = ensure_layout(params, "alpha.example")
        b = ensure_layout(params, "beta.example")
        ingest_maps(
            params, a, "alpha.example", "20260101T000000Z", "completed", {},
            _maps([{"host": "only-alpha.example"}]),
        )
        shutil.copy2(warehouse_path(params, a), warehouse_path(params, b))
        with self.assertRaises(WarehouseError):
            open_bound(params, b, "beta.example")

    def test_unbound_existing_file_is_not_rebound(self):
        params = _params()
        td = ensure_layout(params, "site.example")
        path = warehouse_path(params, td)
        import sqlite3

        conn = sqlite3.connect(str(path))
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.commit()
        conn.close()
        with self.assertRaises(WarehouseError):
            open_bound(params, td, "site.example")

    def test_illegal_warehouse_filename_refused(self):
        params = _params()
        params.settings["warehouse_filename"] = "../escape.sqlite"
        td = ensure_layout(params, "site.example")
        with self.assertRaises(WarehouseError):
            warehouse_path(params, td)

    def test_out_of_order_ingest_refused(self):
        params = _params()
        td = ensure_layout(params, "site.example")
        ingest_maps(
            params, td, "site.example", "20260101T000000Z", "completed", {},
            _maps([{"host": "a.site.example"}]),
        )
        ingest_maps(
            params, td, "site.example", "20260102T000000Z", "completed", {},
            _maps([{"host": "b.site.example"}]),
        )
        with self.assertRaises(WarehouseError):
            ingest_maps(
                params, td, "site.example", "20260101T000000Z", "completed", {},
                _maps([{"host": "evil.site.example"}]),
            )
        hosts = maps_for_run(params, td, "site.example", "20260101T000000Z")["hosts"]
        self.assertIn("a.site.example", hosts)
        self.assertNotIn("evil.site.example", hosts)

    def test_integrity_seal_refuses_retargeted_meta(self):
        params = _params()
        a = ensure_layout(params, "alpha.example")
        ingest_maps(
            params, a, "alpha.example", "20260101T000000Z", "completed", {},
            _maps([{"host": "only-alpha.example"}]),
        )
        path = warehouse_path(params, a)
        import sqlite3

        conn = sqlite3.connect(str(path))
        conn.execute("UPDATE meta SET value='beta.example' WHERE key='target'")
        conn.commit()
        conn.close()
        with self.assertRaises(WarehouseError):
            open_bound(params, a, "beta.example")

    def test_tampered_payload_is_dropped_on_read(self):
        params = _params()
        td = ensure_layout(params, "site.example")
        ingest_maps(
            params, td, "site.example", "20260101T000000Z", "completed", {},
            _maps([{"host": "ok.site.example", "alive": True}]),
        )
        import sqlite3

        conn = sqlite3.connect(str(warehouse_path(params, td)))
        conn.execute("UPDATE fact_versions SET payload_json='{\"host\":\"evil\"}'")
        conn.commit()
        conn.close()
        hosts = maps_for_run(params, td, "site.example", "20260101T000000Z")["hosts"]
        self.assertNotIn("ok.site.example", hosts)
        self.assertNotIn("evil", hosts)

    def test_illegal_stamp_refused(self):
        params = _params()
        td = ensure_layout(params, "site.example")
        with self.assertRaises(WarehouseError):
            ingest_maps(params, td, "site.example", "not-a-stamp", "completed", {}, _maps([]))


class TestRunDiffAndTimeline(unittest.TestCase):
    def test_consecutive_and_arbitrary_pair_diff(self):
        params = _params()
        td = ensure_layout(params, "site.example")
        ingest_maps(
            params, td, "site.example", "20260101T000000Z", "completed", {"assets": 1},
            _maps([{"host": "a.site.example", "ip": "1.1.1.1"}]),
        )
        ingest_maps(
            params, td, "site.example", "20260102T000000Z", "completed", {"assets": 2},
            _maps([
                {"host": "a.site.example", "ip": "1.1.1.2"},
                {"host": "b.site.example", "ip": "2.2.2.2"},
            ]),
        )
        ingest_maps(
            params, td, "site.example", "20260103T000000Z", "completed", {"assets": 1},
            _maps([{"host": "b.site.example", "ip": "2.2.2.2"}]),
        )
        d12 = compare_runs(params, td, "site.example", "20260101T000000Z", "20260102T000000Z")
        self.assertTrue(d12["exists"])
        self.assertEqual(len(d12["added"]["hosts"]), 1)
        self.assertEqual(d12["added"]["hosts"][0]["host"], "b.site.example")
        self.assertEqual(len(d12["changed"]["hosts"]), 1)
        d13 = compare_runs(params, td, "site.example", "20260101T000000Z", "20260103T000000Z")
        added_hosts = {row["host"] for row in d13["added"]["hosts"]}
        removed_hosts = {row["host"] for row in d13["removed"]["hosts"]}
        self.assertIn("b.site.example", added_hosts)
        self.assertIn("a.site.example", removed_hosts)
        tl = host_timeline(params, td, "site.example")
        self.assertEqual(tl["a.site.example"]["first_seen"], "20260101T000000Z")
        self.assertEqual(tl["a.site.example"]["last_seen"], "20260102T000000Z")
        self.assertEqual(tl["b.site.example"]["first_seen"], "20260102T000000Z")
        self.assertEqual(tl["b.site.example"]["last_seen"], "20260103T000000Z")
        snapshot = facts_as_assets(params, td, "site.example", "20260102T000000Z")
        names = {r["host"] for r in snapshot}
        self.assertEqual(names, {"a.site.example", "b.site.example"})
        enriched = enrich_assets(params, td, "site.example", [{"host": "a.site.example"}])
        self.assertEqual(enriched[0]["first_seen"], "20260101T000000Z")

    def test_rebuild_replays_history_snapshots(self):
        from pipeline.jsonio import write_json

        params = _params()
        td = ensure_layout(params, "site.example")
        rel = str(params.require("assets_relpath"))
        for stamp, hosts in (
            ("20260101T000000Z", [{"host": "one.site.example"}]),
            ("20260102T000000Z", [{"host": "one.site.example"}, {"host": "two.site.example"}]),
        ):
            snap = td / "history" / stamp
            dest = snap / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            write_json(dest, {"schema_version": 1, "assets": hosts})
        led = rebuild_from_history(params, td, "site.example")
        self.assertEqual(led["ingested_runs"], 2)
        d = compare_runs(params, td, "site.example", "20260101T000000Z", "20260102T000000Z")
        self.assertEqual(len(d["added"]["hosts"]), 1)
        self.assertEqual(d["added"]["hosts"][0]["host"], "two.site.example")

    def test_all_fact_classes_roundtrip(self):
        params = _params()
        td = ensure_layout(params, "site.example")
        maps = empty_maps()
        maps["hosts"]["h.site.example"] = {"host": "h.site.example"}
        maps["ports"]["h|1.1.1.1|443|tcp"] = {"host": "h.site.example", "ip": "1.1.1.1", "port": 443, "proto": "tcp"}
        maps["vhosts"]["h|www"] = {"base_host": "h.site.example", "vhost": "www"}
        maps["services"]["1.1.1.1|22|tcp"] = {"ip": "1.1.1.1", "port": 22, "proto": "tcp", "service": "ssh"}
        maps["passive_ips"]["9.9.9.9"] = {"ip": "9.9.9.9"}
        ingest_maps(params, td, "site.example", "20260101T000000Z", "completed", {}, maps)
        got = maps_for_run(params, td, "site.example", "20260101T000000Z")
        for cls in FACT_CLASSES:
            self.assertTrue(got[cls], cls)
        st = status(params, td, "site.example")
        self.assertTrue(st["isolated"])
        for cls in FACT_CLASSES:
            self.assertEqual(st["facts"][cls], 1)

    def test_live_ingest_updates_same_stamp(self):
        from pipeline.jsonio import write_json
        from pipeline.warehouse import ingest_live, list_runs

        params = _params()
        td = ensure_layout(params, "site.example")
        dnsr = td / str(params.require("dnsr_data_json"))
        dnsr.parent.mkdir(parents=True, exist_ok=True)
        write_json(
            dnsr,
            {
                "schema_version": 1,
                "module": "dns-resolve",
                "resolved": [
                    {"host": "a.site.example", "ips": ["1.2.3.4"], "resolution_status": "resolved"},
                    {"host": "dead.site.example", "ips": [], "resolution_status": "unresolved"},
                ],
            },
        )
        first = ingest_live(params, td, "site.example")
        self.assertTrue(first["ok"])
        self.assertEqual(first["facts"], 1)
        stamp = first["stamp"]
        write_json(
            dnsr,
            {
                "schema_version": 1,
                "module": "dns-resolve",
                "resolved": [
                    {"host": "a.site.example", "ips": ["1.2.3.4"], "resolution_status": "resolved"},
                    {"host": "b.site.example", "ips": ["1.2.3.5"], "resolution_status": "resolved"},
                ],
            },
        )
        second = ingest_live(params, td, "site.example")
        self.assertEqual(second["stamp"], stamp)
        self.assertEqual(second["facts"], 2)
        runs = list_runs(params, td, "site.example")
        self.assertEqual(len(runs), 1)
        names = {r["host"] for r in facts_as_assets(params, td, "site.example", stamp)}
        self.assertEqual(names, {"a.site.example", "b.site.example"})


class TestDashboardServiceWarehouse(unittest.TestCase):
    def test_service_views_stay_on_one_target(self):
        from dashboard.service import warehouse_diff_view, warehouse_status_view

        params = _params()
        a = ensure_layout(params, "alpha.example")
        b = ensure_layout(params, "beta.example")
        ingest_maps(
            params, a, "alpha.example", "20260101T000000Z", "completed", {},
            _maps([{"host": "only-alpha.example"}]),
        )
        ingest_maps(
            params, a, "alpha.example", "20260102T000000Z", "completed", {},
            _maps([{"host": "only-alpha.example"}, {"host": "new-alpha.example"}]),
        )
        ingest_maps(
            params, b, "beta.example", "20260101T000000Z", "completed", {},
            _maps([{"host": "only-beta.example"}]),
        )
        view_a = warehouse_status_view(params, "alpha.example")
        view_b = warehouse_status_view(params, "beta.example")
        self.assertEqual(view_a["bound_target"], "alpha.example")
        self.assertEqual(view_b["bound_target"], "beta.example")
        diff = warehouse_diff_view(params, "alpha.example", "20260101T000000Z", "20260102T000000Z")
        added = {row["host"] for row in (diff.get("added") or {}).get("hosts") or []}
        self.assertEqual(added, {"new-alpha.example"})
        self.assertNotIn("only-beta.example", added)
