"""SCAN multi-target board: isolated workspaces, no row mixing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dashboard.service import DashboardError, scan_add_target, scan_board_view, scan_delete_target
from pipeline.params import Params

_ROOT = Path(__file__).resolve().parents[1]


def _params() -> Params:
    tmp = Path(tempfile.mkdtemp())
    (tmp / "tools.yaml").write_text((_ROOT / "tools.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    return Params(tmp)


class TestScanBoard(unittest.TestCase):
    def test_add_two_targets_never_share_workspace(self):
        params = _params()
        a = scan_add_target(params, "alpha.example", "site a")
        b = scan_add_target(params, "beta.example", "site b")
        self.assertTrue(a["registered"])
        self.assertTrue(b["registered"])
        self.assertTrue(a["workspace"])
        recon = params.root / "recon"
        self.assertTrue((recon / "alpha.example").is_dir())
        self.assertTrue((recon / "beta.example").is_dir())
        self.assertNotEqual((recon / "alpha.example").resolve(), (recon / "beta.example").resolve())
        board = scan_board_view(params)
        names = [row["target"] for row in board["targets"]]
        self.assertEqual(names, ["alpha.example", "beta.example"])
        self.assertEqual(board["count"], 2)

    def test_add_is_idempotent_and_rejects_bad_names(self):
        params = _params()
        first = scan_add_target(params, "alpha.example", "first")
        again = scan_add_target(params, "alpha.example", "second")
        self.assertEqual(first["description"], "first")
        self.assertEqual(again["description"], "first")
        with self.assertRaises(DashboardError):
            scan_add_target(params, "../escape", "nope")

    def test_board_status_is_per_target(self):
        from pipeline.jsonio import write_json

        params = _params()
        scan_add_target(params, "alpha.example")
        scan_add_target(params, "beta.example")
        write_json(
            params.root / "recon" / "alpha.example" / "state.json",
            {
                "schema_version": 1,
                "target": "alpha.example",
                "run": {"status": "running"},
                "modules": {"ffuf": {"status": "running"}},
            },
        )
        write_json(
            params.root / "recon" / "beta.example" / "state.json",
            {
                "schema_version": 1,
                "target": "beta.example",
                "run": {"status": "completed"},
                "modules": {"ffuf": {"status": "done"}},
            },
        )
        board = {row["target"]: row for row in scan_board_view(params)["targets"]}
        self.assertEqual(board["alpha.example"]["run_status"], "running")
        self.assertEqual(board["beta.example"]["run_status"], "completed")
        self.assertEqual(board["alpha.example"]["modules_running"], 1)

    def test_board_row_exposes_full_profile_for_scan_setup(self):
        from dashboard.service import target_profile_upsert

        params = _params()
        scan_add_target(params, "alpha.example", "site a")
        target_profile_upsert(params, "alpha.example", {
            "description": "site a",
            "budgets": {"passive_recursion_depth": 1},
            "modules": {"active_branch_modules": ["dns-resolve", "ffuf"]},
        })
        board = {row["target"]: row for row in scan_board_view(params)["targets"]}
        prof = board["alpha.example"]["profile"]
        self.assertEqual(prof["description"], "site a")
        settings = prof.get("settings") or {}
        self.assertEqual(settings["budgets"]["passive_recursion_depth"], 1)
        self.assertEqual(settings["modules"]["active_branch_modules"], ["dns-resolve", "ffuf"])
        self.assertFalse(board["alpha.example"]["inherits_globals"])

    def test_parse_and_add_list(self):
        from dashboard.service import parse_scan_target_list, scan_add_targets

        params = _params()
        names, rejected = parse_scan_target_list("a.example, b.example\nc.example")
        self.assertEqual(names, ["a.example", "b.example", "c.example"])
        self.assertEqual(rejected, [])
        bad, rejected = parse_scan_target_list("../x, ok.example")
        self.assertEqual(bad, ["ok.example"])
        self.assertTrue(rejected)
        out = scan_add_targets(params, names, "list")
        self.assertEqual(out["count"], 3)
        self.assertEqual(len(out["targets"]), 3)
        board = scan_board_view(params)
        self.assertEqual([row["target"] for row in board["targets"]], names)
        self.assertTrue(all(row["inherits_globals"] for row in board["targets"]))

    def test_start_requires_add_first(self):
        from dashboard.service import scan_require_registered

        params = _params()
        with self.assertRaises(DashboardError):
            scan_require_registered(params, "missing.example")
        scan_add_target(params, "alpha.example", "site a")
        self.assertEqual(scan_require_registered(params, "alpha.example"), "alpha.example")

    def test_delete_hides_from_scan_but_keeps_warehouse(self):
        from pipeline.deleted import is_tombstoned, purge_if_expired
        from pipeline.warehouse import ingest_maps, warehouse_path
        from pipeline.history import empty_maps

        params = _params()
        scan_add_target(params, "alpha.example", "site a")
        scan_add_target(params, "beta.example", "site b")
        maps = empty_maps()
        maps["hosts"]["a.alpha.example"] = {"host": "a.alpha.example"}
        td_a = params.root / "recon" / "alpha.example"
        ingest_maps(params, td_a, "alpha.example", "20260101T000000Z", "completed", {}, maps)
        led = scan_delete_target(params, "alpha.example")
        self.assertEqual(led["deleted"], "alpha.example")
        self.assertTrue(led["hidden"])
        self.assertFalse(led["workspace_removed"])
        self.assertEqual(led["kept_days"], 7)
        self.assertTrue(is_tombstoned(td_a))
        self.assertTrue(warehouse_path(params, td_a).is_file())
        self.assertTrue((params.root / "recon" / "beta.example").is_dir())
        names = [row["target"] for row in scan_board_view(params)["targets"]]
        self.assertEqual(names, ["beta.example"])
        from datetime import datetime, timedelta, timezone

        future = datetime.now(timezone.utc) + timedelta(days=8)
        purged = purge_if_expired(params, td_a, now=future)
        self.assertTrue(purged["purged"])
        self.assertFalse(td_a.exists())
        self.assertTrue((params.root / "recon" / "beta.example").is_dir())
