"""SCAN multi-target board: isolated workspaces, no row mixing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dashboard.service import DashboardError, scan_add_target, scan_board_view
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
        self.assertEqual(board["beta.example"]["modules_running"], 0)
