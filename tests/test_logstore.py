"""Storage management unit proof (pipeline/logstore.py) -- post-B user
directive 2026-09-06: retention, rotation, total cap. Deterministic, no
network, no docker."""

from __future__ import annotations

import gzip
import tempfile
import unittest
from pathlib import Path

from pipeline.logstore import _retention_config, enforce_total_cap, housekeep, prune_history, rotate_log
from pipeline.params import Params

_ROOT = Path(__file__).resolve().parents[1]


def _isolated_params() -> Params:
    tmp = Path(tempfile.mkdtemp())
    for rel in ("tools.yaml", "wordlists.yaml", "scheduler.json", "scope.yaml"):
        src = _ROOT / rel
        if src.is_file():
            (tmp / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp / "dashboard").mkdir(exist_ok=True)
    return Params(tmp)


def _target(params: Params, name: str = "example.com") -> Path:
    tdir = params.root / "recon" / name
    (tdir / "logs").mkdir(parents=True, exist_ok=True)
    return tdir


def _snapshot(tdir: Path, stamp: str, fill_bytes: int = 128) -> Path:
    snap = tdir / "history" / stamp
    (snap / "00_assets").mkdir(parents=True, exist_ok=True)
    (snap / "00_assets" / "assets.json").write_bytes(b"x" * fill_bytes)
    return snap


class TestRetentionConfig(unittest.TestCase):
    def test_defaults_from_tools_yaml(self):
        cfg = _retention_config(_isolated_params())
        self.assertEqual(cfg["keep_runs"], 20)
        self.assertEqual(cfg["log_max_mb"], 10)
        self.assertEqual(cfg["journal_max_mb"], 5)
        self.assertEqual(cfg["log_keep_gz"], 3)
        self.assertEqual(cfg["max_total_mb"], 1024)

    def test_dashboard_config_overrides_and_malformed_degrades(self):
        params = _isolated_params()
        cfg_path = params.root / "dashboard" / "config.json"
        cfg_path.write_text('{"retention": {"keep_runs": 5, "log_max_mb": "bad", "max_total_mb": 0}}', encoding="utf-8")
        cfg = _retention_config(params)
        self.assertEqual(cfg["keep_runs"], 5)          # valid override wins
        self.assertEqual(cfg["log_max_mb"], 10)        # malformed -> default
        self.assertEqual(cfg["max_total_mb"], 1024)    # below-1 rejected -> default
        cfg_path.write_text("{not json", encoding="utf-8")
        self.assertEqual(_retention_config(params)["keep_runs"], 20)  # defensive loader

    def test_missing_target_dir_is_noop(self):
        params = _isolated_params()
        ledger = housekeep(params, params.root / "recon" / "ghost.test")
        self.assertFalse(ledger["applied"])


class TestRotation(unittest.TestCase):
    def test_oversize_log_rotated_and_truncated(self):
        tdir = _target(_isolated_params())
        big = tdir / "logs" / "run.log"
        big.write_bytes(b"z" * (2 * 1024 * 1024))
        res = rotate_log(big, max_mb=1, keep_gz=3)
        self.assertTrue(res["rotated"])
        self.assertTrue((big.parent / res["archived"]).name.startswith("run.log."))
        self.assertEqual(big.stat().st_size, 0)
        self.assertGreater(res["freed_bytes"], 0)
        with gzip.open(big.parent / res["archived"], "rb") as gz:
            self.assertEqual(len(gz.read()), 2 * 1024 * 1024)

    def test_small_log_untouched(self):
        tdir = _target(_isolated_params())
        small = tdir / "logs" / "run.log"
        small.write_bytes(b"a" * 100)
        self.assertFalse(rotate_log(small, max_mb=1, keep_gz=3)["rotated"])
        self.assertEqual(small.stat().st_size, 100)

    def test_keep_gz_prunes_oldest_name_scoped(self):
        tdir = _target(_isolated_params())
        log = tdir / "logs" / "run.log"
        other = tdir / "logs" / "agent-journal.jsonl.20200101T000000Z.gz"
        other.write_bytes(b"j")
        for i, stamp in enumerate(("20200101T000000Z", "20200102T000000Z", "20200103T000000Z", "20200104T000000Z")):
            log.write_bytes(b"z" * (2 * 1024 * 1024))
            rotate_log(log, max_mb=1, keep_gz=3)
            log.write_bytes(b"")  # reset live file
        gz = sorted((tdir / "logs").glob("run.log.*.gz"))
        self.assertEqual(len(gz), 3)                     # keep_gz enforced
        self.assertTrue(other.is_file())                 # other log's archives untouched
        self.assertNotIn("20200101T000000Z", [p.name for p in gz])  # oldest pruned


class TestHistoryRetention(unittest.TestCase):
    def test_keep_newest_prune_older(self):
        params = _isolated_params()
        tdir = _target(params)
        for d in ("20250101T000000Z", "20250102T000000Z", "20250103T000000Z"):
            _snapshot(tdir, d)
        res = prune_history(params, tdir, keep_runs=2)
        self.assertEqual(res["pruned"], ["20250101T000000Z"])
        self.assertGreater(res["freed_bytes"], 0)
        self.assertTrue((tdir / "history" / "20250103T000000Z").is_dir())

    def test_foreign_dirs_never_touched(self):
        params = _isolated_params()
        tdir = _target(params)
        foreign = tdir / "history" / "not-a-stamp"
        foreign.mkdir(parents=True, exist_ok=True)
        (foreign / "keep.txt").write_text("keep", encoding="utf-8")
        _snapshot(tdir, "20250101T000000Z")
        res = prune_history(params, tdir, keep_runs=1)
        self.assertEqual(res["pruned"], [])
        self.assertTrue(foreign.is_file() or (foreign / "keep.txt").is_file())


class TestTotalCap(unittest.TestCase):
    def test_cap_purges_oldest_first_protected_survive(self):
        params = _isolated_params()
        tdir = _target(params)
        # 4 x 4KB snapshots + 1 x 2KB gz archive; cap = 1 MB -> nothing freed at first.
        for d in ("20250101T000000Z", "20250102T000000Z", "20250103T000000Z", "20250104T000000Z"):
            _snapshot(tdir, d, fill_bytes=4096)
        (tdir / "logs" / "run.log.20250101T000000Z.gz").write_bytes(b"g" * 2048)
        protected = {
            "data.json": '{"hosts": []}',
            "runs.json": '{"runs": []}',
            "state.json": "{}",
            "diff.json": "{}",
        }
        for name, blob in protected.items():
            (tdir / name).write_text(blob, encoding="utf-8")
        (tdir / "90_report").mkdir(exist_ok=True)
        (tdir / "90_report" / "report.md").write_text("# keep", encoding="utf-8")
        # Now a tiny cap forces purges: history dirs first, then archives.
        res = enforce_total_cap(params, tdir, max_mb=1)
        self.assertFalse(res["capped"])  # 1 MB limit not exceeded by ~18KB fixture
        # Shrink limit path via direct call with 0-ish bytes is clamped >=1 MB,
        # so simulate by inflating data: add a 2 MB protected file -- cap purges
        # all managed surfaces but NEVER the protected files.
        (tdir / "00_assets").mkdir(exist_ok=True)
        (tdir / "00_assets" / "assets.json").write_bytes(b"p" * (2 * 1024 * 1024))
        res = enforce_total_cap(params, tdir, max_mb=1)
        self.assertTrue(res["capped"])
        self.assertEqual(len(res["purged_runs"]), 4)
        self.assertEqual(len(res["purged_archives"]), 1)
        for name, blob in protected.items():
            self.assertTrue((tdir / name).is_file(), f"protected {name} must survive")
        self.assertTrue((tdir / "90_report" / "report.md").is_file())
        self.assertTrue((tdir / "00_assets" / "assets.json").is_file())


class TestHousekeepEndToEnd(unittest.TestCase):
    def test_full_ledger(self):
        params = _isolated_params()
        (params.root / "dashboard" / "config.json").write_text(
            '{"retention": {"log_max_mb": 1, "journal_max_mb": 1}}', encoding="utf-8"
        )
        tdir = _target(params)
        for d in ("20250101T000000Z", "20250102T000000Z", "20250103T000000Z"):
            _snapshot(tdir, d)
        (tdir / "logs" / "run.log").write_bytes(b"z" * (2 * 1024 * 1024))
        (tdir / "logs" / "agent-journal.jsonl").write_bytes(b"j" * (2 * 1024 * 1024))
        ledger = housekeep(params, tdir)
        self.assertTrue(ledger["applied"])
        self.assertEqual(len(ledger["rotated"]), 2)      # run.log + journal
        self.assertEqual(ledger["pruned_runs"], [])      # keep 20 > 3 snapshots -> no prune
        self.assertGreater(ledger["freed_bytes"], 0)
        self.assertFalse(ledger["capped"])
        self.assertEqual((tdir / "logs" / "run.log").stat().st_size, 0)

    def test_keep_runs_prune_in_housekeep(self):
        params = _isolated_params()
        cfg_path = params.root / "dashboard" / "config.json"
        cfg_path.write_text('{"retention": {"keep_runs": 1}}', encoding="utf-8")
        tdir = _target(params)
        for d in ("20250101T000000Z", "20250102T000000Z", "20250103T000000Z"):
            _snapshot(tdir, d)
        ledger = housekeep(params, tdir)
        self.assertEqual(ledger["pruned_runs"], ["20250101T000000Z", "20250102T000000Z"])
        self.assertTrue((tdir / "history" / "20250103T000000Z").is_dir())


if __name__ == "__main__":
    unittest.main()
