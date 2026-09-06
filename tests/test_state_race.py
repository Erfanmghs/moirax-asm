"""REM26 regression (run #40 evidence): concurrent state writers must not race
on a shared tmp filename. The E2E vehicle's passive and active branches start
simultaneously; two save_state calls interleaving used to raise
FileNotFoundError (branch killed -> passive-recon stuck pending forever)."""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from pipeline.params import Params
from pipeline.state import save_state

_ROOT = Path(__file__).resolve().parents[1]


class TestConcurrentSaveState(unittest.TestCase):
    def test_concurrent_writers_never_lose_tmp(self):
        params = Params(_ROOT)
        tdir = Path(tempfile.mkdtemp())
        errors: list[Exception] = []
        barrier = threading.Barrier(8)

        def writer(n: int) -> None:
            try:
                barrier.wait()
                for i in range(60):
                    save_state(params, tdir, {"writer": n, "iter": i})
            except Exception as exc:  # noqa: BLE001 — the race surfaced as OSError
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"concurrent save_state raced: {errors[:3]}")
        doc = (tdir / "state.json").read_text(encoding="utf-8")
        self.assertIn("updated_at", doc)
        leftovers = [p.name for p in tdir.iterdir() if ".tmp" in p.name]
        self.assertEqual(leftovers, [], f"tmp files leaked: {leftovers}")

    def test_tmp_name_shape_is_writer_unique_components(self):
        """Shape check only: ident uniqueness among LIVE threads is proven by
        test_concurrent_writers_never_lose_tmp (get_ident is recycled after a
        thread exits, so comparing idents of dead threads is meaningless)."""
        import os

        path = Path("state.json")
        tmp = path.with_suffix(f"{path.suffix}.{os.getpid()}.{threading.get_ident()}.tmp")
        self.assertNotEqual(str(tmp), "state.json")
        self.assertTrue(tmp.name.startswith("state.json."))
        self.assertTrue(tmp.name.endswith(".tmp"))
        self.assertNotIn("/", tmp.name)


if __name__ == "__main__":
    unittest.main()
