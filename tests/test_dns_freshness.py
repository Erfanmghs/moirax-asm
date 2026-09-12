"""TEST 3 (T3-1) bidirectional regression proof: per-run freshness of dnsx outputs.

Defect (OLD): dnsx `-o` APPENDS to an existing file. A stale output committed
in the live tree by a previous run era (evidence: committed
recon/example.com/20_dns/dnsx/brute_chunk_0.json carries 10319 rows / 4860
unique hosts from the dns_fast_top5000 era while the current test-mode
selection yields candidates.brute == 200) is re-read by `_rows_from()` and
pollutes the resolved map with stale-era rows.

Fix (NEW): `_unlink_stale()` removes the output file before every dnsx /
dnsx-list / massdns / alterx invoke, so the parsed rows contain ONLY this
run's output.

Simulated dnsx append semantics: the fake adapter appends a FRESH NDJSON row
to whatever file exists at `dnsx_output` (file kept if present, created if
absent) -- exactly how dnsx `-o` behaves on a pre-existing file.

No docker, no network -- pure function test (mirrors tests/test_ffuf_label.py
REM4-R STEP 1 style).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pipeline.modules.dns_resolve import _dnsx_list, _unlink_stale


class _FakeParams:
    def __init__(self, mount: str) -> None:
        self._mount = mount

    def require(self, key: str):
        if key == "recon_container_mount":
            return self._mount
        raise KeyError(key)


class _FakeResult:
    exit_code = 0
    stdout = ""


class _AppendingDnsxAdapter:
    """dnsx `-o` append semantics: write a fresh NDJSON row to the output file
    if it exists (append), create it if it does not."""

    def __init__(self, out_path: Path, fresh_row: dict) -> None:
        self._out = out_path
        self._row = fresh_row

    def invoke(self, tool, **kwargs):  # signature compatible with Adapter.invoke
        with self._out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(self._row) + "\n")
        return _FakeResult()


class _NoopBalancer:
    def current_qps(self) -> int:
        return 1000


class TestUnlinkStale(unittest.TestCase):
    def test_existing_stale_file_removed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "stale.json"
            p.write_text('{"host": "old.example.com", "a": ["192.0.2.1"]}\n', encoding="utf-8")
            _unlink_stale(p)
            self.assertFalse(p.exists())

    def test_absent_file_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _unlink_stale(Path(td) / "never-written.json")  # must not raise


class TestDnsxListFreshness(unittest.TestCase):
    def test_stale_rows_cannot_leak_into_parsed_rows(self) -> None:
        """OLD class: stale rows in the pre-existing file leak into rows.
        NEW class: with the fix, only the fresh run's rows survive."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out_rel = "20_dns/dnsx/brute_chunk_0.json"
            out_path = root / out_rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps({"host": "old.example.com", "a": ["192.0.2.1"]}) + "\n"
                + json.dumps({"host": "older.example.com", "a": ["192.0.2.2"]}) + "\n",
                encoding="utf-8",
            )
            fresh = {
                "host": "www.example.com",
                "a": ["93.184.216.34"],
                "timestamp": "2026-09-05T00:00:00Z",
            }
            adapter = _AppendingDnsxAdapter(out_path, fresh)
            rows = _dnsx_list(
                params=_FakeParams("/recon"),
                adapter=adapter,
                target_dir=root,
                target="example.com",
                extra={},
                planned=1,
                timeout_sec=None,
                balancer=_NoopBalancer(),
                hosts_rel="20_dns/dnsx/in.txt",
                out_rel=out_rel,
                resolvers_c="/recon/resolvers.txt",
                source="unittest",
            )
            self.assertEqual([r.get("host") for r in rows], ["www.example.com"])


class TestSkipDoneChunk(unittest.TestCase):
    def test_done_marker_skips_invoke(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out_rel = "20_dns/dnsx/brute_chunk_0.json"
            out_path = root / out_rel
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(
                json.dumps({"host": "keep.example.com", "a": ["192.0.2.8"]}) + "\n",
                encoding="utf-8",
            )
            (out_path.parent / (out_path.name + ".done")).write_text("ok\n", encoding="utf-8")

            class _Boom:
                def invoke(self, *args, **kwargs):
                    raise AssertionError("must not re-invoke a completed chunk")

            rows = _dnsx_list(
                params=_FakeParams("/recon"),
                adapter=_Boom(),
                target_dir=root,
                target="example.com",
                extra={},
                planned=1,
                timeout_sec=None,
                balancer=_NoopBalancer(),
                hosts_rel="20_dns/dnsx/in.txt",
                out_rel=out_rel,
                resolvers_c="/recon/resolvers.txt",
                source="unittest",
            )
            self.assertEqual([r.get("host") for r in rows], ["keep.example.com"])


if __name__ == "__main__":
    unittest.main()
