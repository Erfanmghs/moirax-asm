"""HTTP enrich parse + skip-when-disabled (no docker)."""

from __future__ import annotations

import unittest

from pipeline.httpx_probe import apply_enrich, enrich_from_row, index_httpx_payload, probe_hosts


class _OffAdapter:
    def enabled(self, name: str) -> bool:
        return False

    def invoke(self, *args, **kwargs):
        raise AssertionError("httpx must not launch when disabled")


class TestHttpxEnrich(unittest.TestCase):
    def test_parses_length_and_tech(self):
        row = enrich_from_row(
            {
                "host": "api.example.com",
                "status_code": 200,
                "content_length": 4096,
                "title": "API",
                "tech": ["nginx:1.24.0", "PHP"],
            }
        )
        self.assertTrue(row["alive"])
        self.assertEqual(row["http_status"], 200)
        self.assertEqual(row["length"], 4096)
        self.assertEqual(row["tech"], ["nginx:1.24.0", "PHP"])
        self.assertEqual(row["title"], "API")

    def test_index_by_host(self):
        mapped = index_httpx_payload(
            [
                {"input": "https://www.example.com", "status_code": 301, "content_length": 17},
                {"host": "api.example.com", "failed": True},
            ]
        )
        self.assertEqual(mapped["www.example.com"]["http_status"], 301)
        self.assertEqual(mapped["www.example.com"]["length"], 17)
        self.assertFalse(mapped["api.example.com"]["alive"])

    def test_apply_miss_marks_dead(self):
        row = {"fqdn": "gone.example.com"}
        apply_enrich(row, None, miss_alive=True)
        self.assertFalse(row["alive"])

    def test_disabled_httpx_never_invokes(self):
        out = probe_hosts(
            params=None,  # type: ignore[arg-type]
            adapter=_OffAdapter(),  # type: ignore[arg-type]
            target_dir=None,  # type: ignore[arg-type]
            target="example.com",
            extra={},
            planned=1,
            timeout_sec=1,
            hosts=["www.example.com"],
            list_rel="x.txt",
            out_rel="x.json",
            module="dns-resolve",
            raw_dir="logs/raw/x",
        )
        self.assertEqual(out, {})


if __name__ == "__main__":
    unittest.main()
