"""Author credit must stay on generated reports and in source."""

from __future__ import annotations

import unittest
from pathlib import Path

from pipeline.attribution import (
    ATTRIBUTION_TEXT,
    AUTHOR_URL,
    html_footer,
    markdown_footer,
    seal_html,
)
from tests.test_reporting import _pdf_text, _vehicle_dir
from pipeline.reporting import generate_all

_ROOT = Path(__file__).resolve().parents[1]
_REQUIRED_URL = (
    "pipeline/attribution.py",
    "dashboard/static/index.html",
    "AGENTS.md",
)
_REQUIRED_WIRE = (
    ("pipeline/report_html.py", ("html_footer()", "seal_html(")),
    ("pipeline/reporting.py", ("ATTRIBUTION_TEXT", "AUTHOR_URL", "markdown_footer()")),
)


class TestAttributionContract(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(AUTHOR_URL, "https://www.linkedin.com/in/erfanmoghis/")
        self.assertEqual(ATTRIBUTION_TEXT, "Attack Surface Management by Erfan Moghis")
        self.assertIn(AUTHOR_URL, html_footer())
        self.assertIn(ATTRIBUTION_TEXT, html_footer())
        self.assertIn("moirax-author", html_footer())
        self.assertIn(AUTHOR_URL, markdown_footer())

    def test_seal_restores_stripped_html(self):
        sealed = seal_html("<html><body><p>report</p></body></html>")
        self.assertIn(AUTHOR_URL, sealed)
        self.assertIn(ATTRIBUTION_TEXT, sealed)
        self.assertIn("moirax-author", sealed)

    def test_source_files_keep_the_url(self):
        for rel in _REQUIRED_URL:
            text = (_ROOT / rel).read_text(encoding="utf-8")
            self.assertIn(AUTHOR_URL, text, rel)
            self.assertIn("Erfan Moghis", text, rel)
        for rel, needles in _REQUIRED_WIRE:
            text = (_ROOT / rel).read_text(encoding="utf-8")
            for needle in needles:
                self.assertIn(needle, text, f"{rel} missing {needle}")

    def test_generated_html_md_pdf_carry_credit(self):
        params, td = _vehicle_dir()
        generate_all(params, td, "20260101T000000Z")
        html = (td / "90_report" / "report.html").read_text(encoding="utf-8")
        md = (td / "90_report" / "report.md").read_text(encoding="utf-8")
        pdf = (td / "90_report" / "report.pdf").read_bytes()
        self.assertIn(AUTHOR_URL, html)
        self.assertIn(ATTRIBUTION_TEXT, html)
        self.assertIn('href="' + AUTHOR_URL + '"', html)
        self.assertIn(AUTHOR_URL, md)
        self.assertIn(ATTRIBUTION_TEXT, md)
        rendered = _pdf_text(pdf)
        self.assertIn(ATTRIBUTION_TEXT.encode("latin-1"), rendered)
        self.assertIn(b"erfanmoghis", rendered)


if __name__ == "__main__":
    unittest.main()
