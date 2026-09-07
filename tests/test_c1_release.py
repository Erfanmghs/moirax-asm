"""Atomic tests for the C1 release security gate (R-1..R-5).

Each test exercises ONE gate function against a synthetic fixture —
never the real repository tree.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))

import c1_release_gate as gate  # noqa: E402


class R1Secrets(unittest.TestCase):
    def test_real_pat_shape_is_caught(self):
        text = "token = 'github_pat_11BCTH5PQ0hePBMdi9Y9eY1234567890ABCDEFGHIJKLMNOP'"
        hits = gate.scan_secrets(text)
        self.assertTrue(any(n == "github-pat" for n, _ in hits), hits)

    def test_classic_oauth_shape_is_caught(self):
        hits = gate.scan_secrets("ghp_" + "a" * 36)
        self.assertTrue(any(n == "github-oauth" for n, _ in hits))

    def test_aws_and_private_key_caught(self):
        t = "AKIA" + "B" * 16 + "\n-----BEGIN RSA PRIVATE KEY-----"
        names = {n for n, _ in gate.scan_secrets(t)}
        self.assertIn("aws-access-key", names)
        self.assertIn("private-key-block", names)

    def test_assigned_secret_shape_caught(self):
        hits = gate.scan_secrets('api_key = "AbCdEf1234567890+/abcdefghijk"')
        self.assertTrue(any(n == "assigned-secret-shape" for n, _ in hits))

    def test_placeholders_not_flagged(self):
        clean = "\n".join([
            "GITHUB_TOKEN=",
            "API_KEY=your_key_here",
            "SECRET=changeme",
            "TOKEN=${ENV_VAR}",
            'KEY="<paste-your-token>"',
            "# example: set EXAMPLE_KEY=example",
        ])
        self.assertEqual(gate.scan_secrets(clean), [])

    def test_empty_tree_scan_is_clean(self):
        self.assertEqual(gate.scan_secrets("hello world\nnothing here\n"), [])


class R3Ascii(unittest.TestCase):
    def test_pure_ascii_passes(self):
        self.assertEqual(gate.scan_non_ascii("English only: run, scan, report.\n"), set())

    def test_section_sign_flagged(self):
        self.assertEqual(gate.scan_non_ascii("spec §8 says"), {"§"})

    def test_persian_text_flagged_by_ascii_gate(self):
        text = "گام ۱ -- Phase B0"
        self.assertTrue(gate.scan_non_ascii(text))

    def test_waiver_prefix_logic(self):
        waived = ("pipeline/verify_b1.py", ".cursor/rules/", "recon/")
        for rel in ("pipeline/verify_b1.py", ".cursor/rules/x.md", "recon/example.com/logs/run.log"):
            self.assertTrue(rel.startswith(waived), rel)
        for rel in ("dashboard/app.py", "README.md", "pipeline/engine.py"):
            self.assertFalse(rel.startswith(waived), rel)


class R4PersonalData(unittest.TestCase):
    def test_author_email_fragment_caught(self):
        hits = gate.scan_personal("contact moghisserfan@example.com")
        self.assertTrue(any(n == "author-email-fragment" for n, _ in hits))

    def test_gmail_domain_caught(self):
        hits = gate.scan_personal("mail me at someone@gmail.com")
        self.assertTrue(any(n == "personal-mail-domain" for n, _ in hits))

    def test_operator_estate_ips_caught(self):
        hits = gate.scan_personal("resolved to 5.145.118.11 and 46.245.92.206")
        names = {n for n, _ in hits}
        self.assertIn("operator-estate-ip-1", names)
        self.assertIn("operator-estate-ip-2", names)

    def test_public_anycast_ip_not_flagged(self):
        self.assertEqual(gate.scan_personal("resolver 1.1.1.1 and 8.8.8.8 are fine"), [])


class R5ScriptDefense(unittest.TestCase):
    def test_persian_script_detected(self):
        self.assertTrue(gate.scan_arabic_script("پیش‌نیاز: دو فایل spec"))
        self.assertTrue(gate.scan_arabic_script("لیست ۲۰۰ تایی"))

    def test_english_untouched(self):
        self.assertEqual(gate.scan_arabic_script("Run the pipeline, scan the target."), [])

    def test_neutral_non_ascii_not_script(self):
        self.assertEqual(gate.scan_arabic_script("emoji ✓ and math ∑ stay outside script ranges"), [])


class BanditBridge(unittest.TestCase):
    def test_bandit_bridge_returns_counts(self):
        high, med, ids = gate.run_bandit()
        self.assertIsInstance(high, int)
        self.assertIsInstance(med, int)
        self.assertIsInstance(ids, list)


if __name__ == "__main__":
    unittest.main()
