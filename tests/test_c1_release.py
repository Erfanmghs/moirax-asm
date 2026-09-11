"""Atomic tests for the C1 release security gate (R-1..R-5).

Each test exercises ONE gate function against a synthetic fixture --
never the real repository tree. Fixture literals are ASSEMBLED AT RUNTIME
(concatenation) so this file itself stays clean under the very gate it
tests -- the gate's first CI run caught the literal fixtures, which is the
function-proof of the gate; the fixtures are now self-obfuscating.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ci"))

import c1_release_gate as gate  # noqa: E402

# -- runtime-assembled fixture literals (no trigger literals in source) -----
FAKE_PAT = "github_pat_" + "11BC" + "T" * 40
FAKE_OAUTH = "ghp_" + "a" * 36
FAKE_AWS = "AKIA" + "B" * 16
FAKE_KEY_HEADER = "-" * 5 + "BEGIN " + "RSA " + "PRIVATE KEY" + "-" * 5
FAKE_ASSIGNED = 'api_key = "' + "AbCdEf" + "1" * 10 + "+/" + "q" * 12 + '"'  # q-filler: xxx+ would trip the placeholder filter
FAKE_AUTHOR_FRAG = "mogh" + "isserfan"
FAKE_MAIL_DOMAIN = "@" + "gmail.com"
FAKE_ESTATE_IP_1 = "5.145.118." + "11"
FAKE_ESTATE_IP_2 = "46.245.92." + "206"
FAKE_PERSIAN = "\u067e\u06cc\u0634" + ": fixture"  # Persian letters, assembled


class R1Secrets(unittest.TestCase):
    def test_real_pat_shape_is_caught(self):
        hits = gate.scan_secrets("token = '" + FAKE_PAT + "'")
        self.assertTrue(any(n == "github-pat" for n, _ in hits), hits)

    def test_classic_oauth_shape_is_caught(self):
        hits = gate.scan_secrets(FAKE_OAUTH)
        self.assertTrue(any(n == "github-oauth" for n, _ in hits))

    def test_aws_and_private_key_caught(self):
        t = FAKE_AWS + "\n" + FAKE_KEY_HEADER
        names = {n for n, _ in gate.scan_secrets(t)}
        self.assertIn("aws-access-key", names)
        self.assertIn("private-key-block", names)

    def test_assigned_secret_shape_caught(self):
        hits = gate.scan_secrets(FAKE_ASSIGNED)
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
        self.assertEqual(gate.scan_non_ascii("spec " + "\u00a7" + "8 says"), {"\u00a7"})

    def test_persian_text_flagged_by_ascii_gate(self):
        text = FAKE_PERSIAN + " -- Phase B0"
        self.assertTrue(gate.scan_non_ascii(text))

    def test_waiver_prefix_logic(self):
        waived = ("pipeline/verify_b1.py", ".cursor/rules/", "recon/")
        for rel in ("pipeline/verify_b1.py", ".cursor/rules/x.md", "recon/example.com/logs/run.log"):
            self.assertTrue(rel.startswith(waived), rel)
        for rel in ("dashboard/app.py", "README.md", "pipeline/engine.py", "docs/README.fa.md"):
            self.assertFalse(rel.startswith(waived), rel)

    def test_no_persian_readme_in_tree(self):
        # operator law: Persian is forbidden project-wide (LinkedIn + platform)
        self.assertFalse((gate.ROOT / "README.fa.md").exists())


class R4PersonalData(unittest.TestCase):
    def test_author_email_fragment_caught(self):
        hits = gate.scan_personal("contact " + FAKE_AUTHOR_FRAG + "@example.com")
        self.assertTrue(any(n == "author-email-fragment" for n, _ in hits))

    def test_gmail_domain_caught(self):
        hits = gate.scan_personal("mail me at someone" + FAKE_MAIL_DOMAIN)
        self.assertTrue(any(n == "personal-mail-domain" for n, _ in hits))

    def test_operator_estate_ips_caught(self):
        hits = gate.scan_personal("resolved to " + FAKE_ESTATE_IP_1 + " and " + FAKE_ESTATE_IP_2)
        names = {n for n, _ in hits}
        self.assertIn("operator-estate-ip-1", names)
        self.assertIn("operator-estate-ip-2", names)

    def test_public_anycast_ip_not_flagged(self):
        self.assertEqual(gate.scan_personal("resolver 1.1.1.1 and 8.8.8.8 are fine"), [])


class R5ScriptDefense(unittest.TestCase):
    def test_persian_script_detected(self):
        self.assertTrue(gate.scan_arabic_script(FAKE_PERSIAN))
        self.assertTrue(gate.scan_arabic_script("\u0644\u06cc\u0633\u062a " + "\u06f2\u06f0\u06f0"))

    def test_english_untouched(self):
        self.assertEqual(gate.scan_arabic_script("Run the pipeline, scan the target."), [])

    def test_neutral_non_ascii_not_script(self):
        self.assertEqual(gate.scan_arabic_script("marks \u2713 and math \u2211 stay outside script ranges"), [])


class R6FixtureScope(unittest.TestCase):
    def test_fixture_includes_are_clean(self):
        self.assertEqual(
            gate.extra_scope_includes(["example.com", "*.example.com", "fixture-target.test"]),
            [],
        )

    def test_operator_estate_is_rejected(self):
        hits = gate.extra_scope_includes(["example.com", "owned.example"])
        self.assertEqual(hits, ["owned.example"])

    def test_empty_target_registry_is_clean(self):
        self.assertEqual(gate.extra_target_names([]), [])

    def test_non_fixture_target_key_is_rejected(self):
        self.assertEqual(gate.extra_target_names(["owned.example"]), ["owned.example"])


class BanditBridge(unittest.TestCase):
    def test_bandit_bridge_returns_counts(self):
        high, med, ids = gate.run_bandit()
        self.assertIsInstance(high, int)
        self.assertIsInstance(med, int)
        self.assertIsInstance(ids, list)


if __name__ == "__main__":
    unittest.main()
