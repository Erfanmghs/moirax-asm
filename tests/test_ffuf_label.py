"""REM4-R1 bidirectional regression proof for the calib-drop over-drop fix.

Old behavior: a genuine wordlist hit (www) was dropped because -ac desynced
input.FUZZ from the Host/URL that actually answered. The fix
(`pipeline.modules.ffuf._wordlist_fuzz_label`) recovers the relative label
from Host/URL first and only drops values that are NOT in the job wordlist.

Bidirectional contract:
  NEW class accepted : www (label recovered from Host/URL despite FUZZ desync)
  OLD class dropped  : xnrbibej (autocalib FUZZ token, not in the wordlist)

Hits are passed in the FLATTENED shape produced by `pipeline.modules.ffuf._ffuf_hits`
(`fuzz` / `host` / `url` / `status` / `length` keys), i.e. post input.FUZZ extraction.

No docker, no network — pure function test (REM4-R STEP 1 unit proof).
"""

from __future__ import annotations

import unittest

from pipeline.modules.ffuf import _wordlist_fuzz_label

ALLOWED = {"www", "app", "mail", "webmail", "vpn", "dev", "staging"}
PARENT = "fixture-target.test"
BASE = "app.fixture-target.test"


class TestWordlistFuzzLabel(unittest.TestCase):
    def test_www_recovered_from_host_despite_fuzz_desync(self) -> None:
        """NEW: genuine hit with desynced -ac FUZZ token must be accepted."""
        hit = {
            "fuzz": "kGHqerTs",
            "host": "www.fixture-target.test",
            "url": "http://www.fixture-target.test/",
            "status": 200,
            "length": 17,
        }
        self.assertEqual(_wordlist_fuzz_label(hit, PARENT, ALLOWED), "www")

    def test_www_recovered_from_url_when_host_absent(self) -> None:
        hit = {
            "fuzz": "kGHqerTs",
            "host": "",
            "url": "http://www.fixture-target.test/",
            "status": 200,
            "length": 17,
        }
        self.assertEqual(_wordlist_fuzz_label(hit, PARENT, ALLOWED), "www")

    def test_xnrbibej_class_still_dropped_when_host_carries_it(self) -> None:
        """OLD: autocalib FUZZ tokens must stay out even when echoed in Host."""
        hit = {
            "fuzz": "XnRbiBeJ",
            "host": "XnRbiBeJ.fixture-target.test",
            "url": "http://XnRbiBeJ.fixture-target.test/",
            "status": 403,
            "length": 0,
        }
        self.assertIsNone(_wordlist_fuzz_label(hit, PARENT, ALLOWED))

    def test_xnrbibej_class_still_dropped_when_fuzz_only(self) -> None:
        hit = {"fuzz": "XnRbiBeJ", "host": "", "url": ""}
        self.assertIsNone(_wordlist_fuzz_label(hit, PARENT, ALLOWED))

    def test_plain_wordlist_fuzz_still_accepted(self) -> None:
        hit = {"fuzz": "app", "host": "", "url": ""}
        self.assertEqual(_wordlist_fuzz_label(hit, PARENT, ALLOWED), "app")

    def test_nested_base_recovers_first_label(self) -> None:
        hit = {
            "fuzz": "qWnFrPtS",
            "host": "mail.app.fixture-target.test",
            "url": "http://mail.app.fixture-target.test/",
            "status": 200,
            "length": 9014,
        }
        self.assertEqual(_wordlist_fuzz_label(hit, BASE, ALLOWED), "mail")

    def test_non_wordlist_label_dropped(self) -> None:
        hit = {"fuzz": "guest", "host": "", "url": ""}
        self.assertIsNone(_wordlist_fuzz_label(hit, PARENT, ALLOWED))


if __name__ == "__main__":
    unittest.main()
