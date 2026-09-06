"""B5 NOTIFICATIONS & SCHEDULER unit proof (spec §4.5/§4.6/§4.7) — deterministic, no network."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pipeline.notify import (
    DEFAULT_ALERT_RULES,
    alert_worthy,
    evaluate_diff_alerts,
    resolve_credentials,
    run_end_notifications,
    send_run_summary,
)
from pipeline.params import Params
from pipeline.scheduler import due, mark_run, validate

_ROOT = Path(__file__).resolve().parents[1]


def _params(overrides: dict | None = None) -> Params:
    params = Params(_ROOT)
    for key, value in (overrides or {}).items():
        params.settings[key] = value
    return params


def _diff_doc(added: dict, removed: dict | None = None, changed: dict | None = None) -> dict:
    return {
        "schema_version": 1,
        "from_run": "20260101T000000Z",
        "to_run": "20260102T000000Z",
        "added": added,
        "removed": removed or {},
        "changed": changed or {},
    }


def _classes() -> dict:
    return {"hosts": [], "vhosts": [], "ports": [], "services": [], "passive_ips": []}


class TestRunSummary(unittest.TestCase):
    """§4.5 end-of-run summary: target, status, per-module counts, duration, report path."""

    def test_summary_content(self):
        sink: list[str] = []
        ok = send_run_summary(
            _params(), "example.com", "partial",
            {"passive_docs": 2, "active_docs": 1}, 125, "/recon/example.com/90_report",
            sender=sink.append,
        )
        self.assertTrue(ok)
        self.assertEqual(len(sink), 1)
        text = sink[0]
        self.assertIn("RUN partial", text)
        self.assertIn("target: example.com", text)
        self.assertIn("passive_docs=2", text)
        self.assertIn("active_docs=1", text)
        self.assertIn("duration: 2m05s", text)
        self.assertIn("report: /recon/example.com/90_report", text)

    def test_unset_credentials_skips_silently(self):
        params = _params({"dashboard_config_relpath": "/nonexistent/config.json"})
        with mock.patch.dict("os.environ", {}, clear=True):
            with mock.patch("pathlib.Path.is_file", return_value=False):
                ok = send_run_summary(params, "example.com", "completed", {}, 10, "r")
        self.assertFalse(ok)  # skip silently — never raises, never sends


class TestInstantAlerts(unittest.TestCase):
    """§4.6 watchtower: NEW SUBDOMAIN + NEWLY OPENED PORT instant alerts."""

    def test_new_subdomain_instant(self):
        sink: list[str] = []
        doc = _diff_doc({"hosts": [{"host": "dev.example.com", "ip": "1.2.3.4"}]})
        ledger = evaluate_diff_alerts(_params(), doc, sender=sink.append)
        self.assertEqual(len(sink), 1)
        self.assertIn("NEW SUBDOMAIN: dev.example.com ip=1.2.3.4", sink[0])
        self.assertEqual(ledger["instant_sent"], 1)
        self.assertFalse(ledger["digest_sent"])

    def test_newly_opened_port_instant(self):
        sink: list[str] = []
        doc = _diff_doc({"ports": [{"host": "a.example.com", "ip": "1.1.1.1", "port": 8443, "proto": "tcp"}]})
        ledger = evaluate_diff_alerts(_params(), doc, sender=sink.append)
        self.assertIn("NEW PORT: a.example.com:8443/tcp", sink[0])
        self.assertEqual(ledger["instant_sent"], 1)

    def test_closed_port_only_diff_is_silent(self):
        """Acceptance: a closed-port-only diff → NO Telegram alert (dashboard view only)."""
        sink: list[str] = []
        doc = _diff_doc({}, removed={"ports": [{"host": "a", "ip": "1.1.1.1", "port": 80, "proto": "tcp"}]})
        ledger = evaluate_diff_alerts(_params(), doc, sender=sink.append)
        self.assertEqual(sink, [])
        self.assertEqual(ledger["alertable"], 0)
        self.assertEqual(ledger["skipped_reason"], "no_added_assets")

    def test_services_class_never_alerts(self):
        sink: list[str] = []
        doc = _diff_doc({"services": [{"ip": "1.1.1.1", "port": 22, "proto": "tcp", "service": "ssh"}]})
        ledger = evaluate_diff_alerts(_params(), doc, sender=sink.append)
        self.assertEqual(sink, [])
        self.assertEqual(ledger["alertable"], 0)
        self.assertEqual(ledger["non_alert_class_assets"], 1, "services stay dashboard-only by design")


class TestDigest(unittest.TestCase):
    """§4.7 digest threshold: below → per-asset instant; at/above → ONE digest."""

    def _flood(self, n: int) -> dict:
        return {"hosts": [{"host": f"h{i}.example.com"} for i in range(n)]}

    def test_flood_above_threshold_sends_exactly_one_digest(self):
        sink: list[str] = []
        doc = _diff_doc(self._flood(12))
        ledger = evaluate_diff_alerts(_params(), doc, sender=sink.append)
        self.assertEqual(len(sink), 1, "flood must collapse to ONE digest message")
        self.assertIn("DIGEST: 12 new findings (threshold=10)", sink[0])
        self.assertTrue(ledger["digest_sent"])
        self.assertEqual(ledger["instant_sent"], 0)

    def test_below_threshold_sends_per_asset(self):
        sink: list[str] = []
        doc = _diff_doc(self._flood(3))
        ledger = evaluate_diff_alerts(_params(), doc, sender=sink.append)
        self.assertEqual(len(sink), 3)
        self.assertFalse(ledger["digest_sent"])

    def test_digest_listing_cap(self):
        sink: list[str] = []
        doc = _diff_doc(self._flood(25))
        evaluate_diff_alerts(_params(), doc, sender=sink.append)
        self.assertEqual(len(sink), 1)
        self.assertIn("... and 5 more", sink[0])

    def test_threshold_dashboard_override(self):
        sink: list[str] = []
        cfg = Path(tempfile.mkdtemp()) / "config.json"
        cfg.write_text(json.dumps({"digest_threshold": 2}), encoding="utf-8")
        params = _params({"dashboard_config_relpath": str(cfg)})
        ledger = evaluate_diff_alerts(params, _diff_doc(self._flood(3)), sender=sink.append)
        self.assertTrue(ledger["digest_sent"])
        self.assertEqual(ledger["digest_threshold"], 2)

    def test_digest_counts_only_alertworthy_assets(self):
        """Suppressed assets don't push the count over the threshold (§4.7 filters first)."""
        sink: list[str] = []
        cfg = Path(tempfile.mkdtemp()) / "config.json"
        rules = [{"class": "hosts", "enabled": False}, {"class": "ports", "enabled": True}]
        cfg.write_text(json.dumps({"digest_threshold": 2, "alert_rules": rules}), encoding="utf-8")
        params = _params({"dashboard_config_relpath": str(cfg)})
        doc = _diff_doc({"hosts": self._flood(5)["hosts"], "ports": [{"ip": "9.9.9.9", "port": 80, "proto": "tcp"}]})
        ledger = evaluate_diff_alerts(params, doc, sender=sink.append)
        self.assertEqual(ledger["alertable"], 1)  # 5 hosts suppressed, 1 port alert-worthy
        self.assertEqual(ledger["instant_sent"], 1)
        self.assertFalse(ledger["digest_sent"], "suppressed hosts must NOT count toward the threshold")


class TestAlertFilters(unittest.TestCase):
    """§4.7 dashboard-editable alert-filter rules."""

    def test_disabled_class_suppresses(self):
        rules = [{"class": "ports", "enabled": False}]
        self.assertFalse(alert_worthy(rules, "ports", {"port": 80}, {"ips": set()}))

    def test_default_rules_alert_both_classes(self):
        self.assertTrue(alert_worthy(DEFAULT_ALERT_RULES, "hosts", {"host": "x"}, {"ips": set()}))
        self.assertTrue(alert_worthy(DEFAULT_ALERT_RULES, "ports", {"port": 1}, {"ips": set()}))

    def test_require_new_ip_known_ip_not_alerted(self):
        """§4.7 example: new subdomain resolving to a NEW IP only."""
        rules = [{"class": "hosts", "enabled": True, "require_new_ip": True}]
        prev = {"ips": {"1.2.3.4"}}
        self.assertFalse(alert_worthy(rules, "hosts", {"host": "x", "ip": "1.2.3.4"}, prev))
        self.assertTrue(alert_worthy(rules, "hosts", {"host": "x", "ip": "5.6.7.8"}, prev))

    def test_require_new_ip_mines_previous_from_removed_and_changed(self):
        doc = _diff_doc(
            {"hosts": [{"host": "x.example.com", "ip": "1.2.3.4"}]},
            removed={"hosts": [{"host": "old.example.com", "ip": "1.2.3.4"}]},
            changed={"hosts": [{"before": {"host": "c", "ip": "9.9.9.9"}, "after": {"host": "c", "ip": "9.9.9.9"}}]},
        )
        params = _params()
        cfg = Path(tempfile.mkdtemp()) / "config.json"
        cfg.write_text(json.dumps({"alert_rules": [{"class": "hosts", "enabled": True, "require_new_ip": True}]}), encoding="utf-8")
        params.settings["dashboard_config_relpath"] = str(cfg)
        sink: list[str] = []
        ledger = evaluate_diff_alerts(params, doc, sender=sink.append)
        self.assertEqual(sink, [], "host on a previously-seen IP must not alert under require_new_ip")
        self.assertEqual(ledger["suppressed_by_rules"], 1)


class TestCredentials(unittest.TestCase):
    """§4.5 dashboard-configured credentials first; .env fallback; unset → skip."""

    def test_dashboard_config_wins(self):
        cfg = Path(tempfile.mkdtemp()) / "config.json"
        cfg.write_text(json.dumps({"telegram": {"bot_token": "tok-dash", "chat_id": "42"}}), encoding="utf-8")
        params = _params({"dashboard_config_relpath": str(cfg)})
        with mock.patch.dict("os.environ", {"TELEGRAM_BOT_TOKEN": "tok-env", "TELEGRAM_CHAT_ID": "1"}, clear=False):
            token, chat = resolve_credentials(params)
        self.assertEqual((token, chat), ("tok-dash", "42"))

    def test_env_fallback(self):
        params = _params({"dashboard_config_relpath": "/nonexistent/config.json"})
        with mock.patch.dict("os.environ", {"TELEGRAM_BOT_TOKEN": "tok-env", "TELEGRAM_CHAT_ID": "7"}, clear=False):
            token, chat = resolve_credentials(params)
        self.assertEqual((token, chat), ("tok-env", "7"))


class TestSelfMonitoring(unittest.TestCase):
    """§4.7 self-monitoring + §4.5 fan-out via run_end_notifications."""

    def test_failed_status_alert_names_module_and_reason(self):
        sink: list[str] = []
        params = _params({"dashboard_config_relpath": "/nonexistent/config.json"})
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch("pathlib.Path.is_file", return_value=False):
            ledger = run_end_notifications(
                params, Path(tempfile.mkdtemp()), "example.com", params.settings["run_status_failed"],
                "boom", "ffuf", {}, 5, sender=sink.append,
            )
        alerts = [t for t in sink if t.startswith("FAILED")]
        self.assertEqual(len(alerts), 1, "forced module failure → exactly one FAILED alert")
        self.assertIn("module=ffuf", alerts[0])
        self.assertIn("reason=boom", alerts[0])
        self.assertTrue(ledger["summary_sent"], "failed is a §4.5 summary status too")

    def test_completed_sends_summary_no_status_alert(self):
        sink: list[str] = []
        params = _params({"dashboard_config_relpath": "/nonexistent/config.json"})
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch("pathlib.Path.is_file", return_value=False):
            run_end_notifications(
                params, Path(tempfile.mkdtemp()), "example.com", params.settings["run_status_completed"],
                None, None, {"passive_docs": 1}, 5, sender=sink.append,
            )
        self.assertEqual(len(sink), 1)
        self.assertTrue(sink[0].startswith("RUN completed"))
        self.assertFalse(any(t.startswith(("FAILED", "ANOMALY", "STOPPED")) for t in sink))

    def test_anomaly_and_stopped_get_status_alerts(self):
        for status_key in ("run_status_anomaly", "run_status_stopped"):
            sink: list[str] = []
            params = _params({"dashboard_config_relpath": "/nonexistent/config.json"})
            with mock.patch.dict("os.environ", {}, clear=True), mock.patch("pathlib.Path.is_file", return_value=False):
                run_end_notifications(
                    params, Path(tempfile.mkdtemp()), "example.com", params.settings[status_key],
                    "r", "m", {}, 5, sender=sink.append,
                )
            self.assertEqual(len(sink), 1, f"{status_key} → status alert only (no §4.5 summary)")
            self.assertIn("module=m", sink[0])

    def test_never_raises_on_broken_diff(self):
        params = _params({"dashboard_config_relpath": "/nonexistent/config.json", "diff_filename": "diff.json"})
        td = Path(tempfile.mkdtemp())
        (td / "diff.json").write_text("{broken", encoding="utf-8")
        with mock.patch.dict("os.environ", {}, clear=True), mock.patch("pathlib.Path.is_file", return_value=True):
            ledger = run_end_notifications(
                params, td, "example.com", params.settings["run_status_completed"], None, None, {}, 5,
                sender=lambda _t: None,
            )
        self.assertIn("error", ledger)


class TestScheduler(unittest.TestCase):
    """§4.6 scheduler state machine (scheduler.json, min interval 10 min)."""

    def test_validate_enforces_10_min_floor(self):
        errors = validate({"interval_minutes": 9, "enabled": True, "last_run": None}, 10)
        self.assertEqual(len(errors), 1)
        self.assertIn("minimum 10", errors[0])
        self.assertEqual(validate({"interval_minutes": 240, "enabled": True, "last_run": None}, 10), [])

    def test_validate_rejects_bad_types(self):
        self.assertEqual(len(validate({"interval_minutes": "240", "enabled": "yes"}, 10)), 2)

    def test_due_when_never_run_and_enabled(self):
        self.assertTrue(due({"enabled": True, "interval_minutes": 240, "last_run": None}))

    def test_not_due_when_disabled(self):
        self.assertFalse(due({"enabled": False, "interval_minutes": 240, "last_run": None}))

    def test_interval_elapsed_boundary(self):
        doc = {"enabled": True, "interval_minutes": 10, "last_run": "2026-01-01T00:00:00Z"}
        t0 = 1767225600.0  # 2026-01-01T00:00:00Z
        self.assertFalse(due(doc, t0 + 9 * 60))
        self.assertTrue(due(doc, t0 + 10 * 60))

    def test_mark_run_writes_iso_stamp(self):
        stamped = mark_run({"enabled": True, "interval_minutes": 10, "last_run": None}, 1767225600.0)
        self.assertEqual(stamped["last_run"], "2026-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
