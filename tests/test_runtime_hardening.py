"""Dashboard runtime: loopback bind, dropped caps, pinned Python deps."""

from __future__ import annotations

import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


class TestDashboardComposeHardening(unittest.TestCase):
    def test_loopback_bind_drop_all_caps_and_no_new_privileges(self):
        text = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("127.0.0.1", text)
        self.assertIn("/var/run/docker.sock", text)
        self.assertIn("cap_drop:", text)
        self.assertIn("ALL", text)
        self.assertIn("no-new-privileges:true", text)
        self.assertIn("init: true", text)


class TestDashboardImagePins(unittest.TestCase):
    def test_dockerfile_installs_requirements_and_copies_official_cli(self):
        text = (_ROOT / "docker" / "dashboard" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY requirements.txt", text)
        self.assertIn("pip install --no-cache-dir -r", text)
        self.assertIn("FROM docker:27.5.1-cli", text)
        self.assertNotIn("curl -fsSL https://download.docker.com", text)

    def test_requirements_pins_dashboard_runtime(self):
        text = (_ROOT / "requirements.txt").read_text(encoding="utf-8")
        for name in ("fastapi==", "uvicorn==", "httpx==", "reportlab=="):
            self.assertIn(name, text)


if __name__ == "__main__":
    unittest.main()
