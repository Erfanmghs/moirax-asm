"""UI E2E fixture seeder -- everything the 0-100 operator journey needs.

Correct canonical layout (params law):
  recon/<target>/00_assets/assets.json   (assets_relpath)
  recon/<target>/10_dns-resolve/data.json (module canonical doc -> report bundle)
  recon/<target>/runs.json | diff.json | state.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _seed_target(root: Path, target: str) -> None:
    t = root / "recon" / target
    (t / "00_assets").mkdir(parents=True, exist_ok=True)
    (t / "10_dns-resolve").mkdir(parents=True, exist_ok=True)
    (t / "logs").mkdir(parents=True, exist_ok=True)
    assets = {
        "assets": [
            {"host": f"www.{target}", "ip": "93.184.216.34", "alive": True,
             "sources": ["crtsh", "subfinder"], "tags": ["www"], "run": "20260101T000000Z"},
            {"host": f"api.{target}", "ip": "93.184.216.35", "alive": True,
             "sources": ["crtsh"], "tags": ["api"], "run": "20260101T000000Z"},
            {"host": f"old.{target}", "ip": "93.184.216.99", "alive": False,
             "sources": ["dnsdumpster"], "tags": [], "run": "20260101T000000Z"},
        ]
    }
    (t / "00_assets" / "assets.json").write_text(json.dumps(assets, indent=1) + "\n", encoding="utf-8")
    (t / "10_dns-resolve" / "data.json").write_text(
        json.dumps({"module": "dns-resolve", "resolved": [f"www.{target}", f"api.{target}"]}, indent=1) + "\n",
        encoding="utf-8")
    (t / "runs.json").write_text(
        json.dumps({"runs": [{"run": "20260101T000000Z", "status": "completed",
                              "modules": {"dns-resolve": "done"}}]}, indent=1) + "\n", encoding="utf-8")
    (t / "diff.json").write_text(
        json.dumps({"to_run": "20260101T000000Z",
                    "added": {"hosts": [{"host": f"api.{target}", "ip": "93.184.216.35"}], "ports": []},
                    "removed": {"hosts": [], "ports": []}, "changed": {}}, indent=1) + "\n", encoding="utf-8")
    (t / "state.json").write_text(
        json.dumps({"exists": True, "run_status": "completed",
                    "modules": {"dns-resolve": {"status": "done"}, "passive-recon": {"status": "done"}}}, indent=1) + "\n",
        encoding="utf-8")
    (t / "logs" / "run.log").write_text("ui-e2e fixture log line\n", encoding="utf-8")


def seed(root: Path = ROOT) -> None:
    for target in ("example.com", "ui-target.example"):
        _seed_target(root, target)
    (root / "targets.yaml").write_text(
        "schema_version: 1\n"
        "targets:\n"
        "  ui-target.example:\n"
        '    description: "ui journey member"\n'
        "    settings:\n"
        "      budgets:\n"
        "        passive_recursion_depth: 1\n",
        encoding="utf-8")
    dash = root / "dashboard"
    dash.mkdir(exist_ok=True)
    (dash / "config.json").write_text(
        json.dumps({"telegram": {"chat_id": "222222222"}, "digest_threshold": 10}, indent=2) + "\n",
        encoding="utf-8")
    print(f"ui-e2e fixture seeded at {root}")


if __name__ == "__main__":
    seed(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT)
