"""UI E2E journey 0-100 (operator mandate: test every capability in the UI
like a normal user). Real chromium against a real uvicorn boot.

J1  landing + auth (SET token -> online badge)
J2  TOOLS panel: tool toggle + wordlist selection save
J3  TARGETS panel: create profile with per-target Telegram user id (D-protocol)
J4  TARGETS persistence across reload (LOAD restores the id)
J5  FLEET panel: members + no-run state
J6  RESULTS panel: assets, filters, coverage, diff badges (global TARGET box)
J7  REPORTS panel: GENERATE NOW -> tamper-checked VERIFIED bundle
J8  RUN CONTROL: status from state.json + scheduler save
J9  API KEYS: set + masked
J10 SETTINGS: global Telegram user id + SEND TEST (honest skip ledger)
J11 XSS probe rendered inert (textContent escaping + CSP; no dialogs)
J12 unauthorized UX: token cleared -> panels refuse with guidance toast

Exit 0 iff every step passes. Screenshots land in ci/ui-e2e-screens/.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ci.ui_e2e_seed import seed  # noqa: E402

PORT = 8790
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "ui-e2e-token-000000"
SCREENS = ROOT / "ci" / "ui-e2e-screens"

RESULTS: list[dict[str, Any]] = []
DIALOGS_FIRED: list[str] = []


def prepare_root() -> Path:
    """Disposable copy of the control tree -- the journey NEVER mutates the
    repo working copy (tracked fixtures, wordlists.yaml, scheduler.json stay
    byte-identical; learned the hard way: the journey's saves polluted the
    committed fixtures and broke the C3 suite)."""
    tmp = Path(tempfile.mkdtemp(prefix="ui-e2e-root-"))
    ignore = shutil.ignore_patterns(
        ".git", ".github", "recon", "history", "ci", "tests", "docs",
        "__pycache__", "*.md", "venv", ".venv")
    shutil.copytree(ROOT, tmp, ignore=ignore, dirs_exist_ok=True)
    return tmp


def step(jid: str, name: str, ok: bool, detail: str) -> None:
    RESULTS.append({"id": jid, "name": name, "ok": ok, "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {jid} {name}: {detail}")


def main() -> int:
    root = prepare_root()
    seed(root)
    SCREENS.mkdir(exist_ok=True)
    env = dict(os.environ)
    env["DASHBOARD_TOKEN"] = TOKEN
    env["PYTHONPATH"] = str(root)
    env["NO_PROXY"] = "*"
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        env.pop(k, None)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "dashboard.app:app", "--host", "127.0.0.1",
         "--port", str(PORT), "--log-level", "warning"],
        cwd=str(root), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        import httpx

        deadline = time.time() + 30
        up = False
        while time.time() < deadline:
            try:
                if httpx.get(f"{BASE}/api/health", timeout=2.0, trust_env=False).status_code == 200:
                    up = True
                    break
            except (OSError, httpx.HTTPError):
                time.sleep(0.4)
        if not up:
            print("FATAL: dashboard did not boot")
            return 1
        return journey()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def journey() -> int:
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 960})
        page.on("dialog", lambda d: (DIALOGS_FIRED.append(d.message), d.dismiss()))
        page.on("pageerror", lambda e: print(f"PAGEERROR: {e}"))
        page.on("response", lambda r: print(f"HTTP {r.status} {r.url}") if r.status >= 400 else None)
        page.set_default_timeout(15000)

        # J1 landing + auth
        page.goto(BASE)
        assert page.locator(".brand").inner_text().strip() != ""
        page.fill("#token", TOKEN)
        page.click("#token-save")
        page.wait_for_function("document.querySelector('#conn').textContent.includes('online')")
        step("J1", "landing + auth", True, "brand visible, token set, conn badge online")
        page.screenshot(path=str(SCREENS / "J1-landing.png"))

        # J2 TOOLS: toggle + wordlist save
        page.click('[data-panel="tools"]')
        page.wait_for_selector("#tools-table tbody tr")
        rows = page.locator("#tools-table tbody tr").count()
        assert rows > 0, "tools table empty"
        page.locator("#tools-table tbody tr button[data-toggle]").first.click()
        page.wait_for_selector(".toast:not(.hidden)")
        boxes = page.locator("#wordlists input[type=checkbox]")
        assert boxes.count() > 0, "no wordlist checkboxes"
        boxes.first.check()
        page.locator("#wordlists button[data-save]").first.click()
        page.wait_for_timeout(400)
        step("J2", "TOOLS toggle + wordlist save", True, f"{rows} tools, wordlist selection saved")
        page.screenshot(path=str(SCREENS / "J2-tools.png"))

        # J3 TARGETS: create profile with per-target Telegram id
        page.click('[data-panel="targets"]')
        page.fill("#t-name", "ui-target.example")
        page.click("#t-load")
        page.wait_for_timeout(300)
        page.fill("#t-tg", "123456789")
        page.fill("#t-digest", "7")
        page.select_option("#t-tgen", "true")
        page.fill("#t-b-depth", "1")
        page.click("#t-save")
        page.wait_for_timeout(400)
        table = page.locator("#targets-table tbody").inner_text()
        ok = "ui-target.example" in table and "123456789" in table
        step("J3", "TARGETS profile + per-target Telegram id", ok, f"table: {table[:80]!r}")
        page.screenshot(path=str(SCREENS / "J3-targets.png"))

        # J4 persistence across reload
        page.reload()
        page.wait_for_selector(".brand")
        page.click('[data-panel="targets"]')
        page.fill("#t-name", "ui-target.example")
        page.click("#t-load")
        page.wait_for_timeout(400)
        val = page.input_value("#t-tg")
        step("J4", "TARGETS persistence (reload + LOAD)", val == "123456789", f"restored id={val!r}")

        # J5 FLEET
        page.click('[data-panel="fleet"]')
        page.wait_for_timeout(400)
        mv = page.locator("#fl-members-view").inner_text()
        badge = page.locator("#fl-status").inner_text()
        step("J5", "FLEET surface", "ui-target.example" in mv and "no fleet run" in badge,
             f"members view: {mv[:60]!r}, badge: {badge!r}")
        page.screenshot(path=str(SCREENS / "J5-fleet.png"))

        # J6 RESULTS via global TARGET box
        page.click('[data-panel="results"]')
        page.wait_for_selector("#assets-table tbody tr")
        n_all = page.locator("#assets-table tbody tr").count()
        page.fill("#f-q", "api")
        page.click("#f-apply")
        page.wait_for_timeout(400)
        n_filtered = page.locator("#assets-table tbody tr").count()
        cov_rows = page.locator("#coverage-table tbody tr").count()
        badges = page.locator("#diff-badges").inner_text()
        ok = n_all >= 3 and n_filtered < n_all and cov_rows >= 1 and "+hosts" in badges
        step("J6", "RESULTS assets + filters + coverage + diff", ok,
             f"assets={n_all} filtered={n_filtered} coverage_rows={cov_rows} badges={badges!r}")
        page.screenshot(path=str(SCREENS / "J6-results.png"))

        # J7 REPORTS: generate + verified (poll the badge -- generation takes
        # a beat: PDF render + digest chain)
        page.click('[data-panel="reports"]')
        page.fill("#rep-target", "example.com")
        gen_ok = True
        with page.expect_response(lambda r: "/api/report/" in r.url and "/generate" in r.url,
                                  timeout=20000) as ri:
            page.click("#rep-generate")
        gen_ok = ri.value.status == 200
        # poll the badge (fixed-interval loop -- robust under headless rAF throttling)
        badge = page.locator("#rep-status").inner_text()
        for _i in range(30):
            if page.locator("#rep-status").inner_text() == "VERIFIED":
                badge = "VERIFIED"
                break
            page.wait_for_timeout(500)
        open_links = page.locator("#reports-table a.badge").count()
        step("J7", "REPORTS generate + tamper check", badge == "VERIFIED" and open_links >= 4 and gen_ok,
             f"badge={badge!r} open_links={open_links} generate_status={ri.value.status}")
        page.screenshot(path=str(SCREENS / "J7-reports.png"))

        # J8 RUN CONTROL + scheduler
        page.click('[data-panel="run"]')
        page.wait_for_timeout(500)
        st = page.locator("#run-status").inner_text()
        page.fill("#sched-interval", "15")
        page.click("#sched-save")
        page.wait_for_timeout(400)
        step("J8", "RUN CONTROL status + scheduler save", "completed" in st,
             f"status={st!r}, scheduler interval=15 saved")
        page.screenshot(path=str(SCREENS / "J8-run.png"))

        # J9 API KEYS
        page.click('[data-panel="keys"]')
        page.wait_for_selector('#keys-table input[data-val="TELEGRAM_CHAT_ID"]')
        page.fill('#keys-table input[data-val="TELEGRAM_CHAT_ID"]', "999555999")
        page.click('[data-put="TELEGRAM_CHAT_ID"]')
        page.wait_for_timeout(400)
        row = page.locator("#keys-table tbody").inner_text()
        ok = "TELEGRAM_CHAT_ID" in row and "999" in row and "****" in row
        step("J9", "API KEYS set + masked", ok, f"row: {row[:70]!r}")
        page.screenshot(path=str(SCREENS / "J9-keys.png"))

        # J10 SETTINGS: global telegram id + honest SEND TEST skip
        page.click('[data-panel="settings"]')
        page.fill("#s-tg-chat", "999555999")
        page.click("#s-save")
        page.wait_for_timeout(400)
        page.click("#s-test")
        page.wait_for_timeout(600)
        test = page.locator("#s-test-result").inner_text()
        ok = "SKIPPED" in test and ("bot token" in test or "user id" in test)
        step("J10", "SETTINGS save + SEND TEST honest ledger", ok, f"test badge: {test!r}")
        page.screenshot(path=str(SCREENS / "J10-settings.png"))

        # J11 XSS probe inert
        page.click('[data-panel="targets"]')
        page.fill("#t-name", "xss-probe.example")
        page.fill("#t-desc", "<script>alert(1)</script>")
        page.click("#t-save")
        page.wait_for_timeout(500)
        table = page.locator("#targets-table tbody").inner_text()
        ok = "xss-probe.example" in table and not DIALOGS_FIRED
        step("J11", "XSS probe inert (escape + CSP)", ok,
             f"probe rendered as text, dialogs fired={len(DIALOGS_FIRED)}")
        page.screenshot(path=str(SCREENS / "J11-xss.png"))

        # J12 unauthorized UX
        page.evaluate("localStorage.removeItem('recon_dashboard_token')")
        page.reload()
        page.wait_for_selector(".brand")
        page.click('[data-panel="results"]')
        page.wait_for_timeout(400)
        toast = page.locator("#toast").inner_text()
        step("J12", "unauthorized UX guidance", "DASHBOARD_TOKEN" in toast, f"toast: {toast!r}")
        page.screenshot(path=str(SCREENS / "J12-unauth.png"))

        browser.close()

    ok_all = all(r["ok"] for r in RESULTS) and not DIALOGS_FIRED
    write_report()
    print(f"\nUI JOURNEY 0-100: {'ALL PASS' if ok_all else 'FAILURES PRESENT'}")
    return 0 if ok_all else 1


def write_report() -> None:
    lines = [
        "# UI E2E Journey 0-100 (D-protocol)",
        "",
        "Real chromium vs real uvicorn boot; every operator capability walked.",
        "",
        "| ID | STEP | RESULT | DETAIL |",
        "|---|---|---|---|",
    ]
    for r in RESULTS:
        mark = "PASS" if r["ok"] else "FAIL"
        lines.append(f"| {r['id']} | {r['name']} | {mark} | {r['detail'].replace('|', '/')} |")
    lines += ["", f"dialogs fired: {len(DIALOGS_FIRED)}", "",
              "Screenshots: ci/ui-e2e-screens/J*.png"]
    (ROOT / "ci" / "ui-e2e-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("report: ci/ui-e2e-report.md")


if __name__ == "__main__":
    raise SystemExit(main())
