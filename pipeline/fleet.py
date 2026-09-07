"""C4 (release directive): multi-target concurrent execution (FLEET).

Operator mandates covered here:
  - run MULTIPLE targets concurrently
  - automatic network request management + resource management
  - per-target settings (C3 profiles) honored per run

Isolation law: every fleet member gets its OWN prepared root (a full
copy-on-lightweight basis: the repo control files + empty recon tree);
the target's C3 profile is BAKED into that root's tools.yaml/wordlists.yaml
BEFORE the run starts (no transient edits at run time -> zero cross-target
interference). The fleet member executes as a SUBPROCESS of ./recon.sh run
<target> with cwd+PYTHONPATH rooted in its prepared root, so containers,
state, breaker, and forge caches are fully isolated per target.

Resource management:
  - fleet_max_concurrency (tools.yaml, default 3): global parallel-target cap
  - fleet_global_slots (lockfile-counted): an OS-level cross-process guard
    so two fleet invocations cannot oversubscribe the runner
  - per-target budgets come from the baked profile (C3) or committed defaults

Failure isolation: one member failing NEVER stops the others; the fleet
ledger records every member's exit + status; the fleet exit code is 0 iff
EVERY member completed clean (partial counts as success-with-disclosure).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.target_profiles import build_edit_plan
from pipeline.textio import atomic_write_text
from pipeline.yaml_util import load_yaml_file

CONTROL_FILES = (
    "tools.yaml",
    "wordlists.yaml",
    "scope.yaml",
    "search_engines.yaml",
    "dorks.yaml",
    "resolvers.yaml",
    "tools.lock",
    "views.yaml",
    "remediation.yaml",
    "targets.yaml",  # D-protocol: per-target notifications resolve inside the member root too
)
CONTROL_DIRS = (
    "pipeline",
    "dashboard",
    "ci",
    "resolvers",
    "dorks",
    "wordlists/local",
    "wordlists/custom",
    "docker",
    "schemas",
)


class FleetError(ValueError):
    pass


def fleet_targets(params: Params, requested: str) -> list[str]:
    """Resolve the member list: 'all' -> every target with a profile, else a
    comma list of explicit targets (deduplicated, order-preserving)."""
    from pipeline.target_profiles import load_registry

    req = (requested or "").strip()
    if not req:
        raise FleetError("no targets requested")
    if req.lower() == "all":
        return sorted(load_registry(params))
    seen: list[str] = []
    for raw in req.split(","):
        t = sanitize_fleet_target(raw)
        if t and t not in seen:
            seen.append(t)
    if not seen:
        raise FleetError("no valid targets parsed")
    return seen


def sanitize_fleet_target(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^[a-z0-9][a-z0-9.-]{2,253}$", raw):
        return ""  # strict: mixed-case/invalid tokens are rejected, not lowered
    return raw


def max_concurrency(params: Params) -> int:
    try:
        return max(1, min(8, int(params.require("fleet_max_concurrency"))))
    except KeyError:
        return 3


def _replace_block(text: str, key: str, rendered: str) -> tuple[str, bool]:
    """Replace a 2-space-indent settings key INCLUDING its block-list items
    (header line through the last deeper-indented line)."""
    pattern = re.compile(rf"^  {re.escape(key)}:.*$", re.M)
    m = pattern.search(text)
    if not m:
        return text, False
    start, pos = m.start(), m.end()
    lines = text[pos:].splitlines(keepends=True)
    end = pos
    for ln in lines:
        if ln.strip() == "":
            end += len(ln)
            continue
        if ln.startswith("    ") or ln.startswith("\t"):
            end += len(ln)
            continue
        break
    return text[:start] + rendered + "\n" + text[end:], True


def _bake_profile(root: Path, plan: dict[str, Any]) -> list[str]:
    """Bake the C3 edit plan DIRECTLY into the member root's control files
    (no transient semantics needed: the root is per-member and disposable)."""
    baked: list[str] = []
    tools = root / "tools.yaml"
    text = tools.read_text(encoding="utf-8")
    for edit in plan.get("tools_edits") or []:
        key, value = edit["key"], edit["value"]
        if isinstance(value, list):
            rendered = f"  {key}:\n" + "\n".join(f"    - {item}" for item in value)
        else:
            rendered = f"  {key}: {value}"
        text, replaced = _replace_block(text, key, rendered)
        if replaced:
            baked.append(f"tools.yaml:{key}")
        else:
            anchor = "settings:"
            text = text.replace(anchor, anchor + f"\n  {key}: {value}", 1)
            baked.append(f"tools.yaml:+{key}")
    atomic_write_text(tools, text)

    sel = plan.get("wordlist_selection") or {}
    if sel:
        wl = root / "wordlists.yaml"
        text = wl.read_text(encoding="utf-8")
        for task, keys in sel.items():
            m = re.search(rf"^  {re.escape(task)}:\s*(?:#.*)?$", text, re.M)
            if not m:
                raise FleetError(f"wordlists.yaml has no task block {task!r}")
            rendered = f"\n    selection:\n" + "\n".join(f"      - {k}" for k in keys)
            text = text[: m.end()] + rendered + text[m.end():]
            baked.append(f"wordlists.yaml:{task}")
        atomic_write_text(wl, text)
    return baked


def prepare_member(params: Params, target: str, fleet_root: Path) -> dict[str, Any]:
    """Prepare one member's isolated root: control files + dirs copied,
    empty recon tree, scope.yaml intact (fleet-scope), profile baked."""
    member = fleet_root / "members" / target
    (member / "recon").mkdir(parents=True, exist_ok=True)
    for name in CONTROL_FILES:
        src = params.root / name
        if src.is_file() and not (member / name).exists():
            shutil_copy(src, member / name)
    launcher = params.root / "recon.sh"
    if launcher.is_file():
        shutil_copy(launcher, member / "recon.sh")
        os.chmod(member / "recon.sh", 0o755)
    for d in CONTROL_DIRS:
        src = params.root / d
        if src.is_dir():
            shutil_copytree(src, member / d)
    plan = build_edit_plan(params, target)
    baked = _bake_profile(member, plan)
    ledger = {
        "target": target,
        "root": str(member),
        "baked": baked,
        "prepared_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    atomic_write_text(member / "fleet-member.json", json.dumps(ledger, indent=1) + "\n")
    return ledger


def shutil_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())


def shutil_copytree(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.read_bytes())


class GlobalSlots:
    """Cross-process slot counter (lockfile based) so overlapping fleet
    invocations cannot oversubscribe a runner."""

    def __init__(self, params: Params, limit: int) -> None:
        self.dir = params.root / "history" / "fleet-slots"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.limit = max(1, limit)
        self.token: str = ""

    def acquire(self) -> bool:
        # the SHARED limit binds: only slots [0, limit) may ever exist
        for i in range(0, self.limit):
            name = f"slot-{i:04d}"
            p = self.dir / name
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                self.token = name
                return True
            except FileExistsError:
                continue
        return False

    def release(self) -> None:
        if self.token:
            (self.dir / self.token).unlink(missing_ok=True)
            self.token = ""


def run_member(member_root: Path, target: str, timeout_sec: int) -> dict[str, Any]:
    """Execute one member: ./recon.sh run <target> as an isolated subprocess."""
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env = dict(os.environ)
    env["PYTHONPATH"] = str(member_root)
    env["FLEET_MEMBER_ROOT"] = str(member_root)
    proc = subprocess.run(
        ["./recon.sh", "run", target],
        cwd=str(member_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
    )
    return {
        "target": target,
        "exit_code": proc.returncode,
        "started_at": started,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "console_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-800:],
    }


def run_fleet(params: Params, requested: str, concurrency: int | None = None,
              member_timeout_sec: int = 7200) -> dict[str, Any]:
    targets = fleet_targets(params, requested)
    limit = max(1, min(concurrency or max_concurrency(params), len(targets)))
    slots = GlobalSlots(params, limit)
    fleet_root = params.root / "history" / "fleet" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    members: list[dict[str, Any]] = []
    for t in targets:
        members.append(prepare_member(params, t, fleet_root))

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=limit) as pool:
        futures = {}
        for member in members:
            target = member["target"]
            member_root = Path(member["root"])

            def _job(member_root=member_root, target=target):
                if not slots.acquire():
                    return {"target": target, "exit_code": 4, "error": "fleet slots exhausted"}
                try:
                    return run_member(member_root, target, member_timeout_sec)
                except subprocess.TimeoutExpired:
                    return {"target": target, "exit_code": 4, "error": "member timeout"}
                except Exception as exc:  # noqa: BLE001 -- failure isolation: record, never cascade
                    return {"target": target, "exit_code": 1, "error": f"member failed: {exc}"}
                finally:
                    slots.release()

            futures[pool.submit(_job)] = target
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r["target"])
    clean = all(r.get("exit_code") in (0, 3) for r in results)
    ledger = {
        "requested": requested,
        "concurrency": limit,
        "members": members,
        "results": results,
        "clean": clean,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    atomic_write_text(fleet_root / "fleet-ledger.json", json.dumps(ledger, indent=1) + "\n")
    return ledger
