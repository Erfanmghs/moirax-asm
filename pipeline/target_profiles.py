"""C3 (release directive): per-target settings profiles.

Operator mandate: separate settings per target. Profiles live in the
committed registry targets.yaml (frozen-loader dialect):

  schema_version: 1
  targets:
    bugdasht.ir:
      description: operator-owned estate
      settings:
        wordlist_selection:
          FFUF-0: [test_smoke_200]
        budgets:
          passive_branch_budget_sec: 3000
        modules:
          active_branch_modules: [ffuf, dns-resolve, ffuf-3, port-check]
          passive_branch_modules: [passive-recon]
        notifications:
          telegram_chat: "123456"
          digest_threshold: 10
        proxy: {}            # C5 consumes this slot
        rate_caps: {}        # C5 consumes this slot

Resolution precedence: TARGET profile > committed defaults. NOTHING here
mutates committed files: applying a profile produces a TRANSIENT text-edit
plan (same discipline as the vehicle bounding overrides: before-copy +
targeted line edits) that the caller (CLI run / fleet runner / workflow)
applies for the duration of the run and restores afterwards.

Closed override allow-list (attacker-proofing): only the settings below
are overridable per target; anything else in a profile is REJECTED, and
keys that would touch scope.yaml, breaker thresholds or the wordlist
registry STRUCTURE are refused by law.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from pipeline.params import Params
from pipeline.textio import atomic_write_text
from pipeline.yaml_util import load_yaml_file

OVERRIDABLE = {
    "wordlist_selection": dict,      # task -> list of wordlist keys
    "budgets": dict,                 # named budget params (allow-listed below)
    "modules": dict,                 # active_branch_modules / passive_branch_modules
    "notifications": dict,           # telegram_chat / digest_threshold / toggles
    "proxy": dict,                   # C5 slot
    "rate_caps": dict,               # C5 slot
}

BUDGET_KEYS_ALLOW = {
    "passive_branch_budget_sec",
    "active_branch_budget_sec",
    "passive_recursion_depth",
    "ffuf3_max_dead_probes",
}

NOTIFY_KEYS_ALLOW = {
    "telegram_chat",        # D-protocol: per-target Telegram USER id override
    "digest_threshold",
    "watchtower_enabled",
    "telegram_enabled",     # D-protocol: per-system notification opt-out
}

TARGET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{2,253}$")


class ProfileError(ValueError):
    pass


def registry_path(params: Params) -> Path:
    return params.root / "targets.yaml"


def load_registry(params: Params) -> dict[str, Any]:
    p = registry_path(params)
    if not p.is_file():
        return {}
    doc = load_yaml_file(str(p))
    if not isinstance(doc, dict):
        return {}
    return doc.get("targets") or {}


def validate_profile(target: str, profile: dict[str, Any]) -> dict[str, Any]:
    """Closed allow-list validation. Returns the normalized profile."""
    if not TARGET_NAME_RE.match(target):
        raise ProfileError(f"illegal target name {target!r}")
    if not isinstance(profile, dict):
        raise ProfileError("profile must be a mapping")
    normalized: dict[str, Any] = {}
    for section, value in profile.items():
        if section == "description":
            if not isinstance(value, str) or len(value) > 200 or not value.isascii():
                raise ProfileError("description must be short ASCII text")
            normalized[section] = value
            continue
        law = OVERRIDABLE.get(section)
        if law is None:
            raise ProfileError(f"section {section!r} is NOT overridable per target (closed allow-list)")
        if not isinstance(value, law):
            raise ProfileError(f"section {section!r} must be a mapping")
        if section == "budgets":
            bad = set(value) - BUDGET_KEYS_ALLOW
            if bad:
                raise ProfileError(f"budget keys not overridable: {sorted(bad)}")
        if section == "notifications":
            bad = set(value) - NOTIFY_KEYS_ALLOW
            if bad:
                raise ProfileError(f"notification keys not overridable: {sorted(bad)}")
            # D-protocol value laws: injection-safe Telegram id, positive
            # threshold, boolean toggles (attacker-proofing: every write is
            # schema-validated before it reaches the registry).
            for k, v in value.items():
                if k == "telegram_chat":
                    from pipeline.notify import TELEGRAM_CHAT_RE
                    if not isinstance(v, str) or not TELEGRAM_CHAT_RE.match(v.strip()):
                        raise ProfileError(
                            'notifications.telegram_chat must be a Telegram user id '
                            '(digits, optionally negative) or an @channel name')
                elif k == "digest_threshold":
                    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                        raise ProfileError("notifications.digest_threshold must be a positive integer")
                elif k in ("watchtower_enabled", "telegram_enabled"):
                    if not isinstance(v, bool):
                        raise ProfileError(f"notifications.{k} must be a boolean")
        if section == "wordlist_selection":
            # key law enforced at APPLY time against the live registry; here
            # only the shape law (task -> list of key strings) is checked
            for task, keys in value.items():
                if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                    raise ProfileError(f"wordlist_selection.{task} must be a list of keys")
        normalized[section] = value
    return normalized


def set_profile(params: Params, target: str, profile: dict[str, Any]) -> dict[str, Any]:
    """Operator-facing upsert (dashboard/CLI). Validates then text-writes
    the registry in the project minimal-YAML dialect."""
    clean = validate_profile(target, profile)
    targets = load_registry(params)
    if clean:
        targets[target] = clean
    else:
        targets.pop(target, None)
    out = ["schema_version: 1", "targets:"]
    for name in sorted(targets):
        prof = targets[name]
        out.append(f"  {name}:")
        desc = prof.get("description")
        if desc:
            out.append(f'    description: "{desc}"')
        out.append("    settings:")
        for section in sorted(prof):
            if section == "description":
                continue
            out.append(f"      {section}:")
            for k, v in (prof[section] or {}).items():
                if isinstance(v, list):
                    out.append(f"        {k}:")
                    out.extend(f"          - {item}" for item in v)
                else:
                    out.append(f"        {k}: {v}")
    atomic_write_text(registry_path(params), "\n".join(out) + "\n")
    return {"target": target, "sections": sorted(clean)}


def get_profile(params: Params, target: str) -> dict[str, Any]:
    return load_registry(params).get(target) or {}


def build_edit_plan(params: Params, target: str) -> dict[str, Any]:
    """Transient-edit plan for one run: what lines change in tools.yaml /
    wordlists.yaml to realize the profile. Pure function; no mutation."""
    profile = get_profile(params, target)
    settings = profile.get("settings") or {}
    plan: dict[str, Any] = {"target": target, "tools_edits": [], "wordlist_selection": {}}
    for key, value in (settings.get("budgets") or {}).items():
        plan["tools_edits"].append({"key": key, "value": value})
    for key, value in (settings.get("modules") or {}).items():
        plan["tools_edits"].append({"key": key, "value": value})
    plan["wordlist_selection"] = settings.get("wordlist_selection") or {}
    plan["notifications"] = settings.get("notifications") or {}
    plan["proxy"] = settings.get("proxy") or {}
    plan["rate_caps"] = settings.get("rate_caps") or {}
    return plan


def apply_transient(params: Params, target: str, before_copy_dir: Path) -> dict[str, Any]:
    """Apply the profile as TRANSIENT working-copy edits (vehicle pattern:
    before-copies kept, frozen loader must still parse). Returns a restore
    token (paths snapshotted). Caller MUST call restore_transient()."""
    plan = build_edit_plan(params, target)
    snapshots: list[dict[str, str]] = []

    if plan["tools_edits"]:
        tools = params.root / "tools.yaml"
        before = before_copy_dir / "tools.yaml.before"
        before.write_text(tools.read_text(encoding="utf-8"), encoding="utf-8")
        snapshots.append({"path": str(tools), "before": str(before)})
        text = tools.read_text(encoding="utf-8")
        for edit in plan["tools_edits"]:
            key, value = edit["key"], edit["value"]
            pattern = re.compile(rf"^  {re.escape(key)}: .*$", re.M)
            if isinstance(value, list):
                rendered = f"  {key}:\n" + "\n".join(f"    - {item}" for item in value)
                if pattern.search(text):
                    text = pattern.sub(rendered.replace("\\", "\\\\"), text, count=1)
                else:
                    raise ProfileError(f"tools.yaml has no top-level key {key!r} to override")
            else:
                if not pattern.search(text):
                    raise ProfileError(f"tools.yaml has no top-level key {key!r} to override")
                text = pattern.sub(f"  {key}: {value}", text, count=1)
        atomic_write_text(tools, text)

    if plan["wordlist_selection"]:
        wl = params.root / "wordlists.yaml"
        before = before_copy_dir / "wordlists.yaml.before"
        before.write_text(wl.read_text(encoding="utf-8"), encoding="utf-8")
        snapshots.append({"path": str(wl), "before": str(before)})
        text = wl.read_text(encoding="utf-8")
        for task, keys in plan["wordlist_selection"].items():
            # registry-wide + key law enforced through the live registry
            from pipeline.wordlists import WordlistRegistry

            reg = WordlistRegistry(params)
            allowed = reg.allowed_keys(task)
            unknown = [k for k in keys if k not in allowed]
            if unknown:
                raise ProfileError(f"wordlist keys not registered for {task}: {unknown}")
            block_re = re.compile(rf"^  {re.escape(task)}:\s*(?:#.*)?$", re.M)
            m = block_re.search(text)
            if not m:
                raise ProfileError(f"wordlists.yaml has no task block {task!r}")
            # idempotence guard: never stack a second selection under a block
            block_end_m = re.search(r"^  [A-Za-z0-9_-]+:", text[m.end():], re.M)
            block_text = text[m.end(): m.end() + (block_end_m.start() if block_end_m else len(text[m.end():]))]
            if re.search(r"^\s{4}selection:", block_text, re.M):
                raise ProfileError(f"task block {task!r} already carries a selection (remove it first)")
            insert_at = m.end()
            rendered = f"\n{4 * ' '}selection:\n" + "\n".join(f"{4 * ' '}  - {k}" for k in keys)
            text = text[:insert_at] + rendered + text[insert_at:]
        atomic_write_text(wl, text)

    return {"plan": plan, "snapshots": snapshots}


def restore_transient(applied: dict[str, Any]) -> dict[str, Any]:
    """Restore the snapshotted working-copy files byte-identically."""
    restored = []
    for snap in applied.get("snapshots", []):
        before = Path(snap["before"])
        if before.is_file():
            Path(snap["path"]).write_text(before.read_text(encoding="utf-8"), encoding="utf-8")
            restored.append(snap["path"])
    return {"restored": restored}
