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
          active_branch_modules: [dns-resolve, ffuf, ffuf-3, port-check]
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

import json
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
    "scheduler": dict,               # per-target automatic checks (interval / enabled)
}

BUDGET_KEYS_ALLOW = {
    "passive_branch_budget_sec",
    "active_branch_budget_sec",
    "passive_recursion_depth",
    "recon_depth",
    "ffuf_depth",
    "ffuf3_max_dead_probes",
    "ffuf4_max_jobs",
}

NOTIFY_KEYS_ALLOW = {
    "telegram_chat",        # D-protocol: per-target Telegram USER id override
    "digest_threshold",
    "watchtower_enabled",
    "telegram_enabled",     # D-protocol: per-system notification opt-out
}

PROXY_KEYS_ALLOW = {
    "proxy_pool",           # C5: per-target comma-separated proxy pool (IP rotation)
}

SCHEDULER_KEYS_ALLOW = {
    "enabled",
    "interval_minutes",
}
_SCHEDULER_MIN_INTERVAL = 10

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
                            'notifications.telegram_chat must be a Telegram username '
                            '(jackjohns or @jackjohns) or a numeric chat id')
                elif k == "digest_threshold":
                    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                        raise ProfileError("notifications.digest_threshold must be a positive integer")
                elif k in ("watchtower_enabled", "telegram_enabled"):
                    if not isinstance(v, bool):
                        raise ProfileError(f"notifications.{k} must be a boolean")
        if section == "proxy":
            # C5 IP rotation: the reserved slot is now live. Closed key
            # allow-list + scheme law; a bad pool is refused BEFORE it can
            # reach the registry or the run.
            bad = set(value) - PROXY_KEYS_ALLOW
            if bad:
                raise ProfileError(f"proxy keys not overridable: {sorted(bad)}")
            for k, v in value.items():
                if k == "proxy_pool":
                    if not isinstance(v, str):
                        raise ProfileError("proxy.proxy_pool must be a comma-separated string of proxy URLs")
                    try:
                        from pipeline.ip_rotation import validate_pool_value
                        validate_pool_value(v)
                    except ValueError as exc:
                        raise ProfileError(f"proxy.proxy_pool invalid: {exc}") from exc
        if section == "scheduler":
            bad = set(value) - SCHEDULER_KEYS_ALLOW
            if bad:
                raise ProfileError(f"scheduler keys not overridable: {sorted(bad)}")
            for k, v in value.items():
                if k == "enabled" and not isinstance(v, bool):
                    raise ProfileError("scheduler.enabled must be a boolean")
                elif k == "interval_minutes":
                    if not isinstance(v, int) or isinstance(v, bool) or v < _SCHEDULER_MIN_INTERVAL:
                        raise ProfileError(
                            f"scheduler.interval_minutes must be an integer >= {_SCHEDULER_MIN_INTERVAL}"
                        )
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
        sections = profile_sections(prof)
        if not sections:
            continue
        out.append("    settings:")
        for section in sorted(sections):
            out.append(f"      {section}:")
            for k, v in (sections[section] or {}).items():
                if isinstance(v, list):
                    out.append(f"        {k}:")
                    out.extend(f"          - {item}" for item in v)
                else:
                    out.append(f"        {k}: {v}")
    atomic_write_text(registry_path(params), "\n".join(out) + "\n")
    return {"target": target, "sections": sorted(clean)}


def get_profile(params: Params, target: str) -> dict[str, Any]:
    return load_registry(params).get(target) or {}


def profile_sections(profile: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize YAML-nested or flat profiles to overridable sections only."""
    prof = profile or {}
    sections: dict[str, Any] = {}
    inner = prof.get("settings")
    if isinstance(inner, dict):
        for key, value in inner.items():
            if key in OVERRIDABLE:
                sections[key] = value
    for key, value in prof.items():
        if key in OVERRIDABLE:
            sections[key] = value
    return {
        key: value
        for key, value in sections.items()
        if value is not None and value != {} and value != []
    }


def profile_has_overrides(profile: dict[str, Any] | None) -> bool:
    """True only when THIS site has saved setup sections. Empty = global SETTINGS."""
    return bool(profile_sections(profile))


def build_edit_plan(params: Params, target: str) -> dict[str, Any]:
    """Transient-edit plan for one run: what lines change in tools.yaml /
    wordlists.yaml to realize the profile. Pure function; no mutation."""
    profile = get_profile(params, target)
    settings = profile.get("settings") or {}
    plan: dict[str, Any] = {"target": target, "tools_edits": [], "wordlist_selection": {}}
    budgets = settings.get("budgets") or {}
    for key, value in budgets.items():
        plan["tools_edits"].append({"key": key, "value": value})
    # recon_depth (nested DNS) and ffuf_depth (nested vhost) stay independent.
    for key, value in (settings.get("modules") or {}).items():
        plan["tools_edits"].append({"key": key, "value": value})
    plan["wordlist_selection"] = settings.get("wordlist_selection") or {}
    plan["notifications"] = settings.get("notifications") or {}
    plan["proxy"] = settings.get("proxy") or {}
    # C5: the per-target pool rides the SAME top-level tools.yaml edit
    # mechanics as budgets; json.dumps renders a safely quoted YAML scalar.
    pool = str((settings.get("proxy") or {}).get("proxy_pool") or "").strip()
    if pool:
        plan["tools_edits"].append({"key": "proxy_pool", "value": json.dumps(pool)})
    plan["rate_caps"] = settings.get("rate_caps") or {}
    return plan


def _replace_settings_block(text: str, key: str, rendered: str) -> tuple[str, bool]:
    """Replace a 2-space settings key including any indented block-list body."""
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
            if isinstance(value, list):
                rendered = f"  {key}:\n" + "\n".join(f"    - {item}" for item in value)
            else:
                rendered = f"  {key}: {value}"
            text, replaced = _replace_settings_block(text, key, rendered)
            if not replaced:
                raise ProfileError(f"tools.yaml has no top-level key {key!r} to override")
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
            # selection law: exactly ONE selection under a block, ever.
            # A crashed run can leave the previous selection behind; a fresh
            # apply REPLACES it in place (self-heal), it never stacks.
            block_end_m = re.search(r"^  [A-Za-z0-9_-]+:", text[m.end():], re.M)
            block_end = m.end() + (block_end_m.start() if block_end_m else len(text) - m.end())
            block_text = text[m.end():block_end]
            fresh = "\n" + 4 * " " + "selection:\n" + "\n".join(
                f"{6 * ' '}- {k}" for k in keys
            )
            if re.search(r"^\s{4}selection:", block_text, re.M):
                new_block, n = re.subn(
                    r"\n {4}selection:(?:\n {6}- [^\n]*)+",
                    fresh,
                    block_text,
                    count=1,
                )
                if n != 1:
                    raise ProfileError(f"could not replace selection under task {task!r}")
                text = text[: m.end()] + new_block + text[block_end:]
            else:
                text = text[: m.end()] + fresh + text[m.end():]
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
