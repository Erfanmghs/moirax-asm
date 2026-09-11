"""PASSIVE-RECON -- branch: PASSIVE (master spec section 8, sub-steps PSV-0..PSV-8).

Order law (section 7.2a + append-only): PSV-0 infrastructure FIRST, then the parallel
sweep (PSV-1 dorks, PSV-2 cert-transparency, PSV-3 OSINT agents, PSV-4
archives, PSV-7 GitHub-OSINT, PSV-8 IP-discovery), then PSV-5 recursion, then
PSV-6 httpx probe LAST. PSV-7/PSV-8 are appended after PSV-6 in the spec text
purely to preserve append-only ordering; they execute inside the parallel
sweep (spec section 8 PSV-7/PSV-8 headers).

Purpose: maximize subdomain/host CANDIDATE discovery from third-party + OSINT
sources; every candidate is scope-gated (section 3.3) and source-attributed for
MERGE (section 7.3). Zero packets to the target except PSV-6.

Discipline:
- every candidate passes gate.enforce BEFORE entering the candidate set;
  rejections land in logs/out_of_scope.log (section 3.3 logged, never enumerated)
- every skip is an explicit run.log line -- never silent
- per-agent failure -> section 4.3 retry (adapter) + degraded-continue; a failed
  source never blocks the others (branch independence section 7.2c)
- keyword tags are applied as TAGS on candidates, NEVER as drop filters
- PSV-8 activates ONLY with CIDR/range/ASN includes; pure-domain targets skip
- output schema (data.json): {"schema_version":1,"module":"passive-recon",
  "candidates":[{"host","sources":[],"alive","tags":[]}],"passive_ips":[],
  "search_forge":{"engines_used","cooldown","isolated"},
  "recursion":{"depth_used","seeds_total"},"counts":{"candidates","alive"}}
- output paths: per-source raw -> recon/<target>/10_subdomains/passive/sources/
  ; module artifacts -> recon/<target>/10_subdomains/passive/data.json+summary.md
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from pipeline.adapter import Adapter
from pipeline.hostsutil import container_path, normalize_fqdn
from pipeline.jsonio import write_json
from pipeline.params import Params
from pipeline.scope import ScopeGate
from pipeline.search_forge import (
    SearchForge,
    extract_http_status,
    hosts_from_engine_body,
    load_dorks_registry,
    load_registry,
    split_headers_body,
)
from pipeline.textio import atomic_write_text

_ASN_RE = re.compile(r"^AS\d+$", re.IGNORECASE)
_RANGE_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+$")


def run_passive_recon(
    params: Params,
    gate: ScopeGate,
    adapter: Adapter,
    target_dir: Path,
    target: str,
    extra: dict[str, Any],
    planned: int,
    timeout_sec: float | None,
    partial: list[str],
) -> dict[str, Any]:
    clock = adapter.clock
    budget = float(timeout_sec) if timeout_sec and timeout_sec > 1 else float(
        params.require("passive_branch_budget_sec")
    )
    deadline = clock.time() + budget

    def remaining() -> float:
        return deadline - clock.time()

    def timeout_for(cap: float | None = None) -> float | None:
        """Invoke timeout: never exceed the branch deadline, never a floor
        below it (run #22 evidence: remaining()<0 -> 30s floor -> mass 124
        timeouts -> breaker error-ratio pause -> ANOMALY). Returns None when
        the budget is exhausted -- the caller SKIPS, never fires a doomed
        container."""
        left = remaining()
        if left <= 0:
            return None
        if cap is None:
            return left
        return min(left, cap)

    def note(detail: str) -> None:
        from datetime import datetime, timezone

        path = target_dir / str(params.require("run_log"))
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp}\tpassive-recon\t-\t0\tok\t{detail}\n")

    sources_rel = str(params.require("passive_sources_relpath"))
    sources_dir = target_dir / sources_rel
    sources_dir.mkdir(parents=True, exist_ok=True)
    cands = _Candidates(gate, target_dir, params)
    source_files: dict[str, int] = {}
    findings: list[str] = []
    skips: list[str] = []
    agent_rows: list[dict[str, Any]] = []

    # ---- PSV-0 SEARCH-FORGE (ordered sub-step 0 -- infrastructure first) ----
    note("psv-0: SEARCH-FORGE infrastructure init (engine pool + DORK FORGE)")
    registry = load_registry(params)
    forge = SearchForge(params, registry, clock, note)
    dorks_registry = load_dorks_registry(params)
    dorks, dorks_forge_rel = dork_forge(params, target_dir, target, dorks_registry)
    github_dorks = _template_all(dorks_registry.get("github_dorks") or [], target)
    note(
        f"psv-0: dork forge -> {dorks_forge_rel} dorks={len(dorks)} "
        f"github_dorks={len(github_dorks)} engines_available={len(forge.engines)}"
    )
    if not forge.engines:
        skips.append("search-forge: no enabled engine has its key (or keyless engine) available")

    # ---- parallel sweep: PSV-1, PSV-2, PSV-3, PSV-4, PSV-7, PSV-8 ----------
    sweep: dict[str, dict[str, Any]] = {}

    def _sweep(name: str, fn) -> None:
        sweep[name] = {"status": "running"}
        try:
            sweep[name]["result"] = fn()
            sweep[name]["status"] = "done"
        except Exception as exc:  # branch independence: never blocks the others
            sweep[name]["status"] = "failed"
            sweep[name]["error"] = str(exc)
            note(f"{name} FAILED (degraded-continue, branch independence): {exc}")

    threads = {
        "psv1": lambda: _psv1_dorks(params, gate, adapter, target_dir, target, extra, planned,
                                    forge, dorks, cands, source_files, skips, note, remaining),
        "psv2": lambda: _psv2_ct(params, gate, adapter, target_dir, target, extra, planned,
                                 cands, source_files, skips, note, remaining, timeout_for),
        "psv3": lambda: _psv3_agents(params, gate, adapter, target_dir, target, extra, planned,
                                     cands, source_files, skips, note, remaining, timeout_for, agent_rows),
        "psv3b": lambda: _psv3_public_apis(params, gate, adapter, target_dir, target, extra, planned,
                                           cands, source_files, skips, note, remaining, timeout_for),
        "psv4": lambda: _psv4_archives(params, gate, adapter, target_dir, target, extra, planned,
                                       cands, source_files, skips, note, remaining, timeout_for),
        "psv7": lambda: _psv7_github(params, gate, adapter, target_dir, target, extra, planned,
                                     forge, github_dorks, cands, source_files, skips, findings,
                                     note, remaining, timeout_for),
        "psv8": lambda: _psv8_ip(params, gate, adapter, target_dir, target, extra, planned,
                                 cands, source_files, skips, note, remaining, timeout_for),
    }
    with ThreadPoolExecutor(max_workers=len(threads)) as pool:
        futs = {pool.submit(_sweep, name, fn): name for name, fn in threads.items()}
        for fut in as_completed(futs):
            fut.result()

    first_sweep_hosts = cands.host_list()

    # ---- PSV-5 RECURSION LOOP (after the first parallel sweep) -------------
    recursion = {"depth_used": 0, "seeds_total": 0}
    if remaining() <= 0:
        partial.append("passive_budget")
        note("psv-5 skipped: branch budget exhausted before recursion -- disclosed, never silent")
    else:
        _psv5_recursion(params, gate, adapter, target_dir, target, extra, planned, forge,
                        cands, source_files, skips, partial, note, remaining, timeout_for,
                        recursion, first_sweep_hosts, sweep)

    # ---- PSV-6 HTTPX-PROBE (final sub-step -- liveness TAGGING ONLY) --------
    alive_map: dict[str, bool] = {}
    if remaining() <= 0:
        partial.append("passive_budget")
        note("psv-6 skipped: branch budget exhausted -- alive stays null, disclosed, never silent")
    else:
        alive_map = _psv6_probe(params, adapter, target_dir, extra, planned, cands,
                                skips, note, remaining, timeout_for)

    # ---- payload (exact section 8 output schema) ----------------------------------
    rows = cands.rows()
    for row in rows:
        if row["host"] in alive_map:
            row["alive"] = alive_map[row["host"]]
    alive_count = sum(1 for row in rows if row.get("alive") is True)
    passive_ips = cands.passive_ips()
    payload = {
        "schema_version": int(params.require("schema_version")),
        "module": "passive-recon",
        "candidates": rows,
        "passive_ips": passive_ips,
        "search_forge": dict(forge.stats),
        "recursion": recursion,
        "counts": {"candidates": len(rows), "alive": alive_count},
    }
    data_rel = str(params.require("passive_data_json"))
    write_json(target_dir / data_rel, payload)

    sweep_status = {name: meta["status"] for name, meta in sweep.items()}
    summary = target_dir / str(params.require("passive_summary"))
    summary.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# passive-recon (PSV-0..PSV-8)",
        "",
        f"target: {target}",
        f"sweep: {sweep_status}",
        f"engines_available: {len(forge.engines)} search_forge: {forge.stats} rerouted: {forge.rerouted}",
        f"recursion: {recursion}",
        f"candidates: {len(rows)} alive: {alive_count} passive_ips: {len(passive_ips)}",
        "sources:",
    ]
    lines.extend(f"  - {name}.txt {count}" for name, count in sorted(source_files.items()))
    lines.append("skips (never silent):")
    lines.extend(f"  - {item}" for item in skips) if skips else lines.append("  - none")
    if findings:
        lines.append("github findings (reported, never exploited/downloaded):")
        lines.extend(f"  - {item}" for item in findings[:20])
    if agent_rows:
        lines.append("agents (section 7.2c independence):")
        for row in agent_rows:
            lines.append(f"  - {row['agent']}: {row['state']} rows={row.get('rows', 0)}")
    if partial:
        lines.append(f"partial: {', '.join(partial)}")
    lines.append("")
    atomic_write_text(summary, "\n".join(lines))
    note(
        f"passive-recon done: candidates={len(rows)} alive={alive_count} "
        f"ips={len(passive_ips)} sources={sorted(source_files)} skips={len(skips)}"
    )
    return payload


# ---------------------------------------------------------------------------
# PSV-0 helper: DORK FORGE
# ---------------------------------------------------------------------------
def dork_forge(params: Params, target_dir: Path, target: str, registry: dict[str, Any]) -> tuple[list[str], str]:
    """Built-in host-discovery dork templates merged with community dork lists,
    templated per target + deduped -> dorks/forge/search-dorks.txt (section 8 PSV-0)."""
    builtin = _template_all(registry.get("builtin_host_dorks") or [], target)
    community: list[str] = []
    for entry in registry.get("community_lists") or []:
        text = str(entry)
        community.append(text.replace("{target}", target))
    dorks: list[str] = []
    seen: set[str] = set()
    for dork in [*builtin, *community]:
        token = dork.strip()
        if token and token not in seen:
            seen.add(token)
            dorks.append(token)
    rel = str(params.require("dorks_forge_output"))
    path = params.root / rel
    atomic_write_text(path, "\n".join(dorks) + ("\n" if dorks else ""))
    return dorks, rel


def _template_all(templates: list[Any], target: str) -> list[str]:
    return [str(t).replace("{target}", target) for t in templates if str(t).strip()]


# ---------------------------------------------------------------------------
# PSV-1 SEARCH-DORKS (parallel sub-step 1)
# ---------------------------------------------------------------------------
def _psv1_dorks(params, gate, adapter, target_dir, target, extra, planned, forge, dorks,
                cands, source_files, skips, note, remaining) -> dict[str, Any]:
    per_dork_timeout = float(params.require("dork_timeout_sec"))
    executed = cached = rerun_next_run = 0
    pool_exhausted_marked: list[str] = []
    for dork in dorks:
        if remaining() <= 0:
            partial_left = len(dorks) - executed - cached
            if partial_left > 0:
                note(f"psv-1: budget exhausted with {partial_left} dorks unexecuted -- disclosed")
            break
        hit = forge.cache_get(dork)
        if hit is not None:
            cached += 1
            for host in hit:
                cands.add(host, "dorks-cache")
            continue
        if not forge.healthy():
            pool_exhausted_marked.append(dork)
            continue
        executed += 1
        hosts, via = _execute_dork(params, adapter, target_dir, extra, planned, forge, dork,
                                   per_dork_timeout, note, remaining)
        if via == "pool_exhausted":
            pool_exhausted_marked.append(dork)
            continue
        forge.cache_put(dork, hosts)
        if hosts:
            source_files[f"dorks-{via}"] = source_files.get(f"dorks-{via}", 0) + len(hosts)
            path = target_dir / str(params.require("passive_sources_relpath")) / f"dorks-{via}.txt"
            _append_lines(path, hosts)
            for host in hosts:
                cands.add(host, f"dorks-{via}")
    if pool_exhausted_marked:
        # engine pool exhausted: dorks are MARKED and retried next run -- never
        # silently dropped (section 8 PSV-1).
        note(
            f"psv-1: {len(pool_exhausted_marked)} dorks marked rerun-next-run "
            f"(engine pool exhausted): {pool_exhausted_marked[:5]}..."
        )
        skips.append(f"psv-1: {len(pool_exhausted_marked)} dorks marked rerun-next-run")
    note(f"psv-1: executed={executed} cached={cached} engines_used={forge.stats['engines_used']}")
    return {"executed": executed, "cached": cached}


def _execute_dork(params, adapter, target_dir, extra, planned, forge, dork, timeout,
                  note, remaining) -> tuple[list[str], str]:
    """Run one dork through the pool: COOLDOWN on 429/403/captcha with instant
    reroute to the next healthy engine; ISOLATED handled by forge.record."""
    while True:
        engine = forge.pick()
        if engine is None:
            return [], "pool_exhausted"
        if remaining() <= 0:
            return [], "budget"
        forge.pace(engine)
        cmd, _key = forge.fetch_cmd(engine, dork)
        left = remaining()
        if left <= 0:
            return [], "budget"
        result = adapter.invoke(
            "curl-fetch",
            module="curl-fetch",
            extra={**extra, "fetch_cmd": cmd, "fetch_max_time": str(int(max(timeout, 5))), "skip_parse": True},
            planned_concurrency=planned,
            timeout_sec=min(left, timeout),
            allow_fallback=False,
        )
        status = extract_http_status(result.stdout) or 599
        _headers, body = split_headers_body(result.stdout)
        blocked = status in (429, 403) or any(m in body.lower()[:4000] for m in ("captcha", "unusual traffic"))
        forge.record(engine, ok=(200 <= status < 400) and not blocked, status_code=status)
        if blocked or not (200 <= status < 400):
            healthy = forge.pick()
            if healthy is not None and healthy["name"] != engine["name"]:
                forge.rerouted += 1
                note(
                    f"psv-1 reroute: dork={dork[:48]!r} engine={engine['name']} status={status} "
                    f"-> {healthy['name']}"
                )
            continue
        hosts = hosts_from_engine_body(str(engine["cfg"].get("kind") or "html"), body)
        return hosts, engine["name"]


# ---------------------------------------------------------------------------
# PSV-2 CERT-TRANSPARENCY (parallel sub-step 2)
# ---------------------------------------------------------------------------
def _psv2_ct(params, gate, adapter, target_dir, target, extra, planned,
             cands, source_files, skips, note, remaining, timeout_for) -> dict[str, Any]:
    max_time = int(float(params.require("crtsh_max_time_sec")))
    retries = int(params.require("crtsh_retries"))
    queries = [f"https://crt.sh/?q=%.{target}&output=json", f"https://crt.sh/?q={target}&output=json"]
    names: list[str] = []
    via = "crtsh"
    for attempt in range(max(1, retries)):
        ok = True
        for query in queries:
            if remaining() <= 0:
                break
            cmd = "curl -sS -D - --max-time " + str(max_time) + " " + _q(query)
            result = _bounded(adapter, "curl-fetch", "crtsh",
                              {**extra, "fetch_cmd": cmd, "fetch_max_time": str(max_time), "skip_parse": True},
                              planned, float(max_time), timeout_for, allow_fallback=False)
            status = extract_http_status(result.stdout)
            _h, body = split_headers_body(result.stdout)
            if status and 200 <= status < 300:
                names.extend(_crtsh_names(body))
            elif status:
                ok = False
        if ok and names:
            break
        if attempt < retries - 1:
            adapter.clock.sleep(2 ** attempt)
    if not names:
        fallback_tool = str(params.require("ct_fallback_tool"))
        note(
            f"psv-2: crt.sh exhausted its retries (section 4.3) -> registered CT fallback "
            f"{fallback_tool} serves the SAME query to the SAME output contract "
            f"(tools.yaml profile switch, never a pipeline edit)"
        )
        via = fallback_tool
        result = _bounded(adapter, fallback_tool, fallback_tool,
                          {**extra, "fetch_max_time": str(max_time)},
                          planned, float(max_time), timeout_for, allow_fallback=False)
        status = extract_http_status(result.stdout)
        if status and 200 <= status < 300:
            _h, body = split_headers_body(result.stdout)
            names.extend(_certspotter_names(body))
    unique = sorted({normalize_fqdn(n) or "" for n in names} - {""})
    keyword_tags = [str(t) for t in params.require("keyword_tags")]
    tagged = 0
    for host in unique:
        tags = [t for t in keyword_tags if f".{t}." in f".{host}." or host.startswith(f"{t}.")]
        if tags:
            tagged += 1
        # ALL name_values harvested; keyword tags applied as TAGS, NEVER as
        # drop filters (a contains("dev") filter loses candidates).
        cands.add(host, "crtsh" if via == "crtsh" else via, tags=tags)
    _write_lines(target_dir / str(params.require("passive_sources_relpath")) /
                 ("crtsh.txt" if via == "crtsh" else f"{via}.txt"), unique)
    source_files["crtsh" if via == "crtsh" else via] = len(unique)
    note(f"psv-2: via={via} hosts={len(unique)} tagged={tagged} (tags never dropped rows)")
    if not unique:
        skips.append("psv-2: CT sources returned zero rows (service degraded) -- disclosed")
    return {"hosts": len(unique), "via": via, "tagged": tagged}


def _crtsh_names(body: str) -> list[str]:
    try:
        rows = json.loads(body)
    except (ValueError, TypeError):
        return []
    out: list[str] = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = str(row.get("name_value") or "")
            for part in value.split("\n"):
                token = part.strip().lstrip("*.").lower().rstrip(".")
                if token:
                    out.append(token)
    return out


def _certspotter_names(body: str) -> list[str]:
    try:
        rows = json.loads(body)
    except (ValueError, TypeError):
        return []
    out: list[str] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                for name in row.get("dns_names") or []:
                    token = str(name).strip().lstrip("*.").lower().rstrip(".")
                    if token:
                        out.append(token)
    return out


def _q(url: str) -> str:
    import shlex

    return shlex.quote(url)


# ---------------------------------------------------------------------------
# PSV-3 OSINT-AGENTS (parallel sub-step 3)
# ---------------------------------------------------------------------------
def _psv3_agents(params, gate, adapter, target_dir, target, extra, planned,
                 cands, source_files, skips, note, remaining, timeout_for, agent_rows) -> dict[str, Any]:
    amass_cap_min = float(params.require("amass_timeout_min"))
    agents = [
        ("subfinder", None),
        ("amass", amass_cap_min * 60.0),
        ("assetfinder-related", None),
        ("assetfinder", None),
        ("findomain", None),
        ("chaos", None),
    ]
    chaos_keys = _env_keys(params, "CHAOS_KEY")
    results: dict[str, dict[str, Any]] = {}

    def run_agent(agent: str, cap_sec: float | None) -> None:
        if remaining() <= 0:
            results[agent] = {"state": "skipped budget exhausted", "hosts": [], "exit": -1}
            return
        result = _bounded(adapter, agent, agent, extra, planned, cap_sec, timeout_for)
        hosts = _hosts_from_lines(result.stdout)
        state = "ok" if result.exit_code == 0 else f"degraded exit={result.exit_code}"
        results[agent] = {"state": state, "hosts": hosts, "exit": result.exit_code}
        # auto-parsed per-tool file (sources/<agent>.txt) already written by the
        # adapter; candidates get the in-scope subset with attribution.
        for host in hosts:
            if agent == "assetfinder-related":
                # FULL output: related domains are usually OUT of scope -- the
                # harvest file keeps everything (section 3.3 logged), candidates only
                # take the in-scope subset, never enumerated beyond scope.
                if gate.validate_candidate(host)[0]:
                    cands.add(host, agent)
            else:
                cands.add(host, agent)
        if result.exit_code != 0:
            note(f"psv-3: agent={agent} degraded-continue after section 4.3 retries (exit={result.exit_code})")

    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        futs = {}
        for agent, cap in agents:
            if agent == "chaos" and not chaos_keys:
                results[agent] = {"state": "skipped no CHAOS_KEY", "hosts": [], "exit": -1}
                continue
            futs[pool.submit(run_agent, agent, cap)] = agent
        for fut in as_completed(futs):
            fut.result()

    # puredns resolve on the --subs-only assetfinder output (RESOLVER FORGE
    # output; built-in wildcard detection) -> assetfinder-resolved.txt
    subs_hosts = results.get("assetfinder", {}).get("hosts") or []
    resolved: list[str] = []
    resolved_ips: dict[str, list[str]] = {}
    if subs_hosts:
        resolved, resolved_ips = _psv3_resolve(
            params, adapter, target_dir, target, extra, planned, subs_hosts, note, remaining,
            timeout_for,
        )
    for agent, meta in results.items():
        rows = len(meta.get("hosts") or [])
        if agent == "assetfinder" and resolved:
            rows = len(resolved)
        agent_rows.append({"agent": agent, "state": meta["state"], "rows": rows})
        source_files[agent] = rows
    if resolved:
        source_files["assetfinder-resolved"] = len(resolved)
    note(
        "psv-3: " + " ".join(f"{a}={m['state']}" for a, m in results.items())
        + f" resolved={len(resolved)}"
    )
    if results.get("chaos", {}).get("state", "").startswith("skipped"):
        skips.append("psv-3: chaos skipped -- no CHAOS_KEY in .env (disclosed, never silent)")
    return {"agents": {a: m["state"] for a, m in results.items()}, "resolved": len(resolved)}


def _psv3_public_apis(params, gate, adapter, target_dir, target, extra, planned,
                      cands, source_files, skips, note, remaining, timeout_for) -> dict[str, Any]:
    """Keyless OSINT HTTP APIs + optional SecurityTrails/VirusTotal if keys exist."""
    from pipeline.public_apis import hosts_from_api_body

    apex = str(target).strip().lower().rstrip(".")
    sources_rel = str(params.require("passive_sources_relpath"))
    jobs: list[tuple[str, str]] = [
        ("hackertarget", "curl -sS -D - --max-time 45 " + _q(f"https://api.hackertarget.com/hostsearch/?q={apex}")),
        ("anubis", "curl -sS -D - --max-time 45 " + _q(f"https://jldc.me/anubis/subdomains/{apex}")),
        ("otx", "curl -sS -D - --max-time 45 " + _q(f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns")),
        ("urlscan", "curl -sS -D - --max-time 45 " + _q(f"https://urlscan.io/api/v1/search/?q=domain:{apex}")),
    ]
    st_keys = _env_keys(params, "SECURITYTRAILS_API_KEY")
    if st_keys:
        jobs.append((
            "securitytrails",
            "curl -sS -D - --max-time 45 -H " + _q(f"APIKEY: {st_keys[0]}")
            + " " + _q(f"https://api.securitytrails.com/v1/domain/{apex}/subdomains"),
        ))
    else:
        skips.append("psv-3b: securitytrails skipped -- no SECURITYTRAILS_API_KEY (keyless sources still run)")
    vt_keys = _env_keys(params, "VIRUSTOTAL_API_KEY")
    if vt_keys:
        jobs.append((
            "virustotal",
            "curl -sS -D - --max-time 45 -H " + _q(f"x-apikey: {vt_keys[0]}")
            + " " + _q(f"https://www.virustotal.com/api/v3/domains/{apex}/subdomains?limit=40"),
        ))
    else:
        skips.append("psv-3b: virustotal skipped -- no VIRUSTOTAL_API_KEY (keyless sources still run)")

    added = 0
    for name, cmd in jobs:
        if remaining() <= 0:
            skips.append("psv-3b: budget exhausted -- remaining public APIs skipped, never silent")
            break
        result = _bounded(
            adapter, "curl-fetch", "curl-fetch",
            {**extra, "fetch_cmd": cmd, "fetch_max_time": "45", "skip_parse": True},
            planned, 45.0, timeout_for, allow_fallback=False,
        )
        status = extract_http_status(result.stdout)
        _hdr, body = split_headers_body(result.stdout)
        hosts: list[str] = []
        if status and 200 <= int(status) < 300:
            hosts = hosts_from_api_body(name, body, apex)
        else:
            skips.append(f"psv-3b: {name} status={status} -- degraded, disclosed")
        kept: list[str] = []
        for host in hosts:
            if cands.add(host, name):
                kept.append(host)
                added += 1
        _write_lines(target_dir / sources_rel / f"{name}.txt", sorted(set(kept)))
        source_files[name] = len(set(kept))
        note(f"psv-3b: source={name} kept={len(set(kept))} status={status}")
    return {"state": "ok", "added": added}


def _psv3_resolve(params, adapter, target_dir, target, extra, planned, subs_hosts,
                  note, remaining, timeout_for) -> tuple[list[str], dict[str, list[str]]]:
    sources_rel = str(params.require("passive_sources_relpath"))
    input_rel = f"{sources_rel}/puredns-input.txt"
    atomic_write_text(target_dir / input_rel, "\n".join(subs_hosts) + "\n")
    forge_resolvers = params.root / str(params.require("resolver_forge_output"))
    resolvers_rel = str(params.require("passive_resolvers_target_rel"))
    forge_body = ""
    if forge_resolvers.is_file():
        try:
            forge_body = forge_resolvers.read_text(encoding="utf-8")
        except OSError:
            forge_body = ""
    if not forge_body.strip():
        # RESOLVER FORGE is the single resolver source (section 8 inputs); when the
        # forge output is absent or unreadable on this host, produce it from the
        # committed seed instead of silently probing with no resolvers.
        from pipeline.resolver_forge import forge_resolvers as run_forge

        note("psv-3: forge output missing/unreadable -> running RESOLVER FORGE from committed seed")
        run_forge(params, adapter, target_dir, target)
        if forge_resolvers.is_file():
            try:
                forge_body = forge_resolvers.read_text(encoding="utf-8")
            except OSError:
                forge_body = ""
    if forge_body:
        atomic_write_text(target_dir / resolvers_rel, forge_body)
    result = _bounded(adapter, "assetfinder-resolved", "assetfinder-resolved",
                      {**extra,
                       "puredns_input": container_path(params, target, input_rel),
                       "puredns_resolvers": container_path(params, target, resolvers_rel),
                       "dnsx_hosts": container_path(params, target, input_rel),
                       "dnsx_resolvers": container_path(params, target, resolvers_rel),
                       "skip_parse": True},
                      planned, 600.0, timeout_for)
    if result.exit_code == 0 and result.stdout.strip():
        # The adapter fallback chain returns the FALLBACK's stdout here: when
        # puredns fails, puredns-fallback-dnsx served the contract with
        # `-json` lines (run #25: json lines hit the host-lines parser and
        # were swallowed). Detect the dialect, never lose the rows.
        if result.stdout.lstrip().startswith("{"):
            hosts, ips = _dnsx_rows(result.stdout)
        else:
            hosts, ips = _hosts_from_lines(result.stdout), {}
        _write_lines(target_dir / sources_rel / "assetfinder-resolved.txt", hosts)
        if hosts:
            note("psv-3: resolve contract served (primary puredns or dnsx fallback)")
        return hosts, ips
    note("psv-3: puredns resolve failed and fallback produced no rows -- degraded, disclosed")
    return [], {}


# ---------------------------------------------------------------------------
# PSV-4 ARCHIVES (parallel sub-step 4)
# ---------------------------------------------------------------------------
def _psv4_archives(params, gate, adapter, target_dir, target, extra, planned,
                   cands, source_files, skips, note, remaining, timeout_for) -> dict[str, Any]:
    sources_rel = str(params.require("passive_sources_relpath"))
    union: set[str] = set()
    per_tool: dict[str, list[str]] = {}
    failures: list[str] = []
    for agent in ("waybackurls", "gau"):
        if remaining() <= 0:
            failures.append(agent)
            per_tool[agent] = []
            note(f"psv-4: {agent} skipped -- branch budget exhausted (disclosed)")
            continue
        result = _bounded(adapter, agent, agent, {**extra, "skip_parse": True}, planned, 600.0, timeout_for)
        hosts = _hosts_from_lines(result.stdout)
        per_tool[agent] = hosts
        if result.exit_code == 0:
            union.update(hosts)
        else:
            failures.append(agent)
    if len(failures) == 2:
        note("psv-4: waybackurls AND gau failed -> direct CDX fallback (archive.org throttles: backoff on 429/503)")
        result = _bounded(adapter, "cdx-fallback", "cdx-fallback", {**extra, "skip_parse": True},
                          planned, 300.0, timeout_for)
        status = extract_http_status(result.stdout)
        _h, body = split_headers_body(result.stdout)
        if status is None or 200 <= status < 300:
            union.update(_hosts_from_lines(body))
        else:
            skips.append(f"psv-4: CDX fallback also failed (status={status}) -- degraded, disclosed")
    else:
        for agent in failures:
            note(f"psv-4: {agent} failed -> union continues from the other providers (degraded-continue)")
    for agent, hosts in per_tool.items():
        _write_lines(target_dir / sources_rel / f"{agent}.txt", hosts)
        source_files[agent] = len(hosts)
    gated = sorted({h for h in union if cands.add(h, "archives")})
    _write_lines(target_dir / sources_rel / "archives.txt", gated)
    source_files["archives"] = len(gated)
    note(f"psv-4: harvested={len(union)} gated={len(gated)} failures={failures or 'none'}")
    return {"harvested": len(union), "gated": len(gated)}


# ---------------------------------------------------------------------------
# PSV-5 RECURSION LOOP
# ---------------------------------------------------------------------------
def _psv5_recursion(params, gate, adapter, target_dir, target, extra, planned, forge,
                    cands, source_files, skips, partial, note, remaining, timeout_for,
                    recursion, first_sweep_hosts, sweep) -> None:
    depth_cap = int(params.require("passive_recursion_depth"))
    seeds_cap = int(params.require("max_seeds_per_iteration"))
    sources_rel = str(params.require("passive_sources_relpath"))
    baseline = set(first_sweep_hosts)
    seeds = [h for h in first_sweep_hosts if h != target]
    note(f"psv-5: recursion start depth_cap={depth_cap} seeds_cap={seeds_cap} seeds={len(seeds)}")
    for depth in range(1, depth_cap + 1):
        if not seeds:
            note(f"psv-5: iteration {depth - 1} yielded zero new in-scope hosts -- natural stop")
            return
        if len(seeds) > seeds_cap:
            partial.append("passive_recursion_seeds_cap")
            note(
                f"psv-5: {len(seeds)} seeds > max_seeds_per_iteration={seeds_cap} -- "
                f"run marked PARTIAL with reason (spec section 8 PSV-5)"
            )
            seeds = seeds[:seeds_cap]
        if remaining() <= 0:
            partial.append("passive_budget")
            note("psv-5: budget exhausted mid-recursion -- disclosed, never silent")
            return
        new_hosts: set[str] = set()
        per_dork_timeout = float(params.require("dork_timeout_sec"))

        def work_seed(seed: str) -> set[str]:
            found: set[str] = set()
            if remaining() <= 0:
                return found
            if forge.healthy():
                hosts, via = _execute_dork(params, adapter, target_dir, extra, planned, forge,
                                           f"site:*.{seed}", per_dork_timeout, note, remaining)
                if via not in ("pool_exhausted", "budget"):
                    forge.cache_put(f"site:*.{seed}", hosts)
                    if hosts:
                        _append_lines(target_dir / sources_rel / f"dorks-{via}.txt", hosts)
                    found.update(hosts)
            cmd = "curl -sS -D - --max-time 120 " + _q(f"https://crt.sh/?q=%.{seed}&output=json")
            result = _bounded(adapter, "curl-fetch", "crtsh",
                              {**extra, "fetch_cmd": cmd, "fetch_max_time": "120", "skip_parse": True},
                              planned, 120.0, timeout_for, allow_fallback=False)
            status = extract_http_status(result.stdout)
            if status and 200 <= status < 300:
                _h, body = split_headers_body(result.stdout)
                found.update(_crtsh_names(body))
            # skip_parse + manual parse: parallel seed workers must not race on
            # the adapter's shared data.json tmp path (run #22 evidence), and
            # 60s caps keep slow third-party sources out of breaker windows.
            # section 8 PSV-5 names `subfinder -d <host>` (NOT -all) for deeper
            # queries: fewer sources, faster, keeps breaker windows clean
            # (run #23: -all per seed -> 124 timeouts -> error-ratio pause).
            sf = _bounded(adapter, "subfinder-seed", "subfinder-seed",
                          {**extra, "target_domain": seed, "skip_parse": True},
                          planned, 300.0, timeout_for)
            if sf.exit_code == 0 and sf.stdout.strip():
                hosts = _hosts_from_lines(sf.stdout)
                _append_lines(target_dir / sources_rel / "subfinder.txt", hosts)
                found.update(hosts)
            af = _bounded(adapter, "assetfinder", "assetfinder",
                          {**extra, "target_domain": seed, "skip_parse": True},
                          planned, 300.0, timeout_for)
            if af.exit_code == 0 and af.stdout.strip():
                hosts = _hosts_from_lines(af.stdout)
                _append_lines(target_dir / sources_rel / "assetfinder.txt", hosts)
                found.update(hosts)
            return found

        with ThreadPoolExecutor(max_workers=min(len(seeds), 4) or 1) as pool:
            futs = {pool.submit(work_seed, seed): seed for seed in seeds}
            for fut in as_completed(futs):
                if remaining() <= 0:
                    partial.append("passive_budget")
                    break
                try:
                    found = fut.result()
                except Exception as exc:
                    note(f"psv-5: seed worker degraded: {exc}")
                    continue
                for host in found:
                    host_n = normalize_fqdn(str(host))
                    if not host_n or host_n in baseline:
                        continue
                    if cands.add(host_n, "recursion"):
                        new_hosts.add(host_n)
        recursion["depth_used"] = depth
        recursion["seeds_total"] += len(seeds)
        note(f"psv-5: iteration {depth} seeds={len(seeds)} new={len(new_hosts)}")
        seeds = sorted(new_hosts)
        if not seeds:
            note(f"psv-5: iteration {depth} yielded zero new in-scope hosts -- natural stop")
            return


# ---------------------------------------------------------------------------
# PSV-6 HTTPX-PROBE (final sub-step -- liveness TAGGING ONLY)
# ---------------------------------------------------------------------------
def _psv6_probe(params, adapter, target_dir, extra, planned, cands, skips, note,
                remaining, timeout_for) -> dict[str, bool]:
    if not bool(params.require("passive_httpx_probe")):
        note("psv-6: passive_httpx_probe is OFF -- alive stays null (tagging toggle, dashboard-editable)")
        skips.append("psv-6: probe toggle off -- alive stays null")
        return {}
    hosts = cands.host_list()
    if not hosts:
        note("psv-6: zero candidates -- probe skipped (nothing to tag), disclosed")
        return {}
    sources_rel = str(params.require("passive_sources_relpath"))
    list_rel = f"{sources_rel}/probe-candidates.txt"
    out_rel = f"{sources_rel}/httpx.json"
    atomic_write_text(target_dir / list_rel, "\n".join(hosts) + "\n")
    result = _bounded(adapter, "httpx-passive", "httpx-passive",
                      {**extra,
                       "httpx_list": container_path(params, target_dir.name, list_rel),
                       "httpx_output": container_path(params, target_dir.name, out_rel),
                       "skip_parse": True},
                      planned, 600.0, timeout_for)
    alive: dict[str, bool] = {}
    out_path = target_dir / out_rel
    raw_lines = ""
    if out_path.is_file():
        raw_lines = out_path.read_text(encoding="utf-8", errors="replace")
    elif result.stdout.strip():
        # -o may have failed while stdout still carries the -json stream; the
        # alive tags are recovered from stdout (never lost, disclosed).
        raw_lines = result.stdout
        note("psv-6: httpx -o file missing -- alive tags recovered from stdout")
    for line in raw_lines.splitlines():
        if not line.strip().startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        host = normalize_fqdn(str(row.get("host") or row.get("input") or ""))
        if host:
            alive[host] = True
    if not alive:
        note("psv-6: no alive tags parsed -- alive stays null, disclosed")
    note(f"psv-6: probed={len(hosts)} alive_tagged={len(alive)} (tagging NEVER filters candidates)")
    return alive


# ---------------------------------------------------------------------------
# PSV-7 GITHUB-OSINT (user-approved; executes inside the parallel sweep)
# ---------------------------------------------------------------------------
def _psv7_github(params, gate, adapter, target_dir, target, extra, planned, forge,
                 github_dorks, cands, source_files, skips, findings, note, remaining,
                 timeout_for) -> dict[str, Any]:
    tokens = _env_keys(params, "GITHUB_TOKEN")
    if not tokens:
        note("psv-7 skipped: no GITHUB_TOKEN in .env -- sub-step SKIPPED, never silent")
        skips.append("psv-7: no GITHUB_TOKEN -- skipped (never silent)")
        return {"state": "skipped"}
    rate = float(params.require("github_search_req_per_min"))
    raw_rel = str(params.require("passive_github_raw_dir"))
    raw_dir = target_dir / raw_rel
    raw_dir.mkdir(parents=True, exist_ok=True)
    endpoints = ["code", "repositories", "gists"]
    pattern = re.compile(r"(?:[A-Za-z0-9-]+\.)+" + re.escape(target), re.IGNORECASE)
    archived = 0
    extracted = 0
    key_idx = 0
    for dork in github_dorks:
        for endpoint in endpoints:
            if remaining() <= 0:
                note("psv-7: budget exhausted -- remaining github dorks marked rerun-next-run, never silent")
                skips.append("psv-7: budget -- some dorks rerun-next-run")
                return {"state": "partial", "archived": archived}
            key = tokens[key_idx % len(tokens)]
            q = dork.replace(" ", "%20").replace('"', "%22").replace("*", "%2A")
            url = f"https://api.github.com/search/{endpoint}?q={q}&per_page=30"
            cmd = (
                "curl -sS -D - --max-time 60 "
                "-H " + _q(f"Authorization: Bearer {key}") + " "
                "-H " + _q("Accept: application/vnd.github+json") + " "
                "-H " + _q("User-Agent: moirax-ASM") + " " + _q(url)
            )
            result = _bounded(adapter, "curl-fetch", "curl-fetch",
                              {**extra, "fetch_cmd": cmd, "fetch_max_time": "60", "skip_parse": True},
                              planned, 60.0, timeout_for, allow_fallback=False)
            status = extract_http_status(result.stdout)
            _h, body = split_headers_body(result.stdout)
            if status in (403, 429, 451):
                key_idx += 1  # rotate the token pool (SEARCH-FORGE-style rotation)
                note(f"psv-7: github status={status} on {endpoint} -- rotated token pool, dork marked for retry")
                continue
            if not status or status >= 400:
                note(f"psv-7: github {endpoint} status={status} -- degraded-continue")
                continue
            archived += 1
            atomic_write_text(raw_dir / f"{endpoint}-{archived:03d}.json", body[:400000])
            for match in pattern.findall(body):
                host = normalize_fqdn(match)
                if host and gate.validate_candidate(host)[0]:
                    cands.add(host, "github")
                    extracted += 1
            try:
                rows = json.loads(body)
                for item in (rows.get("items") or [])[:10]:
                    url_html = str(item.get("html_url") or "")
                    if url_html:
                        findings.append(f"{endpoint}: {url_html}")
            except ValueError:
                pass
            adapter.clock.sleep(60.0 / max(rate, 1.0))
    source_files["github"] = extracted
    note(f"psv-7: archived={archived} hosts_extracted={extracted} (secrets reported, never exploited)")
    return {"state": "ok", "archived": archived}


# ---------------------------------------------------------------------------
# PSV-8 IP-DISCOVERY (user-approved; appended after PSV-7, inside the sweep)
# ---------------------------------------------------------------------------
def _psv8_ip(params, gate, adapter, target_dir, target, extra, planned,
             cands, source_files, skips, note, remaining, timeout_for) -> dict[str, Any]:
    includes = [str(i) for i in (gate.document.get("includes") or [])]
    targets = [i for i in includes if "/" in i or _RANGE_RE.match(i) or _ASN_RE.match(i)]
    if not targets:
        note(
            "psv-8 skipped: no CIDR/range/ASN includes in scope.yaml (pure-domain target) -- "
            "sub-step skipped per spec, never silent"
        )
        skips.append("psv-8: pure-domain target -- skipped per spec")
        return {"state": "skipped"}
    sources_rel = str(params.require("passive_sources_relpath"))
    ips: dict[str, set[str]] = {}
    host_rows: list[tuple[str, str]] = []
    censys_id = _env_keys(params, "CENSYS_API_ID")
    censys_secret = _env_keys(params, "CENSYS_API_SECRET")
    shodan_key = _env_keys(params, "SHODAN_API_KEY")
    for scope_item in targets:
        quoted = _q(scope_item)
        if censys_id and censys_secret:
            cmd = (
                "curl -sS -D - --max-time 60 -u "
                + _q(f"{censys_id[0]}:{censys_secret[0]}")
                + " -H " + _q("Content-Type: application/json")
                + " " + _q(f"https://search.censys.io/api/v2/hosts/search?q=ip%3A%22{quoted}%22")
            )
            result = _bounded(adapter, "curl-fetch", "curl-fetch",
                              {**extra, "fetch_cmd": cmd, "fetch_max_time": "60", "skip_parse": True},
                              planned, 60.0, timeout_for, allow_fallback=False)
            status = extract_http_status(result.stdout)
            _h, body = split_headers_body(result.stdout)
            if status and 200 <= status < 300:
                found_ips, found_hosts = _walk_ip_payload(body, target)
                for ip in found_ips:
                    ips.setdefault(ip, set()).add("censys-cidr")
                for host in found_hosts:
                    host_rows.append((host, "censys-cidr"))
            else:
                skips.append(f"psv-8: censys status={status} -- degraded, disclosed")
        else:
            skips.append("psv-8: censys skipped -- no CENSYS_API_ID/CENSYS_API_SECRET in .env")
        if shodan_key:
            cmd = (
                "curl -sS -D - --max-time 60 "
                + _q(f"https://api.shodan.io/shodan/host/search?query=net%3A{quoted}&key={shodan_key[0]}")
            )
            result = _bounded(adapter, "curl-fetch", "curl-fetch",
                              {**extra, "fetch_cmd": cmd, "fetch_max_time": "60", "skip_parse": True},
                              planned, 60.0, timeout_for, allow_fallback=False)
            status = extract_http_status(result.stdout)
            _h, body = split_headers_body(result.stdout)
            if status and 200 <= status < 300:
                found_ips, found_hosts = _shodan_payload(body)
                for ip in found_ips:
                    ips.setdefault(ip, set()).add("shodan-cidr")
                for host in found_hosts:
                    host_rows.append((host, "shodan-cidr"))
            else:
                skips.append(f"psv-8: shodan status={status} -- degraded, disclosed")
        else:
            skips.append("psv-8: shodan skipped -- no SHODAN_API_KEY in .env")
    # IPs stored AS-IS (never hostname-gated) -> sources/cidr-ips.txt; they
    # feed the host->IP plane (merged into DNSR-3's map inputs, section 7.1).
    ip_list = sorted(ips)
    _write_lines(target_dir / sources_rel / "cidr-ips.txt", ip_list)
    source_files["cidr-ips"] = len(ip_list)
    for ip, srcs in ips.items():
        cands.add_ip(ip, srcs)
    host_count = 0
    for host, source in host_rows:
        host_n = normalize_fqdn(host)
        if host_n and cands.add(host_n, source):
            host_count += 1
    for source in ("censys-cidr", "shodan-cidr"):
        rows = [h for h, s in host_rows if s == source]
        if rows:
            _write_lines(target_dir / sources_rel / f"{source}.txt", sorted(set(rows)))
            source_files[source] = len(set(rows))
    note(f"psv-8: activated for {targets} ips={len(ip_list)} hostnames_gated={host_count}")
    return {"state": "ok", "ips": len(ip_list)}


# ---------------------------------------------------------------------------
# candidate store
# ---------------------------------------------------------------------------
def _bounded(adapter, tool, module, extra, planned, cap, timeout_for, **kwargs):
    """Invoke with a branch-deadline-bounded timeout; when the budget is
    exhausted, return a synthetic skip WITHOUT spawning a doomed container and
    WITHOUT recording a breaker error (run #22 evidence)."""
    t = timeout_for(cap)
    if t is None:
        from pipeline.adapter import InvokeResult

        return InvokeResult(
            tool=tool, argv=[], docker_cmd=[], exit_code=124, stdout="",
            stderr="branch budget exhausted", duration_sec=0.0,
            used_fallback=False, data_json=None, paused=False, attempts=0,
        )
    return adapter.invoke(
        tool, module=module, extra=extra, planned_concurrency=planned,
        timeout_sec=t, **kwargs,
    )


class _Candidates:
    """Scope-gated candidate store with source attribution (section 7.3 inputs)."""

    def __init__(self, gate: ScopeGate, target_dir: Path, params: Params) -> None:
        self.gate = gate
        self.target_dir = target_dir
        self.params = params
        self._rows: dict[str, dict[str, Any]] = {}
        self._ips: dict[str, set[str]] = {}
        self.rejected = 0

    def add(self, host: str, source: str, tags: list[str] | None = None,
            alive: bool | None = None) -> bool:
        host_n = normalize_fqdn(str(host))
        if not host_n:
            self.rejected += 1
            return False
        if not self.gate.enforce(self.target_dir, host_n):
            self.rejected += 1
            return False
        row = self._rows.get(host_n)
        if row is None:
            row = {"host": host_n, "sources": [], "tags": [], "alive": None, "ips": []}
            self._rows[host_n] = row
        if source and source not in row["sources"]:
            row["sources"].append(source)
        for tag in tags or []:
            if tag and tag not in row["tags"]:
                row["tags"].append(tag)
        if alive is True:
            row["alive"] = True
        if not row["ips"] and row["host"] in self._ips:
            row["ips"] = sorted(self._ips[row["host"]])
        return True

    def add_ip(self, ip: str, sources: set[str]) -> None:
        token = str(ip).strip()
        if not token:
            return
        self._ips.setdefault(token, set()).update(sources)

    def host_list(self) -> list[str]:
        return sorted(self._rows)

    def rows(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for host in sorted(self._rows):
            row = dict(self._rows[host])
            row["sources"] = sorted(row["sources"])
            row["tags"] = sorted(row["tags"])
            if row["alive"] is None:
                row.pop("alive")
            if not row["ips"]:
                row.pop("ips")
            if not row["tags"]:
                row.pop("tags")
            out.append(row)
        return out

    def passive_ips(self) -> list[dict[str, Any]]:
        return [
            {"ip": ip, "sources": sorted(srcs)}
            for ip, srcs in sorted(self._ips.items())
        ]


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _env_keys(params: Params, env_name: str) -> list[str]:
    from pipeline.search_forge import env_keys

    return env_keys(params, env_name)


def _hosts_from_lines(text: str) -> list[str]:
    from urllib.parse import urlparse

    out: list[str] = []
    seen: set[str] = set()
    for raw in (text or "").replace(",", " ").split():
        token = raw.strip().lower().rstrip(".")
        if not token or token in seen:
            continue
        if "://" in token:
            try:
                token = (urlparse(token).hostname or "").rstrip(".")
            except ValueError:
                continue
        token = token.lstrip("*.")
        host = normalize_fqdn(token)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def _write_lines(path: Path, hosts: list[str]) -> None:
    atomic_write_text(path, "\n".join(hosts) + ("\n" if hosts else ""))


def _append_lines(path: Path, hosts: list[str]) -> None:
    """anew-style streaming append per tool file on resume (section 8 PSV-3)."""
    existing: set[str] = set()
    if path.is_file():
        existing = {line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()}
    fresh = [h for h in hosts if h not in existing]
    if not fresh:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(fresh) + "\n")


def _walk_ip_payload(body: str, target: str) -> tuple[list[str], list[str]]:
    """Generic censys v2 hosts payload walk: collect ip strings + hostnames."""
    ips: list[str] = []
    hosts: list[str] = []
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return ips, hosts
    suffix = "." + target

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "ip" and isinstance(value, str):
                    ips.append(value)
                elif key in ("dns", "names") and isinstance(value, dict):
                    for name in value.get("names") or []:
                        if isinstance(name, str):
                            hosts.append(name)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str) and node.lower().endswith(suffix):
            hosts.append(node)

    walk(payload)
    return ips, [h.lower().rstrip(".") for h in hosts]


def _dnsx_rows(text: str) -> tuple[list[str], dict[str, list[str]]]:
    """Parse dnsx `-a -resp -json` lines into (hosts, ip-map)."""
    hosts: list[str] = []
    ips: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        token = line.strip()
        if not token.startswith("{"):
            continue
        try:
            row = json.loads(token)
        except ValueError:
            continue
        host = normalize_fqdn(str(row.get("host") or ""))
        if not host:
            continue
        hosts.append(host)
        a_rows = row.get("a") or []
        if a_rows:
            ips[host] = [str(a) for a in a_rows]
    return hosts, ips


def _shodan_payload(body: str) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    hosts: list[str] = []
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return ips, hosts
    for match in payload.get("matches") or []:
        if not isinstance(match, dict):
            continue
        if match.get("ip_str"):
            ips.append(str(match["ip_str"]))
        for host in match.get("hostnames") or []:
            hosts.append(str(host).lower().rstrip("."))
    return ips, hosts
