# RECON PIPELINE — COMPANION GUIDE FOR CURSOR
# Version: 1.9 | Binds to: cursor-recon-agent-prompt.md (v1.9)
# Read this guide TOGETHER with the master prompt. The master prompt is the CONTRACT; this guide tells you HOW to execute it — in what order, with what acceptance proof.

## 0. HOW TO USE THIS PACKAGE
0.1 The package is two files:
  - `cursor-recon-agent-prompt.md` — the MASTER PROMPT (product specification). Normative.
  - `cursor-recon-companion-guide.md` — this file (build & acceptance playbook). Operational.
0.2 Load BOTH files into Cursor at session start: paste them as Project Rules (`.cursor/rules/`) or paste them at the top of the first message of every session. In long sessions, re-anchor by re-pasting both files verbatim — never from memory or a summary.
0.3 Work strictly phase-by-phase (§4). Finish a phase → run its acceptance check → commit → move on. Never start a later phase before the earlier one passes.
0.4 The pipeline MUST stay runnable via CLI (`./recon.sh`) at every point of the build — the dashboard and the agent are additive layers, never prerequisites (master prompt §12.1).
0.5 OPERATOR WORKSTATION = WSL2 (master prompt §2.7): setup order = install WSL2 + an Ubuntu-class distro → install Docker (Docker Desktop with WSL2 backend, OR native Docker Engine + compose plugin inside the distro — build code must not care which) → clone the repo INTO the Linux filesystem (e.g., `~/recon-pipeline`), NEVER under `/mnt/<drive>/` — 9P-mounted Windows drives cripple wordlist/log I/O. Size the WSL VM in `%UserProfile%\.wslconfig` (`memory`, `processors`) at or above the §11.5 ceiling so the resource ceiling stays enforceable. Reach the dashboard from any Windows browser at `http://127.0.0.1:8080` (WSL2 localhost forwarding). Enforce LF line endings (`git config core.autocrlf input`) — CRLF silently breaks container entrypoints. Sanity check before B0: `wsl --version` → `docker run --rm hello-world` → `docker compose version`.

## 1. SOURCE OF TRUTH & PRECEDENCE
1.1 Precedence when interpreting: master prompt §3 (scope gate) > §2 + §11 (docker & stability/resource laws) > §8 module specs > the rest of the master prompt > this guide.
1.2 If this guide and the master prompt ever disagree, the MASTER PROMPT wins. Stop and flag the conflict — do not improvise.
1.3 No invented requirements. Anything not present in the two files (new tool, panel, field, default) is a CHANGE PROPOSAL (§8 below), never a silent addition.
1.4 Parameters: every value used in code must reference a NAMED parameter registered per master prompt §5.6 (tools.yaml override or dashboard Settings). Hardcoded magic numbers/flags/URLs in module code = spec violation.

## 2. SESSION PROTOCOL FOR CURSOR
2.1 Autonomy: build autonomously — no mid-run questions, no placeholders, no TODO comments in delivered code (master prompt §1).
2.2 Append-only: §8 module specs are locked in order. When implementing, preserve sub-step order exactly (FFUF-0→1→2; DNSR-1→2→3; PSV-0→…→8; PORT-SWEEP strictly post-MERGE). Implement the frozen spec text — never rewrite it.
2.3 One phase per session is ideal. Open each session by stating: current phase + the acceptance check that will prove it done.
2.4 Every phase delivers: code + compose/config + seed config files (scope.yaml.example, tools.yaml, resolvers.yaml, search_engines.yaml, dorks.yaml, views.yaml as they become relevant) + a `PHASE-REPORT.md` entry (what was built, how to run it, what the acceptance check showed).
2.5 Commits: one or more per phase, conventional messages (`feat(dnsr): ...`); the repo stays green at every commit (`docker compose config` valid, `./recon.sh status` works).

## 3. TARGET REPOSITORY LAYOUT
```
repo/
├── docker-compose.yml            # tool containers + dashboard service (master §2.6)
├── recon.sh                      # CLI entry: run | resume | stop | status | report (§12.1)
├── scope.yaml                    # authorization gate — real targets NEVER committed (§3)
├── scope.yaml.example
├── tools.yaml                    # adapter registry + per-tool flag overrides (§5)
├── tools.lock                    # pinned images/tags/digests (§2.2)
├── resolvers.yaml                # RESOLVER FORGE registry (§8 shared component)
├── search_engines.yaml           # SEARCH-FORGE engine pool (PSV-0)
├── dorks.yaml                    # DORK FORGE corpus registry (PSV-0/1/7)
├── remediation.yaml              # supervisor playbook (§12.5)
├── views.yaml                    # per-module dashboard view descriptors (§6.5)
├── wordlists.yaml                # curated wordlist registry keyed per task (§8 WORDLIST REGISTRY)
├── scheduler.json                # watchtower state (§4.6, runtime)
├── dashboard/                    # FastAPI backend + React SPA (§9)
├── docker/<tool>/Dockerfile      # per-tool builds when no official image exists (§2.2)
├── schemas/                      # JSON Schemas: assets.json, per-module data.json, diff.json
├── wordlists/forge/              # FFUF-0 self-growing output
└── recon/<target>/               # runtime data (§6.1): 00_assets/ 10_subdomains/ 15_vhosts/
                                  #   30_ports/ sources/ 90_report/ history/ logs/
```
Gitignored: `recon/`, `dashboard/config.json`, `.env`. ALL provider keys live in `.env` (§9.2-d) — never committed, never logged.

## 4. BUILD ORDER — PHASES & ACCEPTANCE
Phase B0 — SCAFFOLD & CONTRACTS
  Build: repo skeleton per §3; docker-compose.yml skeleton; scope gate (§3) enforced at orchestrator entry; recon/ directory factory (§6.1); state.json engine; FORMAL JSON Schema files under `schemas/` for assets.json + every module's data.json + diff.json (master §6 defines fields — you make them machine-checkable); tools.lock stub.
  Accept: (a) missing/empty/invalid scope.yaml → exit with setup instructions and ZERO network activity; (b) injected out-of-scope candidate → rejected + logged; (c) `./recon.sh status` runs clean on an empty workspace.

Phase B1 — ADAPTER & ORCHESTRATOR
  Build: adapter layer (§5.1–5.6) — tools.yaml load → per-tool command assembly from NAMED parameters only; fallback-profile registration (§4.3); pipeline engine (§7) — PASSIVE parallel ∥ ACTIVE sequential, branch time budgets + independence (§7.2c), MERGE (union + exact dedupe + source attribution passive|active|both + merge-time scope re-validation + wildcard/catch-all quarantine §7.3); circuit breaker (§11.4 — >20% errors/60s → auto-throttle; 2 windows → pause + Telegram ANOMALY; latency-drift signal); resource ceiling (§11.5 — budget → auto-derived per-container --memory/--cpus, split across parallel modules, de-concurrency before OOM); run history & diff (§6.6 — runs.json, history/<UTC-timestamp>/, diff.json added|removed|changed).
  Accept: a fake echo-tool registered in tools.yaml travels the full adapter→container→data.json path; injected error rate trips the breaker; two-run diff yields correct added/removed/changed.

Phase B2 — ACTIVE BRANCH (FFUF → DNS-RESOLVE → PORT-CHECK)
  Build in sub-step order: FFUF-0 WORDLIST FORGE (self-growing; input = union of the DASHBOARD-SELECTED registry keys per §8 WORDLIST REGISTRY & DASHBOARD SELECTION — checkboxes + select-all in Tools panel, union+dedupe cached per selection hash — plus DNSR hits fed back); FFUF-1 recursive enum (level loop 1..ffuf_depth, explosion guards max_hosts_per_level / max_total_requests → PARTIAL); FFUF-2 vhost enum on ALL hosts (alive AND dead → misconfig_suspect) + bounded feedback loop; RESOLVER FORGE (resolvers.yaml; <80% success → auto-quarantine); DNSR-1 dnsx brute → DNSR-2 alterx (max_permutations_per_host 50k) → DNSR-3 resolve-all + records + ASN + wildcard verification; LOAD BALANCE block MANDATORY (RAMP 1000→+1000/30s→dnsx_max_qps; CANARY re-resolve every 30s; ≥100 healthy forged resolvers); PORT-CHECK naabu top-50, rate 300, sequential — with §8 IP-CENTRIC PORT SCANNING dedup (ONE naabu invocation per UNIQUE resolved IP; results attributed to ALL hostnames sharing the IP; no-IP hosts skipped + counted, never silently).
  Accept: forged wordlist grew after a run; a dead-host vhost hit lands flagged misconfig_suspect=true; host→IP map exists for PORT-CHECK; a <80% resolver gets quarantined; two hostnames sharing one IP → exactly ONE naabu invocation in logs (PORT-CHECK dedup); every DNSR-3 output host carries ≥1 resolved IP or an explicit unresolved marker.

Phase B3 — PASSIVE BRANCH (PSV-0…PSV-8)
  Build in sub-step order, executed parallel per §7.2a: PSV-0 SEARCH-FORGE (engine pool + per-request key rotation + COOLDOWN backoff/reroute + ISOLATED >20%/60s + per-dork TTL cache); PSV-1 dorks execution; PSV-2 CT logs (crt.sh `%.target.com` + bare-domain variant, retry ×3, Censys domains; keyword tags NEVER drop-filters; Cert Spotter/Certstream registered as fallback); PSV-3 OSINT agents (subfinder -all / amass -passive 20-min cap / assetfinder full + --subs-only + puredns resolve / chaos / findomain — each into its OWN sources/<tool>.txt); PSV-4 archives (waybackurls + gau + direct CDX fallback); PSV-5 recursion (depth 2, max_seeds_per_iteration 100); PSV-6 httpx probe (tagging-only, toggle, default on); PSV-7 GITHUB-OSINT (token-pool rotation, 30 req/min, secrets reported — never exploited); PSV-8 IP-DISCOVERY (Censys `ip:`, Shodan reverse/`net:` — hostnames scope-gated into MERGE, IPs → sources/cidr-ips.txt → DNSR-3 map). FIRST SUB-STEP (v1.9 Option-1 mandate): implement MASTER §8 MODULE FFUF-3 — POST-DNSR VHOST PASS (production misconfig path; base-host set, probe binding, flag rule and asset-promotion ruling exactly as specified), then the DNSR-2 aggregate cap + suspect-name exclusion refinement, then the passive chain.
  Accept: every sources/<tool>.txt populated for a test target; simulated 429 → COOLDOWN + reroute visible in logs; recursion stops at its cap; PSV-8 activates only with CIDR/range/ASN includes.

Phase B4 — PORT-SWEEP (post-MERGE)
  Build: order-4 stage consuming assets.json alive=true (portsweep_scope alive_only|all_resolved switch); POST-MERGE RESOLUTION GUARANTEE per §8 IP-CENTRIC PORT SCANNING RULE 1 (batch-resolve hosts lacking IPs before the IP map; unresolved → excluded with explicit log line); materialize + log the explicit unique-IP target set (RULE 3) before any scan command; MANDATORY IP DEDUP — exactly ONE scan command per unique IP, results attributed to ALL hostnames sharing it; naabu SYN full range; SCAN PROFILES light|full|custom as a thin config layer (never a new tool); PACING portsweep_duration_hours (default 24, min 1) → derived pps = unique_ips × 65,535 ÷ duration, capped by profile; window breach → PARTIAL + remaining-IP list, never silent; scheduled sweeps never overlap (skipped: previous_in_progress); FILTERING INTELLIGENCE (alive host with zero open ports → filtered_suspect + ONE re-probe at rate ÷ 4; >1000 open → anomalous_open_suspect); SECOND STAGE nmap -sV — toggle portsweep_nmap_sv default OFF, sequential per IP, --max-rate param; this toggle is the designated VA HOOK (implement the toggle only — do NOT build a VA module).
  Accept: two hostnames on one IP → exactly one scan invocation in logs; pacing math verified on a synthetic IP set; toggle OFF → zero nmap containers ever launched.
Phase B5 — NOTIFICATIONS & SCHEDULER
  Build: Telegram per §4.5 (end-of-run summary: target, status, per-module counts, duration, report path) + §4.6 (INSTANT alert on NEW SUBDOMAIN or NEWLY OPENED PORT from PORT-CHECK / PORT-SWEEP diffs; scheduler interval ≥ 10 min; scheduler.json) + §4.7 (digest threshold default 10; dashboard-editable alert-filter rules; self-monitoring statuses FAILED / ANOMALY / STOPPED with reason + failing module). Two separate notification types, same credentials; unset credentials → skip silently.
  Accept: forced module failure → FAILED alert naming module + reason; new-asset flood above threshold → exactly ONE digest message; a closed-port-only diff → NO Telegram alert (dashboard diff view only).

Phase B6 — DASHBOARD
  Build: FastAPI backend + React/Vite SPA (§9.1; bind 127.0.0.1:8080, DASHBOARD_TOKEN auth); the backend is the ONLY docker.sock client (§2.6); panels a–e (§9.2): a) Tools (tools.yaml editor, enable/disable + flag overrides, schema-validated writes); b) Results (schema-driven via views.yaml, read-only from recon/, diff badges, GLOBAL RESULT FILTERS — combinable + URL-shareable — and SOURCE COVERAGE ANALYTICS: per-source contribution, overlap, uniqueness %); c) Run Control (start/stop/resume, live status from state.json, live log streaming incl. agent journal); d) API Keys (.env-backed, masked after save, picked up next run without restart); e) Settings (proxy, Telegram, digest threshold, alert filters, CPU/RAM budget); PROXY RULE (§9.3 — set-but-unreachable → FAIL FAST, never silent direct fallback; unset → direct silently); CYBER-SECURITY THEME (§9.4 — dark palette, monospace for ALL technical values, dense sortable tables + sticky headers, status/severity badges, collapsible raw-JSON inspector, views.yaml-driven so UI tuning stays code-free).
  Accept: edit a flag override in Tools → the next run's constructed command shows the new value (assert in logs); filter state survives URL sharing; proxy set-but-unreachable → run fails fast with a clear error.

Phase B7 — REPORTING
  Build: §10 deliverables under 90_report/: report.md, report.html (in the §9.4 theme), data.json (canonical), export.csv, export.json, PDF — generated on run end AND on demand from the dashboard. PRECISION CONTRACT (§10.2): every format is rendered FROM the canonical data.json only, and embeds the run timestamp + scope.yaml digest for traceability.
  Accept: counts in md/html/csv/pdf all equal data.json for the same run (byte-consistency spot check); a tampered data.json fails the digest check.

Phase B8 — SUPERVISOR AGENT (built LAST — it is an opt-in layer)
  Build §12 exactly: 12.1 agent-optional — the pipeline must already pass B0–B7 standalone; 12.2 one-command autonomy (`info-gather *.example.com`); 12.3 supervision loop — deterministic checks FIRST → §4.3 fallback → agent diagnose → ≤3 bounded remediations from remediation.yaml → Telegram escalation; 12.4 RESOURCE FRUGALITY — event-driven (never polling), ZERO LLM calls on healthy runs, batched + cached diagnoses, agent_max_llm_calls default 20/run → exhausted → pure deterministic alerts; 12.5 remediation.yaml playbook (config-driven, dashboard-editable — OOM → halve concurrency + retry; resolver failures → refresh RESOLVER FORGE; 403/quota → rotate key pool / engine COOLDOWN; corrupt output → quarantine + re-run module; tools.lock drift → re-pin + restart); 12.6 autonomy levels observe | suggest | auto-fix (defaults: auto-fix PASSIVE branch, suggest ACTIVE branch; user-overridable per run or persistent); 12.7 GUARDRAILS (never modify scope.yaml, never weaken the breaker, never bypass the scope gate, never act outside engagement context, never delete raw logs; every decision → append-only logs/agent-journal.jsonl, streamed live in Run Control).
  Accept: agent disabled → full B0–B7 regression green; agent enabled + simulated failure → journal shows deterministic check → diagnosis → ONE bounded remediation → success; healthy run consumes 0 LLM calls.

## 5. GLOBAL DEFINITION OF DONE (applies to every phase)
- No TODOs / placeholders / mock data in delivered code; every module emits schema_version'd JSON.
- Every §8 parameter exists as a named key (tools.yaml override or Settings) carrying its spec default — zero magic values (grep-verifiable).
- Scope gate, circuit breaker, and resource ceiling are structurally non-bypassable — not merely documented.
- All container invocations non-interactive; JSON output wherever supported; images pinned via tools.lock.
- Logs + agent journal append-only; raw results never deleted (history preserved per §6.6).
- Fresh clone → `cp scope.yaml.example scope.yaml` (authorized test target) → `./recon.sh run <target>` completes end-to-end: pipeline → MERGE → PORT-SWEEP → report.

## 6. OPERATOR VERIFICATION PROTOCOL (run after each phase)
6.0 ACCEPTANCE TESTS ARE CURSOR-EXECUTED: after each phase delivery, the operator pastes an atomic TEST PROMPT into the SAME chat. You (Cursor) then execute every acceptance test yourself, capture RAW EVIDENCE for every step (exact command, exit code, relevant file content / log lines), append the PASS/FAIL summary + evidence pointers to PHASE-REPORT.md, and CLEAN UP all test artifacts (fake tools, test runs) before printing the verdict. Nothing is committed — the commit happens only after the operator's explicit acceptance prompt. Never weaken or skip a test to make it pass; if a test cannot run, report BLOCKED with the exact reason.
B0: remove scope.yaml → zero network activity; inject out-of-scope host → rejected + logged.
B1: fake-tool rides the full adapter path; injected errors trip the breaker → ANOMALY fired.
B2: authorized test domain → wordlist grew; host→IP map complete; bad resolver quarantined; two hostnames on one IP → ONE naabu invocation (PORT-CHECK dedup).
B3: all sources/<tool>.txt non-empty; simulated 429 → reroute proven in logs.
B4: same-IP dedup assertion; pacing pps matches the formula; nmap toggle OFF → no nmap container.
B5: digest threshold behaves; closed-port diff → silence.
B6: parameter edit visible in next run command; URL filter state restores correctly.
B7: cross-format counts equal data.json; digest check rejects tampering.
B8: agent OFF regression passes; agent ON journal shows the bounded loop; 0 LLM calls on a healthy run.

## 7. DO-NOT-BUILD LIST (frozen operator decisions — never implement, never "improve")
- NARROW phase (deep-dive / fingerprinting) — deferred by design; do not scaffold it.
- VA module — only the nmap -sV TOGGLE exists (B4); the VA integration is future work by design.
- Confidence scoring in MERGE — explicitly REJECTED by the operator; never add weights/scores.
- Quiet-hours scheduling — REJECTED; duration-budgeted pacing (portsweep_duration_hours) replaces it.
- Shared subs.txt across passive tools — FORBIDDEN; MERGE attribution requires per-tool sources/<tool>.txt files.
- Raw HTML scraping of Google/Bing — FORBIDDEN; all search traffic flows through the SEARCH-FORGE engine pool.
- Agent as a pipeline component — the agent is an OPT-IN supervisor only; the pipeline runs with ZERO LLM dependency.
- Any tool / panel / field absent from the master prompt → change proposal first (§8), implementation only after approval.

## 8. CHANGE MANAGEMENT
8.1 Cursor may PROPOSE; only the operator APPROVES. Proposal format: [what] + [why] + [master-prompt section touched] + [risk].
8.2 Approved changes are APPENDED to the master prompt (frozen sections are never rewritten), the version header bumps, and the change is implemented in the NEXT phase — never retrofitted silently into finished phases.
8.3 The operator may veto any implementation detail after review; rework is a normal part of the loop.

## 9. GLOSSARY (shared vocabulary — keep names EXACT in code and UI)
- FORGE components: WORDLIST FORGE (FFUF-0 self-growing subdomain wordlist) | RESOLVER FORGE (the single resolver source, <80% auto-quarantine) | SEARCH-FORGE (PSV-0 API-routed engine pool) | DORK FORGE (dorks.yaml corpus registry).
- RAMP / CANARY: gradual rate climb / sentinel re-check guarding every fast loop (DNSR, PORT-SWEEP).
- Suspect classes: misconfig_suspect (dead DNS but answers vhost fuzz) | filtered_suspect (alive host, zero open ports after full sweep) | anomalous_open_suspect (>1000 open ports — tarpit/honeypot class).
- PARTIAL: a run that finished with a cap/budget/window breach — reason + missing-IP list recorded, never silent.
- Attribution: every asset carries its discovery sources[] — the reason per-tool source files are mandatory.
- IP-CENTRIC PORT SCANNING (§8, frozen v1.8): ports belong to the SERVER (IP), never the hostname — ONE scan command per unique resolved IP at PORT-CHECK, PORT-SWEEP, and the nmap -sV hook; resolution coverage guaranteed before any scan; the nmap target set is materialized + logged, never implicit.
- views.yaml: the ONLY lever for dashboard column/field changes (§6.5) — UI tuning never touches code.
- tools.lock: pinned image + digest per tool; flag/digest drift is a supervisor-remediable failure (§12.5).
- PARTIAL vs FAILED vs ANOMALY vs STOPPED: partial results | module failure after remediation | stability/resource signal | operator or supervisor stop — all four Telegram-worthy per §4.7.
