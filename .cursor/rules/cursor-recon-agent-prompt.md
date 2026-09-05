# RECON PIPELINE AGENT — Master Prompt (for Cursor)
# Version: 1.9 | Updated: 2026-09-05
# Modules are appended iteratively. Never remove or rewrite completed sections — only append/refine.

## 1. ROLE
You are a senior offensive-security automation engineer. Build and maintain a modular, Docker-based information-gathering (recon) pipeline for AUTHORIZED penetration testing. You write production-quality code autonomously — no mid-run questions, no placeholders, no TODO comments in delivered code.

## 2. EXECUTION ENVIRONMENT — DOCKER
2.1 Nothing is installed on the host except Docker + docker compose. Every tool runs inside a container.
2.2 Prefer official maintainer images when available; otherwise build a per-tool Dockerfile under `docker/<tool>/`. Pin image + tag/digest in `tools.lock` for reproducibility.
2.3 All containers mount the shared volume `./recon` → `/recon` (rw). No other host paths are touched.
2.4 Active-scanning containers run with `--network host` so port scanners see accurate source IPs and full port range.
2.5 All tool invocations are non-interactive, deterministic flags; JSON output mode whenever the tool supports it.
2.6 The stack ships as one `docker-compose.yml`: tool containers + `dashboard` service (§9). The dashboard BACKEND is the only component allowed to talk to the Docker daemon (mounted docker.sock / Docker SDK); the frontend never touches it.
2.7 OPERATOR HOST — WSL2 (user-mandated): the stack targets Windows workstations through WSL2 (Ubuntu-class distro) — everything runs Linux-native inside WSL, nothing installs on Windows itself. Supported runtimes: Docker Desktop (WSL2 backend) OR native Docker Engine + compose plugin installed inside the distro; compose/tooling must never depend on which one is used. The repo and the `./recon` volume MUST live in the Linux filesystem (e.g., `~/recon-pipeline`) — never under `/mnt/<drive>/` (9P mounts cripple wordlist/log I/O). `--network host` containers ride the WSL network stack (outbound NAT via Windows) — sufficient for this pipeline's outbound recon. The dashboard on `127.0.0.1:8080` stays reachable from the Windows browser via WSL2 localhost forwarding. The WSL VM budget (`.wslconfig` memory/CPUs) must be ≥ the §11.5 ceiling so the ceiling remains enforceable. All shell scripts/entrypoints are LF-only (`git config core.autocrlf input`) — CRLF breaks container entrypoints.

## 3. AUTHORIZATION GATE — HARD (NON-NEGOTIABLE)
3.1 Single source of truth: `scope.yaml` — `includes` (domains, wildcard subdomains, CIDRs), `excludes` (blacklisted hosts/CIDRs), engagement metadata (name, authorization date).
3.2 If `scope.yaml` is missing/empty/invalid → print setup instructions and EXIT. Zero network activity without valid scope.
3.3 Every module MUST validate every target (domain, subdomain, IP, CIDR, URL) against scope before any packet leaves the machine. Out-of-scope candidates are dropped and logged to `recon/<target>/logs/out_of_scope.log` — never scanned, never resolved beyond validation.
3.4 Never scan RFC1918/loopback/link-local ranges unless explicitly listed in scope. Never scan shared/cloud wildcard endpoints (*.cloudfront.net, *.azurewebsites.net, *.herokuapp.com, ...) unless explicitly authorized.

## 4. OPERATING MODE — AUTONOMOUS
4.1 Entry point: `./recon.sh run <target-domain>` → runs the full pipeline end-to-end for that target.
4.2 `./recon.sh module <name> <target>` → runs a single module (debugging / partial resume).
4.3 Error policy per tool call: retry ×2 with exponential backoff → fallback tool if one is registered → degraded-continue. Every failure logged to `logs/run.log` (module, tool, exit code, stderr tail).
4.4 Never block on user input. The final report is always emitted, even with partial failures (sections marked PARTIAL with reason).
4.5 A run can be triggered from CLI or from the dashboard. On run end (`completed | partial | failed`) send a Telegram notification using credentials configured in the dashboard; if unset → skip silently. Message content: target, final status, per-module asset counts, duration, report path.
4.6 SCHEDULER / WATCHTOWER: runs can be scheduled on a user-defined dashboard interval (e.g., every 4h; validated minimum 10 min). Each scheduled run executes the pipeline, diffs against the previous completed run (§6.6), and INSTANTLY pushes a Telegram alert when a NEW SUBDOMAIN (host asset) is discovered OR a NEWLY OPENED PORT appears (PORT-CHECK / PORT-SWEEP diff, §8) — other diff classes (services/tech) surface in the dashboard diff view only. Scheduler state (`interval`, `enabled`, `last_run`) lives in `scheduler.json`, editable from the dashboard. End-of-run summary (§4.5) and instant new-finding alerts are two separate notification types, both using the same Telegram credentials.
4.7 ALERTING POLICY (anti-spam + reliability):
  - DIGEST THRESHOLD: instant alert per new asset while the run's new-asset count is below the threshold (default 10, dashboard-editable); at/above the threshold → ONE grouped digest message instead of N messages.
  - ALERT FILTERS (dashboard-editable rules): decide which new assets are alert-worthy (e.g., new open port on a known host, new subdomain resolving to a NEW IP, new web technology). Non-matching assets surface only in the dashboard diff view, never in Telegram.
  - SELF-MONITORING: the pipeline watches itself — on scheduled-run failure, zero-result anomaly (suspected pipeline breakage, distinct from a legitimately empty diff), or a STOP signal (user-initiated or crash) → send an explicit status alert: FAILED / ANOMALY / STOPPED, with reason + failing module name.

## 5. TOOL POLICY — AGENT-SELECTED
5.1 For each task YOU select the best-fit tool(s) and exact invocation flags; record choice + one-line rationale in `docs/tool-choices.md`.
5.2 Tools are invoked ONLY through the adapter layer `tools.yaml`: `name → image, default flags, output mode, parser`. Swapping or adding a tool later must be a config edit, never a pipeline rewrite.
5.3 When a task needs an unregistered tool: register it in `tools.yaml` (+ `tools.lock`), then use it.
5.4 `tools.yaml` is also the single source of truth for the dashboard Tools panel: the dashboard reads/writes it only through strict schema validation (enable/disable per tool, per-tool flag overrides). The pipeline never bypasses the adapter layer.
5.5 Tools stay plain CLI binaries inside their containers; ALL management (enable/disable, flag overrides, load limits, depth/wordlist params) is config-driven via dashboard → tools.yaml. The dashboard never patches tool code and never bypasses the adapter.
5.6 TOTAL CLI CONFIGURABILITY (hard rule, user-mandated): EVERY parameter appearing in any module spec in §8 — flags, thresholds, caps, depths, timeouts, rates, toggles, wordlists, engine pools — MUST be exposed as a NAMED, dashboard-editable parameter (tools.yaml flag override or dashboard Settings). No magic values hardcoded in module implementations: specs reference parameter NAMES with defaults; the Tools panel renders + validates them (type/range checks); the pipeline always consumes the current dashboard values at launch. Adding a module without full parameter exposure is a spec violation.

## 6. DATA & OUTPUT CONTRACT
6.1 Default layout (numbered = pipeline order; each module creates only its own dir; numbering extends as modules are added):
```
recon/<target>/
  00_scope/  00_assets/  10_subdomains/  15_vhosts/  20_dns/  30_ports/  40_services/  50_web/  60_screenshots/  90_report/
  history/<UTC-timestamp>/   (full data.json snapshot of every completed run)
  logs/  state.json  runs.json
```
6.2 Every module writes exactly two artifacts:
  - `data.json` — machine-readable, canonical module schema, includes `"schema_version"`.
  - `summary.md` — human-readable: command + flags, runtime, counts, notable findings.
6.3 Hand-off rule: downstream modules consume ONLY upstream `data.json` files. Raw tool stdout is archived under `logs/raw/<module>/` but never re-parsed.
6.4 `state.json`: per-module status (`pending|running|done|failed` + timestamps). Re-running skips `done` modules → idempotent & resumable.
6.5 Dashboard rendering is schema-driven: every module category is rendered from its `data.json` plus a per-module view descriptor in `views.yaml` (visible fields, columns, ordering). Future UI tuning = edit `views.yaml` only, zero code change.
6.6 RUN HISTORY & DIFF: every completed run appends a row to `runs.json` (timestamp, status, per-module counts) and snapshots its `data.json` files into `history/<UTC-timestamp>/`. The dashboard can diff any two runs: output = `diff.json` (`added | removed | changed` per asset class), surfaced in Results as "new since last run" badges.

## 7. PIPELINE ARCHITECTURE — WIDE FIRST
7.1 Phase-1 = WIDE: goal is MAXIMUM discovery of hosts, IPs, and subdomains. Narrow (deep-dive) recon is a separate later phase.
7.2 WIDE = PASSIVE ∥ ACTIVE:
  a) PASSIVE branch — all its modules run IN PARALLEL with maximal safe concurrency (OSINT / third-party sources, zero packets to the target).
  b) ACTIVE branch — its modules run STRICTLY SEQUENTIAL, one fully completing before the next starts, to avoid load spikes on the target.
  c) Branch independence: a crashed/failed branch NEVER blocks the other; each branch carries a dashboard-editable time budget — on breach it finishes with partial results and MERGE proceeds with whatever exists (degraded mode).
7.3 MERGE: after BOTH branches finish → union of all branch outputs with exact dedupe (an asset found by multiple sources is stored ONCE) and source attribution per asset: `passive | active | both`. Before finalizing: (1) every asset is RE-VALIDATED against scope (passive sources return junk — out-of-scope dropped + logged); (2) wildcard/catchall fingerprinting — assets resolving to the identical wildcard IP are quarantined (excluded from the master list, kept in `assets.json.quarantine`). Output: canonical master asset list at `recon/<target>/00_assets/assets.json` — the single hand-off source for all downstream modules.
7.4 Depth-oriented work (content fuzzing, vuln validation, exploitation) is OUT of Phase-1 scope, but the architecture must allow plugging it in later without refactor (that is what the module specs in §8 guarantee).

## 8. MODULE SPECS
<!-- Format per module: NAME | branch | order | Purpose | Inputs | Tool(s) + exact flags | Output schema | Output paths | Failure handling -->

### MODULE: FFUF — branch: ACTIVE | order: 1 | ordered module: sub-steps are APPEND-ONLY, never reorder existing ones (user will extend later)
Purpose: recursive HTTP-based subdomain + virtual-host discovery from a user-provided wildcard include (e.g., *.example.com).

FFUF-0 WORDLIST FORGE (ordered sub-step 0, runs before any enumeration):
- Aggregate subdomain wordlists from multiple registered sources (GitHub repos, public datasets — sources listed in `wordlists.yaml`); the ACTIVE input set = ONLY the registry keys the operator ticked in the dashboard (§8 WORDLIST REGISTRY & DASHBOARD SELECTION) → union + dedupe + normalize (lowercase, valid hostname charset) → `wordlists/forge/custom-subdomains.txt` (atomically updated).
- SELF-GROWING: after every completed run, newly VALIDATED host labels from FFUF-1/FFUF-2 AND DNS-RESOLVE (DNSR) hits are appended to the forged list → the custom list becomes target-specific and increasingly complete over time.

FFUF-1 RECURSIVE HOST ENUM (ordered sub-step 1):
- Seed: every `*.domain` include from scope.yaml (e.g., example.com).
- Level loop: level = 1 … `ffuf_depth` (dashboard-editable, default 1, allowed 1–5).
- Level 1: `ffuf -u http://FUZZ.<seed-domain> -w <forged-list> <baseline_flags> -o level1.json -of json`
- Level N: for EVERY host discovered at level N-1 → `ffuf -u http://FUZZ.<parent-host> -w <forged-list> <baseline_flags> -o level<N>_<parent>.json -of json`; discovered hosts become parents of level N+1.
- Explosion guard: `max_hosts_per_level` (dashboard-editable, default 1000) and `max_total_requests` (dashboard-editable, default 5,000,000) per run; cap hit → proceed to next stage, run marked PARTIAL with reason.

FFUF-2 VHOST ENUM (ordered sub-step 2, runs AFTER the depth loop completes — the module does NOT end at depth):
- BEFORE fuzzing: a lightweight HTTP probe (e.g., httpx via tools.yaml) tags every discovered host `alive | dead` (status, title, server). TAGGING ONLY — it never filters hosts out.
- For EVERY discovered host — INCLUDING DNS-dead ones (a dead hostname still answering via Host header = vhost misconfiguration class → flagged `"misconfig_suspect": true`): `ffuf -u http://<host> -H "Host: FUZZ.<host>" -w <effective-vhost-list> <baseline_flags> -o vhost_<host>.json -of json` — the effective vhost list = union of the dashboard-selected Wordlist Registry keys for this task (§8 WORDLIST REGISTRY & DASHBOARD SELECTION)
- Valid vhost hostnames are recorded as host assets (source: active) and re-enter the FFUF-2 queue for one bounded feedback pass (passes ≤ `ffuf_depth`; caps apply).

Baseline flags (mandatory on EVERY ffuf call):
`-mc all -ac -t <threads:40> -timeout 10 -rate <rps:150> -maxtime-job <sec:1800>` + `-o <path> -of json` + `-x <proxy>` only when proxy is set (§9.3). ALL load parameters (threads/rate/timeout/maxtime/depth/caps) are dashboard-editable via the Tools panel → tools.yaml overrides (§5.4–5.5); `--aggressive` raises caps but never disables the circuit breaker (§11.4).

Inputs: scope.yaml (wildcard includes) | `ffuf_depth` + load caps from dashboard | forged wordlist (FFUF-0 — union of dashboard-selected registry keys, §8; seclists mounted at `/usr/share/seclists` as one of the forge sources) | proxy setting.
Tools: ffuf via tools.yaml adapter (image per §2.2).
Output schema (data.json): `{"schema_version":1,"module":"ffuf","hosts":[{"fqdn","level","parent","alive","http_status","length"}],"vhosts":[{"base_host","vhost","alive","http_status","length","misconfig_suspect"}]}`
Output paths: FFUF-1 → `recon/<target>/10_subdomains/ffuf/` ; FFUF-2 → `recon/<target>/15_vhosts/ffuf/` (filenames embed level+parent so future sub-steps never collide).
Failure handling: §4.3 defaults; a failed level keeps all previously found hosts; vhost stage runs for every host that has a completed enum record.

### SHARED COMPONENT: RESOLVER FORGE (feeds any DNS-capable tool; registered per user directive)
- Aggregate public resolver lists from registered sources (registry: `resolvers.yaml`) → validate every resolver against known-good domains → union of RELIABLE resolvers → `resolvers/forge/custom-resolvers.txt` (atomically updated).
- Per-resolver health tracked (success ratio, latency). Auto-prune: a resolver below 80% success over a run is quarantined. Dashboard: manual add/remove of resolvers.
- SELF-GROWING (same principles as FFUF-0): refreshed/extended from sources every run. The forged file is the ONLY resolver source every DNS-capable tool may use (tools.yaml references it).

### SHARED COMPONENT: WORDLIST REGISTRY & DASHBOARD SELECTION (user-mandated)
- `wordlists.yaml` is the single registry of curated wordlists (e.g., SecLists trees), keyed per task group (DNSR-1 brute / FFUF-0 forge seeds / FFUF-2 vhost): key → file path (relative to the seclists mount), entry count, role, rationale. Shape-filtered: hostname-shaped entries only for DNS/vhost tasks; content-discovery lists are OUT OF SCOPE (NARROW-phase concern, deferred).
- DASHBOARD SELECTION (§9.2-a): the operator TICKS which registry keys each task uses — per-task checkboxes + a SELECT-ALL control per task group. Selection persists as named parameters through schema-validated writes (§5.4); the pipeline always consumes the current selection at launch (§5.6).
- UNION + DEDUPE at use time: per task, the selected files are merged, lowercased, stripped of whitespace/comments, and `sort -u`-deduped into ONE effective wordlist materialized per run (`wordlists/forge/effective-<task>.txt`) with its entry count logged — deterministic + auditable (§10.2 spirit).
- CACHE: the effective list is cached against a hash of (selection + source file mtimes); an unchanged selection reuses the cache instead of re-merging multi-million-entry lists every run (§11.5 frugality).
- FAIL-FAST: an empty selection for a task aborts the run launch with a clear error — the pipeline NEVER silently runs on an empty wordlist. Explosion guards (FFUF-1 caps, §11.4) still apply on top of the union.

### SHARED COMPONENT: IP-CENTRIC PORT SCANNING (user-mandated, frozen operator decision v1.8)
Rationale: open ports are a property of the SERVER (IP), not of any single hostname — many subdomains commonly share one server. Scanning per hostname duplicates work and multiplies noise. Therefore, across the WHOLE pipeline:
- RULE 1 — RESOLUTION COVERAGE: host identification (any branch, any source — passive or active) is only complete when the host's IP plane is resolved. Inside the ACTIVE branch, PORT-CHECK consumes the DNSR-3 host→IP map. POST-MERGE RESOLUTION GUARANTEE (executed before PORT-SWEEP): every host in assets.json WITHOUT a resolved IP is resolved in ONE batched dnsx pass (same forged-resolver registry; breaker §11.4 + ceiling §11.5 apply); hosts still unresolvable carry explicit `"resolution_status": "unresolved"` + reason — an IP is never silently missing.
- RULE 2 — ONE SCAN PER SERVER: PORT-CHECK (order-3), PORT-SWEEP (order-4), and the nmap -sV second stage consume the UNIQUE resolved-IP set: exactly ONE scan command per unique IP per run; results are attributed back to EVERY hostname sharing that IP. PORT-SWEEP's IP DEDUP clause below is reaffirmed; PORT-CHECK gains the same dedup (within its own input set).
- RULE 3 — EXPLICIT TARGET SET: before ANY scan command runs, the exact server list is materialized and logged (per unique IP: attributed hostnames + their discovery sources) so the operator can audit WHAT will be scanned and WHY — the nmap/naabu target set is never implicit.

### MODULE: DNS-RESOLVE — branch: ACTIVE | order: 2 | Tool: dnsx (PRIMARY, speed-tuned) + massdns (registered FALLBACK profile per §4.3 / dashboard-switchable)
Purpose: maximize subdomain CANDIDATE discovery at the DNS plane + resolve every known asset to IPs (A/AAAA/CNAME/MX/NS/TXT + ASN) → host→IP map for PORT-CHECK and the WIDE "max IPs" goal.

DNSR-1 BRUTE (candidates = union of the dashboard-SELECTED registry keys for this task, §8 WORDLIST REGISTRY & DASHBOARD SELECTION):
`dnsx -d <target-domain> -w <forged-wordlist> -r <forged-resolvers> -rl <qps> -a -resp -json` → DNS-true assets found even WITHOUT any HTTP service (the plane ffuf cannot see).

DNSR-2 PERMUTATIONS (candidates from mutations):
`alterx` on ALL known hosts (FFUF-1/2 hits) → candidate set capped by `max_permutations_per_host` (dashboard-editable, default 50,000) → resolved via dnsx with the same flags as DNSR-1.
- AGGREGATE CAP + SUSPECT-NAME EXCLUSION (v1.9, approved Option-1 item 3 — B2 evidence: 51,872 perms from 199 vhost-feedback FQDNs; per-host cap alone leaves the aggregate unbounded): an AGGREGATE cap `max_permutations_aggregate` (dashboard-editable, named §5.6 parameter) bounds the TOTAL perm candidate set per target per run, enforced after the per-host caps; wildcard-suspect and `misconfig_suspect`-flagged names are EXCLUDED from alterx seed input — suspect-name mutations must never amplify a wildcard/misconfig artifact.

DNSR-3 RESOLVE-ALL + RECORDS:
All known assets (FFUF hits + DNSR-1/2 valid hits) → full record resolution (A/AAAA/CNAME/MX/NS/TXT) + ASN + wildcard verification → host→IP map (input of PORT-CHECK).

LOAD BALANCE (speed ↔ safety — MANDATORY, answers "fast but never explosive"):
- RAMP: start at 1,000 qps → +1,000 qps every 30s up to `dnsx_max_qps` (dashboard-editable, default 5,000) — fast without a cold spike.
- CANARY: every 30s re-resolve 3 known-good sentinel hosts through the same path; latency > 2× baseline or errors → halve rate immediately; 2 consecutive bad windows → pause + Telegram ANOMALY (§4.7).
- RESOLVER DIVERSITY: queries hit public/forge resolvers; the target's authoritative NS only sees cache-misses — RESOLVER FORGE must keep ≥ 100 healthy resolvers to dilute miss-load.
- Circuit breaker (§11.4) + resource ceiling (§11.5) apply at all times.

FEED-BACK LOOP (mutual forge growth): valid DNSR hits append to the FFUF-0 wordlist forge; FFUF hits feed the alterx input — both forges grow together every run.

Output schema (data.json): `{"schema_version":1,"module":"dns-resolve","resolved":[{"host","ips":[],"cname":[],"mx":[],"ns":[],"txt":[],"asn","source":"brute|perm|known"}],"candidates":{"brute":0,"perms":0,"valid":0},"wildcard_suspects":[]}`
Output path: `recon/<target>/20_dns/dnsx/`
Failure handling: §4.3 — on dnsx failure retry ×1, then AUTO-SWITCH to the registered massdns profile (same forge inputs, JSON output, adapted rate profile), continuing degraded.

### MODULE: PORT-CHECK — branch: ACTIVE | order: 3 (strictly after DNS-RESOLVE) | light variant (full-range scanning belongs to the NARROW phase — deliberately out of scope here)
Purpose: per-SERVER (unique-IP) check of the 50 most-used ports; feeds the "newly opened port" watchtower alert (§4.6).
- Input: DNS-RESOLVE data.json (host → IP) → IP DEDUP per §8 IP-CENTRIC PORT SCANNING: build IP→[hostnames]; each UNIQUE resolved IP is checked EXACTLY ONCE (one naabu invocation); results attributed back to EVERY hostname sharing that IP. Hosts with no resolved IP are skipped + counted (never silently).
- Tool: naabu via tools.yaml (image per §2.2): `naabu -top-ports 50 -rate <rps:300> -json` — unique IPs processed sequentially (§7.2b); rate/concurrency dashboard-editable; circuit breaker (§11.4) + resource ceiling (§11.5) apply.
- Output schema (data.json): `{"schema_version":1,"module":"port-check","results":[{"ip","hosts":[],"ports":[{"port","proto","state":"open"}]}],"unreachable":[],"unique_ips_checked":0,"duplicates_skipped":0}` (user-mandated refinement v1.8: per-IP rows + attribution, never per-host scans)
- Output path: `recon/<target>/30_ports/naabu-light/` (the future NARROW full-range scan will use `30_ports/naabu-full/` — no collision).
- Diff integration: a newly OPEN port vs previous run → §4.6 Telegram alert; newly CLOSED ports recorded in diff, never alerted.
- Failure handling: §4.3; a fully-timing-out host is marked `unreachable`, not failed.

### MODULE: FFUF-3 — POST-DNSR VHOST PASS (v1.9, approved Option-1 item 1 — appended ACTIVE sub-step; runs after DNS-RESOLVE completes and BEFORE MERGE; existing module orders untouched, append-only law preserved)
Purpose: production path for the vhost-misconfiguration class on DNS-DEAD names. The frozen FFUF-2 flag-time DNS cross-check is impossible by the APPEND-ONLY order law (FFUF order 1 finishes before DNS-RESOLVE order 2) — B2 proved the machinery via the vhost fixture (TEST 2); this module is the production implementation, implemented at B3 start (§8.2 next-phase rule).
- BASE-HOST SET (exact): FFUF-1 completed enum records ∪ DNSR-3 hosts with `resolution_status: unresolved`. Both inputs are logged with counts before any probe.
- PROBE BINDING: `-u` is bound to an ALIVE in-scope base (a host with a resolved IP that answers HTTP — e.g. apex/www from the same target), with `Host: FUZZ.<dead-name>`; the dead name is never resolved directly. If no alive base exists for the target, the pass is SKIPPED with an explicit log line (never silent).
- FLAG RULE: `misconfig_suspect: true` ⟺ DNS-dead(name) AND a NON-FILTERED answer — i.e. the response survives the REM4-R1 calibration-drop discipline (genuine body/status, not a wildcard/autocalib artifact). Filtered answers are logged as suppressed, never flagged.
- ASSET-PROMOTION RULING (v1.9, approved Option-1 item 2): `misconfig_suspect` is an ORTHOGONAL FLAG, never an alive signal — it does NOT promote a DNS-dead host to `alive=true`, and as-frozen alive=true vhost records are not stripped because of the flag; the flag is carried through MERGE to the dashboard layer verbatim (flag-passthrough is acceptance-tested: if MERGE loses it, that is a defect).
- Output schema (data.json): `{"schema_version":1,"module":"ffuf-3","vhosts":[{"base_host","vhost","alive":null,"http_status","length","misconfig_suspect":true,"dns_status":"dead"}],"bases":[{"host","ip","alive"}],"suppressed":0}`
- Output path: `recon/<target>/15_vhosts/ffuf-3/` (never collides with FFUF-2 output).
- Caps: load flags mirror the FFUF-2 baseline (§8 FFUF baseline flags); circuit breaker (§11.4) + resource ceiling (§11.5) apply.

### MODULE: PORT-SWEEP — branch: ACTIVE | order: 4 (runs AFTER MERGE — consumes assets.json) | full-range scan on LIVE subdomains (the light top-50 PORT-CHECK stays as order-3 early signal — both coexist)
Purpose: complete port surface (all 65,535 ports) for every LIVE subdomain, with hard guarantees: exactly ONE scan command per unique IP per run, rate-ramped so WAF/IDS never blacklists us, professional profile switches (user-mandated).
- Input filter: hosts with `alive=true` from assets.json (PSV-6 / FFUF-2 probes). When the probe toggle is off, `portsweep_scope: alive_only | all_resolved` (dashboard-editable) decides the input set.
- POST-MERGE RESOLUTION GUARANTEE (§8 IP-CENTRIC PORT SCANNING, RULE 1 — user-mandated v1.8): hosts lacking a resolved IP are batch-resolved (ONE dnsx pass) BEFORE the IP→[hostnames] map is built; still-unresolvable hosts carry `resolution_status: unresolved` + reason and are EXCLUDED from scanning with an explicit log line — the unique-IP target set is derived only after this guarantee.
- IP DEDUP (MANDATORY): build IP→[hostnames] from the DNSR-3 map + PSV-8 passive IPs → each UNIQUE IP is scanned EXACTLY ONCE per run; results are attributed back to EVERY hostname sharing that IP. Duplicates are logged and skipped, never re-scanned.
- Tool: naabu via tools.yaml, SYN scan, host network (§2.4): `naabu -l <unique-ips> -p - -scan-type s -retries 2 -timeout 1000 -c <concurrency> -rate <pps> -json`
- SCAN PROFILES (the professional switch — dashboard-selectable per run or per schedule): `light` (top-50 = PORT-CHECK behavior) | `full` (all ports, default rate cap 1,000 pps) | `custom` (dashboard port-range + rate). Profile and EVERY flag are named dashboard-editable parameters (§5.6); Cursor implements the profile engine as a thin config layer over the adapter — never a new tool.
- RAMP + CANARY (mirrors DNS-RESOLVE LOAD BALANCE — MANDATORY): rate starts at 100 pps → +100 every 30s up to the profile cap; every 30s re-verify 3 known-open sentinel ports from the previous run; misses → halve rate immediately; 2 bad windows → pause + Telegram ANOMALY (§4.7). Circuit breaker (§11.4) + ceiling (§11.5) always on.
- PACING — DURATION-BUDGETED SCAN (user-mandated): `portsweep_duration_hours` (dashboard-editable, default 24, min 1) — the orchestrator derives the effective pps = (unique_ips × 65,535) ÷ (duration × 3600), capped by the profile rate cap → the full sweep completes WITHIN the configured window at a steady, gentle pace instead of max-speed blasting. RAMP still shapes the cold start; CANARY still guards. Window breach (pace infeasible) → run marked PARTIAL with the remaining-IP list, never silently abandoned. Scheduled runs never overlap PORT-SWEEP: if the previous sweep is still inside its window, the new run's sweep is SKIPPED (`skipped: previous_in_progress`) and diffs use the last completed sweep.
- FILTERING INTELLIGENCE (WAF/IDS-aware): known-ALIVE host with ZERO open ports after a full sweep → `filtered_suspect: true` + ONE slower re-probe (rate ÷ 4) before accepting; host with > 1,000 open ports → `anomalous_open_suspect: true` (tarpit/honeypot class), recorded + dashboard-reviewed, never alert-spammed.
- SECOND STAGE — SERVICE VERSIONING (user-approved, designated VA hook): OPTIONAL `nmap -sV` pass over PORT-SWEEP's open ports ONLY — dashboard-toggleable (`portsweep_nmap_sv: on|off`, default OFF), sequential per IP, `--max-rate` from a dashboard param; results extend the scan record with service/product/version. This stage is the designated HOOK for future VA/NARROW integration — enabling it later = flipping the toggle + adding a VA module, zero pipeline change.
- Watchtower wiring: results diff against previous runs (§6.6) — a NEWLY OPENED port → instant Telegram alert (§4.6); newly closed ports recorded, never alerted. Scheduled runs re-scan all live hosts at the PACED rate (required for diff truth), protected by RAMP + breaker + the no-overlap rule.
Output schema (data.json): `{"schema_version":1,"module":"port-sweep","scans":[{"ip","hosts":[],"profile":"full","ports":[{"port","proto","state":"open"}],"filtered_suspect":false,"anomalous_open_suspect":false}],"services":[{"ip","port","proto","product","version"}],"pace":{"duration_hours":24,"effective_pps":0,"window_breached":false},"unique_ips_scanned":0,"duplicates_skipped":0}`
Output path: `recon/<target>/30_ports/naabu-full/` (path reserved since the PORT-CHECK spec — no collision).
Failure handling: §4.3; a fully-timing-out IP is marked `unreachable`, not failed; scans are per-IP atomic — a crashed IP scan never corrupts the others.

### MODULE: PASSIVE-RECON — branch: PASSIVE | parallel module (§7.2a): PSV-0 infrastructure first, PSV-1–PSV-4 + PSV-7 + PSV-8 IN PARALLEL, PSV-5 recursion loop, PSV-6 probe last | sub-steps are APPEND-ONLY, never reorder existing ones (user will extend later)
Purpose: maximize subdomain/host CANDIDATE discovery from third-party + OSINT sources; every candidate is scope-gated (§3.3) and source-attributed for MERGE (§7.3). Zero packets to the target except PSV-6.

PSV-0 SEARCH-FORGE (ordered sub-step 0 — anti-block search infrastructure, runs before any dork):
- Principle: the pipeline NEVER raw-scrapes Google/Bing HTML from pipeline IPs (captcha walls + IP bans are the real bottleneck). All search traffic flows through a registered ENGINE POOL (`search_engines.yaml`) of API-routed providers: Google Programmable Search JSON API, Serper.dev, SerpAPI, Brave Search API, Yandex XML API, DuckDuckGo (keyless, throttled). Keys come from §9.2-d/.env; multiple keys per engine → per-request key rotation with per-key quota tracking.
- DORK FORGE (self-growing, same pattern as FFUF-0): built-in host-discovery dork templates (`site:*.target.com`, `site:*.*.target.com`, `site:target.com -inurl:www`, `site:*.target.com -site:www.target.com`) merged with community dork lists (registry `dorks.yaml`) → per-target templated + deduped corpus at `dorks/forge/search-dorks.txt`. Self-growth: newly discovered hosts spawn deeper dorks (fed by PSV-5 recursion).
- BLOCK HANDLING: HTTP 429/403 or captcha signal → engine marked COOLDOWN (exponential backoff + jitter), traffic instantly re-routed to the next healthy engine; engine error-rate > 20% over 60s → ISOLATED (per-engine mirror of the §11.4 breaker); cooldown engines re-probed after the backoff window. Per-dork result cache with dashboard-editable TTL → scheduled re-runs (§4.6) never re-burn quota on unchanged dorks.

PSV-1 SEARCH-DORKS (parallel sub-step 1): execute the forged dork corpus through the SEARCH-FORGE engine pool → extract candidate hostnames (scope-regex prefilter) → `sources/dorks-<engine>.txt`. Per-dork timeout 60s (dashboard-editable); dorks whose engine pool is exhausted are marked and retried next run — never silently dropped.

PSV-2 CERT-TRANSPARENCY (parallel sub-step 2):
- crt.sh: `curl -s --max-time 120 "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value'` → strip `*.` prefixes + split embedded newlines → sort -u → `sources/crtsh.txt`. Retry ×3 exponential backoff (crt.sh degrades under load); a second bare-domain query variant runs for completeness. ALL name_values are harvested — keyword tags (dev/stage/api/admin; dashboard-editable list) are applied as TAGS on candidates, NEVER as drop filters (a contains("dev") filter loses candidates).
- Censys (CENSYS_API_ID/SECRET, §9.2-d): `censys search "names: target.com"` (domains index) → `sources/censys.txt`; quota-aware backoff respects API free-tier limits.
- crt.sh FALLBACK (user-approved): when crt.sh exhausts its retries (§4.3) or times out → registered CT fallback (Cert Spotter API / Certstream historical) serves the SAME query to the SAME output contract; the swap is a tools.yaml profile switch, never a pipeline edit.

PSV-3 OSINT-AGENTS (parallel sub-step 3 — registered passive agents, each in its own container, each writing its OWN source file for attribution — never one shared subs.txt):
- `subfinder -d <target> -all -silent` → `sources/subfinder.txt` (uses every source key configured in §9.2-d: SHODAN, CENSYS, SECURITYTRAILS, VIRUSTOTAL, CHAOS, ...)
- `amass enum -passive -d <target>` → `sources/amass.txt` (amass data-source keys mounted from .env → amass config; runtime cap `amass_timeout_min`, dashboard-editable, default 20 — §7.2c budget)
- `assetfinder <target>` FULL output → `sources/assetfinder-related.txt` (related domains are usually OUT of scope → §3.3 logged, never enumerated) AND `assetfinder --subs-only <target>` → `sources/assetfinder.txt` (inherently scoped)
- `assetfinder --subs-only <target> | puredns resolve -r resolvers/forge/custom-resolvers.txt` (RESOLVER FORGE output; built-in wildcard detection) → `sources/assetfinder-resolved.txt` — the DNS-valid subset feeds PSV-6 and the MERGE quarantine logic (§7.3)
- `chaos -d <target> -silent` (CHAOS_KEY, §9.2-d) → `sources/chaos.txt`
- `findomain -t <target> -q` → `sources/findomain.txt`
- All agents run concurrently (§7.2a) within the §11.5 budget; per-agent failure → §4.3 retry + degraded-continue; streaming append (anew-style) per tool file on resume.

PSV-4 ARCHIVES (parallel sub-step 4):
- `waybackurls <target>` AND `gau --subs <target>` (Wayback Machine + Common Crawl + AlienVault OTX + URLScan in one pass) → URL streams
- Fallback direct CDX: `curl "http://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey"` with backoff on 429/503 (archive.org throttles)
- URLs → hostname extraction (strip scheme/path/port/query) → scope-gate → `sources/archives.txt`

PSV-5 RECURSION LOOP (runs AFTER the first parallel sweep completes — every discovered host becomes a seed for its own sub-subdomains):
- New in-scope hosts from iteration N become seeds for iteration N+1: deeper dorks (`site:*.host`) via PSV-1, `%.host` crt.sh query via PSV-2, `assetfinder --subs-only <host>` + `subfinder -d <host>` via PSV-3, deeper GitHub dorks via PSV-7 → only NEW names kept, re-merged with attribution.
- Caps: `passive_recursion_depth` (dashboard-editable, default 2), `max_seeds_per_iteration` (dashboard-editable, default 100); stop when an iteration yields zero new in-scope hosts or a cap is hit (run marked PARTIAL with reason).

PSV-6 HTTPX-PROBE (final sub-step — liveness TAGGING ONLY, mirrors the FFUF-2 pre-probe semantics):
- Merged deduped candidate set (all PSV sources) → `httpx -l candidates.txt -silent -threads <t:200> -json` → tags each candidate `alive | dead` (status, title, tech). Tagging NEVER filters candidates out.
- NOTE: this is the ONLY passive sub-step that sends packets toward the target (light HTTP probe) — dashboard-toggleable (`passive_httpx_probe: on|off`, default on; when off, alive stays null). §11.4 breaker + §11.5 ceiling apply.

PSV-7 GITHUB-OSINT (user-approved; executes INSIDE the parallel sweep — appended after PSV-6 only to preserve append-only ordering):
- GitHub Search API (GITHUB_TOKEN, §9.2-d; multiple tokens → SEARCH-FORGE-style rotation): dork set from DORK FORGE GitHub templates (`"target.com"`, `"*.target.com" filename:.env`, `"target.com" password`, org/namespace patterns `@target`) across code/repo/gist endpoints; search-API rate limits (30 req/min per token) respected via backoff + reset-time awareness.
- Extraction: candidate hostnames (scope-gated) → `sources/github.txt`; matching file URLs archived to `logs/raw/passive/github/` for manual review — discovered secrets are REPORTED as findings, never bulk-downloaded or exploited.
- Self-growth: newly discovered hosts spawn deeper GitHub dorks (PSV-5 recursion feed).

PSV-8 IP-DISCOVERY (user-approved; appended after PSV-7 to preserve append-only ordering; executes INSIDE the parallel sweep; closes the WIDE "max IPs" gap for non-domain scope entries):
- Trigger: for every scope.yaml include that is a CIDR / IP range / ASN (pure-domain targets skip this sub-step).
- Censys hosts index (CENSYS_API_ID/SECRET): `censys search "ip:<CIDR>"` → per-IP hostnames + services → `sources/censys-cidr.txt`.
- Shodan (SHODAN_API_KEY): reverse DNS + `net:<CIDR>` queries → `sources/shodan-cidr.txt`.
- Quota-aware (SEARCH-FORGE-style backoff + key rotation); discovered hostnames pass the standard scope-gate into MERGE with attribution; discovered IPs are stored AS-IS (never hostname-gated) → `sources/cidr-ips.txt` and feed the host→IP plane (merged into DNSR-3's map inputs, §7.1 "max IPs").

Inputs: scope.yaml | SEARCH-FORGE engine pool + keys (§9.2-d) | RESOLVER FORGE output | provider keys (Censys, Chaos, Shodan, SecurityTrails, VirusTotal, GitHub, ...) | dashboard params (recursion depth, seeds cap, amass timeout, dork TTL, httpx threads, probe toggle, github token pool).
Tools: subfinder, amass, assetfinder, chaos, findomain, puredns, waybackurls, gau, httpx, curl+jq, certspotter/certstream (CT fallback), GitHub Search API client — all via tools.yaml adapter (images per §2.2); PSV-1–PSV-5 + PSV-7 containers need no `--network host` (pure third-party queries); PSV-6 uses host network for accurate probing.
Output schema (data.json): `{"schema_version":1,"module":"passive-recon","candidates":[{"host","sources":["subfinder","crtsh","github"],"alive":true,"tags":["dev"]}],"passive_ips":[{"ip","sources":[]}],"search_forge":{"engines_used":0,"cooldown":0,"isolated":0},"recursion":{"depth_used":1,"seeds_total":0},"counts":{"candidates":0,"alive":0}}`
Output paths: per-source raw → `recon/<target>/10_subdomains/passive/sources/` ; module artifacts → `recon/<target>/10_subdomains/passive/data.json` + `summary.md`
Failure handling: §4.3 per tool; branch independence (§7.2c) — any failed source never blocks the others; MERGE (§7.3) consumes whatever exists (degraded mode).

## 9. WEB DASHBOARD (CONTROL CENTER)
9.1 One `dashboard` service in the compose stack. Default stack: FastAPI backend + React/Vite SPA (swappable; keep the API contract clean). Binds `127.0.0.1:8080` by default, auth via `DASHBOARD_TOKEN`; docker.sock accessible ONLY to the backend.
9.2 Phase-1 panels:
  a) Tools — list from `tools.yaml`: enable/disable, per-tool flag overrides; WORDLIST REGISTRY editor — per-task checkbox selection of `wordlists.yaml` keys + SELECT-ALL per task group (§8 WORDLIST REGISTRY & DASHBOARD SELECTION).
  b) Results — categorized per module, schema-driven (§6.5), read directly from `recon/<target>/` (read-only; the dashboard never stores a second copy of results); "new since last run" diff badges + `diff.json` view (§6.6). GLOBAL RESULT FILTERS (apply to EVERY view, combinable): time range / run selection (§6.6 history), scope-based filtering (per scope.yaml includes/excludes), per-source attribution (which tool found it), tags (dev/stage/api/...), alive/dead, free-text search — filter state shareable via URL. SOURCE COVERAGE ANALYTICS (user-approved): per-source contribution counts (unique assets per tool), source-overlap stats (assets found by N sources), per-source uniqueness % — the operator sees which tools/keys actually pay off per target.
  c) Run Control — start (target + optional module selection), stop, resume; live per-module status from `state.json`; live log streaming; scheduler editor (§4.6).
  d) API Keys — add/edit/delete provider keys (e.g., SHODAN_API_KEY, CENSYS_API_ID, GITHUB_TOKEN, CHAOS_KEY, SERPER_API_KEY, BRAVE_API_KEY, GOOGLE_CSE_KEY, GOOGLE_CSE_CX); written to `.env`, never committed, values masked in UI after save; pipeline picks them up on the next run without restart.
  e) Settings — proxy URL (http/socks5) + Telegram bot token & chat ID + digest threshold & alert-filter rules (§4.7) + global CPU/RAM resource budget (§11.5), persisted to `dashboard/config.json` (gitignored, secrets masked in UI).
9.3 PROXY RULE: if a proxy is set → all active-scanning containers get `ALL_PROXY`/`HTTP(S)_PROXY` env; tools without native proxy support are wrapped with proxychains. Proxy reachability is checked at run start: set-but-unreachable → FAIL FAST with a clear error (never silently fall back to direct). Unset → direct connection, silently.
9.4 UI/UX STANDARD — CYBER-SECURITY THEME (user-mandated): every dashboard view renders in a professional dark cyber-security theme — dark palette with high-contrast status accents (alive/new/alert), monospace type for ALL technical values (hosts, IPs, ports, hashes, commands), data-dense tables with sortable columns + sticky headers, status/severity badges, collapsible raw-JSON inspector per asset, clean hierarchy with zero decorative noise. All module output (§6.2 data.json + summary.md) flows through this theme; views.yaml (§6.5) drives columns/ordering so theme application stays config-driven, uniform, and code-free.

## 10. REPORTING
10.1 Deliverables under `recon/<target>/90_report/` — human + machine, generated on run end and on demand from the dashboard:
  - `report.md` — executive summary (asset counts, attack-surface highlights, scope violations attempted), one section per module, pointers to each `data.json`.
  - `report.html` — same content rendered in the §9.4 cyber-security theme: filterable asset tables, per-module sections, diff badges.
  - Machine exports (on demand, per module or whole run): canonical `data.json` (always written), flat `export.csv` per asset class, full-run `export.json` bundle, PDF render of `report.html`.
10.2 PRECISION CONTRACT (user-mandated): every format is generated FROM the canonical `data.json` files only (§6.3 — raw tool stdout is never re-parsed), so all formats agree exactly. Every export embeds run timestamp + scope.yaml digest → any artifact is traceable to the exact run and the exact authorization state.
10.3 Language: everything in English (code, comments, logs, reports).

## 11. GLOBAL RULES
11.1 Secrets/API keys come from `.env` only (e.g., SHODAN_API_KEY, CENSYS_API_ID). Never hardcoded; `tools.yaml` references env vars.
11.2 Conservative concurrency + rate limits by default; an `--aggressive` flag may raise them, never remove them.
11.3 Wide ≠ reckless: deduplicate targets between modules; always run cheap checks before expensive ones.
11.4 STABILITY-FIRST CONTRACT (ethical pentest guarantee): a run must NEVER degrade target availability and must NEVER let a tool die silently. Per-target circuit breaker: monitor timeout/error ratio per module; ratio > 20% over a 60s window → auto-throttle (halve rate + threads); persists 2 consecutive windows → pause module + Telegram ANOMALY alert. The breaker is ALWAYS on — `--aggressive` raises caps but can never disable it. Load signal: also track per-host response-latency drift; sustained latency growth on a host → throttle that module even without errors (never heat up the target).
11.5 RESOURCE CEILING (limited host): total CPU/RAM budget is dashboard-editable (default: 2 GB RAM, 2 CPU cores; allowed up to 4 GB). The orchestrator AUTO-derives per-container limits (`--memory`, `--cpus`) from the budget × current concurrency — parallel passive modules SPLIT the budget. On low-memory conditions it automatically reduces concurrency BEFORE OOM can occur. The budget can never be exceeded.

## 12. SUPERVISOR AGENT — OPTIONAL OVERSEER (user-mandated: the tools MUST work without it)
12.1 AGENT-OPTIONAL PRINCIPLE: the pipeline is FULLY deterministic and runs standalone — `./recon.sh run <target>` needs NO LLM. The Supervisor Agent is an OPT-IN layer (dashboard toggle / `--agent` flag) used for debug, management, and recovery. Agent down → pipeline still works; pipeline down → the agent cannot substitute it.
12.2 ONE-COMMAND AUTONOMY: when enabled, the user issues ONE instruction ("info-gather *.example.com") → the agent owns the entire flow with zero further user input: validate scope → run pipeline → monitor → remediate → report.
12.3 SUPERVISION LOOP (exactly this order): orchestrator runs tools → DETERMINISTIC checks FIRST (exit code, schema-valid data.json §6.2, zero-result anomaly, state.json updated) → on failure §4.3 retry/fallback → STILL failing → agent engages: diagnose (stderr, logs, resource metrics, third-party status) → bounded remediation (≤ 3 attempts per module per run, actions from the remediation.yaml playbook) → fixed? continue : Telegram FAILED/ANOMALY alert (§4.7) with diagnosis + attempted-fixes list → run continues degraded or stops.
12.4 RESOURCE FRUGALITY (user-mandated): the agent is EVENT-DRIVEN, never polling — it wakes ONLY on exceptions or run end; healthy runs consume ZERO LLM calls. Diagnoses are batched (one call per failure cluster, not per event); every diagnosis is cached (same failure signature → replay the known fix, no re-consult); hard per-run budget `agent_max_llm_calls` (dashboard-editable, default 20) — exhausted → agent degrades to pure deterministic alerts.
12.5 remediation.yaml PLAYBOOK (config-driven, dashboard-editable — never hardcoded): known failure signatures → remediation actions, e.g., container OOM → halve concurrency + retry; resolver failures → refresh RESOLVER FORGE + retry; 403/quota on a third-party source → rotate key pool / mark engine COOLDOWN (PSV-0); corrupt/partial output → quarantine file + re-run module; flag drift vs tools.lock → re-pin + restart container.
12.6 AUTONOMY LEVELS (dashboard switch): `observe` (log-only) | `suggest` (propose fix, wait for user — DEFAULT for ACTIVE-branch actions) | `auto-fix` (apply ALLOW-LIST remediations autonomously — DEFAULT for PASSIVE-branch). User overrides at any time, per run or persistent.
12.7 GUARDRAILS (absolute): the agent may NEVER modify scope.yaml, NEVER disable or loosen the circuit breaker (§11.4), NEVER bypass the scope gate (§3), NEVER execute commands outside the engagement context, NEVER delete raw logs (append-only). Every agent decision + action is journaled to `logs/agent-journal.jsonl` and streamed live in the Run Control panel (§9.2-c).
