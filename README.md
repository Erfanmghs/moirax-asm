# ATTACK VECTOR DETECTION PLATFORM

> **recon-pipeline · control center** — a scope-gated, breaker-protected, fully
> acceptance-tested reconnaissance & attack-surface detection platform.
> Zero-network scope enforcement, keyless-first intelligence gathering,
> wildcard-aware merge, paced port sweeping, Telegram alerting, a cyber-themed
> operator dashboard, tamper-evident reporting, and a deterministic supervisor
> agent — all driven by one command or entirely from the browser.

![status](https://img.shields.io/badge/protocol-B0..B8%20ALL%20CLOSED%20PASS-34d399) ![tests](https://img.shields.io/badge/unit%20suite-163%2F163-22d3ee) ![verify_b1](https://img.shields.io/badge/verify__b1-diff%20EMPTY-34d399)

---

## 1. What it is

`recon-pipeline` enumerates an **authorized** target's external attack surface:
subdomains, virtual hosts, live HTTP endpoints, open ports and service
banners — then merges everything into canonical `data.json` assets, diffs them
against the previous run, alerts on what changed, and renders a tamper-checked
report bundle. It was built through a frozen acceptance protocol (**B0..B8**)
where every stage was executed and proven on real GitHub Actions vehicles —
every claim in this README is backed by a run record (see §9).

Everything is enforced in code, not convention:

- **Scope is law.** The zero-network scope gate runs on the host *before any
  container starts*; excludes always win; out-of-scope hits are hard failures
  (`ANOMALY`), never warnings.
- **Honesty is law.** A missing API key prints an explicit skip line and
  degrades — never silently. A degraded run is labeled `partial`/`anomaly`
  with the failing module named. GROWTH-0 is a legitimate result.
- **Never-fail auxiliaries.** Notifications, reporting and storage housekeeping
  are wrapped so they can *never* flip a run verdict.

## 2. Feature matrix

| Capability | What you get |
|---|---|
| **Passive chain (PSV-0..PSV-8)** | SEARCH-FORGE multi-engine dorking (keyless DuckDuckGo default, keyed engines activate per key), CT-log / OSINT agent / archive harvesting, GitHub OSINT (token pool @ 30 req/min), recursion, httpx probing, IP discovery (CIDR/range/ASN via Censys/Shodan) |
| **Active branch** | DNSR wordlist forging (registry-driven, SecLists materialization), dnsx resolution against a pinned anycast resolver fleet, FFUF-3 vhost discovery with explosion guards, wildcard/catchall-aware MERGE |
| **Port sweep (order-4)** | naabu full+sweep profiles behind a deterministic pacer (exact `pps=1` guarantee proven), nmap `-sV` service fingerprinting on survivors |
| **Merge engine** | source attribution per asset, tag derivation, IP dedup, wildcard/catchall rejection, scope re-check |
| **Notifications (B5)** | Telegram instant alerts (new subdomain / newly opened port), digest above threshold, dashboard-editable alert rules, self-monitoring (`FAILED`/`ANOMALY`/`STOPPED`), never-fail never-silent ledger |
| **Scheduler** | state-machine driven recurring runs, 10-minute floor enforced at every layer, `scheduler.json` editable from the dashboard |
| **Dashboard (B6)** | zero-build cyber-theme SPA + FastAPI: run control, tools editor, wordlist registry, results/filters/coverage analytics, reports, API keys, settings — schema-validated writes everywhere |
| **Reporting (B7)** | `report.md` / `report.html` / `export.csv` / `export.json` / `report.pdf` rendered **from canonical `data.json` only**, cross-format count equality, SHA-256 manifest + tamper/scope-drift check |
| **Supervisor agent (B8)** | opt-in, deterministic-first remediation playbook (5 signatures + closed allow-list), autonomy levels per branch, LLM budget + cache, append-only journal, guardrails in code |
| **Storage management** | run-end housekeeping: history retention, gzip log rotation with size caps, per-target total cap (§6) |
| **CI acceptance rig** | 10 workflows, preflight gates, per-stage assertion tables, evidence artifacts, REM remediation ladder — the pipeline tests *itself* on every vehicle run |

## 3. Quickstart

### 3.1 Dashboard-first (recommended — zero commands)

```bash
git clone https://github.com/Erfanmghs/recon-pipeline && cd recon-pipeline
cp .env.example .env                    # set DASHBOARD_TOKEN (+ optional keys)
echo "dashboard/config.json: /dev/null" # created on first settings save
docker compose --profile dashboard up -d --build
```

Open `http://127.0.0.1:8080`, paste your `DASHBOARD_TOKEN` top-right, then:

1. **API KEYS** — set/clear provider keys (masked after save, picked up next run, no restart).
2. **SETTINGS** — proxy, Telegram bot token + chat/user id, digest threshold, alert rules, supervisor agent, resource budget, storage retention.
3. **RUN CONTROL** — enter the target, press **START**. Live log + module status + agent journal stream in the browser.
4. **RESULTS** — filter/share URLs, diff badges, per-source coverage analytics.
5. **REPORTS** — **GENERATE NOW** → open `report.html`/`report.pdf` straight from the browser.

You never have to touch a terminal again; the CLI (below) remains the advanced path.

### 3.2 CLI (one command each)

```bash
./recon.sh run example.com              # full pipeline (passive -> merge -> port sweep)
./recon.sh resume example.com           # resume from state.json
./recon.sh status example.com           # module/status overview
./recon.sh report example.com           # regenerate the report bundle
./recon.sh module ffuf3 example.com     # single module
./recon.sh reset-breaker example.com    # clear a paused breaker
./recon.sh info-gather example.com      # §12.2 one-command autonomy (agent on, run -> monitor -> remediate -> report)
```

### 3.3 Test fixture (vhosts + nested subdomains, no internet needed)

```bash
docker compose -f docker-compose.yml -f docker-compose.vhost-fixture.yml \
  --profile vhost-fixture up -d --build
sudo -n python3 docker/vhost-fixture/hosts.py install
./recon.sh run fixture-target.test      # see §8 for the full E2E fixture
```

## 4. The dashboard

Panels (all schema-validated writes, fail-closed `DASHBOARD_TOKEN` auth):

| Panel | Controls |
|---|---|
| **TOOLS** | enable/disable tools, per-tool named flag overrides (§5.6), wordlist registry selection per task |
| **RESULTS** | global filters (free-text, source, tag, alive, run, scope in/out) with **URL-shareable state**, diff badges (`+hosts/+ports/−hosts/−ports`), per-source coverage analytics (contribution, uniqueness %, overlap histogram) |
| **REPORTS** | bundle status + tamper verdict, on-demand generation, artifact table with SHA-256 + in-browser OPEN |
| **RUN CONTROL** | START / RESUME / STOP, live module status, streaming `run.log` tail, streaming agent journal, scheduler editor |
| **API KEYS** | registry-driven key inventory (module + fallback behavior), set/replace/delete, masked after save |
| **SETTINGS** | proxy (set-but-unreachable **fails fast**, §9.3), Telegram bot token + chat/user id, digest threshold, alert filter rules, supervisor agent (enabled / autonomy / budget), resource budget (CPU/RAM), storage retention |

Theme: dark cyber palette, monospace technical values, sticky sortable tables,
status badges, collapsible JSON inspectors — zero decorative noise.

## 5. The pipeline in one diagram

```
scope gate (zero-network, host-side, excludes win)
      │
      ▼
PSV-0 SEARCH-FORGE ─ PSV-1 dorks ─ PSV-3 CT/OSINT ─ PSV-6 archives
      │        (key-pool rotation, per-key quota, honest skips)
      ▼
PSV-2/4/5 recursion ─ PSV-7 GitHub OSINT ─ PSV-8 IP discovery
      │
      ▼  passive_data.json  (00_assets)
MERGE ◄── DNSR forged wordlist ── dnsx (pinned fleet) ── FFUF-3 vhosts
      │   wildcard / catchall rejected, sources + tags attributed
      ▼  merge_data.json
PORT-SWEEP  naabu full → sweep (pacer, pps=1) → nmap -sV survivors
      │
      ▼  ports_data.json  +  history/<stamp>/ snapshot  +  diff.json
NOTIFY (instant + digest, never-fail)   REPORT (md/html/csv/json/pdf, manifest)
      │                                        (every terminal status)
      ▼
AGENT (opt-in, deterministic playbook)          LOGSTORE (retention+rotation+cap)
```

## 6. Storage management (logs can't eat your disk)

Housekeeping runs at **every run end** (never-fail) and is editable in
**SETTINGS → STORAGE / LOG RETENTION** (`dashboard/config.json retention.*`
overrides `tools.yaml` defaults):

| Knob | Default | Meaning |
|---|---|---|
| `keep_runs` | 20 | newest `history/<stamp>/` snapshots kept, older pruned (timestamp-named dirs only — anything else is immune) |
| `log_max_mb` | 10 | `logs/run.log` rotation cap → gzip-9 archive + live file truncated in place |
| `journal_max_mb` | 5 | `logs/agent-journal.jsonl` rotation cap |
| `log_keep_gz` | 3 | archives kept per log (name-scoped pruning) |
| `max_total_mb` | 1024 | hard cap per target: oldest snapshots first, then archives; **data.json, runs.json, state.json, diff.json, 90_report/ and live logs are never touched** |

## 7. Technical tricks worth knowing

- **Breaker with latency baseline + drift throttle.** Baseline from the first
  batch; drift throttle 1 → 0.5 → 0.25 → 0.125 (qps 1000 → 125); error-ratio
  breaker trips to `force_pause` → run `ANOMALY`, exit 2. Third-party flakiness
  is absorbed, not propagated.
- **Resolver forge + canaries + quarantine.** A pinned 15-resolver anycast
  fleet with per-batch canary validation; transient override support; poisoned
  IPs are quarantined deterministically (TEST-4 proven) while the fleet stays
  healthy.
- **Key-pool rotation.** Comma-separated env values form a key POOL with
  per-request rotation and per-key quota tracking (SEARCH-FORGE, GitHub OSINT);
  values are never logged.
- **Keyless-first degradation.** Every keyed path has a documented keyless
  fallback; missing keys produce explicit skip lines and are visible in
  coverage analytics — proven on the B3 vehicle.
- **Wildcard-aware merge.** Wildcard/catchall detection before attribution;
  mixed-case 404 probes; stall-tolerant httpx probing (stalls never become
  alive).
- **FFUF-3 explosion guard.** Dead-name probe cap per run (`ffuf3_max_dead_probes`)
  with an explicit truncation marker — never silent.
- **Exact port pacing.** The pacer guarantees the requested pps (unit-proven
  `pps=1`), batching-aware, stage-scoped to the port-sweep lane.
- **Canonical-data precision (§10.2).** Reports render from `data.json` only;
  cross-format count equality is unit-pinned; the manifest re-collects and
  rejects tampered data or scope drift.
- **Agent guardrails in code.** The remediation allow-list contains no
  scope/breaker/log actions; the journal is append-only; zero LLM calls by
  default (deterministic playbook is the knowledge base; budget 20 + cache).
- **verify_b1 diff-empty discipline.** The B1 integrity gate's diff must stay
  empty across every commit — checked in CI preflight on every vehicle run.

## 8. Testing the platform itself

- **Unit suite** — 163/163 (`python3 -m unittest discover -s tests`).
- **B2 vhost fixture** — `docker-compose.vhost-fixture.yml`: wildcard vhost
  HTTP server with stall rules (P1.1), prefixed vhost allow-list (R4.1),
  ffuf-UA awareness — the B2 acceptance vehicle.
- **Full E2E fixture** (`ci/e2e-fixture.yml`, workflow_dispatch): local DNS
  server + multi-port web/TCP server (`80/8080/8443-TLS/2222/9200/6379`) with
  vhosts and **nested subdomains 4 levels deep** under `fixture-target.test`;
  the full pipeline (passive → merge → port sweep → report) runs against it
  and the assertion table proves discovery, probing, port detection and
  reporting end to end.

## 9. The B protocol — every feature was acceptance-tested

Each stage shipped with a preflight gate + assertion table executed on a real
GitHub Actions vehicle (evidence committed under `PHASE-REPORT.md`):

| Stage | Scope | Vehicle verdict |
|---|---|---|
| B0–B1 | bootstrap, params, scope gate, integrity gate | TEST 1–4 PASS (`c6b3d0d`) |
| B2 | resolver fleet + wordlist forge + quarantine/restore | TEST 4 PASS (`0fe2ae0`) |
| B3 | passive chain PSV-0..8 + FFUF-3 + DNSR-2 + MERGE | F-table 10/10 (run #28) |
| B4 | port sweep + pacer | H-table 8/8 (run #30) |
| B5 | notifications + scheduler | I-table 8/8 (run #35) |
| B6 | dashboard | J-table 8/8 (run #33) |
| B7 | reporting bundle | K-table 8/8 (run #38) |
| B8 | supervisor agent | L-table 8/8 (run #37) |

REM ladder (REM4→REM24) documents every harness defect found and fixed on the
way — assertions were fixed against real evidence, the frozen pipeline never
changed to satisfy a test.

## 10. API keys (keyless-first)

Copy `.env.example` → `.env` or manage keys from **API KEYS** in the dashboard.
Comma-separated values form rotated pools. Without a key every module degrades
honestly (explicit skip, never silent). Full matrix with per-key fallback
behavior: **[docs/api-keys.md](docs/api-keys.md)**.

## 11. Legal

Run only against targets you are **authorized** to test. `scope.yaml` is the
single source of truth for includes/excludes; the gate is enforced before any
container starts and re-checked at merge. Unauthorized use is prohibited.

## 12. Project layout

```
pipeline/        engine, modules, breaker, forge, merge, notify, agent, logstore, reporting
dashboard/       FastAPI app + zero-build cyber-theme SPA
docker/          per-tool images + vhost fixture
ci/              preflight gates, assertion tables, acceptance harnesses
docs/            api-keys.md, tool-choices.md
wordlists/ resolvers/ dorks/ schemas/    registries + forge assets
.github/workflows/   10 acceptance workflows (b2..b8 + e2e)
PHASE-REPORT.md      full B0..B8 acceptance evidence
```
