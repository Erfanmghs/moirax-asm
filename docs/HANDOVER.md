# recon-pipeline -- Engineering Handover Document

Version: 1.0 (D-protocol). Audience: the next engineer taking ownership of
this repository. Everything here is ASCII English; the release gate (R-3)
enforces that discipline for the whole tree.

The one-paragraph pitch: recon-pipeline is an attack-vector detection
platform. It enumerates a target's DNS estate (passive OSINT + active
bruteforce), resolves hosts, probes virtual hosts, sweeps ports, diffs every
run against the previous one, raises Telegram alerts on genuinely new
findings, and produces tamper-checked reports -- all driven by a FastAPI
operator dashboard with a per-target settings model, a multi-target fleet
runner, and a security posture that is continuously attacked by its own CI.

---

## 1. Sixty-second orientation

```
recon-pipeline/
  recon.sh                 # the ONLY entrypoint you normally touch
  pipeline/                # orchestrator + all engine modules (python)
    engine.py              #   module ladder execution + state machine
    adapter.py             #   command assembly from tools.yaml params
    breaker.py             #   latency/error circuit breaker
    scope.py               #   ScopeGate: every host checked against scope
    modules/               #   one file per module (ffuf, dns-resolve, ...)
    fleet.py               #   C4 multi-target concurrency
    target_profiles.py     #   C3 per-target settings (closed allow-list)
    notify.py              #   Telegram fan-out (D-protocol resolution chain)
    wordlists.py           #   wordlist registry (merge law)
    seclists_sync.py       #   C2 full-SecLists index builder
    custom_lists.py        #   C2 custom + platform-learned lists
    reporting.py           #   B7 report bundle + tamper check
    logstore.py            #   gzip rotation + retention + total cap
    agent.py               #   B8 supervisor agent (opt-in)
    cli.py                 #   recon.sh subcommand implementations
    verify_b1.py           #   FROZEN: byte-identical, never edit
  dashboard/               # FastAPI backend + vanilla JS SPA
    app.py                 #   HTTP surface (thin routes only)
    service.py             #   all business logic (pure, unit-tested)
    static/                #   index.html / app.js / theme.css
  ci/                      # per-vehicle assertion suites + pentest/journey
  tests/                   # atomic unittests (run with pytest)
  .github/workflows/       # CI vehicles (see section 11)
  tools.yaml               # master settings: params, modules, breaker, budgets
  wordlists.yaml           # per-task registry + selection
  scope.yaml               # includes/excludes (ScopeGate law)
  targets.yaml             # C3 per-target profiles (operator-managed)
  docs/                    # api-keys.md, tool-choices.md, this document
```

## 2. Non-negotiable laws (break these and the CI will (correctly) bite you)

1. **Never-silent**: every module outcome is recorded. A skipped source
   prints WHY. No silent degradation, ever. Vocabulary: module status is
   `done | failed | pending` (terminal) plus `disclosed` for sanctioned
   anomalies.
2. **Scope law**: ScopeGate checks every host against scope.yaml. The
   suffix-trick attack (`evil-target.com` pretending to be `target.com`) is
   rejected. Live-registry wordlist keys are re-validated at apply time.
3. **Acceptance vehicles are frozen**: `pipeline/verify_b1.py` must remain
   byte-identical (waivered in the R-3 gate). The b2/b3 fixtures and their
   assertion scripts are historical acceptance evidence -- extend, never
   rewrite.
4. **Closed allow-lists everywhere**: per-target profile sections, settings
   keys, tool-edit keys, API-key names, artifact-viewer extensions. Unknown
   keys are REFUSED, never merged.
5. **Secrets never enter the tree**: R-1 scans every file (placeholder law:
   fake-looking values only). `.env` is gitignored. Dashboard config masks
   the bot token on read. The pentest battery proves it with a planted
   canary.
6. **ASCII English only** (R-3): no smart quotes, no em-dashes, no box
   drawing, no non-Latin script anywhere in the tree (frozen waivers
   excepted). This includes workflow comments and test docstrings.
7. **Atomic tests with every behavior change**: the suite (240+ units) is
   the contract. New law = new test.

## 3. Execution model

`./recon.sh run <target>` walks a module ladder in two branches:

- ACTIVE: `dns-resolve` (dnsx brute + IPs + optional httpx length/tech) ->
  `ffuf` (vhost Host-header enum) -> `ffuf-3` (dead-name vhost) ->
  `port-check` (optional top-ports preview, default OFF). Full TCP 1-65535
  runs after MERGE on every resolved IP (`portsweep_scope: all_resolved`).
- PASSIVE: `passive-recon` (PSV-0..PSV-8 plus keyless HTTP APIs: HackerTarget,
  Anubis, OTX, urlscan; SecurityTrails/VirusTotal if keys are set).

Each module runs inside its own Docker container (ffuf v2.1.0 image,
passive-tools image). The orchestrator talks to docker through
`pipeline/dockerbin.py`. State lives per target:

```
recon/<target>/
  00_assets/assets.json    # canonical merged asset index
  <NN_module>/data.json    # each module's canonical artifact
  runs.json                # run history ledger
  diff.json                # added/removed/changed vs previous run
  state.json               # live run state (status per module)
  logs/run.log             # live log (streamed by the dashboard)
  logs/agent-journal.jsonl # supervisor agent decisions (append-only)
  90_report/               # B7 bundle: md/html/csv/json/pdf + manifest
```

Transient overrides (vehicle pattern): a run may apply BEFORE-copies +
targeted text edits to control files, then restore byte-identically. The
same discipline appears in C3 profile application and fleet member baking.

## 4. Configuration dialects

- `tools.yaml` -- master settings resolved through `pipeline/params.py`
  (`Params.require("key")`). Tool blocks carry enabled/branch/image_ref/
  params/flag_overrides. `tools.lock` is optional.
- `wordlists.yaml` -- tasks (FFUF-0, DNSR-1, FFUF-2, ...) each list fast/
  expansion/sources groups + `selection:`. The registry merge law: curated
  entries win; registry-wide tasks additionally offer the generated
  SecLists index + custom lists (C2).
- `scope.yaml` -- `includes:`/`excludes:` with wildcards; the suffix trick
  is rejected by ScopeGate.
- `targets.yaml` -- C3 profiles. FILE dialect wraps sections under
  `settings:`; the API dialect (PUT /api/targets) takes sections at TOP
  level. Sections: wordlist_selection, budgets, modules, notifications,
  proxy (C5 slot), rate_caps (C5 slot). Validate -> text-write, frozen
  loader must always parse.
- `dashboard/config.json` -- gitignored settings persistence (telegram,
  proxy, digest, alert rules, agent, retention, resource budget). CLOSED
  key allow-list; masked secrets on read.
- `.env` -- provider keys + DASHBOARD_TOKEN + optional telegram fallbacks.
  Picked up on the next run WITHOUT restart.

## 5. Notifications (D-protocol v2 -- read this before touching notify.py)

Operator UX law: **the operator sets ONLY their Telegram username or user
id.** Bare handles (`jackjohns`) normalize to `@jackjohns`; numeric ids pass
through unchanged. The bot token is platform provisioning
(`.env` TELEGRAM_BOT_TOKEN) and accepts a comma-separated POOL: when a token
is rejected (HTTP 401) the send path marks it invalid in-process and rotates
to the next pool entry inside the same send (operator directive: the tool
must replace a broken token with its replacement without human help).
Rejected tokens are never echoed; the ledger names token indexes only.

Receiver resolution precedence (highest wins):
1. target profile `notifications.telegram_chat`   (targets.yaml)
2. dashboard config `telegram.chat_id`            (global default)
3. `.env` TELEGRAM_CHAT_ID                        (deployment fallback)

Username-shaped receivers consult a LEARNED MAP (`telegram.receiver_map` in
dashboard config): `learn_receiver_map()` calls getUpdates once and maps
username -> numeric chat id for every account that pressed START on the bot
(personal-account handles cannot be messaged by @name directly -- Bot API
limitation -- so the learned numeric id is used; public channel/group
handles deliver directly). Learning is network-free at resolve time and
happens only in the send path; it retries once after a chat-not-found
failure, so "press START, then SEND TEST again" works in one click.

`notifications.telegram_enabled: false` in a profile mutes that target
outright -- it beats every global default and every delivery path
(including injected senders). Per-target `digest_threshold` and
`watchtower_enabled` also win over global config.

Instant alert classes: NEW SUBDOMAIN (hosts) + NEWLY OPENED PORT (ports).
At/above the digest threshold one grouped DIGEST is sent instead of a
flood. `POST /api/notify/test` ("SEND TEST NOTIFICATION" button) sends one
harmless message to the RESOLVED receiver and returns a ledger whose
`reason` explains every skip (never silent) plus a human `hint` with the
next step for the four failure shapes (401-pool-exhausted / chat-not-found /
network / 429). Receivers and tokens are never echoed.

Fleet members: `targets.yaml` is part of fleet CONTROL_FILES, so each
member root resolves ITS OWN per-target receiver.

## 6. Per-target profiles (C3)

`pipeline/target_profiles.py`. Closed allow-list: unknown sections are
rejected; budgets keys allow-list; notification keys allow-list; telegram
chat ids must match the injection-safe regex (digits, optional minus, or
@name). Applying a profile = transient text edits to tools.yaml /
wordlists.yaml with before-copies + byte-identical restore. Wordlist
selections are validated against the LIVE registry at apply time
(unregistered key -> ProfileError) and never stack on an existing
selection block.

## 7. Fleet (C4)

`pipeline/fleet.py`. Members come from the targets registry ("all") or an
explicit comma list (strict name law -- no silent lowering). Every member
gets an ISOLATED root (control files + dirs copied, empty recon tree,
profile BAKED into its tools.yaml/wordlists.yaml BEFORE the run) and runs
`./recon.sh run <target>` as a subprocess with its own state/breaker/
caches. Global concurrency is capped by `fleet_max_concurrency` (default
3, clamp 1..8) plus a cross-process lockfile counter (GlobalSlots) so two
fleet invocations cannot oversubscribe a runner. One member failing never
stops the others; the fleet ledger (history/fleet/<ts>/fleet-ledger.json)
records every member exit; fleet exit is 0 iff every member completed
clean (partial counts as success-with-disclosure).

## 7b. IP rotation / proxy pool (C5)

`pipeline/ip_rotation.py`. Pool resolution chain (most specific wins):
1. tools.yaml settings `proxy_pool` -- per-target profiles reach this through
   the SAME transient top-level-key edit mechanics as budgets (value written
   as a json.dumps-quoted YAML scalar),
2. dashboard config `proxy_pool` (SETTINGS panel field),
3. no pool -> the legacy single `proxy_url` gate path, byte for byte.

Laws: scheme allow-list http/https/socks5 (parse_pool, ValueError names the
bad entry); fail-fast gate health-checks EVERY entry before the first module
(engine + /api/run/start|resume through `gate_pool_or_legacy`) and sanitizes
the checker's own reason (raw entry with credentials must never surface);
PER-REQUEST rotation (C5 v2): assignment happens inside Adapter._attempt_loop,
one pool entry PER ATTEMPT (the first try AND every retry take the next entry
-- not one per module invocation), so a failing entry is naturally abandoned
on the next attempt; tools WITHOUT the `when: proxy_url` hook (naabu, dnsx,
...) run DIRECT and the ledger says so ONCE -- honesty law. Ledger:
logs/proxy-rotation.json (never-fail write, masked `user:***@host:port` via
mask_proxy, `attempt` number on every row). IP HEALTH TELEMETRY (C5 v2):
every proxied attempt records its exit-code outcome per entry; entries with
>= 3 consecutive failures are SKIPPED while a healthy entry remains; when ALL
entries are unhealthy the plain round-robin continues (never stall, never
raise); telemetry persists per target at logs/proxy-health.json -- MASKED
keys only, 500-event ring, corrupt state ignored + rewritten (never-fail,
selftune class); seeded at run start by `assigner.load_health(target_dir)`
and flushed next to the ledger by `write_health` + `health_lines` stdout.
Proxy-hooked tools today: ffuf, ffuf-vhost, httpx, httpx-passive
(-x / -http-proxy). Per-target profile key: `proxy.proxy_pool` (closed
allow-list PROXY_KEYS_ALLOW, scheme-validated). Tests:
tests/test_c5_rotation.py (33 laws incl. per-attempt rotation via
ScriptedRunner + health skip/heal/never-stall/cross-run/corrupt-state).

## 8. Dashboard

FastAPI (`dashboard/app.py` -- thin routes) + pure logic
(`dashboard/service.py`) + zero-build vanilla JS SPA. Bind 127.0.0.1:8080
(compose maps the same). EVERY /api route except /api/health requires
`Authorization: Bearer <DASHBOARD_TOKEN>`; unset token = 503 fail-closed.

Panels: TOOLS (enable/disable + flag overrides + wordlist registry),
TARGETS (per-target profiles incl. per-target Telegram id), FLEET (members,
concurrency, run + ledger), RESULTS (filters, coverage analytics, diff),
REPORTS (bundle generate + tamper check + viewer links), RUN CONTROL
(start/stop/resume, scheduler, live log, agent journal), API KEYS (masked
.env management), SETTINGS (proxy, Telegram user id, digest, alert rules,
agent autonomy, retention, resource budget).

Hardening baked in (proven by the pentest battery):
- security headers on EVERY response: nosniff / DENY / no-referrer /
  no-store; strict CSP (script-src 'self', frame-ancestors 'none') on the
  SPA. No inline script/style -- the CSP is real, not decorative.
- OpenAPI/docs/redoc DISABLED (no attacker map).
- Target names on run/start|stop|resume and fleet/notify routes must pass
  the strict name law BEFORE any spawn (flag/traversal/metachar injection
  refused with 422).
- Settings writes: closed key allow-list (P-10), typed validation.
- Artifact viewer: traversal-confined to recon/<target>/ with an extension
  allow-list.
- API-key values masked everywhere; .env canary never appears in any
  response (P-13 sweep).

## 9. Security posture

Two CI layers attack the platform continuously:
- `c1-release-gate` (R-1..R-5): secret-material scan with placeholder law,
  bandit SAST (high=0 hard, medium disclosed), ASCII tree, personal-data
  scan, script defense. Runs on every push.
- `security-pentest` (dispatch-only): P-1..P-18 DAST battery against a
  REAL uvicorn boot (unauthenticated enumeration, bearer tampering,
  fail-closed boot, traversal, static confinement, extension law, header
  law, recon-surface disabled, spawn gate, settings/profile/wordlist
  injection, canary sweep, XSS reflection, method abuse, oversized
  payloads, content-type confusion, post-attack stability) + pip-audit
  (disclosed). Report artifact: pentest-evidence.

Accepted risks (documented, localhost-bound): no rate limiting (bearer +
loopback bind), dashboard token is a single shared bearer (per-user accounts
deferred), telegram delivery failures are disclosed but not retried.

## 10. UI E2E

`ui-e2e` (dispatch-only) boots the dashboard from a DISPOSABLE control-tree
copy and drives REAL chromium through the whole operator journey (J1..J12):
landing + auth, tool toggle + wordlist save, per-target profile with
Telegram id, persistence across reload, fleet surface, results + filters +
coverage + diff, report generate + tamper check, run control + scheduler,
API keys masked, settings + honest SEND TEST ledger, XSS probe inert,
unauthorized guidance. Screenshots: ci/ui-e2e-screens/. The journey found
and fixed a real bug (task-scoped wordlist save) -- extend it whenever you
add a capability.

## 11. CI vehicles (token frugality)

| vehicle | trigger | purpose |
|---|---|---|
| c1-release-gate | push | R-1..R-5 release hygiene |
| c2-wordlists | dispatch | real-SecLists registry proof (C2-1..C2-8) |
| c4-fleet | dispatch | two passive-only members concurrently |
| b2..b8 suites | dispatch | historical acceptance evidence |
| e2e-fixture | dispatch | containerized deterministic E2E |
| live-validation | dispatch | REAL-target E2E vs operator estate |
| security-pentest | dispatch | P-1..P-18 battery + pip-audit |
| ui-e2e | dispatch | chromium journey 0-100 |

Token law: workflows use the runtime GITHUB_TOKEN (permissions:
contents: read) -- the platform itself NEVER consumes the operator's PAT.
Dispatch-only triggers exist precisely to burn zero minutes on push. When
driving CI from outside (dispatching, polling, fetching artifacts), batch
your calls: one push per work batch, poll at 5+ minute intervals with
per_page=1, download artifacts once at adjudication.

PAT hygiene (operator): fine-grained PAT, least scopes (Contents RW,
Actions R, Metadata R), short expiry, rotate BEFORE expiry; store in the
secret manager of your choice, never in the repo (R-1 enforces).

## 12. Recipes

- Run the suite: `python -m pytest tests/ -q`
- Local gates: `python ci/c1_release_gate.py`
- Boot the dashboard: `DASHBOARD_TOKEN=... python -m uvicorn dashboard.app:app --port 8080`
- Register a wordlist: `./recon.sh wordlist-add <name> <file>`
- Index full SecLists: clone SecLists, then `./recon.sh wordlist-sync`
- Per-target settings: `./recon.sh target-profile set <target> <json-file>`
  or the TARGETS panel
- Fleet run: `./recon.sh fleet run --targets all --concurrency 3`
- Telegram: set your numeric id in SETTINGS (or per-target in TARGETS),
  provision TELEGRAM_BOT_TOKEN in .env, press SEND TEST NOTIFICATION
- Rotate DASHBOARD_TOKEN: compose env -> restart dashboard; the SPA stores
  the token in sessionStorage per browser tab

## 13. Deferred roadmap (agreed, not built)

- C5: IP rotation / proxy pool -- FULLY DELIVERED including the last two
  refinements (C5 v2, per-request rotation + IP health telemetry): one pool
  entry PER ATTEMPT (first try + every retry rotate), per-entry outcome
  telemetry with health-aware skipping (>= 3 consecutive failures skipped
  while a healthy entry remains; all-unhealthy never stalls), masked 500-
  event telemetry persisted per target at logs/proxy-health.json, seeded
  across runs and ignored when corrupt. See section 7b for the full law set.
  THE DEFERRED ROADMAP IS NOW EMPTY -- the agreed scope is 100% delivered.
- C6: OWASP Top 10 + OWASP API Top 10 passive check modules -- DELIVERED
  (single `owasp-passive` module, `pipeline/modules/owasp_passive.py`):
  post-MERGE zero-packet artifact analyzer (same hook law as PORT-SWEEP:
  resume-aware, breaker-aware, partial markers). Reads assets.json +
  raw httpx probe rows + PORT-CHECK/PORT-SWEEP results; emits
  `70_owasp/data.json` + `70_owasp/summary.md` with 7 evidence-backed
  finding classes (A05 banners, A05 misconfig_suspect, A05/API8 management
  ports, A02 cleartext, A06 versioned tech, API3/API1 api-named surface,
  A01/API6 admin-named surface). Honesty laws: severity capped at medium,
  review_required always true, every finding cites its evidence file, and
  items that CANNOT be assessed passively (injection, auth, rate-limit
  classes) are DISCLOSED under coverage.not_passively_assessable -- never
  silently skipped. Params: owasp_module/owasp_data_json/owasp_summary/
  owasp_risk_ports/owasp_api_words/owasp_admin_words (tools.yaml) + layout
  dir 70_owasp. Tests: tests/test_c6_owasp.py (16 atomic laws incl. the
  zero-packet adapter contract).
- C7: self-improvement loop beyond the platform-learned wordlist
  (auto-tuning budgets from breaker telemetry) -- DELIVERED
  (`pipeline/selftune.py`): end-of-run hook observes the run's REAL budget
  signals (passive_budget / active_budget exhaustion markers) and writes
  bounded per-branch budget multipliers for the NEXT run of the same target
  (80_selftune/tuning.json + capped ledger). Growth x1.25 on a marker, decay
  x0.9 toward 1.0 after 2 clean runs, clamped to [0.5, 2.0], never below the
  committed base; module failures never move budgets (breaker owns module
  health, section 11.4); toggle selftune_enabled=false disables read AND
  write; corrupt state ignored and rewritten (never-fail, never-flip).
  Start-of-run hook applies the multipliers through engine._tuned_budgets.
  Tests: tests/test_c7_selftune.py (12 atomic laws).
- C8: v1.0.0 tag + history rewrite with SHA mapping table -- DELIVERED in
  its honest form: annotated v1.0.0 tag + docs/RELEASE-v1.0.0.md
  (milestone-to-SHA traceability table) backed by a FULL-HISTORY audit
  (88 commits / 2094 blobs): zero real secrets, zero personal data; the two
  historical Persian files are the only withdrawn-waiver artifacts and stay
  confined to private history. The destructive rewrite was REJECTED with
  evidence (breaks clones, GHCR sha tags, evidence chains; zero security
  benefit on a private repo) -- if the repo is ever published, scrub those
  two paths with filter-repo first, then re-issue tags.

## 14. Glossary

- **vehicle**: a workflow + assertion pair that proves one capability.
- **disclosed**: a sanctioned, recorded deviation (never silent, never a
  crash).
- **before-copy**: snapshot taken before transient edits; restore must be
  byte-identical.
- **member root**: a fleet member's isolated copy of the control tree.
- **platform-learned list**: passive-discovered in-scope subdomains
  auto-appended to wordlists/custom/platform-learned.txt (C2), selectable
  like any list.
