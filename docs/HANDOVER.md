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

- ACTIVE: `ffuf` (DNS bruteforce, FFUF-0) -> `dns-resolve` (DNSR-1) ->
  `ffuf-3` (dead-vhost misconfig lane) -> `port-check`.
- PASSIVE: `passive-recon` (PSV-0..PSV-8: search forge, crt.sh, subfinder/
  chaos, GitHub OSINT, alterx permutations, recursive subdomain expansion
  with depth + seed caps, Censys/Shodan IP discovery).

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

## 5. Notifications (D-protocol -- read this before touching notify.py)

Operator UX law: **the operator sets ONLY their Telegram user id.** The bot
token is platform provisioning (`.env` TELEGRAM_BOT_TOKEN, set once).

Receiver resolution precedence (highest wins):
1. target profile `notifications.telegram_chat`   (targets.yaml)
2. dashboard config `telegram.chat_id`            (global default)
3. `.env` TELEGRAM_CHAT_ID                        (deployment fallback)

`notifications.telegram_enabled: false` in a profile mutes that target
outright -- it beats every global default and every delivery path
(including injected senders). Per-target `digest_threshold` and
`watchtower_enabled` also win over global config.

Instant alert classes: NEW SUBDOMAIN (hosts) + NEWLY OPENED PORT (ports).
At/above the digest threshold one grouped DIGEST is sent instead of a
flood. `POST /api/notify/test` ("SEND TEST NOTIFICATION" button) sends one
harmless message to the RESOLVED receiver and returns a ledger whose
`reason` explains every skip (never silent). The chat id is never echoed.

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
  the token in localStorage per browser

## 13. Deferred roadmap (agreed, not built)

- C5: IP rotation on block + proxy pool (profile slots `proxy` /
  `rate_caps` already reserved and validated as empty mappings).
- C6: OWASP Top 10 + OWASP API Top 10 passive check modules.
- C7: self-improvement loop beyond the platform-learned wordlist
  (auto-tuning budgets from breaker telemetry).
- C8: v1.0.0 tag + history rewrite with SHA mapping table.

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
