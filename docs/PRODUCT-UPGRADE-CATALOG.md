# Product upgrade catalog (future work)

Audience: product owner and the next engineer. ASCII English only (R-3).

This file is the backlog of capabilities the platform **could** grow into,
collected from the current product (README, HELP, HANDOVER) and from
comparable tools in the External Attack Surface Management (EASM) and
self-hosted recon-dashboard category.

It is **not** an implementation plan and **not** an approval. Cursor may
propose; only the operator approves (companion change-management). Frozen
operator decisions in section 3 stay rejected unless the operator reopens
them in writing.

Compared tools (open source and commercial, 2025-2026):

- Self-hosted dashboards: reNgine, AutoBB, Reconner, Open-ASM, ASM-,
  Reconator, bounthunt, Palisade
- CLI orchestrators: reconFTW, Osmedeus, ProjectDiscovery suite
  (subfinder, httpx, naabu, nuclei, notify, katana, dnsx)
- Commercial EASM / web: Cortex Xpanse, Microsoft Defender EASM, Detectify,
  Intruder, CyCognito, HailBytes ASM, Censys, CrowdStrike Falcon Surface,
  Tenable ASM

---

## 1. Product identity (keep this when picking items)

The platform is a **night watchman for websites the operator owns**:

- enumerate DNS estate (passive OSINT + active brute + permutations)
- resolve, vhost probe, port check + optional full sweep
- diff every run; Telegram on genuinely new findings
- tamper-checked reports; FastAPI dashboard; per-target profiles; fleet
- zero API keys required (skips disclosed, never silent)
- OWASP Top 10 + API Top 10 **passive** analysis on already-collected
  evidence (zero extra packets; severity capped at medium)

It is **not** a DAST scanner, not an internet-wide radar, and not a SOC
replacement. Items below are tagged:

| Fit | Meaning |
|---|---|
| WATCHMAN | Strengthens the current product. Prefer these. |
| EXPAND | Useful, but grows scope (more moving parts, more legal surface). |
| IDENTITY-SHIFT | Turns the product into reconFTW / Detectify / Xpanse. Build only if the owner wants a new product. |
| FROZEN | Operator already rejected or listed as DO-NOT-BUILD. |

---

## 2. Already shipped (do not re-propose)

| Area | What exists today |
|---|---|
| Discovery | Passive chain PSV-0..PSV-8, dnsx/massdns, alterx, ffuf vhost, httpx enrich |
| Ports | PORT-CHECK (top ports, IP-centric) + PORT-SWEEP + optional nmap -sV toggle |
| Diff + alerts | Run diff, digest threshold, Telegram per-target inherit/override/mute, bot token pool rotation |
| Reports | HTML, PDF, CSV, JSON, Markdown + SHA-256 tamper manifest |
| Ops | Scheduler, fleet concurrency, per-target profiles, proxy pool with health + rotation ledger |
| Honesty | ScopeGate, never-silent skips, closed allow-lists, circuit breaker, quarantine |
| Lists | SecLists index, custom lists, platform-learned list, wordlist forge |
| Self-tune | Bounded budget multipliers from exhaustion evidence |
| Passive risk | C6 owasp-passive post-MERGE |
| UI | Dark SPA: targets, run control, results, reports, settings, API keys, HELP |
| Auth | First-run password, idle session (separate auth DB) |
| Packaging | Docker Compose dashboard profile, GHCR image |

README section 10 items already marked DELIVERED: proxy rotation (C5),
OWASP passive (C6).

---

## 3. Frozen / do-not-build (unless the operator reopens)

From the companion guide and historical operator decisions:

| ID | Decision | Why it stays out |
|---|---|---|
| F1 | NARROW phase (deep fingerprint / content discovery as a pipeline phase) | Deferred by design; do not scaffold |
| F2 | Full VA (vulnerability assessment) module | Only the nmap -sV hook exists; VA is future-by-design, not Nuclei-by-default |
| F3 | Confidence scoring inside MERGE | Explicitly rejected; never add weights in merge |
| F4 | Quiet-hours scheduling | Rejected; duration-budgeted pacing replaces it |
| F5 | Shared subs.txt across passive tools | Forbidden; MERGE needs per-tool sources |
| F6 | Raw HTML scraping of Google/Bing | Forbidden; SEARCH-FORGE only |
| F7 | Agent as a pipeline component | Agent is opt-in supervisor; zero LLM on a healthy run |
| F8 | History rewrite of git | Rejected in C8; private-repo audit found no secrets |

IDENTITY-SHIFT items in section 5 (Nuclei, DAST, credential brute, internet
seedless discovery) overlap F1/F2. Treat them as **catalogued, not queued**.

---

## 4. WATCHMAN backlog (best fit for this product)

Priority inside this section is **value for a site owner**, not star count
on GitHub. IDs are stable so later chats can say "build U12".

### 4.1 Operator experience and team

| ID | Capability | Seen in | Notes |
|---|---|---|---|
| U1 | Extra alert channels: Slack, Discord, email, generic webhooks | README wish 6; notify; HailBytes; AutoBB SMTP | Keep Telegram as primary. Same payload/digest laws. Do not reopen notify.py design in a frozen warehouse chat; new channel adapters as approved modules. |
| U2 | Several user accounts + roles (viewer / operator / admin) | README wish 8; reNgine RBAC; HailBytes | Replaces the single shared login. Audit: who started which run, who changed which setting. |
| U3 | Language switch on the dashboard (e.g. Persian) | README wish 7 | UI strings only; tree and reports stay ASCII unless operator waives R-3 for i18n resource files. |
| U4 | One-file / one-script installer for a fresh server | README wish 9 | Git+Docker still required; script wraps clone, .env, compose up. |
| U5 | Charts over time (hosts, open ports, new/gone per week) | README wish 5; Open-ASM; Xpanse | Read existing run history; no new scan traffic. |
| U6 | Risk ranking for **watchman** findings (new host, newly open port, OWASP-passive hit) | README wish 4 | Must **not** be MERGE confidence scores (F3). Rank **after** merge, on the results/report view. |
| U7 | One-click "add this new name to future checks" | README wish 3 | ScopeGate still wins; never auto-expand scope without a click. |
| U8 | Alert templates (what text is sent, per severity / per target) | AutoBB; notify | Closed allow-list of placeholders; no raw HTML injection. |
| U9 | Rate limiting on the dashboard HTTP surface | HANDOVER accepted risk | Today: bearer + loopback, no rate limit. Needed if bind is ever non-loopback. |
| U10 | Telegram inbound commands (`/status`, `/report`) | zwanski-style C2 | Optional. High abuse surface; keep send-only unless approved. |
| U11 | Retry failed Telegram deliveries (bounded) | HANDOVER accepted risk | Failures today are disclosed, not retried. |
| U12 | Dashboard i18n of HELP panel from the same HELP.md | reNgine docs UX | Generate or split locale files; do not fork laws. |

### 4.2 Visibility, history, and reports

| ID | Capability | Seen in | Notes |
|---|---|---|---|
| U13 | Executive one-pager vs technical annex in the same bundle | Raven/EASM reports; HailBytes | Same tamper manifest; two HTML/PDF views. |
| U14 | Diff-only report ("what changed since last run") as a first-class export | bounthunt | RESULTS already badges "new"; export that slice. |
| U15 | Asset inventory screen (host, IPs, ports, last seen, first seen) | AutoBB webui; Open-ASM | Query warehouse/history without a new scan. Warehouse module is frozen for drive-by edits; design a read API first. |
| U16 | Technology column from httpx `-td` as a first-class filter | ASM- WhatWeb; httpx | Data may already exist in enrich; surface it. |
| U17 | TLS certificate expiry / issuer as a **read of handshake metadata** (no exploit) | ASM- TLS audit (subset) | EXPAND if it needs extra probes; WATCHMAN if httpx already captured it. |
| U18 | Screenshot gallery of live HTTP (gowitness / EyeWitness) | ASM-; reconFTW | EXPAND: extra containers, disk, privacy. Scope-gated URLs only. |
| U19 | WHOIS / ASN / registrar panel per apex | ASM- | Passive where possible; disclose when APIs missing. |
| U20 | Compare two historical runs, not only last-vs-previous | commercial EASM | Run picker on RESULTS. |
| U21 | CSV/JSON schema version + changelog so BI tools do not break | HailBytes exports | Version the export contract. |

### 4.3 Discovery and watch quality (still watchman)

| ID | Capability | Seen in | Notes |
|---|---|---|---|
| U22 | Subdomain takeover **check** (dangling CNAME / known fingerprints), no exploit | reconFTW; nuclei dns takeover templates | Opt-in module; disclose false-positive class; ScopeGate. |
| U23 | Certificate Transparency as an always-on passive source (if not already in PSV) | Defender EASM narrative; crt.sh | Disclose skip; no HTML scrape of search engines (F6). |
| U24 | Cloud / SaaS surface names (S3-shaped, Azure blob, GCP) **in-scope only** | CyCognito-style shadow IT (tiny subset) | Never seedless internet search. |
| U25 | Dead DNS + vhost hit already tagged `misconfig_suspect` -- operator playbook in HELP | already in glossary | Docs + RESULTS filter, not new scanning. |
| U26 | Filtered-host and tarpit suspect views (`filtered_suspect`, `anomalous_open_suspect`) | glossary | UI/report only. |
| U27 | Resolver and wordlist forge telemetry on a dashboard card | internal | Operators see quarantine counts without opening logs. |
| U28 | Optional httpx screenshot-less "title + status" timeline | AutoBB http_probes | History of title changes as a diff class (phishing/defacement hint). |
| U29 | Directory / backup-file **opt-in** content discovery | ffuf/ferox in reconFTW; F1 NARROW | Catalogued as EXPAND. Conflicts with F1 unless operator reopens NARROW as a **named opt-in module**, not a hidden phase. |
| U30 | Permutation / dnsgen-style alts already via alterx -- expose a dashboard intensity preset | AutoBB `--dns-alts` | Presets on closed allow-list, not free-form flags. |

### 4.4 Reliability and scale

| ID | Capability | Seen in | Notes |
|---|---|---|---|
| U31 | Distributed workers (Axiom / remote scanners) | reconFTW; Open-ASM | EXPAND. Keep ScopeGate on the controller. |
| U32 | Postgres/Redis instead of file+sqlite for large fleets | reNgine; Open-ASM | Only if fleet size outgrows files. Auth DB stays separate from warehouse. |
| U33 | Prometheus `/metrics` | Reconator | Loopback or token-gated. |
| U34 | Pause / cancel between modules with clean PARTIAL | Reconator cancel | Align with existing STOPPED vocabulary. |
| U35 | Resume from checkpoint after host reboot | reconFTW checkpoints | Engine already has resume-aware hooks; make operator-visible. |
| U36 | Health dashboard for tool images (tools.lock digest drift) | companion glossary | Supervisor already remediates; show it in UI. |
| U37 | Backup/restore of targets, profiles, and report bundles | enterprise EASM | Exclude secrets or encrypt. |
| U38 | Air-gapped / zero-egress mode (passive-only from cached sources) | Sn1per zero-egress narrative | Honest: many PSV sources need internet. |

---

## 5. IDENTITY-SHIFT catalog (do not treat as the default queue)

Build these only after an explicit product decision: "we are becoming an
offensive recon suite" or "we are becoming Detectify".

| ID | Capability | Seen in | Cost to identity |
|---|---|---|---|
| X1 | Nuclei / template CVE scanning | AutoBB, reconFTW, HailBytes | Leaves "zero extra packets after merge" story |
| X2 | Native DAST (XSS, SQLi, SSRF, ...) | Reconner, Detectify | Legal and breaker complexity; not a watchman |
| X3 | JavaScript analysis, secret mining, parameter discovery | Reconner, recon0 | NARROW-adjacent (F1) |
| X4 | OAST / collaborator callbacks | Reconner | Needs outbound infra you control |
| X5 | Credential brute (SSH/SMB/RDP) | Reconner | High harm; keep out of a site-owner watchman |
| X6 | Seedless internet-wide discovery | Xpanse, CyCognito, Censys | Different company, different data, different price |
| X7 | Automated remediation / ticketing | Xpanse | SOC product |
| X8 | Supply-chain / subsidiary mapping | IONIX, CyCognito | Needs third-party data |
| X9 | AI correlation / LLM finding chat on every run | Open-ASM, Raven, HailBytes | Conflicts with F7 unless strictly opt-in and off by default |
| X10 | MCP server exposing scan controls | HailBytes, Open-ASM | Attack surface on the dashboard |
| X11 | White-label MSSP / multi-tenant | HailBytes | RBAC (U2) first |
| X12 | Active OWASP exploitation to raise C6 severity above medium | Detectify | Contradicts C6 honesty laws |

---

## 6. Suggested waves (if the owner stays a watchman)

Wave order is a recommendation, not a schedule.

**Wave A -- promised in README section 10, still open**

1. U1 extra alert channels
2. U5 charts over time
3. U6 post-merge risk ranking (not MERGE scores)
4. U7 one-click watch-list growth
5. U2 multi-user + audit
6. U3 UI language switch
7. U4 one-file installer

**Wave B -- watchman depth without becoming Nuclei**

- U13-U16, U20 inventory and history UX
- U22 takeover **check** (opt-in, disclosed)
- U17 TLS metadata if already in httpx
- U11 Telegram retry
- U9 dashboard rate limit

**Wave C -- only with a written reopen**

- U18 screenshots
- U29 content discovery as a named opt-in (reopen F1 in a narrow form)
- F2 VA module using the existing nmap -sV hook (still not Nuclei unless X1 is approved)

---

## 7. Laws every upgrade must keep

Copy these into the change proposal:

1. Authorized targets only; ScopeGate on every new host and URL.
2. Never-silent: skips, PARTIAL, and "cannot assess" stay disclosed.
3. Closed allow-lists for new settings keys and profile fields.
4. Secrets never enter the git tree; mask in UI and logs.
5. ASCII English in the tree unless a documented waiver (i18n files).
6. Atomic tests + extend ui-e2e when the operator journey changes.
7. `app.js` element IDs stay stable.
8. Do not silently edit frozen files (`pipeline/verify_b1.py`, warehouse
   and notify while those lanes are frozen).
9. No exploit PoCs, malware, or attack procedures in docs or code.

---

## 8. How to use this file in a later chat

Proposal format (companion 8.1):

`[ID] + [what] + [why] + [WATCHMAN or EXPAND] + [files likely touched] + [risk]`

Example: `U5 charts: plot host counts from run history so owners see drift
without reading dumps. WATCHMAN. dashboard static + a read-only history
endpoint. Risk: none to scan traffic.`

When an ID ships, mark it DELIVERED here with the commit subject, the same
way HANDOVER section 13 records C5-C8.
