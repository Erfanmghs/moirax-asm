# API KEY INVENTORY — what the pipeline consumes, where, and what happens without it

The pipeline is **keyless-first**: every keyed capability is an OPTIONAL
enhancement layered over keyless defaults, and every absent key degrades
honestly (explicit skip line in `run.log` + summary, never silent). This was
acceptance-proven on a real public target in the B3 closure run (run #28:
crt.sh, subfinder, amass, assetfinder, findomain, waybackurls, gau, CDX and
duckduckgo all keyless).

**How to install a key:** copy `.env.example` to `.env` (repo root,
gitignored) and fill the values. Keys are picked up on the NEXT run — no
restart needed (§9.2-d). A comma-separated value forms a POOL: per-request
rotation with per-key quota tracking (§8 PSV-0). All CI dispatches inject
keys the same way (GitHub Secrets → `.env`).

## Search engines — PSV-0/PSV-1 (SEARCH-FORGE pool)

| Engine | Key(s) | Free tier | Without key |
|---|---|---|---|
| duckduckgo | — (keyless, priority 50) | n/a | default engine — works |
| google-cse | `GOOGLE_CSE_KEY` + `GOOGLE_CSE_CX` | 100 queries/day | engine disabled, disclosed |
| serper | `SERPER_API_KEY` | 2,500 credits | engine disabled, disclosed |
| brave | `BRAVE_API_KEY` | 2,000 req/month | engine disabled, disclosed |
| serpapi | `SERPAPI_KEY` | 100 searches/month | engine disabled, disclosed |
| yandex-xml | `YANDEX_XML_KEY` + `YANDEX_XML_USER` | free tier | engine disabled, disclosed |

Block handling (PSV-0, acceptance-tested with a simulated 429): 429/403 or
captcha → engine COOLDOWN (exponential backoff + jitter) with instant reroute
to the next healthy engine; >20% errors over 60s → ISOLATED.

## OSINT agents — PSV-3

| Agent | Key | Without key |
|---|---|---|
| subfinder / amass / assetfinder / findomain | — (keyless) | always run |
| chaos (ProjectDiscovery) | `CHAOS_KEY` | agent skipped, disclosed |

## Archives — PSV-4 (all keyless: waybackurls, gau, direct CDX fallback)

## GitHub OSINT — PSV-7

| Key | Rate | Without key |
|---|---|---|
| `GITHUB_TOKEN` (pool) | 30 req/min rotation | sub-step SKIPPED, disclosed |

## IP discovery — PSV-8

Activates ONLY when `scope.yaml` carries CIDR/range/ASN includes (pure-domain
targets skip per spec) **and** the provider key is present.

| Provider | Key(s) | Without key |
|---|---|---|
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | provider skipped, disclosed |
| Shodan | `SHODAN_API_KEY` | provider skipped, disclosed |

## Port plane — B4 PORT-SWEEP

**No external APIs by design.** naabu (SYN full range) and the optional
nmap -sV second stage (toggle OFF by default — designated VA hook) are pure
network scanners driven by the forged resolver fleet and the pacer; there is
nothing to sign up for.

## Notifications — B5 (optional)

| Key | Purpose | Without key |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` | end-of-run summary + instant new-asset alerts (two separate types, same credentials) | skip silently (§4.5) |

## Dashboard — B6

| Key | Purpose |
|---|---|
| `DASHBOARD_TOKEN` | auth for the FastAPI/React control center (bind 127.0.0.1:8080) |

## Reserved slots (registered, wired in a later phase)

`SECURITYTRAILS_API_KEY`, `VIRUSTOTAL_API_KEY` — harmless if set today; they
are reserved for future source integrations and are listed here so the
operator can provision them in advance.
