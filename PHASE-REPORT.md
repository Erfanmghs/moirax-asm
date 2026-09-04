# PHASE-REPORT — B0 Scaffold & Contracts

Phase: **B0 — Scaffold & Contracts** (companion §4). Stopped here; B1 not started.

## What was built

- Repository skeleton per companion §3 (compose, CLI, seed configs, `schemas/`, forge dirs, gitignore for `recon/`, `scope.yaml`, `.env`, `dashboard/config.json`).
- `docker-compose.yml` skeleton: `dashboard` service, `./recon` → `/recon`, bind `127.0.0.1:8080`, docker.sock on the dashboard service only, compose profile `dashboard` so CLI never requires it.
- Authorization gate (master §3) at orchestrator entry: missing/empty/invalid `scope.yaml` prints setup instructions and exits **before** any container or network client is used. Candidates (host, URL, IP, CIDR) are checked against includes/excludes, RFC1918/loopback/link-local, and named cloud suffixes.
- `recon/<target>/` directory factory from named `recon_layout_dirs` (master §6.1 plus §8 output subdirs).
- `state.json` engine: `pending|running|done|failed`, timestamps, idempotent init, skip-`done` for resume.
- Formal JSON Schemas under `schemas/` for `assets.json`, `diff.json`, and every module `data.json` (ffuf, dns-resolve, port-check, port-sweep, passive-recon).
- `tools.lock` stub (dashboard image pin; digest empty until images are registered).
- Named parameters: every §8 / §3 / §9.1 / §11 default used by this phase is a key under `tools.yaml` → `settings` (master §5.6). Compose interpolation fallbacks match those same keys (`dashboard_image`, `dashboard_bind_host`, `dashboard_bind_port`, `recon_volume`).

## How to run

On WSL2 (operator host, master §2.7):

```bash
cp scope.yaml.example scope.yaml   # authorized test target only
chmod +x recon.sh
./recon.sh status
./recon.sh run example.com
./recon.sh status example.com
```

This Windows session invoked the same CLI via `python -m pipeline.cli` (equivalent to `./recon.sh`).

## Acceptance evidence

### (c) `./recon.sh status` on an empty workspace

```
status: empty workspace (no recon/ directory)
exit=0
```

No `scope.yaml` required. No Docker invoked.

### (a) missing / empty / invalid `scope.yaml` → setup instructions, zero network

`python -m pipeline.cli run example.com` with **no** `scope.yaml`:

```
scope.yaml is missing.
[setup instructions]
exit=2
```

Empty file → `scope.yaml is empty.` + same instructions, `exit=2`.

Invalid YAML/document → `scope.yaml missing engagement mapping.` + same instructions, `exit=2`.

`pipeline/` has no `docker`, `subprocess`, `socket`, `urllib.request`, or HTTP client imports. Gate failure cannot start compose or open sockets.

### (b) injected out-of-scope candidate → rejected + logged

With `scope.yaml.example` installed (`example.com` / `*.example.com`, exclude `out.example.com`):

```
./recon.sh run not-in-scope.org
out of scope: not-in-scope.org (host not in includes)
logged: recon/not-in-scope.org/logs/out_of_scope.log
exit=1
```

Log line:

```
2026-09-03T23:40:48Z	rejected	not-in-scope.org	host not in includes
```

Additional injections through the same `ScopeGate.enforce` path (module-facing API):

| candidate | result |
|---|---|
| evil.com | REJECT host not in includes |
| out.example.com | REJECT excluded host |
| 10.1.2.3 | REJECT RFC1918 not listed in includes |
| 127.0.0.1 | REJECT loopback not listed in includes |
| 169.254.1.1 | REJECT link-local not listed in includes |
| foo.cloudfront.net | REJECT cloud wildcard not explicitly authorized |
| https://evil.com/path | REJECT host not in includes |
| www.example.com | ALLOW |
| example.com | ALLOW |

Rejections appended to `recon/example.com/logs/out_of_scope.log`.

### In-scope factory + state

```
scope ok; workspace ready: recon/example.com
exit=0
```

`./recon.sh status` → all modules `pending`. Layout created: `00_scope`, `00_assets`, `10_subdomains/{ffuf,passive/sources}`, `15_vhosts/ffuf`, `20_dns/dnsx`, `30_ports/{naabu-light,naabu-full}`, `40_services`, `50_web`, `60_screenshots`, `90_report`, `history`, `logs/raw`, `sources`.

### Compose / operator environment (completed on WSL2 Linux FS)

Working copy (only): `/home/moirax/recon-pipeline`  
Windows-accessible path: `\\wsl.localhost\Ubuntu\home\moirax\recon-pipeline`  
The previous NTFS tree is backup only and is not the working copy.

Runtime choice: native Docker Engine inside the WSL2 Ubuntu distro (not Docker Desktop). Build code does not depend on which supported runtime is used (master §2.7).

Named parameter: `seclists_host_path` default `~/seclists`. Container mount: `${seclists_host_path}:/usr/share/seclists:ro` (compose `SECLISTS_HOST_PATH` + `SECLISTS_CONTAINER_PATH`). Consumer: FFUF-0 forge (B2). `~/seclists` files: 6253 (matched source).

`./recon.sh status`:

```
example.com: 2026-09-03T23:40:49Z [ffuf=pending, dns-resolve=pending, port-check=pending, passive-recon=pending, merge=pending, port-sweep=pending]
```

`docker version`:

```
Client: Docker Engine - Community
 Version:           29.8.0
 API version:       1.56
 Go version:        go1.26.8
 Git commit:        88096ef
 Built:             Thu Sep  3 21:50:20 2026
 OS/Arch:           linux/amd64
 Context:           default

Server: Docker Engine - Community
 Engine:
  Version:          29.8.0
  API version:      1.56 (minimum version 1.40)
  Go version:       go1.26.8
  Git commit:       3ce5872
  Built:            Thu Sep  3 21:50:20 2026
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          v2.3.4
  GitCommit:        db8809540e1a7a9da5d518876894933ff55692ab
 runc:
  Version:          1.5.1
  GitCommit:        v1.5.1-0-g8f2685a4
 docker-init:
  Version:          0.19.0
  GitCommit:        de40ad0
```

`docker compose version`:

```
Docker Compose version v5.5.1
```

`docker compose config` exit: `0`  
(Default config omits the `dashboard` profile. `docker compose --profile dashboard config` interpolates the seclists bind.)

```
name: recon-pipeline
services:
  dashboard:
    profiles:
      - dashboard
    command:
      - sleep
      - infinity
    environment:
      DASHBOARD_TOKEN: ""
    image: busybox:1.36.1
    networks:
      default: null
    ports:
      - mode: ingress
        host_ip: 127.0.0.1
        target: 8080
        published: "8080"
        protocol: tcp
    restart: unless-stopped
    volumes:
      - type: bind
        source: /home/moirax/recon-pipeline/recon
        target: /recon
        bind: {}
      - type: bind
        source: /home/moirax/seclists
        target: /usr/share/seclists
        read_only: true
        bind: {}
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
        bind: {}
networks:
  default:
    name: recon-pipeline_default
```

`docker run --rm hello-world` exit: `0`

```
Hello from Docker!
This message shows that your installation appears to be working correctly.

To generate this message, Docker took the following steps:
 1. The Docker client contacted the Docker daemon.
 2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (amd64)
 3. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.

To try something more ambitious, you can run an Ubuntu container with:
 $ docker run -it ubuntu bash

Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/

For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```

## Out of scope for B0 (intentional)

Adapter layer, pipeline engine, MERGE, modules, dashboard app, reporting, supervisor agent — later phases.

## Environment — wordlist map (pre-B1)

SecLists audited at `~/seclists` (container path `seclists_root` = `/usr/share/seclists`). Registry: `wordlists.yaml`. Named parameter source (master §5.6): `wordlists_registry` in `tools.yaml`; modules resolve **keys only** via `pipeline.wordlists.WordlistRegistry`. Content-discovery lists were not registered (companion §7 NARROW). Rejected as junk/wrong-shape: `dns-Jhaddix.txt` (`.`, `@`, `*`, binary), `tlds.txt` (leading-dot TLDs), `shubs-stackoverflow.txt` (URLs/CSV junk), `subdomains-top1million-full.7z` (archive), locale lists, `Discovery/Web-Content/**`.

Hygiene: `git check-ignore scope.yaml` → `.gitignore:5:scope.yaml`; `git ls-files` does not track `scope.yaml`. No gitignore change required.

| Task | Registry key | File (relative to `/usr/share/seclists`) | Entries (`wc -l`) | Role | Rationale |
|---|---|---|---:|---|---|
| DNSR-1 | `dns_fast_top5000` | Discovery/DNS/subdomains-top1million-5000.txt | 5000 | fast default | Cloudflare Radar top-5000 labels; compact DNS brute default. |
| DNSR-1 | `dns_fast_fierce` | Discovery/DNS/fierce-hostlist.txt | 2280 | fast | Classic Fierce hostname list for the short default set. |
| DNSR-1 | `dns_fast_services` | Discovery/DNS/services-names.txt | 1419 | fast | Service/product host labels, hostname charset only. |
| DNSR-1 | `dns_fast_deepmagic500` | Discovery/DNS/deepmagic.com-prefixes-top500.txt | 500 | fast | Short deepmagic prefixes; extra fast-default coverage. |
| DNSR-1 | `dns_exp_top20000` | Discovery/DNS/subdomains-top1million-20000.txt | 20000 | forge expansion | Radar 20k; not the fast default. |
| DNSR-1 | `dns_exp_top110000` | Discovery/DNS/subdomains-top1million-110000.txt | 110000 | forge expansion | Radar 110k hostname labels. |
| DNSR-1 | `dns_exp_bitquark` | Discovery/DNS/bitquark-subdomains-top100000.txt | 100000 | forge expansion | Bitquark ranked labels; too large for fast brute. |
| DNSR-1 | `dns_exp_namelist` | Discovery/DNS/namelist.txt | 151265 | forge expansion | Large DNS namelist of hostname labels. |
| DNSR-1 | `dns_exp_shubs` | Discovery/DNS/shubs-subdomains.txt | 484699 | forge expansion | Shub crawled subdomain labels. |
| DNSR-1 | `dns_exp_combined` | Discovery/DNS/combined_subdomains.txt | 653920 | forge expansion | Union of bitquark + shubs + Radar 110k. |
| DNSR-1 | `dns_exp_sortedcombined` | Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt | 102582 | forge expansion | Merged knock/dnsrecon/fierce/recon-ng labels. |
| DNSR-1 | `dns_exp_deepmagic50k` | Discovery/DNS/deepmagic.com-prefixes-top50000.txt | 49928 | forge expansion | Deeper prefixes; not for HTTP vhost. |
| DNSR-1 | `dns_exp_n0kovo` | Discovery/DNS/n0kovo_subdomains.txt | 3000001 | forge expansion | n0kovo 3M labels; expansion only. |
| DNSR-1 | `dns_exp_fuzzsubs1` | Discovery/DNS/FUZZSUBS_CYFARE_1.txt | 5605156 | forge expansion | CYFARE list 1; multi-million expansion. |
| DNSR-1 | `dns_exp_fuzzsubs2` | Discovery/DNS/FUZZSUBS_CYFARE_2.txt | 4850604 | forge expansion | CYFARE list 2; complementary expansion. |
| DNSR-1 | `dns_exp_trickest` | Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt | 1613291 | forge expansion | Trickest program host labels. |
| FFUF-0 | `dns_exp_combined` | Discovery/DNS/combined_subdomains.txt | 653920 | forge seed (default) | Primary upstream union for WORDLIST FORGE. |
| FFUF-0 | `dns_exp_bitquark` | Discovery/DNS/bitquark-subdomains-top100000.txt | 100000 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_exp_shubs` | Discovery/DNS/shubs-subdomains.txt | 484699 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_exp_top110000` | Discovery/DNS/subdomains-top1million-110000.txt | 110000 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_exp_top20000` | Discovery/DNS/subdomains-top1million-20000.txt | 20000 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_fast_top5000` | Discovery/DNS/subdomains-top1million-5000.txt | 5000 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_exp_namelist` | Discovery/DNS/namelist.txt | 151265 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_fast_fierce` | Discovery/DNS/fierce-hostlist.txt | 2280 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_fast_services` | Discovery/DNS/services-names.txt | 1419 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_fast_deepmagic500` | Discovery/DNS/deepmagic.com-prefixes-top500.txt | 500 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_exp_deepmagic50k` | Discovery/DNS/deepmagic.com-prefixes-top50000.txt | 49928 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_exp_sortedcombined` | Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt | 102582 | forge seed | Upstream subdomain list. |
| FFUF-0 | `dns_exp_n0kovo` | Discovery/DNS/n0kovo_subdomains.txt | 3000001 | forge seed | Deep expansion source. |
| FFUF-0 | `dns_exp_fuzzsubs1` | Discovery/DNS/FUZZSUBS_CYFARE_1.txt | 5605156 | forge seed | Deep expansion source. |
| FFUF-0 | `dns_exp_fuzzsubs2` | Discovery/DNS/FUZZSUBS_CYFARE_2.txt | 4850604 | forge seed | Deep expansion source. |
| FFUF-0 | `dns_exp_trickest` | Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt | 1613291 | forge seed | Program-inventory host labels. |
| FFUF-2 | `vhost_top5000` | Discovery/DNS/subdomains-top1million-5000.txt | 5000 | vhost default | Compact hostname list for Host-header fuzz. |
| FFUF-2 | `vhost_fierce` | Discovery/DNS/fierce-hostlist.txt | 2280 | vhost | Short hostname list for vhost probing. |
| FFUF-2 | `vhost_services` | Discovery/DNS/services-names.txt | 1419 | vhost | Service names as virtual-host labels. |
| FFUF-2 | `vhost_env` | Fuzzing/environment-identifiers.txt | 54 | vhost | Env identifiers (dev/staging/uat); not content-discovery. |

Named settings: `wordlists_registry`, `seclists_root`, `wordlist_forge_output`, `dnsr_1_wordlist_key`, `dnsr_1_fast_keys`, `dnsr_1_expansion_keys`, `ffuf_0_source_keys`, `ffuf_2_wordlist_key`, `ffuf_2_source_keys`. Defaults: DNSR-1 → `dns_fast_top5000`; FFUF-0 → `dns_exp_combined`; FFUF-2 → `vhost_top5000`.

---

# PHASE-REPORT — B1 Adapter & Orchestrator

Phase: **B1 — Adapter & Orchestrator** (companion §4). Stopped here; B2 not started.

## What was built

- Adapter (`pipeline/adapter.py`): `tools.yaml` load, command assembly only from named `{parameters}` + per-tool `flag_overrides`, pinned image from `tools.lock`, non-interactive `docker run --rm` with ceiling `--memory`/`--cpus`, recon volume mount, labels for stop. `--aggressive` multiplies named rate/thread caps; it cannot disable the breaker.
- Fallback profiles (§4.3): retry × `tool_retry_count` with exponential `retry_backoff_base_sec`, then registered `fallback` tool, then degraded-continue. Failures append to `logs/run.log` (module, tool, exit, stderr tail).
- Pipeline engine (`pipeline/engine.py`): PASSIVE tools in parallel ∥ ACTIVE tools sequential; branch time budgets `passive_branch_budget_sec` / `active_branch_budget_sec`; a crashed branch does not block the other; budget breach → PARTIAL, MERGE still runs. `./recon.sh run` resets module state (full pipeline); `resume` skips `done`.
- MERGE (`pipeline/merge.py`): union, exact host dedupe, attribution `passive|active|both`, merge-time scope re-validation (drops logged), wildcard/catchall quarantine into `assets.json.quarantine`. No confidence scores.
- Circuit breaker (§11.4): error ratio > `circuit_breaker_error_ratio` over `circuit_breaker_window_sec` → throttle (divide rate/threads by `throttle_divisor`); `circuit_breaker_bad_windows` consecutive windows → pause + Telegram `ANOMALY` (credentials unset → skip silently). Latency drift vs `canary_latency_multiplier` also throttles. Every throttle/pause emits a `breaker` line in `logs/run.log` with `errors=N/T`, window `[start,end)`, `throttle_factor`, and reason. Pause is **persisted** in `state.json` under `breaker.paused.<module>` and survives process exit; subsequent runs skip paused modules with a `skip:` log line until `./recon.sh reset-breaker <target>`.
- Run-level status (§4.7 / §6.6): `state.json` carries `run:{status,reason,failing_module,updated_at}`. Terminal statuses and CLI exit codes:

| status | CLI exit |
|---|---|
| `completed` | `0` (`exit_code_completed`) |
| `failed` | `1` (`exit_code_failed`) |
| `anomaly` | `2` (`exit_code_anomaly`) |
| `partial` | `3` (`exit_code_partial`) |
| `stopped` | `4` (`exit_code_stopped`) |

  `runs.json` entries use the same status strings. A breaker pause classifies the run as `anomaly` (never `completed`).
- Resource ceiling (§11.5): `resource_budget_ram_mb` (capped by `resource_budget_ram_mb_max`) and `resource_budget_cpu_cores` split across current concurrency; host `MemAvailable` de-concurrencys before OOM when `/proc/meminfo` exists.
- History (§6.6): `runs.json` row, `history/<UTC-timestamp>/` snapshot of `data.json` + `assets.json`, `diff.json` with `added|removed|changed` per hosts/vhosts/ports/services/passive_ips. First-run diffs use empty baseline + `baseline:"none"`.
- Fake echo-tool family in `tools.yaml` (busybox pin). dnsx→massdns fallback profile registered (enabled false until B2). Tool rationale: `docs/tool-choices.md`.
- CLI: `./recon.sh module <name> <target>`, `--aggressive`, and `./recon.sh reset-breaker <target>`.

## How to run

```bash
cp scope.yaml.example scope.yaml   # authorized test target only
./recon.sh run example.com
./recon.sh status example.com
./recon.sh reset-breaker example.com   # clear persisted module pauses
python -m pipeline.verify_b1
```

On this Windows session, Docker Engine is reached as `wsl -e docker` when `docker` is not on the Windows PATH (operator host is WSL2, master §2.7). Volume bind uses `/mnt/<drive>/...`.

## Acceptance evidence

### Fake echo-tool: adapter → container → data.json

`python -m pipeline.verify_b1` with real Docker (`busybox:1.36.1` pulled):

```
echo-path: ok docker=True assets ['api.example.com', 'mail.example.com', 'www.example.com'] exit 0
```

Container argv (named `echo_passive_hosts` / `echo_active_hosts`): `echo www.example.com mail.example.com evil.com` and `echo www.example.com api.example.com`. Artifacts: `recon/example.com/logs/raw/echo-tool/data.json`, `logs/raw/echo-tool-active/data.json`, `10_subdomains/passive/sources/echo-tool.txt`. Docker run included `--memory` / `--cpus` (ceiling plan 4-way: `512m` / `0.5`).

MERGE master list (`00_assets/assets.json`):

| host | attribution |
|---|---|
| www.example.com | both |
| mail.example.com | passive |
| api.example.com | active |
| evil.com | dropped + `logs/out_of_scope.log` (`host not in includes`) |

FFUF / DNS-RESOLVE / PORT-CHECK / PORT-SWEEP remain `pending` (not B1). `merge=done`.

Fallback: `echo-fail` (3 failing attempts) → registered `echo-tool` → `fallback: ok attempts 1 tool echo-tool`.

### Injected error rate trips the breaker → ANOMALY

Fake clock, 5 errors in window 0 → throttle (`throttle_factor=0.5`); 5 errors in the next `circuit_breaker_window_sec` window → pause + notify:

```
breaker: ok anomaly ('ANOMALY', 'echo-tool', 'error ratio exceeded circuit breaker windows')
```

Telegram send skipped (no `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`).

### Two-run diff: added / removed / changed

Synthetic history `20200101T000000Z` → `20200102T000000Z`:

```
diff: ok added ['new.example.com'] changed ['old.example.com']
```

Docker pipeline vs prior snapshot also wrote `recon/example.com/diff.json` (`added` api/mail/www, `removed` old/new from the synthetic snapshot, `changed` empty). `runs.json` appends timestamp, status, per-module counts. Snapshots under `history/<UTC-timestamp>/`.

Wildcard/catchall MERGE check: hosts sharing wildcard IP `203.0.113.10` → `quarantine` reason `catchall`.

## Out of scope for B1 (intentional)

FFUF-0/1/2 loops, RESOLVER FORGE, DNSR-1/2/3, PORT-CHECK, PASSIVE PSV-0…8, PORT-SWEEP, dashboard app, reporting formats, supervisor agent.

## Stop

B1 complete. Do not start B2 until this phase is accepted.

---

# B1 ACCEPTANCE — OFFICIAL TESTS 1-3

All runs under `recon/example.com/` (and `history/`) so far are **TEST runs with fixtures** on the authorized target `example.com` — keep them as evidence; no pointer breakage.

- **T1 PASS** — fake-tool happy path (`echo-probe` adapter→container→data.json). Mid-test `write_diff` first-run crash (`prev=None` + `_empty_classes` lists) fixed in `pipeline/history.py` (empty-map baseline + `baseline:"none"`).
- **T2 FAIL → REM2 → PASS** — injected errors tripped breaker (throttle→pause+ANOMALY), but ANOMALY was in-process-only, `runs.json` said `completed`, CLI exit 0. Remediation 2: persist `state.json` `run` + `breaker.paused`, classify `anomaly`, exit codes, transition logs, `./recon.sh reset-breaker <target>`.
- **T3 PASS** — two-run history/diff taxonomy: RUN A restored probe host (`added`); RUN B `probe2` vs `probe` (`added`+`removed`); RUN C same host with `ips` (`changed` before/after). Note: `fqdn` is also used as a host key by MERGE (`hosts[].fqdn or host`), so `fqdn=alt.probe2.example.com` additionally appeared under `added` — host-row `changed` detection compares full `assets.json` rows (host/ips/alive/attribution/sources), not raw tool `fqdn` alone.

### Exit-code mapping

| status | CLI exit |
|---|---|
| `completed` | `0` |
| `failed` | `1` |
| `anomaly` | `2` |
| `partial` | `3` |
| `stopped` | `4` |

### Fixture note

`echo-probe` removed after T3. `echo-tool` / `echo-tool-fallback` / `echo-tool-active` / `echo-fail` remain as `# TEST FIXTURE (verify_b1)` until B2 cleanup. Test run data under `recon/example.com/` retained.

