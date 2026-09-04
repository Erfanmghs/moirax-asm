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

### Compose

`docker compose config` was **not** executed: Docker is not installed on this Windows PATH or the default WSL distro. File `docker-compose.yml` is present; interpolation defaults were asserted equal to `tools.yaml` settings. Re-run `docker compose config` after the companion §0.5 sanity check (`wsl --version` → `docker run --rm hello-world` → `docker compose version`).

## Out of scope for B0 (intentional)

Adapter layer, pipeline engine, MERGE, modules, dashboard app, reporting, supervisor agent — later phases.
