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
