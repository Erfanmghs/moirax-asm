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
