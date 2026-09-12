# Security

This repository is an attack-surface watcher for domains you are authorized
to test. It does not ship exploits or exploit payloads.

## Reporting a vulnerability

Open a private GitHub security advisory on this repository, or contact the
owner. Do not file a public issue that includes tokens, scan artifacts, or
a third-party estate.

## Operator rules

- Never commit `.env`, `dashboard/config.json`, `dashboard/auth/*.sqlite`,
  or anything under `recon/`.
- Committed `scope.yaml` is the fixture allow-list only (`example.com` and
  the local e2e zone). Add real estates from the dashboard; do not push them.
- The C1 release gate (`ci/c1_release_gate.py`) blocks secret-shaped
  material, personal-data shapes, and non-fixture `scope.yaml` includes.
- Dashboard Python deps are pinned in `requirements.txt` and scanned with
  `pip-audit` on the release gate. The compose service drops capabilities
  and binds loopback; `docker.sock` is still required to spawn tool
  containers on this host.

Rotation and bind/auth details: [docs/security.md](docs/security.md).
