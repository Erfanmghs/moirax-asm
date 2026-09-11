# Security & Token Hygiene

Operational security reference for running and evolving the platform.
The engineering posture (headers, gates, closed allow-lists, pentest
battery) lives in docs/HANDOVER.md section 9; this file is about
CREDENTIALS and ACCESS.

## 1. Token inventory (who needs what)

| token | scope | lifetime | stored where |
|---|---|---|---|
| GitHub PAT (operator/automation) | fine-grained: Contents RW, Actions R, Metadata R on THIS repo only | short expiry (30-90 d) | secret manager / local credentials file, NEVER the repo |
| GITHUB_TOKEN (workflows) | injected at runtime, permissions: contents: read | per-job | n/a (GitHub-managed) |
| DASHBOARD_TOKEN | dashboard bearer | rotate at will | .env / compose env |
| TELEGRAM_BOT_TOKEN | bot provisioning | long-lived | .env (masked everywhere on read) |
| provider keys (SERPER/BRAVE/CENSYS/...) | per-provider | per-provider | .env via API KEYS panel (masked) |

The platform itself NEVER consumes the operator PAT: every workflow runs on
the runtime GITHUB_TOKEN with least permissions. The PAT is only used when
a human or automation drives GitHub from outside (dispatch, polling,
artifact fetch, push).

## 2. PAT frugality rules

1. One push per work batch (batch commits; do not push per commit).
2. Dispatch-only vehicles: nothing burns minutes or API calls on push
   except the release gate.
3. Poll run status at 5+ minute intervals, `per_page=1`, stop at terminal
   state; download each artifact exactly once at adjudication.
4. Reuse the local clone; one `git fetch` per work session.
5. Prefer the assertion suite locally before pushing (the push gates will
   run anyway -- arriving green is free, arriving red doubles the burn).

## 3. Rotation runbooks

### GitHub PAT (before expiry)
1. Create the new fine-grained token (same least scopes, owner-scoped to
   this repository, shortest expiry you can live with).
2. Update it in your secret manager / local git credential helper.
3. Revoke the old token immediately after the next successful push.
4. Confirm: `git fetch origin` works; a dispatch vehicle runs.

### DASHBOARD_TOKEN
1. Generate a high-entropy value (`openssl rand -hex 24`).
2. Update compose/.env and restart the dashboard container.
3. Re-enter the token in the SPA (top-right SET; stored in sessionStorage
   for the tab, not localStorage). Minimum length is 8 characters; prefer
   `openssl rand -hex 24`.

### TELEGRAM_BOT_TOKEN
1. Revoke via @BotFather (/revoke), get the new token.
2. `API KEYS` panel -> TELEGRAM_BOT_TOKEN -> save (masked; picked up next
   run without restart).
3. Press SEND TEST NOTIFICATION in SETTINGS to verify end-to-end.

## 4. Leak response

- The C1 release gate (R-1) blocks secret-shaped material from entering
  the tree; CI red = stop and rotate, do not "fix the gate" first.
- If a real credential ever lands in a commit: rotate the credential
  FIRST (rotation invalidates history), then rewrite history (C8 carries a
  SHA-mapping-table rewrite plan), then force-push in coordination with
  open PRs.
- Personal data (operator estate IPs, emails) is scanned for by R-4; the
  hunter patterns are runtime-assembled so the scanner itself carries no
  hunted literals.

## 5. Attacker-proofing stance

Assume the attacker can reach every byte of the repo (it is the
attacker's map problem -- so the map is minimized: OpenAPI disabled, no
debug endpoints) and can hold a dashboard token (so every write is
schema-validated, closed allow-list, spawn-gated). The pentest battery
(ci/pentest_dast.py, P-1..P-18) encodes this stance; extend it with every
new surface. Run it: `python ci/pentest_dast.py` (boots real servers on
loopback from a disposable root).
