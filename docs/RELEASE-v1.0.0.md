# Release v1.0.0 -- traceability manifest (C8)

This manifest is the C8 deliverable in its honest form: a versioned release
tag plus a complete milestone-to-SHA mapping table, backed by a full-history
security audit. It exists so that every capability claim in the README and
HANDOVER can be traced to the exact commit that shipped it, without
rewriting history.

## 1. What v1.0.0 contains

- B0 scaffold: scope gate, contracts, named-parameter assembly
- B1 adapter + orchestrator: PASSIVE||ACTIVE engine, merge with attribution
  and quarantine, circuit breaker with persisted pauses, run history + diff
- B2 acceptance: wordlist forge, misconfig_suspect, real-target T3,
  quarantine + restore T4 (4/4 tests PASS)
- B3 passive chain: FFUF-3 + DNSR-2 aggregate cap + PSV-0..PSV-8 orchestrator
- B4 port sweep: post-MERGE full-range scan with pacer + guarantee rules
- B5 notifications, B6 dashboard, B7 reporting, B8 agent (B protocol closed)
- C1 release security gate (R-1..R-5), C2 wordlist universe, C3 per-target
  profiles, C4 multi-target fleet, C5 IP rotation / proxy pool
- D-protocol + E1: Telegram receivers, token-pool rotation, operator UI,
  HELP panel, Persian purged project-wide
- Functional hardening round: 5 regression classes fixed + engine self-heal
  (transient selection replace-in-place law)
- verify_all.sh: Actions-independent local acceptance fleet (10 stages)
- C6 OWASP passive analyzer: OWASP Top 10 (2021) + API Top 10 (2023)
  zero-packet findings with disclosed coverage
- C7 selftune loop: branch budgets auto-tuned from budget-exhaustion
  evidence, bounded, ledgered, never below the committed base

## 2. Milestone -> SHA mapping table

| Milestone | Commit | Subject (short) |
|-----------|--------|-----------------|
| B0 scaffold | 6666164 | feat(b0): scaffold, scope gate, contracts |
| B1 orchestrator | 44d2148 | feat(b1): adapter & orchestrator |
| B2 ACCEPTANCE (4/4 PASS) | c6b3d0d | B2 ACCEPTANCE: official acceptance record |
| B3 first sub-step | 6b90eee | feat(b3): FFUF-3 + DNSR-2 aggregate cap |
| B3 passive chain | 5dfb44d | feat(b3): passive chain PSV-0..PSV-8 |
| B3 closure (F1..F10) | 3870ee8 | docs(evidence): B3 PASSIVE CHAIN CLOSED PASS |
| B4 port sweep | edaf115 | feat(b4): PORT-SWEEP order-4 post-MERGE |
| B4 closure (H-table) | 60651d5 | docs(evidence): B4 PORT-SWEEP CLOSED PASS |
| B5+B6+B8 closure | 8a16cb7 | docs(evidence): B5+B6+B8 CLOSURE RECORDS |
| B7 closure + B complete | c294ee9 | docs(evidence): B7 CLOSURE + B PROTOCOL FINAL |
| C1 release hygiene | ad4ea67 | chore(release): C1 release security hygiene |
| C2 wordlist universe | 6cb7454 | feat(release): C2 wordlist universe |
| C3 per-target profiles | 821ae29 | feat(release): C3 per-target settings profiles |
| C4 fleet | cc354b5 | feat(release): C4 fleet multi-target concurrent |
| D-protocol | a9f54fa | feat(D-protocol): telegram per-target redesign |
| D-protocol hardening | f3a717b | fix(D-protocol): pentest/e2e bearer literals |
| E1 operator UI + rotation | edc7538 | feat(E1): telegram receivers + rotation + HELP |
| Functional hardening 1/4 | b724e36 | fix(functional): deps before units + self-heal |
| Functional hardening 2/4 | cc0786e | fix(functional): SecLists root + G-Z5 align |
| Functional hardening 3/4 | e08eccb | fix(functional): SecLists clone relocation |
| Functional hardening 4/4 | 18fdb61 | fix(functional): operator-law transient accommodation |
| Local acceptance fleet | 347672e | feat(verify): verify_all.sh 10 stages |
| C6+C7+C8 release | (this commit) | feat(c6-c8): owasp-passive + selftune + v1.0.0 |

## 3. Full-history security audit (rewrite decision record)

Scope: every blob in every commit reachable from any ref (88 commits,
2094 unique blobs), scanned against the R-1 secret patterns, R-4 personal
data patterns, and the R-5 Persian/Arabic script rule.

Verdict:
- NO real secrets anywhere in history. All pattern hits are the release
  gate's own synthetic test fixtures and placeholder-law values
  (example-* tokens, masked proxy fixtures).
- NO personal email addresses: only example-domain fixtures.
- NO real GitHub PAT in any historical blob (verified by exact-match scan).
- Persian script exists in two historical files only (README.fa.md and
  docs/cursor-phase-prompts.txt), both already removed from the tree when
  the operator withdrew the waiver.

Decision: the destructive history rewrite named in the deferred roadmap is
NOT warranted for v1.0.0. The repository is private, the audit found zero
secrets, and rewriting 88 commits would invalidate every clone, the GHCR
sha-* image tags, and the evidence chains referenced by the acceptance
records -- pure risk with zero security benefit. The two historical
Persian files are documented here and stay confined to private history.
If the operator ever publishes or mirrors the repository, run a
filter-repo scrub limited to those two paths first, then re-issue tags.

## 4. Verification at tag time

- Unit suite: 308 tests, green in BOTH pytest and unittest-discover modes
- C1 release gate: VERDICT PASS (R-1..R-5)
- DAST battery: 18/18 (real HTTP attack surface)
- UI journey: 12/12 (real chromium, zero-to-report)
- Fleet preflights: 9/9 runnable locally as-is (test4 is WSL/docker-only
  by design, disclosed)
