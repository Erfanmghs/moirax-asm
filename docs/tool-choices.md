# Tool choices (master prompt §5.1)

| Task | Tool | Image (tools.lock) | Rationale |
|---|---|---|---|
| B1 adapter probe | `echo` (busybox) | `busybox:1.36.1` | Official tiny image; prints named host tokens so the adapter→container→parser→data.json path is observable without touching a target. |
| B1 fallback profile | `echo-tool-fallback` / `echo-fail` | same busybox pin | Exercises §4.3 retry then registered fallback then degraded-continue. |
| ACTIVE DNS (registered, enabled in B2) | dnsx | `projectdiscovery/dnsx:v1.2.2` | Spec PRIMARY for DNS-RESOLVE; JSON (`-json`) and forged-resolver flags are named parameters. |
| ACTIVE DNS fallback | massdns | `c99tn/massdns:latest` | Spec-registered FALLBACK profile for dnsx (§4.3 / DNSR failure handling). |
| ACTIVE HTTP enum (registered, enabled in B2) | ffuf | `ghcr.io/ffuf/ffuf:v2.1.0` | Spec tool for FFUF-1/2; baseline flags assembled only from named settings. |
| ACTIVE port-check (registered, enabled in B2) | naabu | `projectdiscovery/naabu:v2.3.5` | Spec tool for PORT-CHECK; `-top-ports` / `-rate` / `-json` are named. |

B1 does not run FFUF, DNSR, or PORT-CHECK loops. Those tools are registered so swapping later is a `tools.yaml` edit, never a pipeline rewrite (§5.2).
