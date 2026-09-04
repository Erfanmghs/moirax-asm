# Tool choices (master prompt §5.1)

| Task | Tool | Image (tools.lock) | Rationale |
|---|---|---|---|
| B1 adapter probe | `echo` (busybox) | `busybox:1.36.1` | Official tiny image; prints named host tokens so the adapter→container→parser→data.json path is observable without touching a target. Disabled in B2 (fixtures remain registered). |
| B1 fallback profile | `echo-tool-fallback` / `echo-fail` | same busybox pin | Exercises §4.3 retry then registered fallback then degraded-continue. |
| FFUF-1/2 | ffuf | `ghcr.io/ffuf/ffuf:v2.1.0` | Spec tool; baseline flags + optional `-x` from named `proxy_url`; JSON `-of json`. |
| FFUF-2 pre-probe | httpx | `projectdiscovery/httpx:v1.10.0` | Lightweight alive/dead tagging only; never filters hosts out of vhost enum. |
| DNSR PRIMARY | dnsx | `projectdiscovery/dnsx:v1.2.2` | Spec PRIMARY; `-json`, forged resolvers, named `-rl` from LOAD BALANCE. |
| DNSR FALLBACK | massdns | `c99tn/massdns:latest` | Spec-registered FALLBACK; same forge inputs, JSON `-o J`. |
| DNSR-2 | alterx | `projectdiscovery/alterx:v0.0.6` | Spec permutations engine; output capped by `max_permutations_per_host`. |
| PORT-CHECK | naabu | `projectdiscovery/naabu:v2.3.5` | Spec top-50; one `-host <ip>` invocation per unique resolved IP. |

Images are invoked only through `tools.yaml` + `tools.lock` (§5.2).
