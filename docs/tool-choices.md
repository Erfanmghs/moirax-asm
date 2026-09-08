# Tool choices (master prompt section 5.1)

| Task | Tool | Image (tools.lock) | Rationale |
|---|---|---|---|
| B1 adapter probe | `echo` (busybox) | `busybox:1.36.1` | Official tiny image; prints named host tokens so the adapter->container->parser->data.json path is observable without touching a target. Disabled in B2 (fixtures remain registered). |
| B1 fallback profile | `echo-tool-fallback` / `echo-fail` | same busybox pin | Exercises section 4.3 retry then registered fallback then degraded-continue. |
| FFUF-1/2 | ffuf | `ghcr.io/ffuf/ffuf:v2.1.0` | Vhost Host-header enum (optional HTTP label brute is OFF). JSON `-of json`. |
| HTTP enrich | httpx | `projectdiscovery/httpx:v1.10.0` | Operator ENABLED switch: status, content-length, `-td` technology on dnsx-resolved names. |
| DNSR PRIMARY | dnsx | `projectdiscovery/dnsx:v1.2.2` | Active subdomain brute + IP resolve; `-json`, forged resolvers, named `-rl`. |
| DNSR FALLBACK | massdns | `c99tn/massdns:latest` | Spec-registered FALLBACK; same forge inputs, JSON `-o J`. |
| DNSR-2 | alterx | `projectdiscovery/alterx:v0.0.6` | Spec permutations engine; output capped by `max_permutations_per_host`. |
| PORT-CHECK | naabu | `projectdiscovery/naabu:v2.3.5` | Spec top-50; one `-host <ip>` invocation per unique resolved IP. |

Images are invoked only through `tools.yaml` + `tools.lock` (section 5.2).
