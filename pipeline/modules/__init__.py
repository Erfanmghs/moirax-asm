"""Pipeline module dispatch.

ACTIVE branch: DNS-RESOLVE (dnsx brute + IPs) -> FFUF (vhost) -> FFUF-3 -> PORT-CHECK.
PASSIVE branch (B3, spec section 8): PASSIVE-RECON -- PSV-0..PSV-8 sub-steps inside
one orchestrator runner (PSV-0 infrastructure first, parallel sweep, PSV-5
recursion, PSV-6 probe last); existing module orders are untouched.
POST-MERGE (B4, spec section 8): PORT-SWEEP -- order-4 stage consuming assets.json
after MERGE; wired through the engine's post-merge hook, NOT into a branch.
POST-MERGE (FFUF-4): vhost enum on HTTP-like ports from PORT-SWEEP; same hook.
POST-MERGE (C6, operator roadmap): OWASP-PASSIVE -- zero-packet artifact analyzer
after FFUF-4; same post-merge hook pattern, never a branch member.
"""

from pipeline.modules.dns_resolve import run_dns_resolve
from pipeline.modules.ffuf import run_ffuf
from pipeline.modules.ffuf3 import run_ffuf3
from pipeline.modules.ffuf4 import run_ffuf4
from pipeline.modules.owasp_passive import run_owasp_passive
from pipeline.modules.passive_recon import run_passive_recon
from pipeline.modules.port_check import run_port_check
from pipeline.modules.port_sweep import run_port_sweep

RUNNERS = {
    "ffuf": run_ffuf,
    "dns-resolve": run_dns_resolve,
    "ffuf-3": run_ffuf3,
    "ffuf-4": run_ffuf4,
    "port-check": run_port_check,
    "passive-recon": run_passive_recon,
    "port-sweep": run_port_sweep,
    "owasp-passive": run_owasp_passive,
}
