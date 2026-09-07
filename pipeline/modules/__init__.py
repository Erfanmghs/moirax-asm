"""Pipeline module dispatch.

ACTIVE branch: FFUF -> DNS-RESOLVE -> FFUF-3 -> PORT-CHECK (append-only order).
PASSIVE branch (B3, spec section 8): PASSIVE-RECON -- PSV-0..PSV-8 sub-steps inside
one orchestrator runner (PSV-0 infrastructure first, parallel sweep, PSV-5
recursion, PSV-6 probe last); existing module orders are untouched.
POST-MERGE (B4, spec section 8): PORT-SWEEP -- order-4 stage consuming assets.json
after MERGE; wired through the engine's post-merge hook, NOT into a branch.
"""

from pipeline.modules.dns_resolve import run_dns_resolve
from pipeline.modules.ffuf import run_ffuf
from pipeline.modules.ffuf3 import run_ffuf3
from pipeline.modules.passive_recon import run_passive_recon
from pipeline.modules.port_check import run_port_check
from pipeline.modules.port_sweep import run_port_sweep

RUNNERS = {
    "ffuf": run_ffuf,
    "dns-resolve": run_dns_resolve,
    "ffuf-3": run_ffuf3,
    "port-check": run_port_check,
    "passive-recon": run_passive_recon,
    "port-sweep": run_port_sweep,
}
