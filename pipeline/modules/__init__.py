"""ACTIVE module dispatch (FFUF → DNS-RESOLVE → FFUF-3 → PORT-CHECK).

FFUF-3 (spec v1.9 §8, Option-1 item 1) is the appended ACTIVE sub-step that
runs after DNS-RESOLVE completes and BEFORE MERGE; existing module orders are
untouched (append-only law preserved).
"""

from pipeline.modules.dns_resolve import run_dns_resolve
from pipeline.modules.ffuf import run_ffuf
from pipeline.modules.ffuf3 import run_ffuf3
from pipeline.modules.port_check import run_port_check

RUNNERS = {
    "ffuf": run_ffuf,
    "dns-resolve": run_dns_resolve,
    "ffuf-3": run_ffuf3,
    "port-check": run_port_check,
}
