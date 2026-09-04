"""ACTIVE module dispatch (FFUF → DNS-RESOLVE → PORT-CHECK)."""

from pipeline.modules.dns_resolve import run_dns_resolve
from pipeline.modules.ffuf import run_ffuf
from pipeline.modules.port_check import run_port_check

RUNNERS = {
    "ffuf": run_ffuf,
    "dns-resolve": run_dns_resolve,
    "port-check": run_port_check,
}
