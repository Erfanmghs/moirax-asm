"""PORT-SWEEP PACER: RAMP + CANARY + duration budget (master section 8 PORT-SWEEP).

Mirrors the DNS-RESOLVE LOAD BALANCE discipline (pipeline/load_balance.py)
for the port plane:
- RAMP: rate starts at ``portsweep_ramp_start_pps`` and steps by
  ``portsweep_ramp_step_pps`` every ``portsweep_ramp_interval_sec`` up to the
  profile rate cap.
- CANARY: every ``canary_interval_sec`` re-verify up to
  ``portsweep_sentinel_limit`` known-open sentinel (ip, port) pairs mined from
  the PREVIOUS sweep/port-check history via a plain TCP connect. Any miss
  halves the rate immediately; ``circuit_breaker_bad_windows`` consecutive bad
  windows force-pause the module through the circuit breaker (section 4.7 ANOMALY
  path). No sentinels from a previous run -> the canary is explicitly disarmed
  (never silent) and armed from the next completed sweep.
- PACING: the orchestrator derives the duration-budgeted effective pps
  (see port_sweep.py); the pacer's ramp never exceeds that budget.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any

from pipeline.breaker import Clock
from pipeline.params import Params


@dataclass
class PaceState:
    pps: float
    bad_windows: int
    last_canary: float
    last_ramp: float
    paused: bool = False


class PortPacer:
    def __init__(
        self,
        params: Params,
        breaker: Any,
        clock: Clock | None,
        target_dir: Any,
        module: str = "port-sweep",
    ) -> None:
        self.params = params
        self.breaker = breaker
        self.clock = clock
        self.target_dir = target_dir
        self.module = module
        start = float(params.require("portsweep_ramp_start_pps"))
        now = self.clock.time()
        self.state = PaceState(
            pps=start,
            bad_windows=0,
            last_canary=0.0,
            last_ramp=now,
        )

    def current_pps(self, cap: float) -> int:
        """Ramp state clamped by the profile cap (never above the pace budget)."""
        pps = min(self.state.pps, float(cap))
        return max(1, int(pps))

    def tick(self, sentinels: list[tuple[str, int]], cap: float) -> bool:
        """Return False if the canary paused the module (ANOMALY, section 4.7)."""
        now = self.clock.time()
        interval = float(self.params.require("portsweep_ramp_interval_sec"))
        if now - self.state.last_ramp >= interval:
            step = float(self.params.require("portsweep_ramp_step_pps"))
            self.state.pps = min(self.state.pps + step, float(cap))
            self.state.last_ramp = now
        if self.state.last_canary == 0.0 or now - self.state.last_canary >= float(
            self.params.require("canary_interval_sec")
        ):
            self.state.last_canary = now
            if not sentinels:
                # First sweep (or no open ports ever recorded): the canary is
                # disarmed with an explicit disclosure, never silently.
                self._log("canary disarmed: no sentinel ports from a previous run -- armed next sweep")
                return True
            return self._canary(sentinels)
        return not self.state.paused

    def _canary(self, sentinels: list[tuple[str, int]]) -> bool:
        limit = int(self.params.require("portsweep_sentinel_limit"))
        timeout = float(self.params.require("portsweep_canary_connect_timeout_sec"))
        checked = sentinels[: max(1, limit)]
        misses = [(ip, port) for ip, port in checked if not _tcp_open(ip, port, timeout)]
        if misses:
            self.state.pps = max(1.0, self.state.pps / 2.0)
            self.state.bad_windows += 1
            detail = ",".join(f"{ip}:{port}" for ip, port in misses)
            self._log(
                f"canary bad window={self.state.bad_windows} misses={detail} pps={self.current_pps(float(self.params.require('portsweep_full_rate_cap')))}"
            )
            if self.state.bad_windows >= int(self.params.require("circuit_breaker_bad_windows")):
                self.state.paused = True
                reason = "PORT-SWEEP canary: 2 consecutive bad windows"
                self.breaker.force_pause(self.module, reason)
                self._log(f"canary pause: {reason}")
                return False
            return True
        self.state.bad_windows = 0
        self._log(f"canary ok sentinels={len(checked)} pps={self.current_pps(float(self.params.require('portsweep_full_rate_cap')))}")
        return True

    def _log(self, detail: str) -> None:
        from datetime import datetime, timezone

        path = self.target_dir / str(self.params.require("run_log"))
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp}\tport-sweep\tpacer\t0\tok\t{detail}\n")


def _tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False
