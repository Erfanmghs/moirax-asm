"""DNSR LOAD BALANCE: RAMP + CANARY (master section 8)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pipeline.adapter import Adapter, InvokeResult
from pipeline.breaker import Clock
from pipeline.ndjson import parse_json_payload
from pipeline.params import Params
from pipeline.textio import atomic_write_text


@dataclass
class RateState:
    qps: float
    bad_windows: int
    baseline_latency: float | None
    last_canary: float
    last_ramp: float
    paused: bool = False


class LoadBalancer:
    def __init__(
        self,
        params: Params,
        adapter: Adapter,
        target_dir: Any,
        target: str,
        clock: Clock | None = None,
        module: str = "dns-resolve",
    ) -> None:
        self.params = params
        self.adapter = adapter
        self.target_dir = target_dir
        self.target = target
        self.clock = clock or adapter.clock
        self.module = module
        start = float(params.require("dnsx_ramp_start_qps"))
        now = self.clock.time()
        self.state = RateState(
            qps=start,
            bad_windows=0,
            baseline_latency=None,
            last_canary=0.0,
            last_ramp=now,
        )

    def current_qps(self) -> int:
        cap = float(self.params.require("dnsx_max_qps"))
        qps = min(self.state.qps, cap)
        qps = self.adapter.breaker.apply_limit(self.module, qps)
        return max(1, int(qps))

    def tick(self, resolvers_container: str, sentinels_rel: str, extra_base: dict[str, Any]) -> bool:
        """Return False if canary paused the module (ANOMALY)."""
        now = self.clock.time()
        interval = float(self.params.require("dnsx_ramp_interval_sec"))
        canary_every = float(self.params.require("canary_interval_sec"))
        if now - self.state.last_ramp >= interval:
            step = float(self.params.require("dnsx_ramp_step_qps"))
            cap = float(self.params.require("dnsx_max_qps"))
            self.state.qps = min(self.state.qps + step, cap)
            self.state.last_ramp = now
        if self.state.last_canary == 0.0 or now - self.state.last_canary >= canary_every:
            ok = self._canary(resolvers_container, sentinels_rel, extra_base)
            self.state.last_canary = now
            if not ok:
                return False
        return not self.state.paused

    def _canary(self, resolvers_container: str, sentinels_rel: str, extra_base: dict[str, Any]) -> bool:
        extra = dict(extra_base)
        extra["dnsx_resolvers"] = resolvers_container
        extra["dnsx_hosts"] = extra_base["dnsx_canary_hosts"]
        extra["dnsx_max_qps"] = self.current_qps()
        extra["output_raw_dir"] = sentinels_rel
        extra["skip_parse"] = True
        started = self.clock.time()
        result = self.adapter.invoke(
            "dnsx-canary",
            module=self.module,
            extra=extra,
            planned_concurrency=1,
            allow_fallback=True,
        )
        latency = max(0.0, self.clock.time() - started)
        errors = result.exit_code != 0 or not _canary_answers(result)
        multiplier = float(self.params.require("canary_latency_multiplier"))
        slow = False
        if self.state.baseline_latency is None and not errors:
            self.state.baseline_latency = latency if latency > 0 else 0.001
        elif self.state.baseline_latency is not None and latency > self.state.baseline_latency * multiplier:
            slow = True
        if errors or slow:
            self.state.qps = max(1.0, self.state.qps / float(self.params.require("throttle_divisor")))
            self.state.bad_windows += 1
            reason = "canary errors" if errors else "canary latency"
            _log(self.params, self.target_dir, f"canary bad window={self.state.bad_windows} reason={reason} qps={self.current_qps()}")
            if self.state.bad_windows >= int(self.params.require("circuit_breaker_bad_windows")):
                self.state.paused = True
                reason_full = "LOAD BALANCE canary: 2 consecutive bad windows"
                self.adapter.breaker.force_pause(self.module, reason_full)
                _log(self.params, self.target_dir, f"canary pause: {reason_full}")
                return False
            return True
        self.state.bad_windows = 0
        if self.state.baseline_latency is None:
            self.state.baseline_latency = latency
        return True


def write_sentinel_file(path: Any, hosts: list[str]) -> None:
    atomic_write_text(path, "\n".join(hosts) + "\n")


def _canary_answers(result: InvokeResult) -> bool:
    payload = parse_json_payload(result.stdout)
    if isinstance(payload, list):
        return any(isinstance(row, dict) and (row.get("a") or row.get("host")) for row in payload)
    if isinstance(payload, dict):
        return bool(payload.get("a") or payload.get("host"))
    return bool((result.stdout or "").strip()) and result.exit_code == 0


def _log(params: Params, target_dir: Any, detail: str) -> None:
    from datetime import datetime, timezone

    path = target_dir / str(params.require("run_log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{stamp}\tdns-resolve\tload-balance\t0\tok\t{detail}\n")
