"""Per-target circuit breaker -- master prompt section 11.4. Always on."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from pipeline.notify import send_status
from pipeline.params import Params
from pipeline import state as state_engine


class Clock:
    def time(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


class FakeClock(Clock):
    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def time(self) -> float:
        return self._now

    def sleep(self, seconds: float) -> None:
        self._now += seconds

    def advance(self, seconds: float) -> None:
        self._now += seconds


@dataclass
class _Event:
    ts: float
    error: bool
    latency_sec: float | None
    host: str | None


@dataclass
class _ModuleBreaker:
    throttle_factor: float = 1.0
    paused: bool = False
    consecutive_bad: int = 0
    last_bad_window: int | None = None
    last_ok_window: int | None = None
    anomaly_sent: bool = False
    events: list[_Event] = field(default_factory=list)
    baseline_latency: float | None = None
    last_latency_bad_window: int | None = None
    consecutive_latency_bad: int = 0
    pause_reason: str | None = None


class CircuitBreaker:
    def __init__(
        self,
        params: Params,
        clock: Clock | None = None,
        notify: Callable[[str, str, str], None] | None = None,
        target_dir: Path | None = None,
        target: str | None = None,
    ) -> None:
        self.params = params
        self.clock = clock or Clock()
        self._notify = notify
        self.target_dir = target_dir
        self.target = target or (target_dir.name if target_dir else "")
        self._lock = threading.Lock()
        self._modules: dict[str, _ModuleBreaker] = {}
        self.error_ratio = float(params.require("circuit_breaker_error_ratio"))
        self.window_sec = float(params.require("circuit_breaker_window_sec"))
        self.bad_windows = int(params.require("circuit_breaker_bad_windows"))
        self.throttle_divisor = float(params.require("throttle_divisor"))
        self.latency_multiplier = float(params.require("canary_latency_multiplier"))
        self.anomaly_status = str(params.require("self_monitor_anomaly"))
        self._load_persisted_pauses()

    def _state(self, module: str) -> _ModuleBreaker:
        row = self._modules.get(module)
        if row is None:
            row = _ModuleBreaker()
            self._modules[module] = row
        return row

    def _load_persisted_pauses(self) -> None:
        if self.target_dir is None:
            return
        paused = state_engine.paused_modules(self.params, self.target_dir, self.target)
        for module, info in paused.items():
            row = self._state(str(module))
            row.paused = True
            row.anomaly_sent = True
            if isinstance(info, dict):
                row.pause_reason = str(info.get("reason") or "persisted pause")

    def force_pause(self, module: str, reason: str) -> None:
        with self._lock:
            state = self._state(module)
            if state.paused:
                return
            window_id = int(self.clock.time() // self.window_sec) if self.window_sec else 0
            self._pause(module, state, reason, 0, 0, window_id)

    def allow(self, module: str) -> bool:
        with self._lock:
            return not self._state(module).paused

    def pause_reason(self, module: str) -> str | None:
        with self._lock:
            row = self._state(module)
            if not row.paused:
                return None
            return row.pause_reason or "circuit breaker paused this module"

    def any_paused(self) -> bool:
        with self._lock:
            return any(row.paused for row in self._modules.values())

    def paused_module_names(self) -> list[str]:
        with self._lock:
            return [name for name, row in self._modules.items() if row.paused]

    def throttle_factor(self, module: str) -> float:
        with self._lock:
            return self._state(module).throttle_factor

    def apply_limit(self, module: str, value: float | int) -> float:
        factor = self.throttle_factor(module)
        scaled = float(value) * factor
        if isinstance(value, int):
            return max(1, int(scaled))
        return scaled

    def record(
        self,
        module: str,
        success: bool,
        latency_sec: float | None = None,
        host: str | None = None,
        timeout: bool = False,
    ) -> None:
        error = (not success) or timeout
        now = self.clock.time()
        with self._lock:
            state = self._state(module)
            if state.paused:
                return
            state.events.append(_Event(now, error, latency_sec, host))
            cutoff = now - self.window_sec
            state.events = [ev for ev in state.events if ev.ts >= cutoff]
            window_id = int(now // self.window_sec) if self.window_sec else 0
            self._evaluate_errors(module, state, window_id)
            self._evaluate_latency(module, state, window_id)

    def _evaluate_errors(self, module: str, state: _ModuleBreaker, window_id: int) -> None:
        total = len(state.events)
        if total == 0:
            return
        errors = sum(1 for ev in state.events if ev.error)
        ratio = errors / total
        if ratio > self.error_ratio:
            if state.last_bad_window != window_id:
                if state.last_bad_window is not None and window_id == state.last_bad_window + 1:
                    state.consecutive_bad += 1
                else:
                    state.consecutive_bad = 1
                state.last_bad_window = window_id
                self._throttle(
                    module,
                    state,
                    errors,
                    total,
                    window_id,
                    f"error ratio {errors}/{total}={ratio:.2f} > {self.error_ratio}",
                )
            if state.consecutive_bad >= self.bad_windows:
                self._pause(
                    module,
                    state,
                    "error ratio exceeded circuit breaker windows",
                    errors,
                    total,
                    window_id,
                )
        else:
            state.consecutive_bad = 0
            state.last_ok_window = window_id

    def _evaluate_latency(self, module: str, state: _ModuleBreaker, window_id: int) -> None:
        latencies = [ev.latency_sec for ev in state.events if ev.latency_sec is not None]
        if not latencies:
            return
        avg = sum(latencies) / len(latencies)
        if state.baseline_latency is None:
            state.baseline_latency = avg
            return
        total = len(state.events)
        errors = sum(1 for ev in state.events if ev.error)
        if avg > state.baseline_latency * self.latency_multiplier:
            if state.last_latency_bad_window != window_id:
                state.consecutive_latency_bad += 1
                state.last_latency_bad_window = window_id
                self._throttle(
                    module,
                    state,
                    errors,
                    total,
                    window_id,
                    f"latency drift avg={avg:.3f}s baseline={state.baseline_latency:.3f}s",
                )
            # section 11.4 load signal: latency drift -> THROTTLE only. Pause is reserved
            # for error-ratio > circuit_breaker_error_ratio across circuit_breaker_bad_windows.
        else:
            state.consecutive_latency_bad = 0

    def _throttle(
        self,
        module: str,
        state: _ModuleBreaker,
        errors: int,
        total: int,
        window_id: int,
        reason: str,
    ) -> None:
        state.throttle_factor = state.throttle_factor / self.throttle_divisor
        self._log_transition("throttle", module, errors, total, window_id, reason, state.throttle_factor)

    def _pause(
        self,
        module: str,
        state: _ModuleBreaker,
        reason: str,
        errors: int,
        total: int,
        window_id: int,
    ) -> None:
        state.paused = True
        state.pause_reason = reason
        self._log_transition("pause", module, errors, total, window_id, reason, state.throttle_factor)
        if self.target_dir is not None:
            state_engine.persist_pause(self.params, self.target_dir, self.target, module, reason)
        if state.anomaly_sent:
            return
        state.anomaly_sent = True
        if self._notify is not None:
            self._notify(self.anomaly_status, module, reason)
            return
        send_status(self.params, self.anomaly_status, module, reason)

    def _log_transition(
        self,
        kind: str,
        module: str,
        errors: int,
        total: int,
        window_id: int,
        reason: str,
        throttle_factor: float,
    ) -> None:
        window_start = window_id * self.window_sec
        window_end = window_start + self.window_sec
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"{stamp}\tbreaker\t{module}\t{kind}\t"
            f"errors={errors}/{total}\t"
            f"window=[{window_start:.0f},{window_end:.0f})\t"
            f"throttle_factor={throttle_factor:g}\t"
            f"reason={reason}\n"
        )
        print(line.rstrip())
        if self.target_dir is None:
            return
        path = self.target_dir / str(self.params.require("run_log"))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)
