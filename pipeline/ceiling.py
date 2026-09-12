"""Resource ceiling -- master prompt section 11.5. Budget is never exceeded.

When resource_budget_auto is on, the committed tools.yaml numbers are a
floor for tiny hosts and a starting point; the live budget is the host's
usable CPU/RAM minus a reserve so the operator workstation stays responsive.
Per-container CPU is never sliced below container_cpu_floor -- concurrency
drops instead of starving every docker job.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass

from pipeline.params import Params

def _num(params: Params, name: str, default: float) -> float:
    try:
        return float(params.require(name))
    except (KeyError, TypeError, ValueError):
        return float(default)


def _int(params: Params, name: str, default: int) -> int:
    try:
        return int(params.require(name))
    except (KeyError, TypeError, ValueError):
        return int(default)


def _flag(params: Params, name: str, default: bool) -> bool:
    try:
        return bool(params.require(name))
    except KeyError:
        return default


@dataclass(frozen=True)
class ContainerLimits:
    memory_mb: int
    cpus: float
    concurrency: int


def host_cpu_count() -> int:
    n = os.cpu_count() or 2
    return max(1, int(n))


def host_available_mb(meminfo_path: str) -> int | None:
    try:
        text = open(meminfo_path, encoding="utf-8").read()
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("MemAvailable:"):
            parts = line.split()
            if len(parts) >= 2:
                kb = int(parts[1])
                return kb // 1024
    return None


def _dashboard_budget(params: Params) -> dict[str, int]:
    rel = str(params.settings.get("dashboard_config_relpath") or "dashboard/config.json")
    path = params.root / rel
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    raw = doc.get("resource_budget") if isinstance(doc, dict) else None
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    cpu = raw.get("cpu_cores")
    ram = raw.get("ram_mb")
    if isinstance(cpu, int) and not isinstance(cpu, bool) and cpu > 0:
        out["cpu_cores"] = cpu
    if isinstance(ram, int) and not isinstance(ram, bool) and ram > 0:
        out["ram_mb"] = ram
    return out


class ResourceCeiling:
    def __init__(self, params: Params) -> None:
        self.params = params
        ram = _int(params, "resource_budget_ram_mb", 2048)
        ram_max = _int(params, "resource_budget_ram_mb_max", 8192)
        cpu = _num(params, "resource_budget_cpu_cores", 2.0)
        overlay = _dashboard_budget(params)
        if overlay.get("cpu_cores"):
            cpu = float(overlay["cpu_cores"])
        if overlay.get("ram_mb"):
            ram = overlay["ram_mb"]
        self.meminfo_path = str(params.settings.get("meminfo_path") or "/proc/meminfo")
        self.memory_unit = str(params.settings.get("container_memory_unit") or "m")
        self._cpu_floor = _num(params, "container_cpu_floor", 0.5)
        self._ram_floor = _int(params, "container_ram_floor_mb", 256)
        auto = _flag(params, "resource_budget_auto", True)
        if auto:
            cpu, ram = self._fit_host(cpu, ram, ram_max)
        self.budget_ram_mb = min(int(ram), ram_max)
        self.budget_cpu = float(cpu)
        self._lock = threading.Lock()
        self._running = 0

    def _fit_host(self, cpu: float, ram: int, ram_max: int) -> tuple[float, int]:
        reserve_cpu = _num(self.params, "resource_budget_cpu_reserve", 1.0)
        reserve_ram = _int(self.params, "resource_budget_ram_reserve_mb", 1024)
        cpu_max = _num(self.params, "resource_budget_cpu_cores_max", 12.0)
        usable_cpu = max(1.0, host_cpu_count() - reserve_cpu)
        fitted_cpu = min(cpu_max, usable_cpu)
        available = host_available_mb(self.meminfo_path)
        if available is None:
            return fitted_cpu, min(max(int(ram), self._ram_floor), ram_max)
        usable_ram = max(self._ram_floor, available - reserve_ram)
        fitted_ram = min(ram_max, usable_ram)
        return fitted_cpu, int(fitted_ram)

    def plan(self, parallel_count: int) -> ContainerLimits:
        n = max(1, int(parallel_count))
        while n > 1 and not self._fits(n):
            n -= 1
        return self._limits_for(n)

    def acquire(self, planned: int) -> ContainerLimits:
        with self._lock:
            n = max(1, self._running + 1)
            planned_n = max(n, int(planned))
            while planned_n > 1 and not self._fits(planned_n):
                planned_n -= 1
            if n > planned_n:
                n = planned_n
            self._running += 1
            return self._limits_for(max(n, 1))

    def release(self) -> None:
        with self._lock:
            if self._running > 0:
                self._running -= 1

    def docker_flags(self, limits: ContainerLimits) -> list[str]:
        mem = f"{limits.memory_mb}{self.memory_unit}"
        cpus = f"{limits.cpus:.4f}".rstrip("0").rstrip(".")
        return ["--memory", mem, "--cpus", cpus]

    def _limits_for(self, n: int) -> ContainerLimits:
        n = max(1, n)
        memory_mb = max(1, self.budget_ram_mb // n)
        cpus = self.budget_cpu / n
        return ContainerLimits(memory_mb=memory_mb, cpus=cpus, concurrency=n)

    def _fits(self, n: int) -> bool:
        per = max(1, self.budget_ram_mb // n)
        if n * per > self.budget_ram_mb:
            return False
        if per < self._ram_floor and n > 1:
            return False
        if (self.budget_cpu / n) + 1e-12 < self._cpu_floor and n > 1:
            return False
        available = host_available_mb(self.meminfo_path)
        if available is None:
            return True
        return available >= per
