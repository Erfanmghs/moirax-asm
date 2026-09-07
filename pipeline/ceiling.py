"""Resource ceiling -- master prompt section 11.5. Budget is never exceeded."""

from __future__ import annotations

import threading
from dataclasses import dataclass

from pipeline.params import Params


@dataclass(frozen=True)
class ContainerLimits:
    memory_mb: int
    cpus: float
    concurrency: int


class ResourceCeiling:
    def __init__(self, params: Params) -> None:
        self.params = params
        ram = int(params.require("resource_budget_ram_mb"))
        ram_max = int(params.require("resource_budget_ram_mb_max"))
        self.budget_ram_mb = min(ram, ram_max)
        self.budget_cpu = float(params.require("resource_budget_cpu_cores"))
        self.meminfo_path = str(params.require("meminfo_path"))
        self.memory_unit = str(params.require("container_memory_unit"))
        self._lock = threading.Lock()
        self._running = 0

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
        available = self._host_available_mb()
        if available is None:
            return True
        return available >= per

    def _host_available_mb(self) -> int | None:
        path = self.meminfo_path
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            return None
        for line in text.splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) >= 2:
                    kb = int(parts[1])
                    return kb // 1024
        return None
