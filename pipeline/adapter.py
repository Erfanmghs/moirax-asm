"""Tool adapter: named-parameter command assembly + container invoke (section 5, section 4.3)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.breaker import CircuitBreaker, Clock
from pipeline.ceiling import ContainerLimits, ResourceCeiling
from pipeline.dockerbin import docker_prefix, volume_host_path
from pipeline.jsonio import write_json
from pipeline.params import Params

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_HOST_TOKEN = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)


class AdapterError(RuntimeError):
    pass


@dataclass
class InvokeResult:
    tool: str
    argv: list[str]
    docker_cmd: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_sec: float
    used_fallback: bool
    data_json: Path | None
    paused: bool = False
    attempts: int = 1


@dataclass
class ToolSpec:
    name: str
    raw: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)


class Adapter:
    def __init__(
        self,
        params: Params,
        target_dir: Path,
        breaker: CircuitBreaker,
        ceiling: ResourceCeiling,
        clock: Clock | None = None,
        runner: Any | None = None,
        aggressive: bool = False,
        proxy_pool: Any | None = None,
    ) -> None:
        self.params = params
        self.target_dir = target_dir
        self.breaker = breaker
        self.ceiling = ceiling
        self.clock = clock or Clock()
        if runner is None:
            self.runner = _DockerRunner(params, abort_check=self.stop_requested)
        else:
            self.runner = runner
        self.aggressive = aggressive
        # C5 IP rotation: optional ProxyAssigner; ONE pool entry PER ATTEMPT
        # (first try + every retry rotate -- per-request law), ledgered,
        # outcome-telemetered per entry, credentials never echoed.
        self.proxy_pool = proxy_pool
        self._live: dict[str, str] = {}
        self._live_lock = threading.Lock()

    def stop_requested(self) -> bool:
        from pipeline import state as state_engine

        try:
            return state_engine.operator_stopped(self.params, self.target_dir, self.target_dir.name)
        except Exception:  # noqa: BLE001
            return False

    def spec(self, name: str) -> ToolSpec:
        tools = self.params.tools
        if name not in tools or not isinstance(tools[name], dict):
            raise AdapterError(f"tool {name!r} is not registered in tools.yaml")
        return ToolSpec(name, tools[name])

    def enabled(self, name: str) -> bool:
        return bool(self.spec(name).get("enabled", True))

    def assemble(self, name: str, extra: dict[str, Any] | None = None, module: str | None = None) -> list[str]:
        spec = self.spec(name)
        template = spec.get("argv_template") or []
        if not isinstance(template, list) or not template:
            raise AdapterError(f"tool {name!r} has no argv_template")
        values = self._values(name, extra or {}, module)
        argv: list[str] = []
        for token in template:
            rendered = _render_token(str(token), values)
            argv.append(rendered)
        for block in spec.get("optional_argv") or []:
            if not isinstance(block, dict):
                continue
            when = str(block.get("when") or "")
            if when and not str(values.get(when) or "").strip():
                continue
            for token in block.get("argv") or []:
                argv.append(_render_token(str(token), values))
        return argv

    def invoke(
        self,
        name: str,
        module: str,
        extra: dict[str, Any] | None = None,
        planned_concurrency: int = 1,
        timeout_sec: float | None = None,
        allow_fallback: bool = True,
    ) -> InvokeResult:
        extra = extra or {}
        if self.stop_requested():
            return InvokeResult(
                tool=name,
                argv=[],
                docker_cmd=[],
                exit_code=130,
                stdout="",
                stderr="operator stop",
                duration_sec=0.0,
                used_fallback=False,
                data_json=None,
                paused=False,
                attempts=0,
            )
        if not self.breaker.allow(module):
            return InvokeResult(
                tool=name,
                argv=[],
                docker_cmd=[],
                exit_code=1,
                stdout="",
                stderr="circuit breaker paused this module",
                duration_sec=0.0,
                used_fallback=False,
                data_json=None,
                paused=True,
                attempts=0,
            )
        spec = self.spec(name)
        proxy_state = {"idx": -1}  # last assigned pool index for this invocation
        retries = int(self.params.require("tool_retry_count"))
        backoff = float(self.params.require("retry_backoff_base_sec"))
        result = self._attempt_loop(spec, module, extra, planned_concurrency, timeout_sec, retries, backoff,
                                    proxy_state)
        if result.exit_code != 0 and allow_fallback:
            fallback = spec.get("fallback")
            if fallback:
                fb = self.spec(str(fallback))
                # section 4.3: pause blocks the primary tool only. Fallback runs under its own
                # breaker key so a mid-retry pause on `module` cannot skip the chain.
                fb_module = str(fb.name)
                fb_result = self._attempt_loop(
                    fb, fb_module, extra, planned_concurrency, timeout_sec, retries, backoff,
                    {"idx": -1},
                )
                fb_result.used_fallback = True
                if fb_result.exit_code == 0:
                    return fb_result
                result = fb_result
                result.used_fallback = True
        return result

    def _attempt_loop(
        self,
        spec: ToolSpec,
        module: str,
        extra: dict[str, Any],
        planned_concurrency: int,
        timeout_sec: float | None,
        retries: int,
        backoff: float,
        proxy_state: dict[str, int] | None = None,
    ) -> InvokeResult:
        last: InvokeResult | None = None
        attempts = retries + 1
        for attempt in range(attempts):
            if not self.breaker.allow(module):
                return InvokeResult(
                    tool=spec.name,
                    argv=[],
                    docker_cmd=[],
                    exit_code=1,
                    stdout="",
                    stderr="circuit breaker paused this module",
                    duration_sec=0.0,
                    used_fallback=False,
                    data_json=None,
                    paused=True,
                    attempts=attempt,
                )
            # C5 v2 PER-REQUEST ROTATION: every attempt (first try + retries)
            # takes the next pool entry. Hook-less tools are assigned ONCE (a
            # single honest DIRECT row, no per-retry noise) and stay DIRECT.
            if (self.proxy_pool is not None and proxy_state is not None
                    and (attempt == 0 or proxy_state["idx"] >= 0)):
                frag, idx = self.proxy_pool.hook_values_for_attempt(
                    spec.name, module, spec.raw, attempt=attempt + 1
                )
                if frag:
                    extra = {**extra, **frag}
                proxy_state["idx"] = idx
            last = self._once(spec, module, extra, planned_concurrency, timeout_sec, attempt + 1)
            # C5 v2 HEALTH TELEMETRY: this attempt's exit code is the entry's
            # outcome signal (masked, capped, persisted per target; never
            # raises, never flips a verdict -- same law class as selftune).
            if self.proxy_pool is not None and proxy_state is not None:
                self.proxy_pool.record_outcome(
                    proxy_state["idx"], ok=(last.exit_code == 0),
                    duration_sec=last.duration_sec, tool=spec.name,
                    module=module, attempt=attempt + 1,
                )
            if last.exit_code == 0:
                return last
            if attempt < retries:
                self.clock.sleep(backoff * (2 ** attempt))
        assert last is not None
        return last

    def _once(
        self,
        spec: ToolSpec,
        module: str,
        extra: dict[str, Any],
        planned_concurrency: int,
        timeout_sec: float | None,
        attempt: int,
    ) -> InvokeResult:
        argv = self.assemble(spec.name, extra, module)
        image = self._image(str(spec.get("image_ref") or spec.name))
        limits = self.ceiling.acquire(planned_concurrency)
        started = self.clock.time()
        label = uuid.uuid4().hex[:12]
        container = f"recon-{label}"
        docker_cmd = self._docker_cmd(spec, image, argv, limits, container, module)
        with self._live_lock:
            self._live[container] = spec.name
        try:
            completed = self.runner.run(docker_cmd, timeout_sec)
        finally:
            self.ceiling.release()
            with self._live_lock:
                self._live.pop(container, None)
        ended = self.clock.time()
        duration = max(0.0, ended - started)
        stdout = completed.stdout
        stderr = completed.stderr
        code = int(completed.returncode)
        success = code == 0
        probe = bool(extra.get("breaker_probe")) or str(spec.name).endswith("-canary") or str(
            spec.name
        ).endswith("-probe")
        if probe:
            self.breaker.record(module, success=success, latency_sec=duration, timeout=code == 124)
        elif code in (124, 130):
            self.breaker.record(module, success=True, latency_sec=None, timeout=False)
        else:
            self.breaker.record(module, success=success, latency_sec=None, timeout=False)
        self._log_run(module, spec.name, code, stderr, argv, success)
        data_path = None
        if extra.get("skip_parse"):
            raw_rel = Path(str(extra.get("output_raw_dir") or spec.get("output_raw_dir") or f"logs/raw/{spec.name}"))
            raw_dir = self.target_dir / raw_rel
            raw_dir.mkdir(parents=True, exist_ok=True)
            (raw_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
            if stderr:
                (raw_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
        elif success:
            data_path = self._parse(spec, stdout, argv, duration, extra)
        return InvokeResult(
            tool=spec.name,
            argv=argv,
            docker_cmd=docker_cmd,
            exit_code=code,
            stdout=stdout,
            stderr=stderr,
            duration_sec=duration,
            used_fallback=False,
            data_json=data_path,
            attempts=attempt,
        )

    def live_containers(self) -> list[str]:
        with self._live_lock:
            return list(self._live)

    def _values(self, tool_name: str, extra: dict[str, Any], module: str | None) -> dict[str, Any]:
        spec = self.spec(tool_name)
        merged: dict[str, Any] = dict(self.params.settings)
        overrides = spec.get("flag_overrides") or {}
        if isinstance(overrides, dict):
            merged.update(overrides)
        merged.update(extra)
        if self.aggressive:
            mult = float(self.params.require("aggressive_multiplier"))
            for key in ("ffuf_threads", "ffuf_rate", "dnsx_max_qps", "dnsx_rl", "portcheck_rate", "httpx_threads"):
                if key in merged and merged[key] is not None:
                    merged[key] = _as_number(merged[key]) * mult
        if module:
            for key in ("ffuf_threads", "ffuf_rate", "dnsx_max_qps", "dnsx_rl", "portcheck_rate", "httpx_threads"):
                if key in merged and merged[key] is not None:
                    merged[key] = self.breaker.apply_limit(module, _as_number(merged[key]))
        return merged

    def _image(self, image_ref: str) -> str:
        images = (self.params.lock.get("images") or {})
        row = images.get(image_ref) or {}
        image = row.get("image")
        tag = row.get("tag")
        digest = row.get("digest") or ""
        if not image:
            raise AdapterError(f"tools.lock missing image for {image_ref!r}")
        if digest:
            return f"{image}@{digest}"
        if tag:
            return f"{image}:{tag}"
        return str(image)

    def _docker_cmd(
        self,
        spec: ToolSpec,
        image: str,
        argv: list[str],
        limits: ContainerLimits,
        container: str,
        module: str,
    ) -> list[str]:
        binary = docker_prefix(self.params)
        recon_mount = str(self.params.require("recon_container_mount"))
        host_recon = volume_host_path(self.params, self.params.root / str(self.params.require("recon_root")))
        cmd = [*binary, "run", "--rm", "--name", container]
        cmd.extend(self.ceiling.docker_flags(limits))
        cmd.extend(
            [
                "--label",
                f"{self.params.require('docker_label_pipeline')}=1",
                "--label",
                f"{self.params.require('docker_label_target')}={self.target_dir.name}",
                "--label",
                f"{self.params.require('docker_label_tool')}={spec.name}",
                "--label",
                f"{self.params.require('docker_label_module')}={module}",
                "-v",
                f"{host_recon}:{recon_mount}",
                "-w",
                recon_mount,
            ]
        )
        env_file = self.params.root / str(self.params.require("env_filename"))
        if env_file.is_file():
            cmd.extend(["--env-file", str(env_file)])
        for item in spec.get("docker_env") or []:
            cmd.extend(["-e", _render_token(str(item), dict(self.params.settings))])
        if spec.get("network_host"):
            cmd.extend(["--network", "host"])
        binary = spec.get("binary")
        if binary:
            cmd.extend(["--entrypoint", str(binary)])
        cmd.append(image)
        if binary and argv and argv[0] == str(binary):
            cmd.extend(argv[1:])
        else:
            cmd.extend(argv)
        return cmd

    def _parse(self, spec: ToolSpec, stdout: str, argv: list[str], duration: float, extra: dict[str, Any] | None = None) -> Path:
        extra = extra or {}
        parser = str(spec.get("parser") or "host_lines")
        raw_rel = Path(str(extra.get("output_raw_dir") or spec.get("output_raw_dir") or f"logs/raw/{spec.name}"))
        raw_dir = self.target_dir / raw_rel
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
        data_rel = Path(str(spec.get("output_data_json") or raw_rel / "data.json"))
        data_path = self.target_dir / data_rel
        if parser == "json":
            import json

            try:
                payload = json.loads(stdout) if stdout.strip() else {"schema_version": 1, "module": spec.name}
            except json.JSONDecodeError:
                payload = {"schema_version": 1, "module": spec.name, "raw": stdout}
            if not isinstance(payload, dict):
                payload = {"schema_version": 1, "module": spec.name, "raw": payload}
            payload.setdefault("schema_version", int(self.params.require("schema_version")))
            write_json(data_path, payload)
        else:
            hosts = _hosts_from_text(stdout)
            kind = str(spec.get("data_kind") or "passive")
            sources_rel = Path(str(self.params.require("passive_sources_relpath")))
            source_file = self.target_dir / sources_rel / f"{spec.name}.txt"
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
            payload = {
                "schema_version": int(self.params.require("schema_version")),
                "module": spec.name,
                "hosts": [{"host": host, "fqdn": host} for host in hosts],
                "candidates": [{"host": host, "sources": [spec.name]} for host in hosts],
                "vhosts": [],
                "passive_ips": [],
                "resolved": [],
                "wildcard_suspects": [],
                "branch": kind,
                "sources": [spec.name],
            }
            write_json(data_path, payload)
        summary_rel = Path(str(spec.get("output_summary") or raw_rel / "summary.md"))
        summary = self.target_dir / summary_rel
        summary.parent.mkdir(parents=True, exist_ok=True)
        counts = _count_hosts(data_path)
        summary.write_text(
            "\n".join(
                [
                    f"# {spec.name}",
                    "",
                    f"command: {' '.join(argv)}",
                    f"runtime_sec: {duration:.3f}",
                    f"counts: {counts}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return data_path

    def _log_run(self, module: str, tool: str, exit_code: int, stderr: str, argv: list[str], success: bool) -> None:
        log_rel = Path(str(self.params.require("run_log")))
        path = self.target_dir / log_rel
        path.parent.mkdir(parents=True, exist_ok=True)
        tail_n = int(self.params.require("stderr_tail_lines"))
        lines = stderr.splitlines()
        tail = " | ".join(lines[-tail_n:]) if lines else ""
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        status = "ok" if success else "fail"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                f"{stamp}\t{module}\t{tool}\t{exit_code}\t{status}\t{tail}\tcmd={' '.join(argv)}\n"
            )


@dataclass
class Completed:
    returncode: int
    stdout: str
    stderr: str


class _DockerRunner:
    def __init__(self, params: Params, abort_check=None) -> None:
        self.params = params
        self.abort_check = abort_check or (lambda: False)

    def run(self, docker_cmd: list[str], timeout_sec: float | None) -> Completed:
        prefix = docker_prefix(self.params)
        binary = prefix[0] if prefix else str(self.params.require("docker_binary"))
        if shutil.which(binary) is None:
            raise AdapterError(f"{binary} is not installed on PATH")
        if self.abort_check():
            return Completed(130, "", "operator stop")
        try:
            proc = subprocess.Popen(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except OSError as exc:
            return Completed(1, "", str(exc))
        # Drain stdout/stderr on a side thread. Waiting on poll() with unread
        # PIPEs deadlocks dnsx once the kernel pipe fills (~64KiB) because
        # those tools write NDJSON to stdout even when `-o` is set.
        box: dict[str, Any] = {}

        def _wait() -> None:
            try:
                out, err = proc.communicate()
                box["stdout"] = out or ""
                box["stderr"] = err or ""
            except Exception as exc:  # noqa: BLE001 -- still return an exit
                box["stdout"] = box.get("stdout") or ""
                box["stderr"] = str(exc)
            box["rc"] = proc.returncode

        waiter = threading.Thread(target=_wait, name="recon-docker-wait", daemon=True)
        waiter.start()
        start = time.time()
        while waiter.is_alive():
            if self.abort_check():
                _stop_docker_container(self.params, docker_cmd)
                _kill_popen(proc)
                waiter.join(1.0)
                return Completed(130, str(box.get("stdout") or ""), str(box.get("stderr") or "operator stop"))
            if timeout_sec is not None and (time.time() - start) >= float(timeout_sec):
                _stop_docker_container(self.params, docker_cmd)
                _kill_popen(proc)
                waiter.join(1.0)
                return Completed(
                    124,
                    str(box.get("stdout") or ""),
                    str(box.get("stderr") or "container timeout"),
                )
            waiter.join(0.12)
        return Completed(int(box.get("rc") or 0), str(box.get("stdout") or ""), str(box.get("stderr") or ""))


def _container_name(docker_cmd: list[str]) -> str:
    try:
        idx = docker_cmd.index("--name")
    except ValueError:
        return ""
    if idx + 1 >= len(docker_cmd):
        return ""
    return str(docker_cmd[idx + 1]).strip()


def _stop_docker_container(params: Params, docker_cmd: list[str]) -> None:
    """Kill the named tool container. SIGKILL on `docker run` does not always
    reap the daemon-side container (`--rm` only runs after the container exits).
    """
    name = _container_name(docker_cmd)
    if not name:
        return
    try:
        prefix = docker_prefix(params)
    except Exception:  # noqa: BLE001 -- timeout path must still return
        return
    try:
        subprocess.run([*prefix, "kill", name], capture_output=True, text=True, check=False, timeout=8)
        subprocess.run([*prefix, "rm", "-f", name], capture_output=True, text=True, check=False, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return


def _kill_popen(proc: subprocess.Popen) -> None:
    import signal as _signal

    pid = proc.pid
    if not pid:
        return
    try:
        os.killpg(pid, _signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=1.0)
    except Exception:  # noqa: BLE001
        pass


class ScriptedRunner:
    """Deterministic container stand-in for breaker/fallback checks (no network)."""

    def __init__(self, outcomes: dict[str, list[Completed]] | None = None) -> None:
        self.outcomes = outcomes or {}
        self.calls: list[list[str]] = []

    def run(self, docker_cmd: list[str], timeout_sec: float | None) -> Completed:
        self.calls.append(list(docker_cmd))
        tool = _tool_label(docker_cmd)
        queue = self.outcomes.get(tool) or self.outcomes.get("*") or []
        if queue:
            return queue.pop(0)
        if "echo" in docker_cmd:
            idx = docker_cmd.index("echo")
            return Completed(0, " ".join(docker_cmd[idx + 1 :]) + "\n", "")
        return Completed(0, "", "")


def _tool_label(docker_cmd: list[str]) -> str:
    for i, token in enumerate(docker_cmd):
        if token == "--label" and i + 1 < len(docker_cmd) and "recon.tool=" in docker_cmd[i + 1]:
            return docker_cmd[i + 1].split("=", 1)[1]
    return ""


def _as_number(value: Any) -> float | int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    text = str(value).strip()
    if "." in text:
        return float(text)
    return int(text)


def _render_token(token: str, values: dict[str, Any]) -> str:
    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise AdapterError(f"unnamed parameter {name!r} in argv template")
        value = values[name]
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    return _PLACEHOLDER.sub(repl, token)


def _hosts_from_text(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for raw in text.replace(",", " ").split():
        host = raw.strip().lower().rstrip(".")
        if not host or host in seen:
            continue
        if _HOST_TOKEN.match(host):
            seen.add(host)
            found.append(host)
    return found


def _count_hosts(data_path: Path) -> int:
    try:
        from pipeline.jsonio import read_json

        payload = read_json(data_path)
    except (OSError, ValueError):
        return 0
    if isinstance(payload, dict) and "hosts" in payload:
        return len(payload.get("hosts") or [])
    return 0
