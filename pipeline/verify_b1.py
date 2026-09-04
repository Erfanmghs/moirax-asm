"""B1 acceptance checks: adapter path, breaker, MERGE, two-run diff."""

from __future__ import annotations

from pathlib import Path

from pipeline.adapter import Adapter, Completed, ScriptedRunner
from pipeline.breaker import CircuitBreaker, FakeClock
from pipeline.ceiling import ResourceCeiling
from pipeline.engine import run_pipeline
from pipeline.factory import ensure_layout
from pipeline.history import append_run, snapshot, write_diff
from pipeline.jsonio import read_json, write_json
from pipeline.merge import merge_branches
from pipeline.params import Params
from pipeline.scope import ScopeGate
from pipeline import state as state_engine


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _reset_harness(params: Params) -> Path:
    """Clear persisted breaker pauses so each check is order-independent."""
    target_dir = ensure_layout(params, "example.com")
    state_engine.clear_breaker_pauses(params, target_dir, "example.com")
    return target_dir


def _gate(params: Params) -> ScopeGate:
    example = params.root / "scope.yaml.example"
    live = params.root / "scope.yaml"
    return ScopeGate.load(params, live if live.is_file() else example)


def check_assemble(params: Params) -> None:
    target_dir = _reset_harness(params)
    breaker = CircuitBreaker(params, notify=lambda *_: None)
    adapter = Adapter(params, target_dir, breaker, ResourceCeiling(params), runner=ScriptedRunner())
    argv = adapter.assemble("echo-tool")
    assert argv[0] == "echo"
    assert "www.example.com" in argv[1]
    assert "{" not in " ".join(argv)
    dnsx = adapter.assemble(
        "dnsx",
        extra={"target_domain": "example.com", "dnsx_wordlist": "/w.txt"},
    )
    assert str(params.require("dnsx_max_qps")) in dnsx
    assert "example.com" in dnsx
    mass = adapter.assemble("dnsx")
    spec = adapter.spec("dnsx")
    assert spec.get("fallback") == "massdns"
    print("assemble: ok", argv, "dnsx_qps_named=yes", "fallback", spec.get("fallback"), mass[0])


def check_echo_path(params: Params, use_docker: bool) -> None:
    target_dir = _reset_harness(params)
    gate = _gate(params)
    runner = None if use_docker else ScriptedRunner()
    code = run_pipeline(params, gate, "example.com", runner=runner)
    assert code == 0
    data = target_dir / "logs" / "raw" / "echo-tool" / "data.json"
    assert data.is_file(), data
    doc = read_json(data)
    hosts = {row["host"] for row in doc["hosts"]}
    assert "www.example.com" in hosts
    assets = read_json(target_dir / str(params.require("assets_relpath")))
    names = {row["host"] for row in assets["assets"]}
    assert "www.example.com" in names
    assert "evil.com" not in names
    www = next(row for row in assets["assets"] if row["host"] == "www.example.com")
    assert www["attribution"] == "both"
    api = next(row for row in assets["assets"] if row["host"] == "api.example.com")
    assert api["attribution"] == "active"
    mail = next(row for row in assets["assets"] if row["host"] == "mail.example.com")
    assert mail["attribution"] == "passive"
    diff = read_json(target_dir / str(params.require("diff_filename")))
    assert set(diff.keys()) >= {"schema_version", "added", "removed", "changed"}
    assert (target_dir / str(params.require("runs_filename"))).is_file()
    hist = target_dir / str(params.require("history_dirname"))
    assert any(hist.iterdir())
    print("echo-path: ok docker=" + str(use_docker), "assets", sorted(names), "exit", code)


def check_fallback(params: Params) -> None:
    target_dir = _reset_harness(params)
    window = float(params.require("circuit_breaker_window_sec"))

    class WindowClock(FakeClock):
        def sleep(self, seconds: float) -> None:
            # Cross a breaker window on every retry backoff so the primary can pause mid-loop.
            self.advance(window)

    clock = WindowClock(10.0)
    breaker = CircuitBreaker(params, clock=clock, notify=lambda *_: None)
    fail = Completed(1, "", "injected fail")
    ok = Completed(0, "www.example.com\n", "")
    runner = ScriptedRunner(
        {
            "echo-fail": [fail, fail, fail],
            "echo-tool": [ok],
        }
    )
    adapter = Adapter(
        params, target_dir, breaker, ResourceCeiling(params), clock=clock, runner=runner
    )
    result = adapter.invoke("echo-fail", module="echo-fail", allow_fallback=True)
    assert result.used_fallback is True, result
    assert result.exit_code == 0, result
    assert result.data_json is not None
    assert result.tool == "echo-tool"
    # Primary may be paused after window-crossing retries; fallback must still succeed.
    assert breaker.allow("echo-fail") is False
    assert breaker.allow("echo-tool") is True
    print("fallback: ok attempts", result.attempts, "tool", result.tool)


def check_breaker(params: Params) -> None:
    _reset_harness(params)
    clock = FakeClock(10.0)
    alerts: list[tuple[str, str, str]] = []
    breaker = CircuitBreaker(params, clock=clock, notify=lambda s, m, r: alerts.append((s, m, r)))
    for _ in range(5):
        breaker.record("echo-tool", success=False, latency_sec=0.01)
    assert breaker.allow("echo-tool") is True
    assert breaker.throttle_factor("echo-tool") == 1.0 / float(params.require("throttle_divisor"))
    clock.advance(float(params.require("circuit_breaker_window_sec")))
    for _ in range(5):
        breaker.record("echo-tool", success=False, latency_sec=0.01)
    assert breaker.allow("echo-tool") is False
    assert alerts
    assert alerts[0][0] == str(params.require("self_monitor_anomaly"))
    assert alerts[0][1] == "echo-tool"
    print("breaker: ok anomaly", alerts[0])


def check_merge_quarantine(params: Params) -> None:
    target_dir = _reset_harness(params)
    gate = _gate(params)
    wildcard_ip = "203.0.113.10"
    passive = {
        "schema_version": 1,
        "module": "echo-tool",
        "hosts": [{"host": "a.example.com", "ips": [wildcard_ip]}, {"host": "evil.com"}],
        "wildcard_suspects": [wildcard_ip],
    }
    active = {
        "schema_version": 1,
        "module": "echo-tool-active",
        "hosts": [{"host": "a.example.com", "ips": [wildcard_ip]}, {"host": "b.example.com", "ips": [wildcard_ip]}],
        "wildcard_suspects": [wildcard_ip],
    }
    path = merge_branches(params, gate, target_dir, "example.com", [passive], [active])
    doc = read_json(path)
    hosts = {row["host"] for row in doc["assets"]}
    q = {row["host"]: row["reason"] for row in doc["quarantine"]}
    assert "evil.com" not in hosts
    assert "a.example.com" in q
    assert q["a.example.com"] == str(params.require("merge_catchall_reason"))
    assert "b.example.com" in q
    print("merge-quarantine: ok", q)


def check_diff(params: Params) -> None:
    target_dir = _reset_harness(params)
    assets_rel = Path(str(params.require("assets_relpath")))
    t1, t2 = "20200101T000000Z", "20200102T000000Z"
    write_json(
        target_dir / assets_rel,
        {
            "schema_version": 1,
            "assets": [{"host": "old.example.com", "attribution": "passive", "sources": ["echo-tool"], "ips": []}],
            "quarantine": [],
        },
    )
    snapshot(params, target_dir, t1)
    append_run(params, target_dir, t1, str(params.require("run_status_completed")), {"assets": 1})
    write_json(
        target_dir / assets_rel,
        {
            "schema_version": 1,
            "assets": [
                {"host": "old.example.com", "attribution": "both", "sources": ["echo-tool", "echo-tool-active"], "ips": ["1.2.3.4"]},
                {"host": "new.example.com", "attribution": "active", "sources": ["echo-tool-active"], "ips": []},
            ],
            "quarantine": [],
        },
    )
    snapshot(params, target_dir, t2)
    append_run(params, target_dir, t2, str(params.require("run_status_completed")), {"assets": 2})
    diff_path = write_diff(params, target_dir, t1, t2)
    diff = read_json(diff_path)
    added_hosts = [row["host"] for row in diff["added"]["hosts"]]
    removed_hosts = [row["host"] for row in diff["removed"]["hosts"]]
    changed_hosts = [row["after"]["host"] for row in diff["changed"]["hosts"]]
    assert "new.example.com" in added_hosts
    assert "old.example.com" in changed_hosts
    assert "gone.example.com" not in added_hosts
    assert removed_hosts == []
    print("diff: ok added", added_hosts, "changed", changed_hosts)


def check_ceiling(params: Params) -> None:
    _reset_harness(params)
    ceiling = ResourceCeiling(params)
    four = ceiling.plan(4)
    assert four.concurrency <= 4
    assert four.memory_mb * four.concurrency <= ceiling.budget_ram_mb
    assert four.cpus * four.concurrency <= ceiling.budget_cpu + 1e-9
    flags = ceiling.docker_flags(four)
    assert "--memory" in flags and "--cpus" in flags
    print("ceiling: ok", four, flags)


def main() -> int:
    params = Params(repo_root())
    checks = [
        ("assemble", lambda: check_assemble(params)),
        ("ceiling", lambda: check_ceiling(params)),
        ("breaker", lambda: check_breaker(params)),
        ("merge_quarantine", lambda: check_merge_quarantine(params)),
        ("diff", lambda: check_diff(params)),
        ("fallback", lambda: check_fallback(params)),
        ("echo_path", lambda: _run_echo_path(params)),
    ]
    for name, fn in checks:
        fn()
        print(f"CHECK {name}: PASS")
    print("B1 acceptance: PASS")
    return 0


def _run_echo_path(params: Params) -> None:
    from pipeline.dockerbin import docker_available

    docker = docker_available(params)
    try:
        check_echo_path(params, use_docker=bool(docker))
    except Exception as exc:
        if docker:
            raise
        print("echo-path docker skipped:", exc)
        check_echo_path(params, use_docker=False)


if __name__ == "__main__":
    raise SystemExit(main())
