"""Helpers for the worker restart tests: systemd `InvocationID` snapshots and log counts."""

import asyncio
import re
from datetime import datetime, timezone

CP_APP = "kubernetes-control-plane"
WORKER_APP = "kubernetes-worker"

# `InvocationID` changes every time systemd starts a unit, so it counts restarts.
# (`NRestarts` does not: it only counts restarts systemd does itself.)
WORKER_SERVICES = [
    "snap.kubelet.daemon",
    "snap.kube-proxy.daemon",
]

_NO_CHANGE = re.compile(
    r"^unit-(?P<unit>\S+)-(?P<num>\d+): (?P<time>\d\d:\d\d:\d\d) INFO \S+ "
    r"(?P<service>\S+): no change$"
)


async def run_on_unit(ops_test, unit, script):
    rc, out, err = await ops_test.run(
        "juju", "exec", "-m", ops_test.model_full_name, "--unit", unit, "--", script
    )
    assert rc == 0, f"{unit}: {script!r} failed: {err or out}"
    return out


def units_of(ops_test, app):
    return sorted(u.name for u in ops_test.model.applications[app].units)


async def invocation_ids(ops_test):
    """Map unit -> service -> systemd InvocationID for every worker unit."""
    script = "; ".join(
        f"echo {s} $(systemctl show -p InvocationID --value {s})" for s in WORKER_SERVICES
    )
    units = units_of(ops_test, WORKER_APP)
    outputs = await asyncio.gather(*(run_on_unit(ops_test, u, script) for u in units))
    return {
        unit: dict(line.split() for line in out.splitlines() if line.strip())
        for unit, out in zip(units, outputs)
    }


def restarted(before, after):
    """Map unit -> services whose InvocationID changed, for units present in both."""
    return {
        unit: sorted(s for s, i in services.items() if after[unit].get(s) != i)
        for unit, services in before.items()
        if unit in after
    }


def restarted_services(before, after):
    """Return the set of worker service names restarted on any worker unit."""
    return {service for services in restarted(before, after).values() for service in services}


async def settle(ops_test, timeout=30 * 60, idle_period=15):
    """Wait until every application is active and idle for `idle_period` seconds."""
    await ops_test.model.wait_for_idle(status="active", timeout=timeout, idle_period=idle_period)


def utc_now():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


async def no_change_counts(ops_test, since):
    """Count the "<service>: no change" INFO lines logged since `since` (HH:MM:SS UTC)."""
    rc, out, err = await ops_test.run(
        "juju",
        "debug-log",
        "-m",
        ops_test.model_full_name,
        "--replay",
        "--no-tail",
        "--utc",
        "--level",
        "INFO",
    )
    assert rc == 0, err
    counts = {}
    for line in out.splitlines():
        m = _NO_CHANGE.match(line)
        if m and m["time"] >= since:
            key = (f"{m['unit']}/{m['num']}", m["service"])
            counts[key] = counts.get(key, 0) + 1
    return counts
