import asyncio
import json
import logging
from pathlib import Path
import shlex
import re

import pytest

log = logging.getLogger(__name__)


def _check_status_messages(ops_test):
    """Validate that the status messages are correct."""
    is_running = re.compile(r"Kubernetes \S+ running.")
    expected_running_apps = {
        "kubernetes-control-plane",
        "kubernetes-worker",
    }
    for app in expected_running_apps:
        for unit in ops_test.model.applications[app].units:
            assert is_running.match(unit.workload_status_message)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test, series: str):
    log.info("Build Charm...")
    charm = await ops_test.build_charm(".")

    build_script = Path.cwd() / "build-cni-resources.sh"
    resources = await ops_test.build_resources(build_script)
    expected_resources = {"cni-amd64", "cni-arm64", "cni-s390x"}

    if resources and all(rsc.stem in expected_resources for rsc in resources):
        resources = {rsc.stem.replace("-", "_"): rsc for rsc in resources}
    else:
        log.info("Failed to build resources, downloading from latest/edge")
        arch_resources = ops_test.arch_specific_resources(charm)
        resources = await ops_test.download_resources(charm, resources=arch_resources)
        resources = {name.replace("-", "_"): rsc for name, rsc in resources.items()}

    assert resources, "Failed to build or download charm resources."

    log.info("Build Bundle...")
    context = dict(charm=charm, series=series, **resources)
    overlays = [
        ops_test.Bundle("kubernetes-core", channel="1.27/stable"),
        Path("tests/data/charm.yaml"),
    ]
    bundle, *overlays = await ops_test.async_render_bundles(*overlays, **context)

    log.info("Deploy Bundle...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} " + " ".join(
        f"--overlay={f}" for f in overlays
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    log.info(stdout)
    await ops_test.model.block_until(
        lambda: "kubernetes-worker" in ops_test.model.applications, timeout=60
    )

    try:
        await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
    except asyncio.TimeoutError:
        if "kubernetes-control-plane" not in ops_test.model.applications:
            raise
        app = ops_test.model.applications["kubernetes-control-plane"]
        if not app.units:
            raise
        unit = app.units[0]
        if "kube-system pod" in unit.workload_status_message:
            log.debug(
                await juju_run(
                    unit, "kubectl --kubeconfig /root/.kube/config get all -A"
                )
            )
        raise

    _check_status_messages(ops_test)


async def juju_run(unit, cmd):
    action = await unit.run(cmd)
    await action.wait()
    code = action.results.get("Code", action.results.get("return-code"))
    if code is None:
        log.error(f"Failed to find the return code in {action.results}")
        return -1
    code = int(code)
    stdout = action.results.get("Stdout", action.results.get("stdout")) or ""
    stderr = action.results.get("Stderr", action.results.get("stderr")) or ""
    assert code == 0, f"{cmd} failed ({code}): {stderr or stdout}"
    return stdout


async def test_kube_api_endpoint(ops_test):
    """Validate that adding the kube-api-endpoint relation works"""
    await ops_test.model.add_relation(
        "kubernetes-control-plane:kube-api-endpoint",
        "kubernetes-worker:kube-api-endpoint",
    )

    # It can take some time for the relation hook to trigger, which can lead to
    # wait_for_idle giving a false positive.
    k8s_cp = ops_test.model.applications["kubernetes-control-plane"].units[0]
    waiting_msg = "Waiting for kube-api-endpoint relation"
    try:
        await ops_test.model.block_until(
            lambda: k8s_cp.workload_status_message == waiting_msg,
            timeout=5 * 60,
        )
    except asyncio.TimeoutError:
        pass

    goal_state = await juju_run(k8s_cp, "goal-state --format=json")
    relation_status = json.loads(goal_state)
    kube_api_endpoint = relation_status["relations"]["kube-api-endpoint"]
    assert kube_api_endpoint["kubernetes-worker"]["status"] == "joined"

    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)
    _check_status_messages(ops_test)


async def test_node_label(ops_test):
    app = ops_test.model.applications["kubernetes-control-plane"]
    unit = app.units[0]
    nodes = await juju_run(
        unit, "kubectl --kubeconfig /root/.kube/config get nodes -o json"
    )
    nodes = json.loads(nodes)
    for node in nodes["items"]:
        if "juju-application" in node["metadata"]["labels"]:
            assert node["metadata"]["labels"]["juju-application"] in [
                "kubernetes-worker",
                "kubernetes-control-plane",
            ]
