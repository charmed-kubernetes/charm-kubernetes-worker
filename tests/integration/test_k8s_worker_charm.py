#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from pathlib import Path

import pytest
from helpers import (
    CP_APP,
    WORKER_APP,
    WORKER_SERVICES,
    invocation_ids,
    no_change_counts,
    restarted_services,
    settle,
    units_of,
    utc_now,
)
from juju import application, model
from pytest_operator.plugin import OpsTest

log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    """Build kubernetes-worker and deploy with kubernetes-core bundle."""
    charm = next(Path().glob("kubernetes-worker*.charm"), None)
    if not charm:
        log.info("Building charm")
        charm = await ops_test.build_charm(".")

    resource_path = ops_test.tmp_path / "charm-resources"
    resource_path.mkdir()
    resource_build_script = Path("./build-cni-resources.sh").resolve()
    log.info("Building charm resources")
    rc, stdout, stderr = await ops_test.run(
        "env", "ARCH=amd64", str(resource_build_script), cwd=resource_path
    )
    if rc != 0:
        log.error(f"rc: {rc}\nstdout: {stdout}\nstderr: {stderr}")
        pytest.fail("Failed to build charm resources")
    log.info("Building bundle")
    bundle, *overlays = await ops_test.async_render_bundles(
        ops_test.Bundle("kubernetes-core", channel="edge"),
        Path("tests/data/charm.yaml"),
        arch="amd64",
        charm=charm.resolve(),
        resource_path=resource_path,
    )

    log.info("Deploying bundle")
    cmd = ["juju", "deploy", "-m", ops_test.model_full_name, bundle]
    for overlay in overlays:
        cmd += ["--overlay", overlay]
    rc, stdout, stderr = await ops_test.run(*cmd)
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    async with ops_test.fast_forward(fast_interval="30s"):
        await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


def test_status(ops_test):
    worker_app = ops_test.model.applications["kubernetes-worker"]
    k8s_version_str = worker_app.data["workload-version"]
    assert k8s_version_str, "Workload version is unset"
    assert tuple(int(i) for i in k8s_version_str.split(".")[:2]) >= (1, 26)


async def get_nodes(k8s):
    """Get list of Nodes.

    Args:
        k8s: any k8s unit

    Returns:
        list of nodes

    """
    action = await k8s.run("kubectl --kubeconfig=/root/.kube/config get nodes -o json")
    result = await action.wait()
    assert result.results["return-code"] == 0, "Failed to get nodes with kubectl"
    log.info("Parsing node list...")
    node_list = json.loads(result.results["stdout"])
    assert node_list["kind"] == "List", "Should have found a list of nodes"
    return node_list["items"]


async def test_nodes_labelled_restarts_no_worker_service(request, ops_test):
    """Test node labelling and that hooks changing no service inputs restart nothing."""
    testname: str = request.node.name
    kubernetes_cluster: model.Model = ops_test.model
    kcp: application.Application = kubernetes_cluster.applications[CP_APP]
    worker: application.Application = kubernetes_cluster.applications[WORKER_APP]
    label_config = {"labels": f"{testname}="}
    juju_charm_label = "juju-charm"
    before = await invocation_ids(ops_test)
    since = utc_now()

    await asyncio.gather(kcp.set_config(label_config), worker.set_config(label_config))
    await settle(ops_test, timeout=10 * 60)

    try:
        nodes = await get_nodes(kcp.units[0])
        labelled = [n for n in nodes if testname in n["metadata"]["labels"]]
        juju_nodes = [n for n in nodes if juju_charm_label in n["metadata"]["labels"]]
        assert len(kcp.units + worker.units) == len(
            labelled
        ), f"{len(labelled)}/{len(kcp.units + worker.units)} nodes labelled with custom-label"
        assert len(kcp.units + worker.units) == len(
            juju_nodes
        ), f"{len(juju_nodes)}/{len(kcp.units + worker.units)} nodes labelled as juju-charms"
    finally:
        await asyncio.gather(
            kcp.reset_config(list(label_config)), worker.reset_config(list(label_config))
        )

    await settle(ops_test, timeout=10 * 60)
    nodes = await get_nodes(kcp.units[0])
    labelled = [n for n in nodes if testname in n["metadata"]["labels"]]
    assert 0 == len(labelled), f"No nodes should have custom labels, found {len(labelled)}"

    assert restarted_services(before, await invocation_ids(ops_test)) == set()
    counts = await no_change_counts(ops_test, since)
    for unit in units_of(ops_test, WORKER_APP):
        for service in WORKER_SERVICES:
            assert counts.get((unit, service), 0) >= 2, f"{unit} {service}: {counts}"


KUBELET = "snap.kubelet.daemon"
KUBE_PROXY = "snap.kube-proxy.daemon"


async def test_proxy_arg_change_restarts_only_kube_proxy(ops_test: OpsTest):
    worker = ops_test.model.applications[WORKER_APP]
    before = await invocation_ids(ops_test)

    await worker.set_config({"proxy-extra-args": "v=2"})
    await settle(ops_test)
    after = await invocation_ids(ops_test)

    assert restarted_services(before, after) == {KUBE_PROXY}
    changed = [
        u
        for u in units_of(ops_test, WORKER_APP)
        if before[u][KUBE_PROXY] != after[u][KUBE_PROXY]
    ]
    assert changed == units_of(ops_test, WORKER_APP)


async def test_kubelet_arg_change_restarts_only_kubelet(ops_test: OpsTest):
    worker = ops_test.model.applications[WORKER_APP]
    before = await invocation_ids(ops_test)

    await worker.set_config({"kubelet-extra-args": "v=2"})
    await settle(ops_test)
    after = await invocation_ids(ops_test)

    assert restarted_services(before, after) == {KUBELET}
    changed = [
        u
        for u in units_of(ops_test, WORKER_APP)
        if before[u][KUBELET] != after[u][KUBELET]
    ]
    assert changed == units_of(ops_test, WORKER_APP)


async def test_multi_control_plane_endpoints_do_not_flap_restarts(ops_test: OpsTest):
    """With multiple control-plane units on `kube-control`, worker hooks do not rewrite kubeconfigs."""
    kcp = ops_test.model.applications[CP_APP]
    worker = ops_test.model.applications[WORKER_APP]
    if len(kcp.units) < 2:
        await kcp.add_unit()
        await settle(ops_test)

    before = await invocation_ids(ops_test)
    await worker.set_config({"labels": "endpoint-stability=1"})
    await settle(ops_test)
    await worker.reset_config(["labels"])
    await settle(ops_test)

    assert restarted_services(before, await invocation_ids(ops_test)) == set()
