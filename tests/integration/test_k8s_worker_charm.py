#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

import asyncio
import json
import logging
from pathlib import Path

import pytest
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
    rc, stdout, stderr = await ops_test.run(str(resource_build_script), cwd=resource_path)
    if rc != 0:
        log.error(f"rc: {rc}\nstdout: {stdout}\nstderr: {stderr}")
        pytest.fail("Failed to build charm resources")

    log.info("Building bundle")
    bundle, *overlays = await ops_test.async_render_bundles(
        ops_test.Bundle("kubernetes-core", channel="1.32/stable"),
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


async def test_nodes_labelled(request, ops_test):
    """Test the charms label the nodes appropriately."""
    testname: str = request.node.name
    kubernetes_cluster: model.Model = ops_test.model
    kcp: application.Application = kubernetes_cluster.applications["kubernetes-control-plane"]
    worker: application.Application = kubernetes_cluster.applications["kubernetes-worker"]
    label_config = {"labels": f"{testname}="}
    juju_charm_label = "juju-charm"
    await asyncio.gather(kcp.set_config(label_config), worker.set_config(label_config))
    await kubernetes_cluster.wait_for_idle(status="active", timeout=10 * 60)

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

    await kubernetes_cluster.wait_for_idle(status="active", timeout=10 * 60)
    nodes = await get_nodes(kcp.units[0])
    labelled = [n for n in nodes if testname in n["metadata"]["labels"]]
    assert 0 == len(labelled), f"No nodes should have custom labels, found {len(labelled)}"
