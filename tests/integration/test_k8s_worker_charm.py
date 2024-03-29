#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
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

    await ops_test.model.wait_for_idle(status="active", timeout=60 * 60)


def test_status(ops_test):
    worker_app = ops_test.model.applications["kubernetes-worker"]
    k8s_version_str = worker_app.data["workload-version"]
    assert k8s_version_str, "Workload version is unset"
    assert tuple(int(i) for i in k8s_version_str.split(".")[:2]) >= (1, 26)
