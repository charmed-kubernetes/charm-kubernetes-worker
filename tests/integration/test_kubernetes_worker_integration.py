import logging
from urllib.request import urlretrieve

import pytest


CNI_AMD64_URL = "https://api.jujucharms.com/charmstore/v5/~containers/kubernetes-worker-743/resource/cni-amd64/747"  # noqa

log = logging.getLogger(__name__)


def _check_status_messages(ops_test):
    """Validate that the status messages are correct."""
    expected_messages = {
        "kubernetes-control-plane": "Kubernetes master running.",
        "kubernetes-worker": "Kubernetes worker running.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    cni_amd64 = ops_test.tmp_path / "cni-amd64.tgz"
    urlretrieve(CNI_AMD64_URL, cni_amd64)
    worker_charm = await ops_test.build_charm(".")

    # Work around libjuju not handling local file resources by manually
    # pre-deploying the charm w/ resource via the CLI. See
    # https://github.com/juju/python-libjuju/issues/223
    rc, stdout, stderr = await ops_test._run(
        "juju",
        "deploy",
        "-m",
        ops_test.model_full_name,
        worker_charm,
        "--resource",
        f"cni-amd64={cni_amd64}",
        "--constraints",
        "cores=4 mem=4G root-disk=16G",
    )
    assert rc == 0, f"Failed to deploy with resource: {stderr or stdout}"

    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml",
        worker_charm=worker_charm,
        # cni_amd64=cni_amd64,  # This doesn't work currently
    )
    await ops_test.model.deploy(bundle)

    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
    _check_status_messages(ops_test)


async def test_kube_api_endpoint(ops_test):
    """Validate that adding the kube-api-endpoint relation works"""
    await ops_test.model.add_relation(
        "kubernetes-control-plane:kube-api-endpoint",
        "kubernetes-control-plane:kube-api-endpoint",
    )

    # It can take some time for the relation hook to trigger, which can lead to
    # wait_for_idle giving a false positive.
    k8s_cp = ops_test.model.applications["kubernetes-control-plane"].units[0]
    waiting_msg = "Waiting for kube-api-endpoint relation"
    await ops_test.model.block_until(
        lambda: k8s_cp.workload_status_message == waiting_msg,
        timeout=5 * 60,
    )

    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)
    _check_status_messages(ops_test)
