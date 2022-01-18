import asyncio
import logging
from urllib.request import urlretrieve
from pathlib import Path
import shlex

import pytest

log = logging.getLogger(__name__)
CNI_ARCH_URL = "https://api.jujucharms.com/charmstore/v5/~containers/kubernetes-worker-{charm}/resource/cni-{arch}"  # noqa


async def _retrieve_url(charm, arch, target_file):
    url = CNI_ARCH_URL.format(
        charm=charm,
        arch=arch,
    )
    path, _ = urlretrieve(url, target_file)
    return Path(path)


def _check_status_messages(ops_test):
    """ Validate that the status messages are correct. """
    expected_messages = {
        "kubernetes-master": "Kubernetes master running.",
        "kubernetes-worker": "Kubernetes worker running.",
    }
    for app, message in expected_messages.items():
        for unit in ops_test.model.applications[app].units:
            assert unit.workload_status_message == message


@pytest.fixture()
async def setup_resources(ops_test):
    """Provides the cni resources needed to deploy the charm."""
    cwd = Path.cwd()
    current_resources = list(cwd.glob("*.tgz"))
    tmpdir = ops_test.tmp_path / "resources"
    tmpdir.mkdir(parents=True, exist_ok=True)
    if not current_resources:
        # If they are not locally available, try to build them
        log.info("Build Resources...")
        build_script = cwd / "build-cni-resources.sh"
        rc, stdout, stderr = await ops_test.run(
            *shlex.split(f"sudo {build_script}"), cwd=tmpdir, check=False
        )
        if rc != 0:
            log.warning(f"build-cni-resources failed: {(stderr or stdout).strip()}")
        current_resources = list(Path(tmpdir).glob("*.tgz"))
    if not current_resources:
        # if we couldn't build them, just download a fixed version
        log.info("Downloading Resources...")
        current_resources = await asyncio.gather(
            *(
                _retrieve_url(816, arch, tmpdir / f"cni-{arch}.tgz")
                for arch in ("amd64", "arm64", "s390x")
            ), return_exceptions=True
        )
    for resource in current_resources:
        if not isinstance(resource, Path):
            pytest.fail("Failed to gather resource\n\t{}".format(resource))

    yield current_resources


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test, setup_resources):
    log.info("Build Charm...")
    charm = await ops_test.build_charm(".")

    log.info("Build Bundle...")
    charm_resources = {rsc.stem.replace("-", "_"): rsc for rsc in setup_resources}
    bundle = ops_test.render_bundle(
        "tests/data/bundle.yaml", worker_charm=charm, **charm_resources
    )

    log.info("Deploy Bundle...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle}"
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    log.info(stdout)
    await ops_test.model.block_until(
        lambda: "kubernetes-worker" in ops_test.model.applications, timeout=60
    )

    try:
        await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)
    except asyncio.TimeoutError:
        if "kubernetes-master" not in ops_test.model.applications:
            raise
        app = ops_test.model.applications["kubernetes-master"]
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


async def juju_run(unit, cmd):
    result = await unit.run(cmd)
    code = result.results["Code"]
    stdout = result.results.get("Stdout")
    stderr = result.results.get("Stderr")
    assert code == "0", f"{cmd} failed ({code}): {stderr or stdout}"
    return stdout


async def test_kube_api_endpoint(ops_test):
    """ Validate that adding the kube-api-endpoint relation works """
    await ops_test.model.add_relation(
        "kubernetes-master:kube-api-endpoint", "kubernetes-worker:kube-api-endpoint"
    )

    # It can take some time for the relation hook to trigger, which can lead to
    # wait_for_idle giving a false positive.
    k8s_master = ops_test.model.applications["kubernetes-master"].units[0]
    waiting_msg = "Waiting for kube-api-endpoint relation"
    await ops_test.model.block_until(
        lambda: k8s_master.workload_status_message == waiting_msg,
        timeout=5 * 60,
    )

    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=10 * 60)
    _check_status_messages(ops_test)
