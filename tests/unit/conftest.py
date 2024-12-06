import contextlib
import unittest.mock as mock

import ops.testing
import pytest
from ops.testing import Harness

from charm import KubernetesWorkerCharm

ops.testing.SIMULATE_CAN_CONNECT = True

MARKERS_AND_MOCKS = {
    "_check_kubecontrol_integration": "skip_check_kubecontrol_integration",
    "_request_certificates": "skip_request_certificates",
    "_write_certificates": "skip_write_certificates",
    "_request_kubelet_and_proxy_credentials": "skip_request_kubelet_and_proxy_credentials",
    "_create_kubeconfigs": "skip_create_kubeconfigs",
    "_configure_cni": "skip_configure_cni",
    "_configure_container_runtime": "skip_configure_container_runtime",
    "_configure_kernel_parameters": "skip_configure_kernel_parameters",
    "_configure_kubelet": "skip_configure_kubelet",
    "_configure_kubeproxy": "skip_configure_kubeproxy",
    "_install_cni_binaries": "skip_install_cni_binaries",
}


def pytest_configure(config):
    for method, marker in MARKERS_AND_MOCKS.items():
        description = f"Mark tests which do not mock out {method}"
        config.addinivalue_line("markers", f"{marker}: {description}")


@pytest.fixture
def harness():
    harness = Harness(KubernetesWorkerCharm)
    try:
        harness.add_network("10.0.0.10", endpoint="kube-control")
        yield harness
    finally:
        harness.cleanup()


@pytest.fixture
def charm_environment(request, harness: Harness[KubernetesWorkerCharm]):
    """Create a charm with mocked methods.

    This fixture utilizes ExitStack to dynamically mock methods in the Kubernetes Worker Charm,
    using the request markers defined in the `pytest_configure` method.
    """
    with contextlib.ExitStack() as stack:
        mocks = {}
        for method, marker in MARKERS_AND_MOCKS.items():
            if marker not in request.keywords:
                mock_method = mock.MagicMock()
                stack.enter_context(
                    mock.patch(f"charm.KubernetesWorkerCharm.{method}", mock_method)
                )
                mocks[method] = mock_method
        with mock.patch("charm.kubernetes_snaps", autospec=True) as mock_kubernetes_snaps:
            mocks["kubernetes_snaps"] = mock_kubernetes_snaps
            harness.begin()
            yield (harness.charm, mocks)
