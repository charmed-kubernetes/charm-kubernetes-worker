# Copyright 2023 Canonical
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from typing import Mapping, Tuple
from unittest.mock import MagicMock, PropertyMock, call, patch

import ops
import ops.testing
import pytest
from charms.contextual_status import ReconcilerError
from charms.interface_container_runtime import ContainerRuntimeProvides
from charms.interface_kubernetes_cni import KubernetesCniProvides
from ops.interface_tls_certificates import CertificatesRequires
from ops.testing import Harness

from charm import KubernetesWorkerCharm

ops.testing.SIMULATE_CAN_CONNECT = True

CharmEnvironment = Tuple[KubernetesWorkerCharm, Mapping[str, MagicMock]]


@pytest.mark.parametrize(
    "evaluation,result",
    [
        pytest.param("", True, id="Integration ready"),
        pytest.param("Waiting", False, id="Integration not ready"),
    ],
)
@pytest.mark.skip_check_kubecontrol_integration
def test__check_kubecontrol_integration(
    charm_environment: CharmEnvironment, evaluation: str, result: bool
):
    charm, _ = charm_environment
    with patch.object(charm.kube_control, "evaluate_relation") as mock_evaluate:
        mock_event = MagicMock()
        mock_evaluate.return_value = evaluation
        result = charm._check_kubecontrol_integration(mock_event)
        assert result is result


@pytest.mark.skip_configure_cni
@patch("charms.interface_kubernetes_cni.hash_file")
def test_configure_cni_registry(
    mock_hash, charm_environment: CharmEnvironment, harness: Harness[KubernetesWorkerCharm]
):
    charm, _ = charm_environment
    harness.disable_hooks()
    mock_hash.return_value = hash = (
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    )
    with patch.object(charm.kube_control, "get_registry_location") as mock_get_registry:
        mock_get_registry.return_value = registry = "myregistry.com"
        cni_relation_id = harness.add_relation("cni", "calico")
        harness.add_relation_unit(cni_relation_id, "calico/0")
        charm._configure_cni()
        relation_data = harness.get_relation_data(cni_relation_id, "kubernetes-worker/0")
        assert relation_data.get("image-registry", None) == registry
        assert relation_data.get("kubeconfig-hash") == hash


@pytest.mark.skip_configure_cni
def test_configure_cni_registry_no_cni(
    charm_environment: CharmEnvironment, harness: Harness[KubernetesWorkerCharm]
):
    charm, _ = charm_environment
    harness.disable_hooks()
    with pytest.raises(ReconcilerError) as ie:
        charm._configure_cni()
    assert ie.match("Found expected exception: CNI relation not established")


@pytest.mark.skip_configure_container_runtime
def test_configure_container_runtime(
    charm_environment: CharmEnvironment, harness: Harness[KubernetesWorkerCharm]
):
    charm, mocks = charm_environment
    harness.disable_hooks()
    mock_k8s_snaps = mocks["kubernetes_snaps"]

    with patch.object(charm.kube_control, "get_registry_location") as mock_get_registry:
        mock_k8s_snaps.get_sandbox_image.return_value = image = "myregistry.com/pause:3.9"
        mock_get_registry.return_value = "myregistry.com"
        cri_relation_id = harness.add_relation("container-runtime", "containerd")
        harness.add_relation_unit(cri_relation_id, "containerd/0")
        charm._configure_container_runtime()
        relation_data = harness.get_relation_data(cri_relation_id, "kubernetes-worker/0")
        assert relation_data.get("sandbox_image", None) == image


@pytest.mark.skip_configure_container_runtime
def test_configure_container_runtime_no_integration(
    charm_environment: CharmEnvironment, harness: Harness[KubernetesWorkerCharm]
):
    charm, _ = charm_environment
    harness.disable_hooks()
    with pytest.raises(ReconcilerError) as ie:
        charm._configure_container_runtime()
    assert ie.match("Found expected exception: container-runtime not established")


@pytest.mark.skip_configure_kernel_parameters
def test__configure_kernel_parameters(charm_environment: CharmEnvironment):
    charm, mocks = charm_environment
    mock_k8s_snaps = mocks["kubernetes_snaps"]
    charm._configure_kernel_parameters()
    mock_k8s_snaps.configure_kernel_parameters.assert_called_with(
        {
            "net.ipv4.conf.all.forwarding": 1,
            "net.ipv4.conf.all.rp_filter": 1,
            "net.ipv4.neigh.default.gc_thresh1": 128,
            "net.ipv4.neigh.default.gc_thresh2": 28672,
            "net.ipv4.neigh.default.gc_thresh3": 32768,
            "net.ipv6.neigh.default.gc_thresh1": 128,
            "net.ipv6.neigh.default.gc_thresh2": 28672,
            "net.ipv6.neigh.default.gc_thresh3": 32768,
            "fs.inotify.max_user_instances": 8192,
            "fs.inotify.max_user_watches": 1048576,
            "kernel.panic": 10,
            "kernel.panic_on_oops": 1,
            "vm.overcommit_memory": 1,
        }
    )


@pytest.mark.skip_configure_kubelet
def test__configure_kubelet(charm_environment: CharmEnvironment):
    charm, mocks = charm_environment
    mock_event = MagicMock()

    mocks["_check_kubecontrol_integration"].return_value = True
    dns_config = {
        "port": 53,
        "domain": "cluster.local",
        "sdn-ip": "10.0.0.10",
        "enable-kube-dns": True,
    }

    with patch.multiple(
        charm.kube_control,
        get_dns=MagicMock(return_value=dns_config),
        get_registry_location=MagicMock(return_value="myregistry.com"),
    ):
        with patch.object(
            ContainerRuntimeProvides,
            "socket",
            new_callable=PropertyMock,
            return_value="test_my_socket",
        ):
            charm._configure_kubelet(mock_event)

            mocks["kubernetes_snaps"].configure_kubelet.assert_called_with(
                container_runtime_endpoint="test_my_socket",
                dns_domain="cluster.local",
                dns_ip="10.0.0.10",
                extra_args_config="",
                extra_config={},
                external_cloud_provider=charm.external_cloud_provider,
                kubeconfig="/root/cdk/kubeconfig",
                node_ip="10.0.0.10",
                registry="myregistry.com",
                taints=None,
            )


@pytest.mark.skip_configure_kubeproxy
def test__configure_kubeproxy(charm_environment: CharmEnvironment):
    charm, mocks = charm_environment
    mock_event = MagicMock()
    mocks["_check_kubecontrol_integration"].return_value = True
    with patch.object(
        KubernetesCniProvides, "cidr", new_callable=PropertyMock, return_value="192.168.0.0/16"
    ):
        charm._configure_kubeproxy(mock_event)
        mocks["kubernetes_snaps"].configure_kube_proxy.assert_called_with(
            cluster_cidr="192.168.0.0/16",
            extra_args_config="",
            extra_config={},
            kubeconfig="/root/cdk/kubeproxyconfig",
            external_cloud_provider=charm.external_cloud_provider,
        )


@pytest.mark.skip_create_kubeconfigs
def test__create_kubeconfigs(charm_environment: CharmEnvironment):
    charm, mocks = charm_environment
    mock_event = MagicMock()

    auth_credentials = {
        "user": "foo",
        "kubelet_token": "test_kubelet_token",
        "proxy_token": "test_kubeproxy_token",
        "client_token": "test_client_token",
    }

    with patch.object(
        CertificatesRequires, "ca", new_callable=PropertyMock, return_value="test_ca"
    ), patch.object(
        charm.kube_control, "get_auth_credentials", return_value=auth_credentials
    ), patch.object(
        charm.kube_control, "get_api_endpoints", return_value=["10.0.0.10", "10.1.1.10"]
    ):
        charm._create_kubeconfigs(mock_event)

        calls = [
            call(
                dest="/home/ubuntu/.kube/config",
                ca="test_ca",
                server="10.0.0.10",
                user="ubuntu",
                token="test_client_token",
            ),
            call(
                dest="/root/.kube/config",
                ca="test_ca",
                server="10.0.0.10",
                user="root",
                token="test_client_token",
            ),
            call(
                dest="/root/cdk/kubeconfig",
                ca="test_ca",
                server="10.0.0.10",
                user="kubelet",
                token="test_kubelet_token",
            ),
            call(
                dest="/root/cdk/kubeproxyconfig",
                ca="test_ca",
                server="10.0.0.10",
                user="kube-proxy",
                token="test_kubeproxy_token",
            ),
        ]

        mocks["kubernetes_snaps"].create_kubeconfig.assert_has_calls(calls)


def test__get_unit_number(charm_environment: CharmEnvironment):
    charm, _ = charm_environment
    result = charm._get_unit_number()
    assert result == 0


@pytest.mark.skip_request_kubelet_and_proxy_credentials
def test__request_kubelet_and_proxy_credentials(charm_environment: CharmEnvironment):
    charm, mocks = charm_environment
    with patch.object(charm.kube_control, "set_auth_request") as mock_set_auth:
        mocks["kubernetes_snaps"].get_node_name.return_value = "foo"
        charm._request_kubelet_and_proxy_credentials()
        mock_set_auth.assert_called_with("system:node:foo")
