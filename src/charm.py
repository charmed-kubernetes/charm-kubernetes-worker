#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""Charmed Machine Operator for Kubernetes Worker."""

import logging
from pathlib import Path
from socket import gethostname

import charms.contextual_status as status
import ops
import yaml
from charms import kubernetes_snaps
from charms.interface_container_runtime import ContainerRuntimeProvides
from charms.interface_kubernetes_cni import KubernetesCniProvides
from charms.reconciler import BlockedStatus, Reconciler
from ops.interface_kube_control import KubeControlRequirer
from ops.interface_tls_certificates import CertificatesRequires
from ops.model import MaintenanceStatus, WaitingStatus

log = logging.getLogger(__name__)

ROOT_KUBECONFIG_PATH = Path("/root/.kube/config")
UBUNTU_KUBECONFIG_PATH = Path("/home/ubuntu/.kube/config")
KUBELET_KUBECONFIG_PATH = Path("/root/cdk/kubeconfig")
KUBEPROXY_KUBECONFIG_PATH = Path("/root/cdk/kubeproxyconfig")


class KubernetesWorkerCharm(ops.CharmBase):
    """Charmed Operator for Kubernetes Worker."""

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = CertificatesRequires(self, endpoint="certificates")
        self.cni = KubernetesCniProvides(self, endpoint="cni", default_cni="")
        self.container_runtime = ContainerRuntimeProvides(self, endpoint="container-runtime")
        self.kube_control = KubeControlRequirer(self)
        self.reconciler = Reconciler(self, self.reconcile)

    def _check_kubecontrol_integration(self, event) -> bool:
        """Check the integration status with kube-control."""
        log.info("Checking kube-control integration")
        evaluation = self.kube_control.evaluate_relation(event)
        if evaluation:
            current_status = (
                WaitingStatus(evaluation) if "Waiting" in evaluation else BlockedStatus(evaluation)
            )
            status.add(current_status)
            log.info(f"kube-control integration status: {evaluation}")
            return False
        return True

    def _configure_cni(self):
        """Configure the CNI integration databag."""
        registry = self.kube_control.get_registry_location()
        if registry:
            self.cni.set_image_registry(registry)
            self.cni.set_kubeconfig_hash_from_file(str(ROOT_KUBECONFIG_PATH))
            kubernetes_snaps.set_default_cni_conf_file(self.kube_control.get_default_cni())

    def _configure_container_runtime(self):
        """Configure the container runtime in the node."""
        if not self.container_runtime.relations:
            status.add(BlockedStatus("Missing container-runtime integration"))
            return

        registry = self.kube_control.get_registry_location()
        if registry:
            sandbox_image = kubernetes_snaps.get_sandbox_image(registry)
            self.container_runtime.set_sandbox_image(sandbox_image)

    def _configure_kernel_parameters(self):
        """Configure the Kernel with the provided configuration."""
        status.add(MaintenanceStatus("Configuring Kernel parameters"))

        sysctl = yaml.safe_load(self.model.config.get("sysctl"))
        kubernetes_snaps.configure_kernel_parameters(sysctl)

    def _configure_kubelet(self, event):
        """Configure kubelet with the configuration parameters."""
        status.add(MaintenanceStatus("Configuring kubelet"))
        if not self._check_kubecontrol_integration(event):
            return

        dns = self.kube_control.get_dns()
        kubernetes_snaps.configure_kubelet(
            container_runtime_endpoint=self.container_runtime.socket,
            dns_domain=dns.get("domain"),
            dns_ip=dns.get("sdn-ip"),
            extra_args_config=self.model.config.get("kubelet-extra-args"),
            extra_config=yaml.safe_load(self.model.config.get("kubelet-extra-config")),
            has_xcp=self.kube_control.has_xcp,
            kubeconfig=str(KUBELET_KUBECONFIG_PATH),
            node_ip=self.model.get_binding("kube-control").network.ingress_address.exploded,
            registry=self.kube_control.get_registry_location(),
            taints=None,
        )

    def _configure_kubeproxy(self, event):
        """Configure kube-proxy with the configuration parameters."""
        status.add(MaintenanceStatus("Configuring kube-proxy"))
        if not self._check_kubecontrol_integration(event):
            return
        kubernetes_snaps.configure_kube_proxy(
            cluster_cidr=self.cni.cidr,
            extra_args_config=self.model.config.get("proxy-extra-args"),
            extra_config=yaml.safe_load(self.model.config.get("proxy-extra-config")),
            kubeconfig=str(KUBEPROXY_KUBECONFIG_PATH),
        )

    def _create_kubeconfigs(self, event):
        """Generate kubeconfig files for the cluster components."""
        status.add(MaintenanceStatus("Generating Kubeconfig"))
        ca = self.certificates.ca
        if not ca:
            status.add(WaitingStatus("Waiting for certificates"))
            return

        if not self._check_kubecontrol_integration(event):
            return

        node_user = f"system:node:{kubernetes_snaps.get_node_name()}"
        credentials = self.kube_control.get_auth_credentials(node_user)
        if not credentials:
            status.add(WaitingStatus("Waiting for kube-control credentials"))
            return False

        servers = self.kube_control.get_api_endpoints()
        if not servers:
            status.add(WaitingStatus("Waiting for API endpoints URLs"))
            return

        server = servers[self._get_unit_number() % len(servers)]

        # Create K8s config in the default location for Ubuntu.
        kubernetes_snaps.create_kubeconfig(
            dest=str(UBUNTU_KUBECONFIG_PATH),
            ca=ca,
            server=server,
            user="ubuntu",
            token=credentials.get("client_token"),
        )
        # Create K8s config in the default location for root.
        kubernetes_snaps.create_kubeconfig(
            dest=str(ROOT_KUBECONFIG_PATH),
            ca=ca,
            server=server,
            user="root",
            token=credentials.get("client_token"),
        )
        # Create K8s config for kubelet and kube-proxy.
        kubernetes_snaps.create_kubeconfig(
            dest=str(KUBELET_KUBECONFIG_PATH),
            ca=ca,
            server=server,
            user="kubelet",
            token=credentials.get("kubelet_token"),
        )
        kubernetes_snaps.create_kubeconfig(
            dest=str(KUBEPROXY_KUBECONFIG_PATH),
            ca=ca,
            server=server,
            user="kube-proxy",
            token=credentials.get("proxy_token"),
        )

    def _get_unit_number(self) -> int:
        return int(self.unit.name.split("/")[1])

    def _request_kubelet_and_proxy_credentials(self):
        """Request authorization for kubelet and kube-proxy."""
        status.add(MaintenanceStatus("Requesting kubelet and kube-proxy credentials"))

        node_user = f"system:node:{kubernetes_snaps.get_node_name()}"
        self.kube_control.set_auth_request(node_user)

    def reconcile(self, event):
        """Reconcile state changing events."""
        kubernetes_snaps.install(channel=self.model.config["channel"])
        kubernetes_snaps.configure_services_restart_always()
        self._request_certificates()
        self._write_certificates()
        self._request_kubelet_and_proxy_credentials()
        self._create_kubeconfigs(event)
        self._configure_cni()
        self._configure_container_runtime()
        self._configure_kernel_parameters()
        self._configure_kubelet(event)
        self._configure_kubeproxy(event)

    def _request_certificates(self):
        """Request client and server certificates."""
        status.add(MaintenanceStatus("Requesting certificates"))
        if not self.certificates.relation:
            status.add(BlockedStatus("Missing integration to certificate authority."))
            return

        bind_addrs = kubernetes_snaps.get_bind_addresses()
        common_name = kubernetes_snaps.get_public_address()

        sans = sorted(set([common_name, gethostname()] + bind_addrs))

        self.certificates.request_server_cert(cn=common_name, sans=sans)
        self.certificates.request_client_cert("system:kubelet")

    def _write_certificates(self):
        """Write certificates from the certificates relation."""
        status.add(MaintenanceStatus("Writing certificates"))

        common_name = kubernetes_snaps.get_public_address()
        ca = self.certificates.ca
        server_cert = self.certificates.server_certs_map.get(common_name)
        client_cert = self.certificates.client_certs_map.get("system:kubelet")

        if not ca or not server_cert or not client_cert:
            status.add(WaitingStatus("Waiting for certificates"))
            log.info("Certificates are not yet available.")
            return

        kubernetes_snaps.write_certificates(
            ca=ca,
            client_cert=client_cert.cert,
            client_key=client_cert.key,
            server_cert=server_cert.cert,
            server_key=server_cert.key,
        )


if __name__ == "__main__":  # pragma: nocover
    ops.main(KubernetesWorkerCharm)
