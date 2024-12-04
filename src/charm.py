#!/usr/bin/env python3
# Copyright 2023 Canonical
# See LICENSE file for licensing details.

"""Charmed Machine Operator for Kubernetes Worker."""

import logging
import os
import shlex
import subprocess
from base64 import b64encode
from pathlib import Path
from socket import gethostname
from subprocess import CalledProcessError

import charms.contextual_status as status
import ops
import yaml
from charms import kubernetes_snaps
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.interface_container_runtime import ContainerRuntimeProvides
from charms.interface_external_cloud_provider import ExternalCloudProvider
from charms.interface_kubernetes_cni import KubernetesCniProvides
from charms.interface_tokens import TokensRequirer
from charms.node_base import LabelMaker
from charms.reconciler import Reconciler
from jinja2 import Environment, FileSystemLoader
from ops.interface_kube_control import KubeControlRequirer
from ops.interface_tls_certificates import CertificatesRequires

from cloud_integration import CloudIntegration
from cos_integration import COSIntegration
from http_provides import HttpProvides
from kubectl import kubectl

log = logging.getLogger(__name__)

ROOT_KUBECONFIG_PATH = Path("/root/.kube/config")
UBUNTU_KUBECONFIG_PATH = Path("/home/ubuntu/.kube/config")
KUBELET_KUBECONFIG_PATH = Path("/root/cdk/kubeconfig")
KUBEPROXY_KUBECONFIG_PATH = Path("/root/cdk/kubeproxyconfig")

OBSERVABILITY_GROUP = "system:cos"


class KubernetesWorkerCharm(ops.CharmBase):
    """Charmed Operator for Kubernetes Worker."""

    def __init__(self, *args):
        """Start entrypoint for Kubernetes Worker!"""
        super().__init__(*args)
        self.certificates = CertificatesRequires(self, endpoint="certificates")
        self.cni = KubernetesCniProvides(self, endpoint="cni", default_cni="")
        self.container_runtime = ContainerRuntimeProvides(self, endpoint="container-runtime")
        self.cos_integration = COSIntegration(self)
        self.cos_agent = COSAgentProvider(
            self,
            relation_name="cos-agent",
            scrape_configs=self._get_scrape_jobs,
            refresh_events=[
                self.on.kube_control_relation_joined,
                self.on.kube_control_relation_changed,
                self.on.tokens_relation_joined,
                self.on.tokens_relation_changed,
                self.on.upgrade_charm,
            ],
        )
        self.external_cloud_provider = ExternalCloudProvider(self, "kube-control")
        self.ingress_proxy = HttpProvides(self, "ingress-proxy")
        self.kube_control = KubeControlRequirer(self)
        self.label_maker = LabelMaker(self, kubeconfig_path=ROOT_KUBECONFIG_PATH)
        self.cloud_integration = CloudIntegration(self)
        self.tokens = TokensRequirer(self)
        self.reconciler = Reconciler(self, self.reconcile)
        self.framework.observe(self.on.update_status, self.update_status)
        self.framework.observe(self.on.upgrade_action, self._on_upgrade_action)

    def _check_kubecontrol_integration(self, event) -> bool:
        """Check the integration status with kube-control."""
        log.info("Checking kube-control integration")
        evaluation = self.kube_control.evaluate_relation(event)
        if evaluation:
            current_status = (
                ops.WaitingStatus(evaluation)
                if "Waiting" in evaluation
                else ops.BlockedStatus(evaluation)
            )
            status.add(current_status)
            return False
        return True

    def _check_tokens_integration(self, event) -> bool:
        """Check the integration status with tokens."""
        log.info("Checking tokens integration")
        evaluation = self.tokens.evaluate_relation(event)
        if not evaluation:
            return True
        if any(e in evaluation for e in ("Waiting", "Token request")):
            status.add(ops.WaitingStatus(evaluation))
        return False

    @status.on_error(ops.BlockedStatus("Missing CNI Integration"))
    def _configure_cni(self):
        """Configure the CNI integration databag."""
        if not (self.cni and self.cni.default_relation):
            raise status.ReconcilerError("CNI relation not established")
        status.add(ops.MaintenanceStatus("Configuring CNI"))
        registry = self.kube_control.get_registry_location()
        self.cni.set_image_registry(registry)
        self.cni.set_kubeconfig_hash_from_file(str(ROOT_KUBECONFIG_PATH))
        kubernetes_snaps.set_default_cni_conf_file(self.kube_control.get_default_cni())

    @status.on_error(ops.BlockedStatus("Missing container-runtime integration"))
    def _configure_container_runtime(self):
        """Configure the container runtime in the node."""
        if not self.container_runtime.relations:
            raise status.ReconcilerError("container-runtime not established")
        status.add(ops.MaintenanceStatus("Configuring CRI"))
        registry = self.kube_control.get_registry_location()
        sandbox_image = kubernetes_snaps.get_sandbox_image(registry)
        self.container_runtime.set_sandbox_image(sandbox_image)

    def _configure_kernel_parameters(self):
        """Configure the Kernel with the provided configuration."""
        status.add(ops.MaintenanceStatus("Configuring Kernel parameters"))
        sysctl = yaml.safe_load(self.model.config.get("sysctl"))
        kubernetes_snaps.configure_kernel_parameters(sysctl)

    @status.on_error(ops.WaitingStatus("Waiting for kube-control relation"))
    def _configure_kubelet(self, event):
        """Configure kubelet with the configuration parameters."""
        status.add(ops.MaintenanceStatus("Configuring kubelet"))
        if not self._check_kubecontrol_integration(event):
            raise status.ReconcilerError("kube-control not ready")

        dns = self.kube_control.get_dns()
        kubernetes_snaps.configure_kubelet(
            container_runtime_endpoint=self.container_runtime.socket,
            dns_domain=dns.get("domain"),
            dns_ip=dns.get("sdn-ip"),
            extra_args_config=self.model.config.get("kubelet-extra-args"),
            extra_config=yaml.safe_load(self.model.config.get("kubelet-extra-config")),
            external_cloud_provider=self.external_cloud_provider,
            kubeconfig=str(KUBELET_KUBECONFIG_PATH),
            node_ip=self.model.get_binding("kube-control").network.ingress_address.exploded,
            registry=self.kube_control.get_registry_location(),
            taints=None,
        )

    @status.on_error(ops.WaitingStatus("Waiting for kube-control relation"))
    def _configure_kubeproxy(self, event):
        """Configure kube-proxy with the configuration parameters."""
        status.add(ops.MaintenanceStatus("Configuring kube-proxy"))
        if not self._check_kubecontrol_integration(event):
            raise status.ReconcilerError("kube-control not ready")
        kubernetes_snaps.configure_kube_proxy(
            cluster_cidr=self.cni.cidr,
            extra_args_config=self.model.config.get("proxy-extra-args"),
            extra_config=yaml.safe_load(self.model.config.get("proxy-extra-config")),
            kubeconfig=str(KUBEPROXY_KUBECONFIG_PATH),
            external_cloud_provider=self.external_cloud_provider,
        )

    def _apply_node_labels(self):
        """Apply node labels."""
        status.add(ops.MaintenanceStatus("Apply Node Labels"))
        node = self.get_node_name()
        if self.label_maker.active_labels() is not None:
            self.label_maker.apply_node_labels()
            log.info("Node %s labelled successfully", node)
        else:
            log.info("Node %s not yet labelled", node)

    @status.on_error(ops.WaitingStatus("Waiting to configure ingress controller"))
    def _configure_nginx_ingress_controller(self):
        """Configure nginx-ingress-controller."""
        if not ROOT_KUBECONFIG_PATH.exists():
            raise status.ReconcilerError("kubeconfig needed to configuring ingress controller")

        status.add(ops.MaintenanceStatus("Configuring ingress"))

        manifest_dir = "/root/cdk/addons"
        manifest_path = manifest_dir + "/ingress-daemon-set.yaml"

        if self.config["ingress"]:
            image = self.config["nginx-image"]
            if image == "" or image == "auto":
                registry = self.kube_control.get_registry_location() or "registry.k8s.io"
                image = f"{registry}/ingress-nginx/controller:v1.6.4"

            context = {
                "daemonset_api_version": "apps/v1",
                "default_ssl_certificate_option": None,
                "enable_ssl_passthrough": self.config["ingress-ssl-passthrough"],
                "ingress_image": image,
                "ingress_uid": "101",
                "juju_application": self.app.name,
                "ssl_chain_completion": self.config["ingress-ssl-chain-completion"],
                "use_forwarded_headers": (
                    "true" if self.config["ingress-use-forwarded-headers"] else "false"
                ),
            }

            ssl_cert = self.config["ingress-default-ssl-certificate"]
            ssl_key = self.config["ingress-default-ssl-key"]
            if ssl_cert and ssl_key:
                default_cert_option = (
                    "- --default-ssl-certificate=$(POD_NAMESPACE)/default-ssl-certificate"
                )
                context.update(
                    {
                        "default_ssl_certificate": b64encode(ssl_cert.encode("utf-8")).decode(
                            "utf-8"
                        ),
                        "default_ssl_certificate_option": default_cert_option,
                        "default_ssl_key": b64encode(ssl_key.encode("utf-8")).decode("utf-8"),
                    }
                )

            env = Environment(loader=FileSystemLoader("templates"))
            template = env.get_template("ingress-daemon-set.yaml")
            output = template.render(context)
            os.makedirs(manifest_dir, exist_ok=True)
            with open(manifest_path, "w") as f:
                f.write(output)
            kubectl("apply", "-f", manifest_path)

            self.unit.open_port("tcp", 80)
            self.unit.open_port("tcp", 443)
        else:
            self.unit.close_port("tcp", 80)
            self.unit.close_port("tcp", 443)

            if os.path.exists(manifest_path):
                kubectl("delete", "--ignore-not-found", "-f", manifest_path)
                os.remove(manifest_path)

    @status.on_error(ops.WaitingStatus("Waiting for kube-control relation"))
    def _create_kubeconfigs(self, event):
        """Generate kubeconfig files for the cluster components."""
        if not self.certificates.ca:
            raise status.ReconcilerError("CA Certificate not ready")
        if not self._check_kubecontrol_integration(event):
            raise status.ReconcilerError("kube-control not ready")

        node_user = f"system:node:{self.get_node_name()}"
        credentials = self.kube_control.get_auth_credentials(node_user)
        servers = self.kube_control.get_api_endpoints()
        if not credentials:
            raise status.ReconcilerError("Credentials not ready")
        if not servers:
            raise status.ReconcilerError("API servers not ready")

        status.add(ops.MaintenanceStatus("Generating KubeConfig"))
        server = servers[self._get_unit_number() % len(servers)]

        # Create K8s config in the default location for Ubuntu.
        kubernetes_snaps.create_kubeconfig(
            dest=str(UBUNTU_KUBECONFIG_PATH),
            ca=self.certificates.ca,
            server=server,
            user="ubuntu",
            token=credentials.get("client_token"),
        )
        # Create K8s config in the default location for root.
        kubernetes_snaps.create_kubeconfig(
            dest=str(ROOT_KUBECONFIG_PATH),
            ca=self.certificates.ca,
            server=server,
            user="root",
            token=credentials.get("client_token"),
        )
        # Create K8s config for kubelet and kube-proxy.
        kubernetes_snaps.create_kubeconfig(
            dest=str(KUBELET_KUBECONFIG_PATH),
            ca=self.certificates.ca,
            server=server,
            user="kubelet",
            token=credentials.get("kubelet_token"),
        )
        kubernetes_snaps.create_kubeconfig(
            dest=str(KUBEPROXY_KUBECONFIG_PATH),
            ca=self.certificates.ca,
            server=server,
            user="kube-proxy",
            token=credentials.get("proxy_token"),
        )

    def get_cloud_name(self) -> str:
        """Return cloud name."""
        return self.external_cloud_provider.name

    def _get_scrape_jobs(self):
        node_name = self.get_node_name()
        cos_user = f"system:cos:{self.get_node_name()}"
        token = self.tokens.get_token(cos_user)
        cluster_name = self.kube_control.get_cluster_tag()

        if not token or not cluster_name:
            log.info("COS token not provided by the relation")
            return []

        return self.cos_integration.get_metrics_endpoints(node_name, token, cluster_name)

    def _get_unit_number(self) -> int:
        return int(self.unit.name.split("/")[1])

    @status.on_error(ops.WaitingStatus("Waiting for cluster name"))
    def get_cluster_name(self) -> str:
        """Get the cluster name from the kube-control relation."""
        if not self.kube_control.is_ready:
            raise status.ReconcilerError("kube-control not ready")
        return self.kube_control.get_cluster_tag()

    def get_node_name(self) -> str:
        """Return node name."""
        fqdn = self.external_cloud_provider.name == "aws" and self.external_cloud_provider.has_xcp
        return kubernetes_snaps.get_node_name(fqdn=fqdn)

    @status.on_error(ops.BlockedStatus("cni-plugins resource missing or invalid"))
    def _install_cni_binaries(self):
        try:
            resource_path = self.model.resources.fetch("cni-plugins")
        except (ops.ModelError, NameError):
            log.error("Something went wrong when claiming 'cni-plugins' resource.")
            raise

        unpack_path = Path("/opt/cni/bin")
        unpack_path.mkdir(parents=True, exist_ok=True)

        command = f"tar -xzvf {resource_path} -C {unpack_path} --no-same-owner"
        try:
            subprocess.check_call(shlex.split(command))
        except CalledProcessError:
            log.error("Failed to extract 'cni-plugins'")
            raise

        log.info(f"Extracted 'cni-plugins' to {unpack_path}")

    def _on_upgrade_action(self, event):
        """Handle the upgrade action."""
        channel = self.model.config.get("channel")
        with status.context(self.unit):
            kubernetes_snaps.upgrade_snaps(channel=channel, event=event)
        if isinstance(self.unit.status, ops.ActiveStatus):
            # After successful upgrade, reconcile the charm to ensure it is in the desired state
            self.reconciler.reconcile(event)

    def _request_kubelet_and_proxy_credentials(self):
        """Request authorization for kubelet and kube-proxy."""
        status.add(ops.MaintenanceStatus("Requesting kubelet and kube-proxy credentials"))

        node_user = f"system:node:{self.get_node_name()}"
        self.kube_control.set_auth_request(node_user)

    @status.on_error(ops.WaitingStatus("Waiting for COS token"))
    def _request_monitoring_token(self, event):
        if not self._check_tokens_integration(event):
            return

        status.add(ops.MaintenanceStatus("Requesting COS token"))
        cos_user = f"system:cos:{self.get_node_name()}"
        self.tokens.request_token(cos_user, OBSERVABILITY_GROUP)
        if self.tokens.in_flight_requests():
            raise status.ReconcilerError("Token request in flight")

    def reconcile(self, event):
        """Reconcile state changing events."""
        self._install_cni_binaries()
        kubernetes_snaps.install(channel=self.model.config["channel"])
        kubernetes_snaps.configure_services_restart_always()
        self._request_certificates()
        self._write_certificates()
        self._request_kubelet_and_proxy_credentials()
        self._request_monitoring_token(event)
        self._create_kubeconfigs(event)
        self._configure_cni()
        self._configure_container_runtime()
        self._configure_kernel_parameters()
        self._configure_kubelet(event)
        self._configure_kubeproxy(event)
        self._configure_nginx_ingress_controller()
        self._apply_node_labels()
        self.ingress_proxy.configure(port=80)
        self.cloud_integration.integrate(event)
        self.update_status(event)

    @status.on_error(ops.WaitingStatus("Waiting for certificate authority"))
    def _request_certificates(self):
        """Request client and server certificates."""
        if not self.certificates.ca:
            raise status.ReconcilerError("CA Certificate not ready")

        status.add(ops.MaintenanceStatus("Requesting certificates"))

        bind_addrs = kubernetes_snaps.get_bind_addresses()
        common_name = kubernetes_snaps.get_public_address()

        sans = sorted(set([common_name, gethostname()] + bind_addrs))

        self.certificates.request_server_cert(cn=common_name, sans=sans)
        self.certificates.request_client_cert("system:kubelet")

    def update_status(self, _event):
        """Handle the update status hook event.

        Changes to the unit.status shouldn't be triggered
        here, but any periodic health events may be performed.
        """
        self._set_workload_version()

    @status.on_error(ops.WaitingStatus("Waiting for certificates"))
    def _write_certificates(self):
        """Write certificates from the certificates relation."""
        common_name = kubernetes_snaps.get_public_address()
        ca = self.certificates.ca
        server_cert = self.certificates.server_certs_map.get(common_name)
        client_cert = self.certificates.client_certs_map.get("system:kubelet")
        if not ca:
            raise status.ReconcilerError("CA Certificate not ready")
        if not client_cert:
            raise status.ReconcilerError("Client Cert not ready")
        if not server_cert:
            raise status.ReconcilerError("Server Cert not ready")

        status.add(ops.MaintenanceStatus("Writing certificates"))
        kubernetes_snaps.write_certificates(
            ca=ca,
            client_cert=client_cert.cert,
            client_key=client_cert.key,
            server_cert=server_cert.cert,
            server_key=server_cert.key,
        )

    def _set_workload_version(self):
        cmd = ["kubelet", "--version"]
        try:
            version = subprocess.run(cmd, stdout=subprocess.PIPE)
        except FileNotFoundError:
            log.warning("kubelet not yet found, skip setting workload version")
            return
        if not version.returncode:
            val = version.stdout.split(b" v")[-1].rstrip().decode()
            log.info("Setting workload version to %s.", val)
            self.unit.set_workload_version(val)
        else:
            self.unit.set_workload_version("")


if __name__ == "__main__":  # pragma: nocover
    ops.main(KubernetesWorkerCharm)
