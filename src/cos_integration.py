# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""COS Integration module."""

import logging
from dataclasses import dataclass
from typing import Dict, List

from ops import CharmBase

log = logging.getLogger(__name__)


@dataclass
class JobConfig:
    """Data class representing the configuration for a Prometheus scrape job.

    Attributes:
        name (str): The name of the scrape job. Corresponds to the name of the Kubernetes
                    component being monitored (e.g., 'kube-apiserver').
        metrics_path (str): The endpoint path where the metrics are exposed by the
                            component (e.g., '/metrics').
        scheme (str): The scheme used for the endpoint. (e.g.'http' or 'https').
        target (str): The network address of the target component along with the port.
                      Format is 'hostname:port' (e.g., 'localhost:6443').
        relabel_configs (List[Dict[str, str]]): Additional configurations for relabeling.

    """

    name: str
    metrics_path: str
    scheme: str
    target: str
    relabel_configs: List[Dict[str, str]]


class COSIntegration:
    """Utility class that handles the integration with COS.

    This class provides methods to retrieve and configure Prometheus metrics
    scraping endpoints based on the Kubernetes components running within
    the cluster.

    Attributes:
        charm (CharmBase): Reference to the base charm instance.

    """

    def __init__(self, charm: CharmBase) -> None:
        """Initialize a COSIntegration instance.

        Args:
            charm (CharmBase): A charm object representing the current charm.

        """
        self.charm = charm

    def _create_scrape_job(
        self, config: JobConfig, node_name: str, token: str, cluster_name: str
    ) -> Dict:
        """Create a scrape job configuration.

        Args:
            config (JobConfig): The configuration for the scrape job.
            node_name (str): The name of the node.
            token (str): The token for authorization.
            cluster_name (str): The name of the cluster.

        Returns:
            Dict: The scrape job configuration.

        """
        return {
            "tls_config": {"insecure_skip_verify": True},
            "authorization": {"credentials": token},
            "job_name": config.name,
            "metrics_path": config.metrics_path,
            "scheme": config.scheme,
            "static_configs": [
                {
                    "targets": [config.target],
                    "labels": {
                        "node": node_name,
                        "cluster": cluster_name,
                    },
                }
            ],
            "relabel_configs": config.relabel_configs,
        }

    def get_metrics_endpoints(self, node_name: str, token: str, cluster_name: str) -> List[Dict]:
        """Retrieve Prometheus scrape job configurations for Kubernetes components.

        Args:
            node_name (str): The name of the node.
            token (str): The authentication token.
            cluster_name (str): The name of the cluster.

        Returns:
            List[Dict]: A list of Prometheus scrape job configurations.

        """
        log.info("Building Prometheus scraping jobs.")

        instance_relabel = {
            "source_labels": ["instance"],
            "target_label": "instance",
            "replacement": node_name,
        }

        kubernetes_jobs = [
            JobConfig(
                "kube-proxy",
                "/metrics",
                "http",
                "localhost:10249",
                [{"target_label": "job", "replacement": "kube-proxy"}, instance_relabel],
            ),
        ]
        kubelet_metrics_paths = [
            "/metrics",
            "/metrics/resource",
            "/metrics/cadvisor",
            "/metrics/probes",
        ]
        kubelet_jobs = [
            JobConfig(
                f"kubelet-{metric}" if metric else "kubelet",
                path,
                "https",
                "localhost:10250",
                [
                    {"target_label": "metrics_path", "replacement": path},
                    {"target_label": "job", "replacement": "kubelet"},
                    instance_relabel,
                ],
            )
            for path in kubelet_metrics_paths
            if (metric := path.strip("/metrics")) is not None
        ]

        return [
            self._create_scrape_job(job, node_name, token, cluster_name)
            for job in kubernetes_jobs + kubelet_jobs
        ]
