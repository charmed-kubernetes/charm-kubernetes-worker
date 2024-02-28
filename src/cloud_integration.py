# Copyright 2024 Canonical
# See LICENSE file for licensing details.

"""Cloud Integration for Charmed Kubernetes Worker."""

import logging

import charms.contextual_status as status
import ops
from ops.interface_aws.requires import AWSIntegrationRequires

log = logging.getLogger(__name__)


class CloudIntegration:
    """Utility class that handles the integration with clouds for Charmed Kubernetes.

    This class provides methods to configure instance tags and roles for control-plane
    units

    Attributes:
        charm (CharmBase): Reference to the base charm instance.
        aws (AWSIntegrationRequires): Reference to relation integration
        gcp (GCPIntegrationRequires): Reference to relation integration
        azure (AzureIntegrationRequires): Reference to relation integration
    """

    def __init__(self, charm: ops.CharmBase) -> None:
        """Integrate with all possible clouds."""
        self.charm = charm
        self.aws = AWSIntegrationRequires(charm)
        self.gcp = None  # GCPIntegrationRequires(charm)
        self.azure = None  # AzureIntegrationRequires(charm)

    def integrate(self):
        """Request tags and permissions for a control-plane node."""
        cluster_tag = self.charm.get_cluster_name()
        cloud_name = self.charm.get_cloud_name()
        cloud_support = {
            "aws": self.aws,
        }

        if not (cloud := cloud_support.get(cloud_name)):
            log.error(
                "Skipping Cloud integration: unsupported cloud %s",
            )

        if not cloud.relation:
            log.info(
                "Skipping Cloud integration: Needs an active %s relation to integrate.", cloud_name
            )
            return

        status.add(ops.MaintenanceStatus(f"Integrate with {cloud}"))
        if cloud_name == "aws":
            cloud.tag_instance(
                {
                    f"kubernetes.io/cluster/{cluster_tag}": "owned",
                }
            )
            cloud.tag_instance_security_group(
                {
                    f"kubernetes.io/cluster/{cluster_tag}": "owned",
                }
            )
            cloud.tag_instance_subnet(
                {
                    f"kubernetes.io/cluster/{cluster_tag}": "owned",
                }
            )
            cloud.enable_object_storage_management(["kubernetes-*"])
        elif cloud_name == "gcp":
            cloud.tag_instance(
                {
                    "k8s-io-cluster-name": cluster_tag,
                }
            )
            cloud.enable_object_storage_management()
        elif cloud_name == "azure":
            cloud.tag_instance(
                {
                    "k8s-io-cluster-name": cluster_tag,
                }
            )
            cloud.enable_object_storage_management()
        cloud.enable_instance_inspection()
        cloud.enable_dns_management()
