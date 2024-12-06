# Copyright 2024 Canonical
# See LICENSE file for licensing details.

"""Upgrade action for Kubernetes Worker."""

import charms.contextual_status as status
import ops
from charms import kubernetes_snaps


def upgrade_action(charm, event: ops.ActionEvent):
    """Handle the upgrade action."""
    channel = event.framework.model.config.get("channel")
    with status.context(charm.unit):
        kubernetes_snaps.upgrade_snaps(channel=channel, event=event)
    if isinstance(charm.unit.status, ops.ActiveStatus):
        # After successful upgrade, reconcile the charm to ensure it is in the desired state
        charm.reconciler.reconcile(event)
