from unittest import mock

import charms.contextual_status as status
import ops
import pytest

from charm import kubernetes_snaps


@mock.patch.object(kubernetes_snaps, "upgrade_snaps")
def test_upgrade_action_success(upgrade_snaps: mock.Mock, harness):
    """Verify that the upgrade action runs the upgrade_snap method and reconciles."""

    def mock_reconciler(_):
        status.add(ops.BlockedStatus("reconciled"))

    harness.begin_with_initial_hooks()
    harness.model.unit.status = ops.model.BlockedStatus("pre-test")
    with mock.patch.object(
        harness.charm.reconciler, "reconcile_function", side_effect=mock_reconciler
    ) as mocked_reconciler:
        harness.run_action("upgrade")
    upgrade_snaps.assert_called_once()
    mocked_reconciler.assert_called_once()
    assert harness.model.unit.status == ops.BlockedStatus("reconciled")


@mock.patch.object(kubernetes_snaps, "upgrade_snaps")
def test_upgrade_action_fails(upgrade_snaps: mock.Mock, harness):
    """Verify that the upgrade action runs the upgrade_snap method and reconciles."""

    def mock_upgrade(channel, event):
        assert channel == harness.charm.config["channel"]
        status.add(ops.BlockedStatus("snap-upgrade-failed"))
        event.fail("snap upgrade failed")

    upgrade_snaps.side_effect = mock_upgrade

    harness.begin_with_initial_hooks()
    harness.model.unit.status = ops.model.BlockedStatus("pre-test")
    with mock.patch.object(harness.charm.reconciler, "reconcile_function") as mocked_reconciler:
        with pytest.raises(ops.testing.ActionFailed) as action_err:
            harness.run_action("upgrade")
    upgrade_snaps.assert_called_once()
    mocked_reconciler.assert_not_called()
    assert action_err.value.message == "snap upgrade failed"
    assert harness.model.unit.status == ops.BlockedStatus("snap-upgrade-failed")
