import pytest
from unittest.mock import patch
from reactive import kubernetes_worker
from charms.reactive import set_flag, clear_flag
from charmhelpers.core import hookenv


def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with patch(patch_target) as m:
            yield m
    return _fixture


kubectl = patch_fixture('reactive.kubernetes_worker.kubectl')


def test_series_upgrade(kubectl):
    assert kubectl.call_count == 0
    assert kubernetes_worker.service_pause.call_count == 0
    assert kubernetes_worker.service_resume.call_count == 0
    kubernetes_worker.pre_series_upgrade()
    assert kubectl.call_count == 1
    assert kubernetes_worker.service_pause.call_count == 2
    assert kubernetes_worker.service_resume.call_count == 0
    kubernetes_worker.post_series_upgrade()
    assert kubectl.call_count == 2
    assert kubernetes_worker.service_pause.call_count == 2
    assert kubernetes_worker.service_resume.call_count == 2


def test_status_set_on_missing_ca():
    """Test that set_final_status() will set blocked state if CA is missing"""

    set_flag("certificates.available")
    kubernetes_worker.charm_status()
    hookenv.status_set.assert_called_with('blocked',
                                          'Connect a container runtime.')
    clear_flag("certificates.available")
    kubernetes_worker.charm_status()
    hookenv.status_set.assert_called_with('blocked',
                                          'Missing relation to certificate '
                                          'authority.')
