import pathlib
import unittest.mock

import pytest
from unittest.mock import patch
from reactive import kubernetes_worker
from charms.reactive import endpoint_from_flag, set_flag, clear_flag
from charmhelpers.core import hookenv


def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with patch(patch_target) as m:
            yield m

    return _fixture


kubectl = patch_fixture("reactive.kubernetes_worker.kubectl")


@patch("os.listdir")
@patch("os.remove")
@patch("os.symlink")
def test_configure_default_cni(os_symlink, os_remove, os_listdir):
    os_listdir.return_value = ["05-default.conflist", "10-cni.conflist"]
    kube_control = endpoint_from_flag("kube-control.default_cni.available")
    kube_control.get_default_cni.return_value = "test-cni"
    cni = endpoint_from_flag("cni.available")
    cni.get_config.return_value = {
        "cidr": "192.168.0.0/24",
        "cni-conf-file": "10-cni.conflist",
    }
    kubernetes_worker.configure_default_cni()
    os_remove.assert_called_once_with("/etc/cni/net.d/05-default.conflist")
    os_symlink.assert_called_once_with(
        "10-cni.conflist", "/etc/cni/net.d/05-default.conflist"
    )


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
    hookenv.status_set.assert_called_with("blocked", "Connect a container runtime.")
    clear_flag("certificates.available")
    kubernetes_worker.charm_status()
    hookenv.status_set.assert_called_with(
        "blocked", "Missing relation to certificate " "authority."
    )


@unittest.mock.patch("subprocess.check_output")
def test_deprecated_extra_args(mock_check_output, request):
    def check_output(args, **_kwargs):
        app, _ = args
        test_name = request.node.name
        return (
            pathlib.Path(__file__).parent.parent / "data" / test_name / f"{app}_h"
        ).read_bytes()

    def extra_args(config_key):
        if config_key.startswith("kubelet"):
            return {"v": "1", "log-flush-frequency": "5s", "alsologtostderr": True}
        elif config_key.startswith("proxy"):
            return {
                "v": "1",
                "profiling": True,
                "log-flush-frequency": "5s",
                "log-dir": "/tmp",
            }

    mock_check_output.side_effect = check_output
    kubernetes_worker.parse_extra_args.side_effect = extra_args

    deprecated = kubernetes_worker.deprecated_extra_args()
    assert deprecated == [
        ("kubelet-extra-args", "alsologtostderr"),
        ("proxy-extra-args", "log-dir"),
    ]
