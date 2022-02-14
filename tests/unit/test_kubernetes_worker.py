import pathlib
import unittest.mock
from collections import defaultdict

import pytest
from unittest.mock import patch, ANY
from reactive import kubernetes_worker
from charms.reactive import (  # auto-mocked
    set_flag, clear_flag,
    endpoint_from_flag,
    endpoint_from_name,
)
from charmhelpers.core import hookenv  # auto-mocked
from charms.layer import kubernetes_common  # auto-mocked


def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with patch(patch_target) as m:
            yield m

    return _fixture


kubectl = patch_fixture("reactive.kubernetes_worker.kubectl")


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


@unittest.mock.patch("reactive.kubernetes_worker.check_call")
@unittest.mock.patch("reactive.kubernetes_worker.deprecated_extra_args")
def test_xcp(dea, *_):
    dea.return_value = []
    kubernetes_worker.db.set("credentials", defaultdict(str))
    endpoint_from_flag().has_xcp = False
    endpoint_from_name().services.return_value = [
        {"hosts": [{"hostname": "foo", "port": "80"}]}
    ]
    kubernetes_common.get_unit_number.return_value = 0
    kubernetes_worker.start_worker()
    assert kubernetes_worker.configure_kubelet.called
    assert kubernetes_worker.configure_kubelet.call_args == (ANY, {"has_xcp": False})

    endpoint_from_flag().has_xcp = True
    kubernetes_worker.start_worker()
    assert kubernetes_worker.configure_kubelet.call_args == (ANY, {"has_xcp": True})
