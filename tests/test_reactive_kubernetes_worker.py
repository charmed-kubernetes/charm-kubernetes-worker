import pytest
from unittest import mock

from reactive.kubernetes_worker import open_close_ports_if_needed

def patch_fixture(patch_target):
    @pytest.fixture()
    def _fixture():
        with mock.patch(patch_target) as m:
            yield m
    return _fixture


mock_close_port   = patch_fixture('charmhelpers.core.hookenv.close_port')
mock_open_port    = patch_fixture('charmhelpers.core.hookenv.open_port')
mock_config_get   = patch_fixture('charmhelpers.core.hookenv.config')
mock_opened_ports = patch_fixture('charmhelpers.core.hookenv.opened_ports')
mock_log          = patch_fixture('charmhelpers.core.hookenv.log')

def test_open_close_ports_dup_in_config(mock_close_port,
                                        mock_open_port,
                                        mock_config_get,
                                        mock_opened_ports,
                                        mock_log):
    # Test dups on config + real icmp entry on opened_ports
    mock_opened_ports.return_value = ["80/tcp", "80/udp", "443/tcp","icmp"]
    # Check if spaces are processed correctly
    mock_config_get.return_value = {
        "open-ports": "80, 80,443",
    }
    # Should not call 80 but close 443
    open_close_ports_if_needed()
    mock_open_port.assert_not_called()
    mock_close_port.assert_called_with("icmp")


def test_open_close_ports_non_digits(mock_close_port,
                                     mock_open_port,
                                     mock_config_get,
                                     mock_opened_ports,
                                     mock_log):
    # Test dups on config + real icmp entry on opened_ports
    mock_opened_ports.return_value = ["80/tcp", "80/udp", "443","icmp"]
    mock_config_get.return_value = {
        "open-ports": "80,error",
    }
    open_close_ports_if_needed()
    mock_log.assert_called_with("[WARN] open-ports: port error must have only digits, ignoring port...")
        
        
