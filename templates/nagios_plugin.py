#!/usr/bin/env python3

# Copyright (C) 2019 Canonical Ltd.

import nagios_plugin3
import yaml
from subprocess import check_output, CalledProcessError, PIPE

snap_resources = ['kubectl', 'kubelet', 'kube-proxy']


def check_snaps_installed():
    """Confirm the snaps are installed, raise an error if not"""
    for snap_name in snap_resources:
        cmd = ['snap', 'list', snap_name]
        try:
            check_output(cmd).decode('UTF-8')
        except Exception:
            msg = '{} snap is not installed'.format(snap_name)
            raise nagios_plugin3.CriticalError(msg)


def check_node(node):
    # Note: Keep the Ready check first since all checks will fail when not Ready
    checks = [{'name': 'Ready',
               'expected': 'True',
               'type': 'error',
               'error': 'Node Not Ready'},
              {'name': 'MemoryPressure',
               'expected': 'False',
               'type': 'warn',
               'error': 'Memory Pressure'},
              {'name': 'DiskPressure',
               'expected': 'False',
               'type': 'warn',
               'error': 'Disk Pressure'},
              {'name': 'PIDPressure',
               'expected': 'False',
               'type': 'warn',
               'error': 'PID Pressure'},
              ]
    msg = []
    error = False
    for check in checks:
        # find the status that matches
        for s in node['status']['conditions']:
            if s['type'] == check['name']:
                # does it match expectations? If not, toss it on the list
                # of errors so we don't show the first issue, but all.
                if s['status'].lower() != check['expected'].lower():
                    msg.append(check['error'])
                    if check['type'] == 'error':
                        error = True
                else:
                    break
        else:
            err_msg = 'Unable to find status for {}'.format(check['error'])
            raise nagios_plugin3.CriticalError(err_msg)

    if msg:
        if error:
            raise nagios_plugin3.CriticalError(msg)
        else:
            raise nagios_plugin3.WarnError(msg)


def verify_node_registered_and_ready():
    node = None
    try:
        cmd = [
            "/snap/bin/kubectl", "--kubeconfig", "/var/lib/nagios/.kube/config",
            "get", "no", "{{node_name}}", "-o=yaml"
        ]
        node = yaml.safe_load(check_output(cmd, stderr=PIPE))
    except CalledProcessError as e:
        err = e.stderr.decode('UTF-8')
        if "not found" in err:
            raise nagios_plugin3.CriticalError("Unable to find "
                                               "node registered on API server")
    if not node:
        raise nagios_plugin3.CriticalError("Unable to run kubectl "
                                           "and parse output")
    return check_node(node)


def main():
    nagios_plugin3.try_check(check_snaps_installed)
    nagios_plugin3.try_check(verify_node_registered_and_ready)
    print("OK - No memory, disk, or PID pressure. Registered with API server")


if __name__ == "__main__":
    main()
