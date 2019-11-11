#!/usr/bin/env python

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import shutil
import subprocess
import time
import traceback
import yaml

from subprocess import check_call, check_output
from subprocess import CalledProcessError
from socket import gethostname

import charms.coordinator
from charms import layer
from charms.layer import snap
from charms.reactive import hook
from charms.reactive import endpoint_from_flag
from charms.reactive import remove_state, clear_flag
from charms.reactive import set_state, set_flag
from charms.reactive import is_state
from charms.reactive import when, when_any, when_not, when_none
from charms.reactive import data_changed
from charms.templating.jinja2 import render

from charmhelpers.core import hookenv, unitdata
from charmhelpers.core.host import service_stop, service_restart
from charmhelpers.contrib.charmsupport import nrpe

from charms.layer.kubernetes_common import kubeclientconfig_path
from charms.layer.kubernetes_common import migrate_resource_checksums
from charms.layer.kubernetes_common import check_resources_for_upgrade_needed
from charms.layer.kubernetes_common import calculate_and_store_resource_checksums  # noqa
from charms.layer.kubernetes_common import get_ingress_address
from charms.layer.kubernetes_common import create_kubeconfig
from charms.layer.kubernetes_common import kubectl
from charms.layer.kubernetes_common import arch, get_node_name
from charms.layer.kubernetes_common import configure_kubernetes_service
from charms.layer.kubernetes_common import parse_extra_args
from charms.layer.kubernetes_common import cloud_config_path
from charms.layer.kubernetes_common import write_gcp_snap_config
from charms.layer.kubernetes_common import write_azure_snap_config
from charms.layer.kubernetes_common import kubeproxyconfig_path
from charms.layer.kubernetes_common import configure_kube_proxy
from charms.layer.kubernetes_common import get_version
from charms.layer.kubernetes_common import ca_crt_path
from charms.layer.kubernetes_common import server_crt_path
from charms.layer.kubernetes_common import server_key_path
from charms.layer.kubernetes_common import client_crt_path
from charms.layer.kubernetes_common import client_key_path
from charms.layer.kubernetes_common import get_unit_number

from charms.layer.nagios import install_nagios_plugin_from_text
from charms.layer.nagios import remove_nagios_plugin

# Override the default nagios shortname regex to allow periods, which we
# need because our bin names contain them (e.g. 'snap.foo.daemon'). The
# default regex in charmhelpers doesn't allow periods, but nagios itself does.
nrpe.Check.shortname_re = r'[\.A-Za-z0-9-_]+$'
nrpe_kubeconfig_path = '/var/lib/nagios/.kube/config'

kubeconfig_path = '/root/cdk/kubeconfig'
gcp_creds_env_key = 'GOOGLE_APPLICATION_CREDENTIALS'
snap_resources = ['kubectl', 'kubelet', 'kube-proxy']
worker_services = ('kubelet', 'kube-proxy')
checksum_prefix = 'kubernetes-worker.resource-checksums.'
configure_prefix = 'kubernetes-worker.prev_args.'
cpu_manager_state = "/var/lib/kubelet/cpu_manager_state"

cohort_snaps = ['kubectl', 'kubelet', 'kube-proxy']

os.environ['PATH'] += os.pathsep + os.path.join(os.sep, 'snap', 'bin')
db = unitdata.kv()


@hook('upgrade-charm')
def upgrade_charm():
    # migrate to new flags
    if is_state('kubernetes-worker.restarted-for-cloud'):
        remove_state('kubernetes-worker.restarted-for-cloud')
        set_state('kubernetes-worker.cloud.ready')
    if is_state('kubernetes-worker.cloud-request-sent'):
        # minor change, just for consistency
        remove_state('kubernetes-worker.cloud-request-sent')
        set_state('kubernetes-worker.cloud.request-sent')

    set_state('config.changed.install_from_upstream')
    hookenv.atexit(remove_state, 'config.changed.install_from_upstream')

    cleanup_pre_snap_services()
    migrate_resource_checksums(checksum_prefix, snap_resources)
    if check_resources_for_upgrade_needed(checksum_prefix, snap_resources):
        set_upgrade_needed()

    # Remove the RC for nginx ingress if it exists
    if hookenv.config().get('ingress'):
        set_state('kubernetes-worker.remove-old-ingress')

    # Remove gpu.enabled state so we can reconfigure gpu-related kubelet flags,
    # since they can differ between k8s versions
    if is_state('kubernetes-worker.gpu.enabled'):
        remove_state('kubernetes-worker.gpu.enabled')
        try:
            disable_gpu()
        except ApplyNodeLabelFailed:
            # Removing node label failed. Probably the master is unavailable.
            # Proceed with the upgrade in hope GPUs will still be there.
            hookenv.log('Failed to remove GPU labels. Proceed with upgrade.')

    if hookenv.config('ingress'):
        set_state('kubernetes-worker.ingress.enabled')
    else:
        remove_state('kubernetes-worker.ingress.enabled')

    # force certs to be updated
    if is_state('certificates.available') and \
       is_state('kube-control.connected'):
        send_data()

    if is_state('kubernetes-worker.registry.configured'):
        set_state('kubernetes-master-worker-base.registry.configured')
        remove_state('kubernetes-worker.registry.configured')

    remove_state('kubernetes-worker.cni-plugins.installed')
    remove_state('kubernetes-worker.config.created')
    remove_state('kubernetes-worker.ingress.available')
    remove_state('worker.auth.bootstrapped')
    set_state('kubernetes-worker.restart-needed')


@when('kubernetes-worker.remove-old-ingress')
def remove_old_ingress():
    try:
        kubectl('delete', 'rc', 'nginx-ingress-controller',
                '--ignore-not-found')

        # these moved into a different namespace for 1.12
        kubectl('delete', 'rc', 'default-http-backend',
                '--ignore-not-found')
        kubectl('delete', 'svc', 'default-http-backend',
                '--ignore-not-found')
        kubectl('delete', 'ds', 'nginx-ingress-{}-controller'.format(
                    hookenv.service_name()), '--ignore-not-found')
        kubectl('delete', 'serviceaccount',
                'nginx-ingress-{}-serviceaccount'.format(
                    hookenv.service_name()), '--ignore-not-found')
        kubectl('delete', 'clusterrolebinding',
                'nginx-ingress-clusterrole-nisa-{}-binding'.format(
                    hookenv.service_name()), '--ignore-not-found')
        kubectl('delete', 'configmap',
                'nginx-load-balancer-{}-conf'.format(
                    hookenv.service_name()), '--ignore-not-found')
    except CalledProcessError:
        # try again next time
        return

    remove_state('kubernetes-worker.remove-old-ingress')


def set_upgrade_needed():
    set_state('kubernetes-worker.snaps.upgrade-needed')
    config = hookenv.config()
    previous_channel = config.previous('channel')
    require_manual = config.get('require-manual-upgrade')
    if previous_channel is None or not require_manual:
        set_state('kubernetes-worker.snaps.upgrade-specified')


def cleanup_pre_snap_services():
    # remove old states
    remove_state('kubernetes-worker.components.installed')

    # disable old services
    services = ['kubelet', 'kube-proxy']
    for service in services:
        hookenv.log('Stopping {0} service.'.format(service))
        service_stop(service)

    # cleanup old files
    files = [
        "/lib/systemd/system/kubelet.service",
        "/lib/systemd/system/kube-proxy.service",
        "/etc/default/kube-default",
        "/etc/default/kubelet",
        "/etc/default/kube-proxy",
        "/usr/local/bin/kubectl",
        "/usr/local/bin/kubelet",
        "/usr/local/bin/kube-proxy",
        "/etc/kubernetes"
    ]
    for file in files:
        if os.path.isdir(file):
            hookenv.log("Removing directory: " + file)
            shutil.rmtree(file)
        elif os.path.isfile(file):
            hookenv.log("Removing file: " + file)
            os.remove(file)


@when('config.changed.channel')
def channel_changed():
    set_upgrade_needed()


@when('kubernetes-worker.snaps.upgrade-specified')
def install_snaps():
    channel = hookenv.config('channel')
    hookenv.status_set('maintenance', 'Installing core snap')
    snap.install('core')
    hookenv.status_set('maintenance', 'Installing kubectl snap')
    snap.install('kubectl', channel=channel, classic=True)
    hookenv.status_set('maintenance', 'Installing kubelet snap')
    snap.install('kubelet', channel=channel, classic=True)
    hookenv.status_set('maintenance', 'Installing kube-proxy snap')
    snap.install('kube-proxy', channel=channel, classic=True)
    calculate_and_store_resource_checksums(checksum_prefix, snap_resources)
    set_state('kubernetes-worker.snaps.installed')
    set_state('kubernetes-worker.restart-needed')
    remove_state('kubernetes-worker.snaps.upgrade-needed')
    remove_state('kubernetes-worker.snaps.upgrade-specified')


@when('kubernetes-worker.snaps.installed',
      'kube-control.cohort_keys.available')
@when_none('coordinator.granted.cohort',
           'coordinator.requested.cohort')
def safely_join_cohort():
    '''Coordinate the rollout of snap refreshes.

    When cohort keys change, grab a lock so that only 1 unit in the
    application joins the new cohort at a time. This allows us to roll out
    snap refreshes without risking all units going down at once.
    '''
    kube_control = endpoint_from_flag('kube-control.cohort_keys.available')

    # It's possible to join a cohort before snapd knows about the snap proxy.
    # When this happens, we'll join a cohort, yet install default snaps. We
    # won't refresh those until the k8s-master keys change. Ensure we always
    # check for available refreshes even if the master keys haven't changed.
    force_join = False
    for snapname in cohort_snaps:
        if snap.is_refresh_available(snapname):
            force_join = True
            break

    cohort_keys = kube_control.cohort_keys
    # NB: initial data-changed is always true
    if data_changed('master-cohorts', cohort_keys) or force_join:
        clear_flag('kubernetes-worker.cohorts.joined')
        charms.coordinator.acquire('cohort')


@when('kubernetes-worker.snaps.installed',
      'kube-control.cohort_keys.available',
      'coordinator.granted.cohort')
@when_not('kubernetes-worker.cohorts.joined')
def join_or_update_cohorts():
    '''Join or update a cohort snapshot.

    All units of this application (leader and followers) need to refresh their
    installed snaps to the current cohort snapshot.
    '''
    kube_control = endpoint_from_flag('kube-control.cohort_keys.available')
    cohort_keys = kube_control.cohort_keys
    for snapname in cohort_snaps:
        hookenv.status_set('maintenance', 'Joining snap cohort.')
        cohort_key = cohort_keys[snapname]
        snap.join_cohort_snapshot(snapname, cohort_key)
    hookenv.log('{} has joined the snap cohort'.format(hookenv.local_unit()))
    set_flag('kubernetes-worker.cohorts.joined')


@hook('stop')
def shutdown():
    ''' When this unit is destroyed:
        - delete the current node
        - stop the worker services
    '''
    try:
        if os.path.isfile(kubeconfig_path):
            kubectl('delete', 'node', get_node_name())
    except CalledProcessError:
        hookenv.log('Failed to unregister node.')
    service_stop('snap.kubelet.daemon')
    service_stop('snap.kube-proxy.daemon')


@when('endpoint.container-runtime.available')
@when_not('kubernetes-worker.cni-plugins.installed')
def install_cni_plugins():
    ''' Unpack the cni-plugins resource '''
    # Get the resource via resource_get
    try:
        resource_name = 'cni-{}'.format(arch())
        archive = hookenv.resource_get(resource_name)
    except Exception:
        message = 'Error fetching the cni resource.'
        hookenv.log(message)
        hookenv.status_set('blocked', message)
        return

    if not archive:
        hookenv.log('Missing cni resource.')
        hookenv.status_set('blocked', 'Missing cni resource.')
        return

    # Handle null resource publication, we check if filesize < 1mb
    filesize = os.stat(archive).st_size
    if filesize < 1000000:
        hookenv.status_set('blocked', 'Incomplete cni resource.')
        return

    hookenv.status_set('maintenance', 'Unpacking cni resource.')

    unpack_path = '/opt/cni/bin'
    os.makedirs(unpack_path, exist_ok=True)
    cmd = ['tar', 'xfvz', archive, '-C', unpack_path]
    hookenv.log(cmd)
    check_call(cmd)

    # Used by the "registry" action. The action is run on a single worker, but
    # the registry pod can end up on any worker, so we need this directory on
    # all the workers.
    os.makedirs('/srv/registry', exist_ok=True)

    set_state('kubernetes-worker.cni-plugins.installed')


@when('kubernetes-worker.snaps.installed')
def set_app_version():
    ''' Declare the application version to juju '''
    cmd = ['kubelet', '--version']
    version = check_output(cmd)
    hookenv.application_version_set(version.split(b' v')[-1].rstrip())


@hookenv.atexit
def charm_status():
    '''Update the status message with the current status of kubelet.'''
    container_runtime_connected = \
        is_state('endpoint.container-runtime.joined')
    vsphere_joined = is_state('endpoint.vsphere.joined')
    azure_joined = is_state('endpoint.azure.joined')
    cloud_blocked = is_state('kubernetes-worker.cloud.blocked')

    if not container_runtime_connected:
        hookenv.status_set('blocked',
                           'Connect a container runtime.')
        return
    if vsphere_joined and cloud_blocked:
        hookenv.status_set('blocked',
                           'vSphere integration requires K8s 1.12 or greater')
        return
    if azure_joined and cloud_blocked:
        hookenv.status_set('blocked',
                           'Azure integration requires K8s 1.11 or greater')
        return
    if is_state('kubernetes-worker.cloud.pending'):
        hookenv.status_set('waiting', 'Waiting for cloud integration')
        return
    if not is_state('kube-control.dns.available'):
        # During deployment the worker has to start kubelet without cluster dns
        # configured. If this is the first unit online in a service pool
        # waiting to self host the dns pod, and configure itself to query the
        # dns service declared in the kube-system namespace
        hookenv.status_set('waiting', 'Waiting for cluster DNS.')
        return
    if is_state('kubernetes-worker.snaps.upgrade-specified'):
        hookenv.status_set('waiting', 'Upgrade pending')
        return
    if is_state('kubernetes-worker.snaps.upgrade-needed'):
        hookenv.status_set('blocked',
                           'Needs manual upgrade, run the upgrade action')
        return
    if is_state('kubernetes-worker.snaps.installed'):
        update_kubelet_status()
        return
    else:
        pass  # will have been set by snap layer or other handler


def deprecated_extra_args():
    '''Returns a list of tuples (config_key, arg) for args that have been set
    via extra-args, but are deprecated.

    This works by parsing help output, which can be brittle. Be cautious when
    calling this.
    '''
    deprecated_args = []
    services = [
        # service       config_key
        ('kubelet',    'kubelet-extra-args'),
        ('kube-proxy', 'proxy-extra-args')
    ]
    for service, config_key in services:
        # Parse help output into a format we can check easily
        cmd = [service, '-h']
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        sections = re.split(r'\n\s*--', output.decode('utf-8'))[1:]
        partitioned_sections = [section.partition(' ') for section in sections]
        arg_help = {part[0]: part[2] for part in partitioned_sections}

        # Check extra-args against the help output
        extra_args = parse_extra_args(config_key)
        for arg in extra_args:
            if arg not in arg_help:
                # This is most likely a problem, though it could also be
                # intentional use of a hidden arg. Let's just log a warning.
                hookenv.log(
                    '%s: %s is missing from help output' % (config_key, arg),
                    level='WARNING'
                )
            elif 'DEPRECATED:' in arg_help[arg]:
                deprecated_args.append((config_key, arg))
    return deprecated_args


def update_kubelet_status():
    ''' There are different states that the kubelet can be in, where we are
    waiting for dns, waiting for cluster turnup, or ready to serve
    applications.'''
    # deprecated_extra_args is brittle, be cautious
    deprecated_args = []
    try:
        deprecated_args = deprecated_extra_args()
    except Exception:
        # this isn't vital, log it and move on
        traceback.print_exc()
    if deprecated_args:
        messages = ['%s: %s is deprecated' % arg for arg in deprecated_args]
        for message in messages:
            hookenv.log(message, level='WARNING')
        status = messages[0]
        if len(messages) > 1:
            other_count = len(messages) - 1
            status += " (+%d others, see juju debug-log)" % other_count
        hookenv.status_set('blocked', status)
        return

    services = [
        'kubelet',
        'kube-proxy'
    ]
    failing_services = []
    for service in services:
        daemon = 'snap.{}.daemon'.format(service)
        if not _systemctl_is_active(daemon):
            failing_services.append(service)
    if failing_services:
        msg = 'Waiting for {} to start.'.format(','.join(failing_services))
        hookenv.status_set('waiting', msg)
        return

    hookenv.status_set('active', 'Kubernetes worker running.')


@when('certificates.available', 'kube-control.connected')
def send_data():
    '''Send the data that is required to create a server certificate for
    this server.'''
    kube_control = endpoint_from_flag('kube-control.connected')

    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = hookenv.unit_public_ip()

    ingress_ip = get_ingress_address(kube_control.endpoint_name)

    # Create SANs that the tls layer will add to the server cert.
    sans = [
        hookenv.unit_public_ip(),
        ingress_ip,
        gethostname()
    ]

    # Request a server cert with this information.
    layer.tls_client.request_server_cert(common_name, sorted(set(sans)),
                                         crt_path=server_crt_path,
                                         key_path=server_key_path)

    # Request a client cert for kubelet.
    layer.tls_client.request_client_cert('system:kubelet',
                                         crt_path=client_crt_path,
                                         key_path=client_key_path)


@when('kube-api-endpoint.available', 'kube-control.dns.available',
      'cni.available', 'endpoint.container-runtime.available')
def watch_for_changes():
    ''' Watch for configuration changes and signal if we need to restart the
    worker services '''
    kube_api = endpoint_from_flag('kube-api-endpoint.available')
    kube_control = endpoint_from_flag('kube-control.dns.available')
    cni = endpoint_from_flag('cni.available')
    container_runtime = \
        endpoint_from_flag('endpoint.container-runtime.available')

    servers = get_kube_api_servers(kube_api)
    dns = kube_control.get_dns()
    cluster_cidr = cni.get_config().get('cidr')
    container_runtime_name = \
        container_runtime.get_runtime()
    container_runtime_socket = \
        container_runtime.get_socket()
    container_runtime_nvidia = \
        container_runtime.get_nvidia_enabled()

    if container_runtime_nvidia:
        set_state('nvidia.ready')
    else:
        remove_state('nvidia.ready')

    if (data_changed('kube-api-servers', servers) or
            data_changed('kube-dns', dns) or
            data_changed('cluster-cidr', cluster_cidr) or
            data_changed('container-runtime', container_runtime_name) or
            data_changed('container-socket', container_runtime_socket)):
        set_state('kubernetes-worker.restart-needed')


@when('kubernetes-worker.snaps.installed', 'kube-api-endpoint.available',
      'tls_client.ca.saved', 'tls_client.certs.saved',
      'kube-control.dns.available', 'kube-control.auth.available',
      'cni.available', 'kubernetes-worker.restart-needed',
      'worker.auth.bootstrapped', 'endpoint.container-runtime.available')
@when_not('kubernetes-worker.cloud.pending',
          'kubernetes-worker.cloud.blocked')
def start_worker():
    ''' Start kubelet using the provided API and DNS info.'''
    # Note that the DNS server doesn't necessarily exist at this point. We know
    # what its IP will eventually be, though, so we can go ahead and configure
    # kubelet with that info. This ensures that early pods are configured with
    # the correct DNS even though the server isn't ready yet.
    kube_api = endpoint_from_flag('kube-api-endpoint.available')
    kube_control = endpoint_from_flag('kube-control.dns.available')
    cni = endpoint_from_flag('cni.available')

    servers = get_kube_api_servers(kube_api)
    dns = kube_control.get_dns()
    ingress_ip = get_ingress_address(kube_control.endpoint_name)
    cluster_cidr = cni.get_config()['cidr']

    if cluster_cidr is None:
        hookenv.log('Waiting for cluster cidr.')
        return

    creds = db.get('credentials')
    data_changed('kube-control.creds', creds)

    create_config(servers[get_unit_number() % len(servers)], creds)
    configure_kubelet(dns, ingress_ip)
    configure_kube_proxy(configure_prefix, servers,
                         cluster_cidr)
    set_state('kubernetes-worker.config.created')
    restart_unit_services()
    update_kubelet_status()
    set_state('kubernetes-worker.label-config-required')
    set_state('nrpe-external-master.reconfigure')
    remove_state('kubernetes-worker.restart-needed')


@when('cni.connected')
@when_not('cni.configured')
def configure_cni(cni):
    ''' Set worker configuration on the CNI relation. This lets the CNI
    subordinate know that we're the worker so it can respond accordingly. '''
    cni.set_config(is_master=False, kubeconfig_path=kubeconfig_path)


@when('config.changed.labels')
def handle_labels_changed():
    set_state('kubernetes-worker.label-config-required')


@when('kubernetes-worker.label-config-required',
      'kubernetes-worker.config.created')
def apply_node_labels():
    ''' Parse the labels configuration option and apply the labels to the
        node. '''
    # Get the user's configured labels.
    config = hookenv.config()
    user_labels = {}
    for item in config.get('labels').split(' '):
        if '=' in item:
            key, val = item.split('=')
            user_labels[key] = val
        else:
            hookenv.log('Skipping malformed option: {}.'.format(item))
    # Collect the current label state.
    current_labels = db.get('current_labels') or {}

    try:
        # Remove any labels that the user has removed from the config.
        for key in list(current_labels.keys()):
            if key not in user_labels:
                remove_label(key)
                del current_labels[key]
                db.set('current_labels', current_labels)

        # Add any new labels.
        for key, val in user_labels.items():
            set_label(key, val)
            current_labels[key] = val
            db.set('current_labels', current_labels)

        # Set the juju-application label.
        set_label('juju-application', hookenv.service_name())

        # Set the juju.io/cloud label.
        if is_state('endpoint.aws.ready'):
            set_label('juju.io/cloud', 'ec2')
        elif is_state('endpoint.gcp.ready'):
            set_label('juju.io/cloud', 'gce')
        elif is_state('endpoint.openstack.ready'):
            set_label('juju.io/cloud', 'openstack')
        elif is_state('endpoint.vsphere.ready'):
            set_label('juju.io/cloud', 'vsphere')
        elif is_state('endpoint.azure.ready'):
            set_label('juju.io/cloud', 'azure')
        else:
            remove_label('juju.io/cloud')
    except ApplyNodeLabelFailed as e:
        hookenv.log(str(e))
        return

    # Label configuration complete.
    remove_state('kubernetes-worker.label-config-required')


@when_any('config.changed.kubelet-extra-args',
          'config.changed.proxy-extra-args',
          'config.changed.kubelet-extra-config')
def config_changed_requires_restart():
    # LP bug #1826833, always delete the state file when extra config changes
    # since CPU manager doesn’t support offlining and onlining of CPUs at runtime.
    if os.path.isfile(cpu_manager_state):
        hookenv.log("Removing file: " + cpu_manager_state)
        os.remove(cpu_manager_state)
    set_state('kubernetes-worker.restart-needed')


@when_any('tls_client.certs.changed',
          'tls_client.ca.written')
def restart_for_certs():
    set_state('kubernetes-worker.restart-needed')
    remove_state('tls_client.certs.changed')
    remove_state('tls_client.ca.written')


def create_config(server, creds):
    '''Create a kubernetes configuration for the worker unit.'''
    # Create kubernetes configuration in the default location for ubuntu.
    create_kubeconfig('/home/ubuntu/.kube/config', server, ca_crt_path,
                      token=creds['client_token'], user='ubuntu')
    # Make the config dir readable by the ubuntu users so juju scp works.
    cmd = ['chown', '-R', 'ubuntu:ubuntu', '/home/ubuntu/.kube']
    check_call(cmd)
    # Create kubernetes configuration in the default location for root.
    create_kubeconfig(kubeclientconfig_path, server, ca_crt_path,
                      token=creds['client_token'], user='root')
    # Create kubernetes configuration for kubelet, and kube-proxy services.
    create_kubeconfig(kubeconfig_path, server, ca_crt_path,
                      token=creds['kubelet_token'], user='kubelet')
    create_kubeconfig(kubeproxyconfig_path, server, ca_crt_path,
                      token=creds['proxy_token'], user='kube-proxy')


def merge_kubelet_extra_config(config, extra_config):
    ''' Updates config to include the contents of extra_config. This is done
    recursively to allow deeply nested dictionaries to be merged.

    This is destructive: it modifies the config dict that is passed in.
    '''
    for k, extra_config_value in extra_config.items():
        if isinstance(extra_config_value, dict):
            config_value = config.setdefault(k, {})
            merge_kubelet_extra_config(config_value, extra_config_value)
        else:
            config[k] = extra_config_value


def configure_kubelet(dns, ingress_ip):
    kubelet_opts = {}
    kubelet_opts['kubeconfig'] = kubeconfig_path
    kubelet_opts['network-plugin'] = 'cni'
    kubelet_opts['v'] = '0'
    kubelet_opts['logtostderr'] = 'true'
    kubelet_opts['node-ip'] = ingress_ip

    container_runtime = \
        endpoint_from_flag('endpoint.container-runtime.available')

    kubelet_opts['container-runtime'] = container_runtime.get_runtime()
    if kubelet_opts['container-runtime'] == 'remote':
        kubelet_opts['container-runtime-endpoint'] = container_runtime.get_socket()

    kubelet_cloud_config_path = cloud_config_path('kubelet')
    if is_state('endpoint.aws.ready'):
        kubelet_opts['cloud-provider'] = 'aws'
    elif is_state('endpoint.gcp.ready'):
        kubelet_opts['cloud-provider'] = 'gce'
        kubelet_opts['cloud-config'] = str(kubelet_cloud_config_path)
    elif is_state('endpoint.openstack.ready'):
        kubelet_opts['cloud-provider'] = 'external'
    elif is_state('endpoint.vsphere.joined'):
        # vsphere just needs to be joined on the worker (vs 'ready')
        kubelet_opts['cloud-provider'] = 'vsphere'
        # NB: vsphere maps node product-id to its uuid (no config file needed).
        uuid_file = '/sys/class/dmi/id/product_uuid'
        with open(uuid_file, 'r') as f:
            uuid = f.read().strip()
        kubelet_opts['provider-id'] = 'vsphere://{}'.format(uuid)
    elif is_state('endpoint.azure.ready'):
        azure = endpoint_from_flag('endpoint.azure.ready')
        kubelet_opts['cloud-provider'] = 'azure'
        kubelet_opts['cloud-config'] = str(kubelet_cloud_config_path)
        kubelet_opts['provider-id'] = azure.vm_id

    if get_version('kubelet') >= (1, 10):
        # Put together the KubeletConfiguration data
        kubelet_config = {
            'apiVersion': 'kubelet.config.k8s.io/v1beta1',
            'kind': 'KubeletConfiguration',
            'address': '0.0.0.0',
            'authentication': {
                'anonymous': {
                    'enabled': False
                },
                'x509': {
                    'clientCAFile': str(ca_crt_path)
                }
            },
            'clusterDomain': dns['domain'],
            'failSwapOn': False,
            'port': 10250,
            'tlsCertFile': str(server_crt_path),
            'tlsPrivateKeyFile': str(server_key_path)
        }
        if dns['enable-kube-dns']:
            kubelet_config['clusterDNS'] = [dns['sdn-ip']]
        if is_state('kubernetes-worker.gpu.enabled'):
            kubelet_config['featureGates'] = {
                'DevicePlugins': True
            }

        # Workaround for DNS on bionic
        # https://github.com/juju-solutions/bundle-canonical-kubernetes/issues/655
        resolv_path = os.path.realpath('/etc/resolv.conf')
        if resolv_path == '/run/systemd/resolve/stub-resolv.conf':
            kubelet_config['resolvConf'] = '/run/systemd/resolve/resolv.conf'

        # Add kubelet-extra-config. This needs to happen last so that it
        # overrides any config provided by the charm.
        kubelet_extra_config = hookenv.config('kubelet-extra-config')
        kubelet_extra_config = yaml.safe_load(kubelet_extra_config)
        merge_kubelet_extra_config(kubelet_config, kubelet_extra_config)

        # Render the file and configure Kubelet to use it
        os.makedirs('/root/cdk/kubelet', exist_ok=True)
        with open('/root/cdk/kubelet/config.yaml', 'w') as f:
            f.write('# Generated by kubernetes-worker charm, do not edit\n')
            yaml.dump(kubelet_config, f)
        kubelet_opts['config'] = '/root/cdk/kubelet/config.yaml'
    else:
        # NOTE: This is for 1.9. Once we've dropped 1.9 support, we can remove
        # this whole block and the parent if statement.
        kubelet_opts['address'] = '0.0.0.0'
        kubelet_opts['anonymous-auth'] = 'false'
        kubelet_opts['client-ca-file'] = str(ca_crt_path)
        kubelet_opts['cluster-domain'] = dns['domain']
        kubelet_opts['fail-swap-on'] = 'false'
        kubelet_opts['port'] = '10250'
        kubelet_opts['tls-cert-file'] = str(server_crt_path)
        kubelet_opts['tls-private-key-file'] = str(server_key_path)
        if dns['enable-kube-dns']:
            kubelet_opts['cluster-dns'] = dns['sdn-ip']
        if is_state('kubernetes-worker.gpu.enabled'):
            kubelet_opts['feature-gates'] = 'DevicePlugins=true'

        # Workaround for DNS on bionic, for k8s 1.9
        # https://github.com/juju-solutions/bundle-canonical-kubernetes/issues/655
        resolv_path = os.path.realpath('/etc/resolv.conf')
        if resolv_path == '/run/systemd/resolve/stub-resolv.conf':
            kubelet_opts['resolv-conf'] = '/run/systemd/resolve/resolv.conf'

    if get_version('kubelet') >= (1, 11):
        kubelet_opts['dynamic-config-dir'] = '/root/cdk/kubelet/dynamic-config'

    # If present, ensure kubelet gets the pause container from the configured
    # registry. When not present, kubelet uses a default image location
    # (currently k8s.gcr.io/pause:3.1).
    registry_location = get_registry_location()
    if registry_location:
        kubelet_opts['pod-infra-container-image'] = \
            '{}/pause-{}:3.1'.format(registry_location, arch())

    configure_kubernetes_service(configure_prefix, 'kubelet', kubelet_opts,
                                 'kubelet-extra-args')


@when('config.changed.ingress')
def toggle_ingress_state():
    ''' Ingress is a toggled state. Remove ingress.available if set when
    toggled '''
    if hookenv.config('ingress'):
        set_state('kubernetes-worker.ingress.enabled')
    else:
        remove_state('kubernetes-worker.ingress.enabled')


@when_any('config.changed.default-backend-image',
          'config.changed.ingress-ssl-chain-completion',
          'config.changed.nginx-image',
          'config.changed.ingress-ssl-passthrough')
def reconfigure_ingress():
    remove_state('kubernetes-worker.ingress.available')


@when('kubernetes-worker.config.created', 'kubernetes-worker.ingress.enabled')
@when_not('kubernetes-worker.ingress.available')
def render_and_launch_ingress():
    ''' Launch the Kubernetes ingress controller & default backend (404) '''
    config = hookenv.config()

    # need to test this in case we get in
    # here from a config change to the image
    if not config.get('ingress'):
        return

    context = {}
    context['arch'] = arch()
    addon_path = '/root/cdk/addons/{}'
    context['juju_application'] = hookenv.service_name()

    # If present, workers will get the ingress containers from the configured
    # registry. Otherwise, we'll set an appropriate upstream image registry.
    registry_location = get_registry_location()

    context['defaultbackend_image'] = config.get('default-backend-image')
    if (context['defaultbackend_image'] == "" or
       context['defaultbackend_image'] == "auto"):
        if registry_location:
            backend_registry = registry_location
        else:
            backend_registry = 'k8s.gcr.io'
        if context['arch'] == 's390x':
            context['defaultbackend_image'] = \
                "{}/defaultbackend-s390x:1.4".format(backend_registry)
        elif context['arch'] == 'arm64':
            context['defaultbackend_image'] = \
                "{}/defaultbackend-arm64:1.5".format(backend_registry)
        else:
            context['defaultbackend_image'] = \
                "{}/defaultbackend-amd64:1.5".format(backend_registry)

    # Render the ingress daemon set controller manifest
    context['ssl_chain_completion'] = config.get(
        'ingress-ssl-chain-completion')
    context['enable_ssl_passthrough'] = config.get(
        'ingress-ssl-passthrough')
    context['ingress_image'] = config.get('nginx-image')
    if context['ingress_image'] == "" or context['ingress_image'] == "auto":
        if registry_location:
            nginx_registry = registry_location
        else:
            nginx_registry = 'quay.io'
        images = {'amd64': 'kubernetes-ingress-controller/nginx-ingress-controller-amd64:0.26.1',  # noqa
                  'arm64': 'kubernetes-ingress-controller/nginx-ingress-controller-arm64:0.26.1',  # noqa
                  's390x': 'kubernetes-ingress-controller/nginx-ingress-controller-s390x:0.20.0',  # noqa
                  'ppc64el': 'kubernetes-ingress-controller/nginx-ingress-controller-ppc64le:0.20.0',  # noqa
                 }
        context['ingress_image'] = '{}/{}'.format(nginx_registry,
                                                  images.get(context['arch'],
                                                             images['amd64']))

    kubelet_version = get_version('kubelet')
    if kubelet_version < (1, 9):
        context['daemonset_api_version'] = 'extensions/v1beta1'
        context['deployment_api_version'] = 'extensions/v1beta1'
    elif kubelet_version < (1, 16):
        context['daemonset_api_version'] = 'apps/v1beta2'
        context['deployment_api_version'] = 'extensions/v1beta1'
    else:
        context['daemonset_api_version'] = 'apps/v1'
        context['deployment_api_version'] = 'apps/v1'
    manifest = addon_path.format('ingress-daemon-set.yaml')
    render('ingress-daemon-set.yaml', manifest, context)
    hookenv.log('Creating the ingress daemon set.')
    try:
        kubectl('apply', '-f', manifest)
    except CalledProcessError as e:
        hookenv.log(e)
        hookenv.log('Failed to create ingress controller. Will attempt again next update.')  # noqa
        hookenv.close_port(80)
        hookenv.close_port(443)
        return

    # Render the default http backend (404) deployment manifest
    # needs to happen after ingress-daemon-set since that sets up the namespace
    manifest = addon_path.format('default-http-backend.yaml')
    render('default-http-backend.yaml', manifest, context)
    hookenv.log('Creating the default http backend.')
    try:
        kubectl('apply', '-f', manifest)
    except CalledProcessError as e:
        hookenv.log(e)
        hookenv.log('Failed to create default-http-backend. Will attempt again next update.')  # noqa
        hookenv.close_port(80)
        hookenv.close_port(443)
        return

    set_state('kubernetes-worker.ingress.available')
    hookenv.open_port(80)
    hookenv.open_port(443)


@when('kubernetes-worker.config.created',
      'kubernetes-worker.ingress.available')
@when_not('kubernetes-worker.ingress.enabled')
def disable_ingress():
    hookenv.log('Deleting the http backend and ingress.')
    hookenv.close_port(80)
    hookenv.close_port(443)
    try:
        kubectl('delete', '--ignore-not-found', '-f',
                '/root/cdk/addons/default-http-backend.yaml')
        kubectl('delete', '--ignore-not-found', '-f',
                '/root/cdk/addons/ingress-daemon-set.yaml')
    except CalledProcessError:
        traceback.print_exc()
        hookenv.log('Failed to disable ingress, waiting to retry')
        return
    remove_state('kubernetes-worker.ingress.available')


def restart_unit_services():
    '''Restart worker services.'''
    hookenv.log('Restarting kubelet and kube-proxy.')
    services = ['kube-proxy', 'kubelet']
    for service in services:
        service_restart('snap.%s.daemon' % service)


def get_kube_api_servers(kube_api):
    '''Return the kubernetes api server address and port for this
    relationship.'''
    hosts = []
    # Iterate over every service from the relation object.
    for service in kube_api.services():
        for unit in service['hosts']:
            hosts.append('https://{0}:{1}'.format(unit['hostname'],
                                                  unit['port']))
    return hosts


@when('kubernetes-worker.config.created')
@when('nrpe-external-master.available')
@when('kube-api-endpoint.available')
@when('kube-control.auth.available')
@when_any('config.changed.nagios_context',
          'config.changed.nagios_servicegroups',
          'nrpe-external-master.reconfigure')
def update_nrpe_config():
    services = ['snap.{}.daemon'.format(s) for s in worker_services]
    data = render('nagios_plugin.py', context={'node_name': get_node_name()})
    plugin_path = install_nagios_plugin_from_text(data,
                                                  'check_k8s_worker.py')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe_setup.add_check("node",
                         "Node registered with API Server",
                         str(plugin_path))
    nrpe.add_init_service_checks(nrpe_setup, services, current_unit)
    nrpe_setup.write()

    creds = db.get('credentials')
    if creds:
        kube_api = endpoint_from_flag('kube-api-endpoint.available')
        servers = get_kube_api_servers(kube_api)
        server = servers[get_unit_number() % len(servers)]
        create_kubeconfig(nrpe_kubeconfig_path, server, ca_crt_path,
                          token=creds['client_token'], user='nagios')
        # Make the config dir owned by the nagios user.
        cmd = ['chown', '-R', 'nagios:nagios',
               os.path.dirname(nrpe_kubeconfig_path)]
        check_call(cmd)

        remove_state('nrpe-external-master.reconfigure')
        set_state('nrpe-external-master.initial-config')


@when_not('nrpe-external-master.available')
@when('nrpe-external-master.initial-config')
def remove_nrpe_config():
    remove_state('nrpe-external-master.initial-config')
    remove_nagios_plugin('check_k8s_worker.py')

    # The current nrpe-external-master interface doesn't handle a lot of logic,
    # use the charm-helpers code for now.
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname)

    for service in worker_services:
        nrpe_setup.remove_check(shortname=service)
    nrpe_setup.remove_check('node')


@when('nvidia.ready')
@when('kubernetes-worker.config.created')
@when_not('kubernetes-worker.gpu.enabled')
def enable_gpu():
    """Enable GPU usage on this node.

    """
    if get_version('kubelet') < (1, 9):
        hookenv.status_set(
            'active',
            'Upgrade to snap channel >= 1.9/stable to enable GPU support.'
        )
        return

    hookenv.log('Enabling gpu mode')
    try:
        # Not sure why this is necessary, but if you don't run this, k8s will
        # think that the node has 0 gpus (as shown by the output of
        # `kubectl get nodes -o yaml`
        check_call(['nvidia-smi'])
    except CalledProcessError as cpe:
        hookenv.log('Unable to communicate with the NVIDIA driver.')
        hookenv.log(cpe)
        return

    set_label('gpu', 'true')
    set_label('cuda', 'true')

    set_state('kubernetes-worker.gpu.enabled')
    set_state('kubernetes-worker.restart-needed')


@when('kubernetes-worker.gpu.enabled')
@when_not('nvidia.ready')
@when_not('kubernetes-worker.restart-needed')
def nvidia_departed():
    """Cuda departed."""
    disable_gpu()
    remove_state('kubernetes-worker.gpu.enabled')
    set_state('kubernetes-worker.restart-needed')


def disable_gpu():
    """Disable GPU usage on this node.

    """
    hookenv.log('Disabling gpu mode')

    # Remove node labels
    remove_label('gpu')
    remove_label('cuda')


@when('kubernetes-worker.gpu.enabled')
@when('kube-control.connected')
def notify_master_gpu_enabled(kube_control):
    """Notify kubernetes-master that we're gpu-enabled.

    """
    kube_control.set_gpu(True)


@when_not('kubernetes-worker.gpu.enabled')
@when('kube-control.connected')
def notify_master_gpu_not_enabled(kube_control):
    """Notify kubernetes-master that we're not gpu-enabled.

    """
    kube_control.set_gpu(False)


@when('kube-control.connected')
def request_kubelet_and_proxy_credentials(kube_control):
    """ Request kubelet node authorization with a well formed kubelet user.
    This also implies that we are requesting kube-proxy auth. """

    # The kube-cotrol interface is created to support RBAC.
    # At this point we might as well do the right thing and return the hostname
    # even if it will only be used when we enable RBAC
    nodeuser = 'system:node:{}'.format(get_node_name().lower())
    kube_control.set_auth_request(nodeuser)


@when('kube-control.connected')
def catch_change_in_creds(kube_control):
    """Request a service restart in case credential updates were detected."""
    nodeuser = 'system:node:{}'.format(get_node_name().lower())
    creds = kube_control.get_auth_credentials(nodeuser)
    if creds and creds['user'] == nodeuser:
        # We need to cache the credentials here because if the
        # master changes (master leader dies and replaced by a new one)
        # the new master will have no recollection of our certs.
        db.set('credentials', creds)
        set_state('worker.auth.bootstrapped')
        if data_changed('kube-control.creds', creds):
            set_state('kubernetes-worker.restart-needed')


@when_not('kube-control.connected')
def missing_kube_control():
    """Inform the operator they need to add the kube-control relation.

    If deploying via bundle this won't happen, but if operator is upgrading a
    a charm in a deployment that pre-dates the kube-control relation, it'll be
    missing.

    """
    try:
        goal_state = hookenv.goal_state()
    except NotImplementedError:
        goal_state = {}

    if 'kube-control' in goal_state.get('relations', {}):
        hookenv.status_set(
            'waiting',
            'Waiting for kubernetes-master to become ready')
    else:
        hookenv.status_set(
            'blocked',
            'Relate {}:kube-control kubernetes-master:kube-control'.format(
                hookenv.service_name()))


def _systemctl_is_active(application):
    ''' Poll systemctl to determine if the application is running '''
    cmd = ['systemctl', 'is-active', application]
    try:
        raw = check_output(cmd)
        return b'active' in raw
    except Exception:
        return False


class ApplyNodeLabelFailed(Exception):
    pass


def persistent_call(cmd, retry_message):
    deadline = time.time() + 180
    while time.time() < deadline:
        code = subprocess.call(cmd)
        if code == 0:
            return True
        hookenv.log(retry_message)
        time.sleep(1)
    else:
        return False


def set_label(label, value):
    nodename = get_node_name()
    cmd = 'kubectl --kubeconfig={0} label node {1} {2}={3} --overwrite'
    cmd = cmd.format(kubeconfig_path, nodename, label, value)
    cmd = cmd.split()
    retry = 'Failed to apply label %s=%s. Will retry.' % (label, value)
    if not persistent_call(cmd, retry):
        raise ApplyNodeLabelFailed(retry)


def remove_label(label):
    nodename = get_node_name()
    cmd = 'kubectl --kubeconfig={0} label node {1} {2}-'
    cmd = cmd.format(kubeconfig_path, nodename, label)
    cmd = cmd.split()
    retry = 'Failed to remove label {0}. Will retry.'.format(label)
    if not persistent_call(cmd, retry):
        raise ApplyNodeLabelFailed(retry)


@when_any('endpoint.aws.joined',
          'endpoint.gcp.joined',
          'endpoint.openstack.joined',
          'endpoint.vsphere.joined',
          'endpoint.azure.joined')
@when_not('kubernetes-worker.cloud.ready')
def set_cloud_pending():
    k8s_version = get_version('kubelet')
    k8s_1_11 = k8s_version >= (1, 11)
    k8s_1_12 = k8s_version >= (1, 12)
    vsphere_joined = is_state('endpoint.vsphere.joined')
    azure_joined = is_state('endpoint.azure.joined')
    if (vsphere_joined and not k8s_1_12) or (azure_joined and not k8s_1_11):
        set_state('kubernetes-worker.cloud.blocked')
    else:
        remove_state('kubernetes-worker.cloud.blocked')
    set_state('kubernetes-worker.cloud.pending')


@when_any('endpoint.aws.joined',
          'endpoint.gcp.joined',
          'endpoint.azure.joined')
@when('kube-control.cluster_tag.available')
@when_not('kubernetes-worker.cloud.request-sent')
def request_integration():
    hookenv.status_set('maintenance', 'requesting cloud integration')
    kube_control = endpoint_from_flag('kube-control.cluster_tag.available')
    cluster_tag = kube_control.get_cluster_tag()
    if is_state('endpoint.aws.joined'):
        cloud = endpoint_from_flag('endpoint.aws.joined')
        cloud.tag_instance({
            'kubernetes.io/cluster/{}'.format(cluster_tag): 'owned',
        })
        cloud.tag_instance_security_group({
            'kubernetes.io/cluster/{}'.format(cluster_tag): 'owned',
        })
        cloud.tag_instance_subnet({
            'kubernetes.io/cluster/{}'.format(cluster_tag): 'owned',
        })
        cloud.enable_object_storage_management(['kubernetes-*'])
    elif is_state('endpoint.gcp.joined'):
        cloud = endpoint_from_flag('endpoint.gcp.joined')
        cloud.label_instance({
            'k8s-io-cluster-name': cluster_tag,
        })
        cloud.enable_object_storage_management()
    elif is_state('endpoint.azure.joined'):
        cloud = endpoint_from_flag('endpoint.azure.joined')
        cloud.tag_instance({
            'k8s-io-cluster-name': cluster_tag,
        })
        cloud.enable_object_storage_management()
    cloud.enable_instance_inspection()
    cloud.enable_dns_management()
    set_state('kubernetes-worker.cloud.request-sent')
    hookenv.status_set('waiting', 'Waiting for cloud integration')


@when_none('endpoint.aws.joined',
           'endpoint.gcp.joined',
           'endpoint.openstack.joined',
           'endpoint.vsphere.joined',
           'endpoint.azure.joined')
@when_any('kubernetes-worker.cloud.pending',
          'kubernetes-worker.cloud.request-sent',
          'kubernetes-worker.cloud.blocked',
          'kubernetes-worker.cloud.ready')
def clear_cloud_flags():
    remove_state('kubernetes-worker.cloud.pending')
    remove_state('kubernetes-worker.cloud.request-sent')
    remove_state('kubernetes-worker.cloud.blocked')
    remove_state('kubernetes-worker.cloud.ready')
    set_state('kubernetes-worker.restart-needed')  # force restart


@when_any('endpoint.aws.ready',
          'endpoint.gcp.ready',
          'endpoint.openstack.ready',
          'endpoint.vsphere.ready',
          'endpoint.azure.ready')
@when_not('kubernetes-worker.cloud.blocked',
          'kubernetes-worker.cloud.ready')
def cloud_ready():
    remove_state('kubernetes-worker.cloud.pending')
    if is_state('endpoint.gcp.ready'):
        write_gcp_snap_config('kubelet')
    elif is_state('endpoint.azure.ready'):
        write_azure_snap_config('kubelet')
    set_state('kubernetes-worker.cloud.ready')
    set_state('kubernetes-worker.restart-needed')  # force restart


def get_first_mount(mount_relation):
    mount_relation_list = mount_relation.mounts()
    if mount_relation_list and len(mount_relation_list) > 0:
        # mount relation list is a list of the mount layer relations
        # for now we just use the first one that is nfs
        for mount in mount_relation_list:
            # for now we just check the first mount and use that.
            # the nfs charm only supports one for now.
            if ('mounts' in mount and
                    mount['mounts'][0]['fstype'] == 'nfs'):
                return mount['mounts'][0]
    return None


@when('nfs.available')
def nfs_state_control(mount):
    ''' Determine if we should remove the state that controls the re-render
    and execution of the nfs-relation-changed event because there
    are changes in the relationship data, and we should re-render any
    configs '''

    mount_data = get_first_mount(mount)
    if mount_data:
        nfs_relation_data = {
            'options': mount_data['options'],
            'host': mount_data['hostname'],
            'mountpoint': mount_data['mountpoint'],
            'fstype': mount_data['fstype']
        }

        # Re-execute the rendering if the data has changed.
        if data_changed('nfs-config', nfs_relation_data):
            hookenv.log('reconfiguring nfs')
            remove_state('nfs.configured')


@when('nfs.available')
@when_not('nfs.configured')
def nfs_storage(mount):
    '''NFS on kubernetes requires nfs config rendered into a deployment of
    the nfs client provisioner. That will handle the persistent volume claims
    with no persistent volume to back them.'''

    mount_data = get_first_mount(mount)
    if not mount_data:
        return

    # If present, use the configured registry to define the nfs image location.
    registry_location = get_registry_location()
    if registry_location:
        mount_data['registry'] = registry_location

    addon_path = '/root/cdk/addons/{}'
    # Render the NFS deployment
    manifest = addon_path.format('nfs-provisioner.yaml')
    render('nfs-provisioner.yaml', manifest, mount_data)
    hookenv.log('Creating the nfs provisioner.')
    try:
        kubectl('apply', '-f', manifest)
    except CalledProcessError as e:
        hookenv.log(e)
        hookenv.log('Failed to create nfs provisioner. Will attempt again next update.')  # noqa
        return

    set_state('nfs.configured')


@when('kube-control.registry_location.available')
def update_registry_location():
    """Handle changes to the container image registry.

    Monitor the image registry location. If it changes, manage flags to ensure
    our image-related handlers will be invoked with an accurate registry.
    """
    registry_location = get_registry_location()

    if registry_location:
        runtime = endpoint_from_flag('endpoint.container-runtime.available')
        if runtime:
            # Construct and send the sandbox image (pause container) to our runtime
            uri = '{}/pause-{}:3.1'.format(registry_location, arch())
            runtime.set_config(
                sandbox_image=uri
            )

    if data_changed('registry-location', registry_location):
        remove_state('kubernetes-worker.config.created')
        remove_state('kubernetes-worker.ingress.available')
        remove_state('nfs.configured')
        set_state('kubernetes-worker.restart-needed')


def get_registry_location():
    """Get the image registry from the kube-control relation.

    If an image-registry has been configured on the k8s-master, it will be set
    set on the kube-control relation. This function returns that value stripped
    of any trailing slash. If the relation or registry location are missing,
    this returns an empty string.
    """
    kube_control = endpoint_from_flag(
        'kube-control.registry_location.available')
    if kube_control:
        rel_registry = kube_control.get_registry_location()
        registry = rel_registry.rstrip('/') if rel_registry else ""
    else:
        registry = ""

    return registry
