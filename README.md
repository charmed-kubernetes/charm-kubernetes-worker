# Kubernetes Worker

## Usage

This charm deploys a container runtime, and additionally stands up the Kubernetes
worker applications: kubelet, and kube-proxy.

In order for this charm to be useful, it should be deployed with its companion
charm [kubernetes-master](https://jujucharms.com/u/containers/kubernetes-master)
and linked with an SDN-Plugin.

This charm has also been bundled up for your convenience so you can skip the
above steps, and deploy it with a single command:

```shell
juju deploy canonical-kubernetes
```

For more information about [Canonical Kubernetes](https://jujucharms.com/canonical-kubernetes)
consult the bundle `README.md` file.

## Scale out

To add additional compute capacity to your Kubernetes workers, you may
`juju add-unit` scale the cluster of applications. They will automatically
join any related kubernetes-master, and enlist themselves as ready once the
deployment is complete.

## Snap Configuration

The kubernetes resources used by this charm are snap packages. When not
specified during deployment, these resources come from the public store. By
default, the `snapd` daemon will refresh all snaps installed from the store
four (4) times per day. A charm configuration option is provided for operators
to control this refresh frequency.

>NOTE: this is a global configuration option and will affect the refresh
time for all snaps installed on a system.

Examples:

```sh
## refresh kubernetes-worker snaps every tuesday
juju config kubernetes-worker snapd_refresh="tue"

## refresh snaps at 11pm on the last (5th) friday of the month
juju config kubernetes-worker snapd_refresh="fri5,23:00"

## delay the refresh as long as possible
juju config kubernetes-worker snapd_refresh="max"

## use the system default refresh timer
juju config kubernetes-worker snapd_refresh=""
```

For more information on the possible values for `snapd_refresh`, see the
*refresh.timer* section in the [system options][] documentation.

[system options]: https://forum.snapcraft.io/t/system-options/87

## Operational actions

The kubernetes-worker charm supports the following Operational Actions:

### Pause

Pausing the workload enables administrators to both [drain](http://kubernetes.io/docs/user-guide/kubectl/kubectl_drain/) and [cordon](http://kubernetes.io/docs/user-guide/kubectl/kubectl_cordon/)
a unit for maintenance.

### Resume

Resuming the workload will [uncordon](http://kubernetes.io/docs/user-guide/kubectl/kubectl_uncordon/) a paused unit. Workloads will automatically migrate unless otherwise directed via their application declaration.

## Private registry

This charm supports the `docker-registry` interface, which can automatically
configure docker on the kubernetes-worker to communicate with a deployed
[docker-registry][] charm.

### Example usage

Deploy and relate `docker-registry` to kubernetes-worker, with optional basic auth and TLS enabled:

```bash
juju deploy ~containers/docker-registry
juju config docker-registry auth-basic-user=YOUR_USER auth-basic-password=YOUR_PASSWORD

juju relate docker-registry easyrsa
juju relate kubernetes-worker:docker-registry docker-registry:docker-registry
```

Configure kubernetes-worker to use images pushed to the `docker-registry` charm:

```bash
juju config kubernetes-worker default-backend-image=YOUR_REGISTRY/defaultbackend-amd64:1.5
```

Learn more about the `docker-registry` capabilities at [docker-registry][].

[docker-registry]: https://jujucharms.com/u/containers/docker-registry

## Known Limitations

Kubernetes workers currently only support 'phaux' HA scenarios. Even when configured with an HA cluster string, they will only ever contact the first unit in the cluster map. To enable a proper HA story, kubernetes-worker units are encouraged to proxy through a [kubeapi-load-balancer](https://jujucharms.com/kubeapi-load-balancer)
application. This enables a HA deployment without the need to
re-render configuration and disrupt the worker services.

External access to pods must be performed through a [Kubernetes
Ingress Resource](http://kubernetes.io/docs/user-guide/ingress/).

When using NodePort type networking, there is no automation in exposing the
ports selected by kubernetes or chosen by the user. They will need to be
opened manually and can be performed across an entire worker pool.

If your NodePort service port selected is `30510` you can open this across all
members of a worker pool named `kubernetes-worker` like so:

```bash
juju run --application kubernetes-worker open-port 30510/tcp
```

Don't forget to expose the kubernetes-worker application if its not already
exposed, as this can cause confusion once the port has been opened and the
service is not reachable.

Note: When debugging connection issues with NodePort services, its important
to first check the kube-proxy service on the worker units. If kube-proxy is not
running, the associated port-mapping will not be configured in the iptables
rulechains.

If you need to close the NodePort once a workload has been terminated, you can
follow the same steps inversely.

```bash
juju run --application kubernetes-worker close-port 30510
```

## LXD

The [LXD profile](https://github.com/charmed-kubernetes/bundle/wiki/Deploying-on-LXD) included in this charm uses keys which are not allowed in the current [juju version](https://docs.jujucharms.com/lxd-cloud-advanced#charms-and-lxd-profiles) this means that you are required to supply `--force` to your `deploy` and `upgrade-charm` commands.


