# Kubernetes Worker

## Usage

This charm deploys a container runtime, and additionally stands up the Kubernetes
worker applications: kubelet, and kube-proxy.

In order for this charm to be useful, it should be deployed with its companion
charm [kubernetes-control-plane](https://charmhub.io/kubernetes-control-plane)
and linked with an SDN-Plugin and a container runtime such as
[containerd](https://charmhub.io/containerd).

This charm is a component of Charmed Kubernetes. For full information,
please visit the [official Charmed Kubernetes docs](https://www.ubuntu.com/kubernetes/docs/charm-kubernetes-worker).

## Developers

### Building the charm

```
make charm
```
