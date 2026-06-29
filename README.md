<!--
Avoid using this README file for information that is maintained or published elsewhere, e.g.:

* metadata.yaml > published on Charmhub
* documentation > published on (or linked to from) Charmhub
* detailed contribution guide > documentation or CONTRIBUTING.md

Use links instead.
-->

# kubernetes-worker

Charmhub package name: operator-template
More information: https://charmhub.io/kubernetes-worker

Describe your charm in one or two sentences.

## What changed: Kubernetes Dashboard addon removal

From CK 1.36, the Kubernetes Dashboard addon is no longer managed by `cdk-addons`.
The legacy `enable-dashboard` and `dashboard-auth` options are removed and are unset on upgrade.
If you previously relied on the addon, deploy and manage Dashboard directly from upstream.

### Migration path

The Kubernetes Dashboard is no longer maintained by Charmed Kubernetes and receives
no security updates through this distribution. Canonical recommends **not** running it
in production environments.

If you still need the dashboard, you can deploy it directly from the upstream project —
accepting that support and security patching become your own responsibility:

```bash
helm upgrade --install kubernetes-dashboard kubernetes-dashboard \
  --repo https://kubernetes.github.io/dashboard \
  --namespace kubernetes-dashboard --create-namespace
```

## Other resources

<!-- If your charm is documented somewhere else other than Charmhub, provide a link separately. -->

- [Read more](https://example.com)

- [Contributing](CONTRIBUTING.md) <!-- or link to other contribution documentation -->

- See the [Juju SDK documentation](https://juju.is/docs/sdk) for more information about developing and improving charms.
