# Kubernetes monitoring collector

This application installs `kube-prometheus-stack` `91.8.2` (Prometheus
Operator `v0.94.1`) in the `monitoring` namespace. Grafana and Alertmanager
are deliberately disabled: the external monitoring VM owns the durable
VictoriaMetrics and Grafana plane.

Prometheus keeps a six-hour local outage buffer and remote-writes to
`http://192.168.0.157:8428/api/v1/write` with the external label
`cluster=homelab`. The remote-write queue is intentionally conservative for
the three-node cluster. Prometheus, the operator, and kube-state-metrics run
on `tools=true`; node-exporter tolerates the control-plane, tools, and apps
NoSchedule taints so it covers every node.

ServiceMonitor and PodMonitor selection is explicit: empty label selectors plus
empty namespace selectors discover all monitors across namespaces, while both
`*SelectorNilUsesHelmValues` flags are disabled so chart defaults cannot narrow
the scope. Prometheus storage is ephemeral by design; VictoriaMetrics is the
long-term store.

### Accepted transport risk

Remote write uses unauthenticated plain HTTP on the trusted LAN. The external
monitoring VM's host and Proxmox firewalls accept TCP/8428 only from the three
declared Kubernetes node addresses; the endpoint must not be exposed to an
untrusted network. Add authenticated TLS before expanding that trust boundary.

## Kind

`kind/tools/monitoring` renders the same pinned chart using the shared values
plus `kind/tools/monitoring/values.yaml`. The overlay removes the production
remote-write endpoint, cluster label, resource requests/limits, and `tools`
node scheduling. It renders the Helm chart directly instead of layering the
production render, so resources are not duplicated.

## Validation

From the repository root:

```bash
bash hack/tests/monitoring-render.sh
kustomize build --enable-helm tools/monitoring
kustomize build --enable-helm --load-restrictor LoadRestrictionsNone kind/tools/monitoring
```
