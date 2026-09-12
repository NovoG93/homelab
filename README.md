# homelab

Argo CD GitOps content for the Kubernetes cluster built by
[`homelab-infra`](https://github.com/NovoG93/homelab-infra): one directory per
workload under `apps/`, `tools/` and `core/`, each with a four-field `app.yaml`
that the ApplicationSets in `tools/argocd/appSets/` turn into an Application.

The interface `homelab-infra` relies on — bootstrap path, ApplicationSet names,
deferred kinds, node roles, secret store, handover marker — is declared in
[`cluster-contract.yaml`](cluster-contract.yaml) and checked by
`hack/check-cluster-contract.sh` in this repo's CI.
