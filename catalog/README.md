# Homepage producer catalog

This directory is the producer-owned contract consumed by the independently
managed Homepage instance. The catalog is deliberately static: it is reviewed
in Git, rendered from the same checkout as the Kubernetes source objects, and
contains no Kubernetes credentials or runtime discovery settings.

## Files

- `homepage.yaml` — the reviewed selection policy and source references.
- `homepage-services.yaml` — generated Homepage-native `services.yaml`; do not
  edit it by hand.
- `../hack/render-homepage-catalog.py` — fail-closed validator and renderer.

Each catalog entry has a stable `id`, one of the two `group` values
`virtualservers` or `httproutes`, a display name/description/icon/weight, an
explicit `enabled` flag, and a `source` reference. The source reference names
the repository path, Kubernetes kind, object name, and `expectedHostname`.
The generator resolves the owning `app.yaml` (or Kustomization) to determine
namespace, locates the exact object, and compares its current hostname to the
catalog declaration.

`metadata.exposure` and `metadata.restricted` are descriptive labels only.
They do not authorize access or cause the generator to include credentials.
The renderer turns `restricted-admin` and `backing-admin` into visible tile
labels and emits only `href`, `description`, and `icon` for each enabled tile.

## Selection policy

- Only reviewed primary VirtualServers are enabled.
- CouchDB and backend/API VirtualServers remain cataloged but disabled.
- Vault remains cataloged but disabled until the Homepage LAN trust boundary
  is explicitly reviewed.
- The CouchDB HTTPRoute is enabled as a visibly marked backing/admin link.
- The Pi-hole links are enabled and visibly marked restricted/admin.
- Sources under `kind/` are rejected, including test fixtures.
- The output always contains separate `Kubernetes VirtualServers` and
  `Kubernetes HTTPRoutes` groups.

The generator rejects missing or ambiguous sources, namespace mismatches,
hostname mismatches, duplicate IDs, duplicate enabled URLs or names, backend or
API-only enabled sources, non-HTTPS/invalid host declarations, unknown fields,
and credential/widget-shaped catalog fields. It writes deterministic YAML in
weight/ID order and atomically replaces the requested output only after all
validation succeeds.

## Local validation

From the repository root:

```bash
python3 hack/render-homepage-catalog.py --check
bash hack/tests/homepage-catalog.sh
python3 hack/render-homepage-catalog.py
python3 hack/render-homepage-catalog.py --check
git diff --check
git diff --exit-code -- catalog/homepage-services.yaml
```

The focused test is cluster-free. It validates every selected source, the two
output groups and approved enabled policy, output safety, reproducibility, and
negative mutations for hostname/source/URL/Kind/credential failures. CI runs
the same test when the catalog, generator/test, app descriptors, Kustomizations,
route sources, or VirtualServer sources change, then regenerates the committed
artifact and requires a clean diff.
