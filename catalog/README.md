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

Each Kubernetes catalog entry has a stable `id`, one of the two `group` values
`virtualservers` or `httproutes`, a display name/description/icon/weight, an
explicit `enabled` flag, and a required `source` reference. The source reference
names the repository path, Kubernetes kind, object name, and `expectedHostname`.
The generator resolves the owning `app.yaml` (or Kustomization) to determine
namespace, locates the exact object, and compares its current hostname to the
catalog declaration.

The separate top-level `pveNativeServices` list contains curated, static,
live-evidence-backed Proxmox-cluster web cards. These records are reviewed
catalog data, not runtime discovery: they have `id`, `displayName`,
`description`, `icon`, `weight`, `enabled`, and a safe `url`, with optional
`metadata`. PVE records deliberately have no Kubernetes `source`, namespace,
widget, credential, or secret fields.

`metadata.exposure` and `metadata.restricted` are descriptive labels only.
They do not authorize access or cause the generator to include credentials.
The renderer turns `restricted-admin` and `backing-admin` into visible tile
labels, and renders a restricted-only record with `[Restricted]`; it emits only
`href`, `description`, and `icon` for each enabled tile.

## Selection policy

- PVE Native Services are curated, static, live-evidence-backed links from the
  Proxmox-cluster inventory; the generator does not perform runtime discovery.
- Include only user-facing PVE/PVE2 guest or host web surfaces with direct
  reachability evidence and a reviewed safe LAN URL.
- The approved native set is exactly the 12 cards in `homepage.yaml`: Homepage,
  Pi-hole, Grafana, Hermes Agent dashboard, Agent Vault, Symphony Hub, the four
  named Symphony/workmate boards, and the two Proxmox node UIs.
- Exclude API-only MCPJungle and Symphony gateways, monitoring data-plane
  backends, Kubernetes routes, `wmtest`, mission-control or other stale names,
  and unverified public/stale service records.
- Only reviewed primary VirtualServers are enabled.
- CouchDB and backend/API VirtualServers remain cataloged but disabled.
- Vault remains cataloged but disabled until the Homepage LAN trust boundary
  is explicitly reviewed.
- The CouchDB HTTPRoute is enabled as a visibly marked backing/admin link.
- The Pi-hole links are enabled and visibly marked restricted/admin.
- Sources under `kind/` are rejected, including test fixtures.
- The rendered artifact always contains these exact groups, in this order:
  `PVE Native Services`, `Kubernetes VirtualServers`, `Kubernetes HTTPRoutes`.

PVE URLs must use HTTP or HTTPS, contain no username/password, query, or
fragment, and use only `/` or `/admin/` paths. The host must be either a private
RFC1918 IPv4 address (`10/8`, `172.16/12`, or `192.168/16`) or a hostname ending
in `.home.arpa` or `.novotny.live`; explicit ports are allowed. Loopback,
link-local, unspecified, multicast, public raw IPs, deceptive suffixes, and
other schemes are rejected. URLs must use canonical lowercase scheme/host
spelling, omit default ports, contain no control characters, and use ordinary
decimal spelling for non-default ports. Kubernetes links retain their separate
HTTPS/root-only source-derived policy.

The generator rejects missing or ambiguous sources, namespace mismatches,
hostname mismatches, duplicate IDs, duplicate enabled URLs or names, backend or
API-only enabled sources, unsafe PVE URLs, non-HTTPS/invalid Kubernetes host
declarations, unknown fields, and credential/widget-shaped catalog fields. It
writes deterministic YAML in weight/ID order and atomically replaces the
requested output only after all validation succeeds.

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

The focused test is cluster-free. It validates every selected Kubernetes source,
the exact 12-card PVE inventory, the three output groups and approved enabled
policy, output safety, URL policies, reproducibility, and mutation failures for
schema, credential, widget, uniqueness, URL, Kind, hostname, and group-shape
failures. CI runs the same test when the catalog, generator/test, app
descriptors, Kustomizations, route sources, or VirtualServer sources change,
then regenerates the committed artifact and requires a clean diff.
