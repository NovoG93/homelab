#!/usr/bin/env bash
# Focused, cluster-free contract test for the producer-owned Homepage catalog.
set -euo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
catalog_file="${repo_dir}/catalog/homepage.yaml"
artifact_file="${repo_dir}/catalog/homepage-services.yaml"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/homepage-catalog.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
python3 - <<'PY' || exit 1
try:
    import yaml  # noqa: F401
except ImportError as exc:
    raise SystemExit(f'PyYAML is required: {exc}')
PY

[[ -f "${catalog_file}" ]] || fail 'catalog/homepage.yaml is missing'
[[ -f "${artifact_file}" ]] || fail 'catalog/homepage-services.yaml is missing'
[[ -f "${repo_dir}/hack/render-homepage-catalog.py" ]] || fail 'Homepage catalog generator is missing'

rendered_file="${tmp_dir}/homepage-services.yaml"
python3 "${repo_dir}/hack/render-homepage-catalog.py" \
  --repo-root "${repo_dir}" \
  --catalog "${catalog_file}" \
  --output "${rendered_file}" || fail 'Homepage catalog generator failed for the committed catalog'
cmp -s "${rendered_file}" "${artifact_file}" || \
  fail 'committed Homepage services artifact is not reproducible from the catalog and sources'

python3 - "${catalog_file}" "${artifact_file}" <<'PY'
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

catalog_path, artifact_path = map(Path, sys.argv[1:])
catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
artifact = yaml.safe_load(artifact_path.read_text(encoding="utf-8"))

assert catalog["apiVersion"] == "homelab.novotny.live/v1alpha1"
assert catalog["kind"] == "HomepageCatalog"
entries = catalog["entries"]
assert isinstance(entries, list) and entries
assert all(isinstance(entry.get("enabled"), bool) for entry in entries)

expected_sources = {
    ("virtualservers", "apps/beans-and-bites/virtualserver-frontend.yaml", "VirtualServer", "beans-and-bites"),
    ("virtualservers", "apps/beans-and-bites/virtualserver-api.yaml", "VirtualServer", "beans-and-bites-api"),
    ("virtualservers", "apps/beans-and-bites/virtualserver-backend.yaml", "VirtualServer", "beans-and-bites-backend"),
    ("virtualservers", "apps/immich/virtualserver.yaml", "VirtualServer", "immich"),
    ("virtualservers", "apps/ntfy/virtualserver.yaml", "VirtualServer", "ntfy"),
    ("virtualservers", "apps/rcl/virtualserver-frontend.yaml", "VirtualServer", "robotics-content-lab"),
    ("virtualservers", "apps/rcl/virtualserver-api.yaml", "VirtualServer", "robotics-content-lab-api"),
    ("virtualservers", "apps/rcl/virtualserver-backend.yaml", "VirtualServer", "robotics-content-lab-backend"),
    ("virtualservers", "apps/couchdb/virtualserver.yaml", "VirtualServer", "obsidian-couchdb"),
    ("virtualservers", "tools/argo-workflows/virtualserver.yaml", "VirtualServer", "argo-workflows"),
    ("virtualservers", "tools/argocd/virtualserver.yaml", "VirtualServer", "argocd"),
    ("virtualservers", "tools/pihole/virtualserver.yaml", "VirtualServer", "pihole"),
    ("virtualservers", "tools/vault/virtualserver.yaml", "VirtualServer", "vault"),
    ("httproutes", "apps/beans-and-bites/httproute.yaml", "HTTPRoute", "beans-and-bites-http"),
    ("httproutes", "apps/couchdb/httproute.yaml", "HTTPRoute", "obsidian-couchdb-http"),
    ("httproutes", "apps/immich/httproute.yaml", "HTTPRoute", "immich-http"),
    ("httproutes", "apps/ntfy/httproute.yaml", "HTTPRoute", "ntfy-http"),
    ("httproutes", "apps/rcl/httproute.yaml", "HTTPRoute", "robotics-content-lab-http"),
    ("httproutes", "tools/argo-workflows/httproute.yaml", "HTTPRoute", "argo-workflows"),
    ("httproutes", "tools/argocd/httproute.yaml", "HTTPRoute", "argocd"),
    ("httproutes", "tools/pihole/httproute.yaml", "HTTPRoute", "pihole"),
    ("httproutes", "tools/vault/httproute.yaml", "HTTPRoute", "vault"),
}
actual_sources = {
    (
        entry["group"],
        entry["source"]["path"],
        entry["source"]["kind"],
        entry["source"]["name"],
    )
    for entry in entries
}
assert actual_sources == expected_sources, (actual_sources ^ expected_sources)
assert len({entry["id"] for entry in entries}) == len(entries)

expected_virtualservers = {
    "Beans & Bites": "https://beans-and-bites.novotny.live/",
    "Immich": "https://immich.novotny.live/",
    "ntfy": "https://ntfy.novotny.live/",
    "Robotics Content Lab": "https://robotics-content-lab.novotny.live/",
    "Argo Workflows": "https://argo-workflows.novotny.live/",
    "Argo CD": "https://argocd.novotny.live/",
    "Pi-hole": "https://pihole.novotny.live/",
}
expected_httproutes = {
    "Beans & Bites": "https://beans-and-bites-gateway.novotny.live/",
    "CouchDB": "https://couchdb-gateway.novotny.live/",
    "Immich": "https://immich-gateway.novotny.live/",
    "ntfy": "https://ntfy-gateway.novotny.live/",
    "Robotics Content Lab": "https://robotics-content-lab-gateway.novotny.live/",
    "Argo Workflows": "https://argo-workflows-gateway.novotny.live/",
    "Argo CD": "https://argocd-gateway.novotny.live/",
    "Pi-hole": "https://pihole-gateway.novotny.live/",
}
expected_pve = {
    "Homepage": "http://homepage.home.arpa:3000/",
    "Pi-hole": "http://192.168.0.154/admin/",
    "Grafana": "http://grafana.home.arpa:3000/",
    "Hermes Agent dashboard": "https://hermes.home.arpa/",
    "Agent Vault": "https://agent-vault.home.arpa/",
    "Symphony Hub": "http://symphony.home.arpa:1000/",
    "oh-my-symphony board": "http://symphony.home.arpa:9999/",
    "workmate-ai board": "http://symphony.home.arpa:10000/",
    "workmate-site board": "http://symphony.home.arpa:10001/",
    "workmate-internal board": "http://symphony.home.arpa:10002/",
    "Proxmox PVE UI": "https://pve.novotny.live:8006/",
    "Proxmox PVE2 UI": "https://192.168.0.3:8006/",
}
expected_enabled = {
    ("virtualservers", name, url)
    for name, url in expected_virtualservers.items()
} | {
    ("httproutes", name, url)
    for name, url in expected_httproutes.items()
} | {
    ("pveNativeServices", name, url)
    for name, url in expected_pve.items()
}
assert len(catalog["pveNativeServices"]) == 12
assert all(entry["enabled"] is True for entry in catalog["pveNativeServices"])
assert {
    entry["displayName"]: entry["url"] for entry in catalog["pveNativeServices"]
} == expected_pve
assert {
    entry["displayName"] for entry in catalog["pveNativeServices"]
} == set(expected_pve)
all_catalog_entries = entries + catalog["pveNativeServices"]
assert len({entry["id"] for entry in all_catalog_entries}) == len(all_catalog_entries)
actual_enabled = {
    (entry["group"], entry["displayName"], f"https://{entry['source']['expectedHostname']}/")
    for entry in entries
    if entry["enabled"]
}
actual_enabled |= {
    ("pveNativeServices", entry["displayName"], entry["url"])
    for entry in catalog["pveNativeServices"]
    if entry["enabled"]
}
assert actual_enabled == expected_enabled, (actual_enabled ^ expected_enabled)

# Vault is deliberately cataloged but disabled until the trust boundary is reviewed.
vault_entries = [entry for entry in entries if entry["source"]["name"] == "vault"]
assert len(vault_entries) == 2 and all(not entry["enabled"] for entry in vault_entries)
# Backend/API and CouchDB VirtualServers are cataloged for auditability but disabled.
for entry in entries:
    source_name = entry["source"]["name"]
    if entry["group"] == "virtualservers" and source_name in {
        "beans-and-bites-api",
        "beans-and-bites-backend",
        "robotics-content-lab-api",
        "robotics-content-lab-backend",
        "obsidian-couchdb",
    }:
        assert not entry["enabled"], source_name

assert isinstance(artifact, list) and len(artifact) == 3
assert [next(iter(group)) for group in artifact] == [
    "PVE Native Services",
    "Kubernetes VirtualServers",
    "Kubernetes HTTPRoutes",
]

def read_group(group):
    services = group[next(iter(group))]
    assert isinstance(services, list)
    result = {}
    for service in services:
        assert isinstance(service, dict) and len(service) == 1
        name, fields = next(iter(service.items()))
        assert name not in result
        assert set(fields) == {"description", "href", "icon"}, (name, fields)
        result[name] = fields
    return result

actual_pve = read_group(artifact[0])
actual_virtualservers = read_group(artifact[1])
actual_httproutes = read_group(artifact[2])
assert {name: fields["href"] for name, fields in actual_pve.items()} == expected_pve
assert len(actual_pve) == 12
assert len(actual_virtualservers) == 7
assert len(actual_httproutes) == 8
assert {name: fields["href"] for name, fields in actual_virtualservers.items()} == expected_virtualservers
assert {name: fields["href"] for name, fields in actual_httproutes.items()} == expected_httproutes
assert sum(len(group[next(iter(group))]) for group in artifact) == 27

all_urls = []
rfc1918_networks = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
for fields in actual_pve.values():
    parsed = urlparse(fields["href"])
    assert parsed.scheme in {"http", "https"} and parsed.netloc
    assert parsed.path in {"/", "/admin/"}
    assert parsed.username is None and parsed.password is None
    assert not parsed.query and not parsed.fragment
    assert parsed.hostname
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        assert parsed.hostname.endswith((".home.arpa", ".novotny.live"))
    else:
        assert isinstance(address, ipaddress.IPv4Address)
        assert any(address in network for network in rfc1918_networks)
    assert fields["description"] and fields["icon"]
    all_urls.append(fields["href"])

for services in (actual_virtualservers, actual_httproutes):
    for fields in services.values():
        parsed = urlparse(fields["href"])
        assert parsed.scheme == "https" and parsed.netloc and parsed.path == "/"
        assert parsed.username is None and parsed.password is None
        assert not parsed.query and not parsed.fragment
        assert fields["description"] and fields["icon"]
        all_urls.append(fields["href"])
assert len(all_urls) == 27
assert len(all_urls) == len(set(all_urls))
assert "https://vault.novotny.live/" not in all_urls
assert "https://vault-gateway.novotny.live/" not in all_urls
assert "https://couchdb.novotny.live/" not in all_urls
assert "https://beans-and-bites-api.novotny.live/" not in all_urls
assert "https://robotics-content-lab-api.novotny.live/" not in all_urls

for services in (actual_pve, actual_virtualservers, actual_httproutes):
    for fields in services.values():
        serialized = repr(fields).lower()
        assert not re.search(r"credential|kubeconfig|password|secret|token|widget|namespace", serialized), serialized
serialized_catalog = repr(catalog).lower()
assert not re.search(r"credential|kubeconfig|password|secret|token|widget|namespace", serialized_catalog), serialized_catalog
serialized_pve = repr(catalog["pveNativeServices"]).lower()
for forbidden in ("mcpjungle", "gateway", "monitoring", "wmtest", "mission-control", "control"):
    assert forbidden not in serialized_pve, forbidden

assert "[Restricted/Admin]" in actual_pve["Pi-hole"]["description"]
assert "[Restricted/Admin]" in actual_pve["Grafana"]["description"]
assert "[Restricted/Admin]" in actual_pve["Hermes Agent dashboard"]["description"]
assert "[Restricted/Admin]" in actual_pve["Proxmox PVE UI"]["description"]
assert "[Restricted]" in actual_pve["workmate-internal board"]["description"]
assert "[Restricted/Admin]" in actual_virtualservers["Pi-hole"]["description"]
assert "[Restricted/Admin]" in actual_httproutes["Pi-hole"]["description"]
assert "[Backing/Admin]" in actual_httproutes["CouchDB"]["description"]
PY

expect_failure() {
  local label="$1"
  local mutated_catalog="$2"
  local needle="$3"
  local output_file="${tmp_dir}/${label}.yaml"
  local error_file="${tmp_dir}/${label}.stderr"

  if python3 "${repo_dir}/hack/render-homepage-catalog.py" \
    --repo-root "${repo_dir}" \
    --catalog "${mutated_catalog}" \
    --output "${output_file}" \
    >"${tmp_dir}/${label}.stdout" 2>"${error_file}"; then
    fail "mutation ${label} unexpectedly passed"
  fi
  grep -qi -- "${needle}" "${error_file}" || \
    fail "mutation ${label} did not report the expected diagnostic: ${needle}"
}

mutated_catalog="${tmp_dir}/wrong-host.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
entry = next(item for item in data["entries"] if item["id"] == "vs-beans-and-bites")
entry["source"]["expectedHostname"] = "wrong.novotny.live"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure wrong-host "${mutated_catalog}" 'hostname mismatch'

mutated_catalog="${tmp_dir}/missing-source.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
entry = next(item for item in data["entries"] if item["id"] == "vs-beans-and-bites")
entry["source"]["path"] = "apps/beans-and-bites/does-not-exist.yaml"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure missing-source "${mutated_catalog}" 'source path'

mutated_catalog="${tmp_dir}/duplicate-url.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
entry = next(item for item in data["entries"] if item["id"] == "route-beans-and-bites")
entry["source"].update({
    "path": "apps/ntfy/httproute.yaml",
    "kind": "HTTPRoute",
    "name": "ntfy-http",
    "expectedHostname": "ntfy-gateway.novotny.live",
})
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure duplicate-url "${mutated_catalog}" 'duplicate enabled URL'

namespace_repo="${tmp_dir}/namespace-conflict-repo"
mkdir -p "${namespace_repo}/apps/beans-and-bites" "${namespace_repo}/catalog"
cp "${repo_dir}/apps/beans-and-bites/app.yaml" \
  "${repo_dir}/apps/beans-and-bites/kustomization.yaml" \
  "${repo_dir}/apps/beans-and-bites/virtualserver-frontend.yaml" \
  "${repo_dir}/apps/beans-and-bites/httproute.yaml" \
  "${namespace_repo}/apps/beans-and-bites/"
cp "${catalog_file}" "${namespace_repo}/catalog/homepage.yaml"
python3 - "${namespace_repo}" <<'PY'
import sys
from pathlib import Path

import yaml

repo = Path(sys.argv[1])
kustomization_path = repo / "apps/beans-and-bites/kustomization.yaml"
kustomization = yaml.safe_load(kustomization_path.read_text(encoding="utf-8"))
kustomization["namespace"] = "wrong-namespace"
kustomization_path.write_text(
    yaml.safe_dump(kustomization, sort_keys=False), encoding="utf-8"
)

catalog_path = repo / "catalog/homepage.yaml"
catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
catalog["entries"] = [
    entry
    for entry in catalog["entries"]
    if entry["id"] in {"vs-beans-and-bites", "route-beans-and-bites"}
]
catalog_path.write_text(yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8")
PY
namespace_error="${tmp_dir}/namespace-conflict.stderr"
if python3 "${repo_dir}/hack/render-homepage-catalog.py" \
  --repo-root "${namespace_repo}" \
  --catalog "${namespace_repo}/catalog/homepage.yaml" \
  --output "${tmp_dir}/namespace-conflict.yaml" \
  >"${tmp_dir}/namespace-conflict.stdout" 2>"${namespace_error}"; then
  fail 'mutation namespace-conflict unexpectedly passed'
fi
grep -qi -- 'conflicting namespace' "${namespace_error}" || \
  fail 'namespace-conflict did not report the expected diagnostic'

mutated_catalog="${tmp_dir}/kind-source.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
entry = next(item for item in data["entries"] if item["id"] == "vs-beans-and-bites")
entry["source"].update({
    "path": "kind/apps/nginx/nginx.yaml",
    "kind": "VirtualServer",
    "name": "nginx-test",
    "expectedHostname": "nginx.127.0.0.1.nip.io",
})
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure kind-source "${mutated_catalog}" 'kind sources are not allowed'

kind_symlink_repo="${tmp_dir}/kind-symlink-repo"
mkdir -p "${kind_symlink_repo}/apps/beans-and-bites" \
  "${kind_symlink_repo}/kind/apps/nginx" "${kind_symlink_repo}/catalog"
cp "${repo_dir}/apps/beans-and-bites/app.yaml" \
  "${repo_dir}/apps/beans-and-bites/kustomization.yaml" \
  "${repo_dir}/apps/beans-and-bites/httproute.yaml" \
  "${kind_symlink_repo}/apps/beans-and-bites/"
cp "${repo_dir}/kind/apps/nginx/app.yaml" \
  "${repo_dir}/kind/apps/nginx/kustomization.yaml" \
  "${repo_dir}/kind/apps/nginx/nginx.yaml" \
  "${kind_symlink_repo}/kind/apps/nginx/"
ln -s "../../kind/apps/nginx/nginx.yaml" \
  "${kind_symlink_repo}/apps/beans-and-bites/kind-link.yaml"
cp "${catalog_file}" "${kind_symlink_repo}/catalog/homepage.yaml"
python3 - "${kind_symlink_repo}" <<'PY'
import sys
from pathlib import Path

import yaml

repo = Path(sys.argv[1])
catalog_path = repo / "catalog/homepage.yaml"
catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
catalog["entries"] = [
    entry
    for entry in catalog["entries"]
    if entry["id"] in {"vs-beans-and-bites", "route-beans-and-bites"}
]
entry = next(item for item in catalog["entries"] if item["id"] == "vs-beans-and-bites")
entry["source"].update(
    {
        "path": "apps/beans-and-bites/kind-link.yaml",
        "kind": "VirtualServer",
        "name": "nginx-test",
        "expectedHostname": "nginx.127.0.0.1.nip.io",
    }
)
catalog_path.write_text(yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8")
PY
kind_symlink_error="${tmp_dir}/kind-symlink.stderr"
if python3 "${repo_dir}/hack/render-homepage-catalog.py" \
  --repo-root "${kind_symlink_repo}" \
  --catalog "${kind_symlink_repo}/catalog/homepage.yaml" \
  --output "${tmp_dir}/kind-symlink.yaml" \
  >"${tmp_dir}/kind-symlink.stdout" 2>"${kind_symlink_error}"; then
  fail 'mutation kind-symlink unexpectedly passed'
fi
grep -qi -- 'kind sources are not allowed' "${kind_symlink_error}" || \
  fail 'kind-symlink did not report the expected diagnostic'

dns_label_repo="${tmp_dir}/dns-label-repo"
mkdir -p "${dns_label_repo}/apps/beans-and-bites" "${dns_label_repo}/catalog"
cp "${repo_dir}/apps/beans-and-bites/app.yaml" \
  "${repo_dir}/apps/beans-and-bites/kustomization.yaml" \
  "${repo_dir}/apps/beans-and-bites/virtualserver-frontend.yaml" \
  "${repo_dir}/apps/beans-and-bites/httproute.yaml" \
  "${dns_label_repo}/apps/beans-and-bites/"
cp "${catalog_file}" "${dns_label_repo}/catalog/homepage.yaml"
python3 - "${dns_label_repo}" <<'PY'
import sys
from pathlib import Path

import yaml

repo = Path(sys.argv[1])
invalid_hostname = "beans.-invalid.novotny.live"
source_path = repo / "apps/beans-and-bites/virtualserver-frontend.yaml"
documents = list(yaml.safe_load_all(source_path.read_text(encoding="utf-8")))
source = next(
    document
    for document in documents
    if document.get("kind") == "VirtualServer"
    and document.get("metadata", {}).get("name") == "beans-and-bites"
)
source["spec"]["host"] = invalid_hostname
source_path.write_text(yaml.safe_dump_all(documents, sort_keys=False), encoding="utf-8")

catalog_path = repo / "catalog/homepage.yaml"
catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
catalog["entries"] = [
    entry
    for entry in catalog["entries"]
    if entry["id"] in {"vs-beans-and-bites", "route-beans-and-bites"}
]
entry = next(item for item in catalog["entries"] if item["id"] == "vs-beans-and-bites")
entry["source"]["expectedHostname"] = invalid_hostname
catalog_path.write_text(yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8")
PY
dns_label_error="${tmp_dir}/dns-label.stderr"
if python3 "${repo_dir}/hack/render-homepage-catalog.py" \
  --repo-root "${dns_label_repo}" \
  --catalog "${dns_label_repo}/catalog/homepage.yaml" \
  --output "${tmp_dir}/dns-label.yaml" \
  >"${tmp_dir}/dns-label.stdout" 2>"${dns_label_error}"; then
  fail 'mutation dns-label unexpectedly passed'
fi
grep -qi -- 'not a valid hostname' "${dns_label_error}" || \
  fail 'dns-label did not report the expected diagnostic'

mutated_catalog="${tmp_dir}/credential-field.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
entry = next(item for item in data["entries"] if item["id"] == "vs-beans-and-bites")
entry["widget"] = {"type": "generic"}
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure credential-field "${mutated_catalog}" 'unsupported field'

mutated_catalog="${tmp_dir}/pve-missing-field.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0].pop("url")
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-missing-field "${mutated_catalog}" 'missing required field'

mutated_catalog="${tmp_dir}/pve-missing-section.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data.pop("pveNativeServices")
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-missing-section "${mutated_catalog}" 'missing required field'

mutated_catalog="${tmp_dir}/pve-empty-section.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"] = []
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-empty-section "${mutated_catalog}" 'non-empty list'

mutated_catalog="${tmp_dir}/pve-unknown-field.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["namespace"] = "default"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-unknown-field "${mutated_catalog}" 'unsupported field'

mutated_catalog="${tmp_dir}/pve-source-field.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["source"] = {"path": "not-a-kubernetes-source"}
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-source-field "${mutated_catalog}" 'unsupported field'

mutated_catalog="${tmp_dir}/pve-credential-field.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["token"] = "not-a-real-token"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-credential-field "${mutated_catalog}" 'credential-shaped field'

mutated_catalog="${tmp_dir}/pve-credential-value.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["description"] = "contains token material"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-credential-value "${mutated_catalog}" 'credential-shaped value'

mutated_catalog="${tmp_dir}/pve-widget.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["widget"] = {"type": "generic"}
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-widget "${mutated_catalog}" 'unsupported field'

mutated_catalog="${tmp_dir}/pve-invalid-scheme.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "ftp://homepage.home.arpa:3000/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-invalid-scheme "${mutated_catalog}" 'HTTP or HTTPS'

mutated_catalog="${tmp_dir}/pve-url-userinfo.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://user:pass@homepage.home.arpa:3000/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-url-userinfo "${mutated_catalog}" 'username or password'

mutated_catalog="${tmp_dir}/pve-url-query.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://homepage.home.arpa:3000/?view=full"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-url-query "${mutated_catalog}" 'query or fragment'

mutated_catalog="${tmp_dir}/pve-url-fragment.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://homepage.home.arpa:3000/#top"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-url-fragment "${mutated_catalog}" 'query or fragment'

mutated_catalog="${tmp_dir}/pve-empty-query.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://homepage.home.arpa:3000/?"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-empty-query "${mutated_catalog}" 'query or fragment'

mutated_catalog="${tmp_dir}/pve-empty-fragment.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://homepage.home.arpa:3000/#"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-empty-fragment "${mutated_catalog}" 'query or fragment'

for mutation in \
  'pve-empty-port|https://hermes.home.arpa:/' \
  'pve-uppercase-authority|HTTPS://HERMES.HOME.ARPA/' \
  'pve-default-port|https://hermes.home.arpa:443/' \
  'pve-leading-zero-port|https://hermes.home.arpa:000443/'
do
  label=${mutation%%|*}
  url=${mutation#*|}
  mutated_catalog="${tmp_dir}/${label}.yaml"
  cp "${catalog_file}" "${mutated_catalog}"
  python3 - "${mutated_catalog}" "${url}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = sys.argv[2]
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
  expect_failure "${label}" "${mutated_catalog}" 'canonical'
done

mutated_catalog="${tmp_dir}/pve-control-character.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "https://hermes.home.arpa\t/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-control-character "${mutated_catalog}" 'control character'

mutated_catalog="${tmp_dir}/pve-unsupported-path.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://homepage.home.arpa:3000/private/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-unsupported-path "${mutated_catalog}" 'path must be'

mutated_catalog="${tmp_dir}/pve-public-ip.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "https://8.8.8.8/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-public-ip "${mutated_catalog}" 'private RFC1918'

mutated_catalog="${tmp_dir}/pve-loopback-ip.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://127.0.0.1/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-loopback-ip "${mutated_catalog}" 'private RFC1918'

mutated_catalog="${tmp_dir}/pve-link-local-ip.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://169.254.1.1/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-link-local-ip "${mutated_catalog}" 'private RFC1918'

mutated_catalog="${tmp_dir}/pve-unspecified-ip.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://0.0.0.0/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-unspecified-ip "${mutated_catalog}" 'private RFC1918'

mutated_catalog="${tmp_dir}/pve-multicast-ip.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "http://224.0.0.1/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-multicast-ip "${mutated_catalog}" 'private RFC1918'

mutated_catalog="${tmp_dir}/pve-deceptive-hostname.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "https://pve.novotny.live.attacker.example/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-deceptive-hostname "${mutated_catalog}" 'novotny.live'

mutated_catalog="${tmp_dir}/pve-duplicate-id.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import copy
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
clone = copy.deepcopy(data["pveNativeServices"][0])
clone["displayName"] = "Duplicate PVE ID"
clone["url"] = "http://duplicate.home.arpa:3001/"
data["pveNativeServices"].append(clone)
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-duplicate-id "${mutated_catalog}" 'duplicate entry ID'

mutated_catalog="${tmp_dir}/pve-k8s-id-collision.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["id"] = "vs-beans-and-bites"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-k8s-id-collision "${mutated_catalog}" 'duplicate entry ID'

mutated_catalog="${tmp_dir}/pve-duplicate-url.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import copy
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
clone = copy.deepcopy(data["pveNativeServices"][0])
clone["id"] = "pve-duplicate-url"
clone["displayName"] = "Duplicate PVE URL"
data["pveNativeServices"].append(clone)
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-duplicate-url "${mutated_catalog}" 'duplicate enabled URL'

mutated_catalog="${tmp_dir}/pve-k8s-url-collision.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data["pveNativeServices"][0]["url"] = "https://beans-and-bites.novotny.live/"
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-k8s-url-collision "${mutated_catalog}" 'duplicate enabled URL'

mutated_catalog="${tmp_dir}/pve-duplicate-name.yaml"
cp "${catalog_file}" "${mutated_catalog}"
python3 - "${mutated_catalog}" <<'PY'
import copy
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
clone = copy.deepcopy(data["pveNativeServices"][0])
clone["id"] = "pve-duplicate-name"
clone["url"] = "http://duplicate-name.home.arpa:3001/"
data["pveNativeServices"].append(clone)
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_failure pve-duplicate-name "${mutated_catalog}" 'duplicate enabled display name'

expect_output_group_failure() {
  local label="$1"
  local mutated_artifact="$2"

  if python3 - "${mutated_artifact}" >/dev/null 2>&1 <<'PY'
import sys
from pathlib import Path
import yaml

artifact = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = [
    "PVE Native Services",
    "Kubernetes VirtualServers",
    "Kubernetes HTTPRoutes",
]
actual = [next(iter(group)) for group in artifact]
assert actual == expected, (actual, expected)
PY
  then
    fail "output group mutation ${label} unexpectedly passed"
  fi
}

mutated_artifact="${tmp_dir}/output-groups-reordered.yaml"
cp "${artifact_file}" "${mutated_artifact}"
python3 - "${mutated_artifact}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data[0], data[2] = data[2], data[0]
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_output_group_failure output-groups-reordered "${mutated_artifact}"

mutated_artifact="${tmp_dir}/output-groups-missing.yaml"
cp "${artifact_file}" "${mutated_artifact}"
python3 - "${mutated_artifact}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data.pop(0)
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_output_group_failure output-groups-missing "${mutated_artifact}"

mutated_artifact="${tmp_dir}/output-groups-extra.yaml"
cp "${artifact_file}" "${mutated_artifact}"
python3 - "${mutated_artifact}" <<'PY'
import sys
from pathlib import Path
import yaml

path = Path(sys.argv[1])
data = yaml.safe_load(path.read_text(encoding="utf-8"))
data.append({"Unexpected Group": []})
path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY
expect_output_group_failure output-groups-extra "${mutated_artifact}"

printf 'homepage-catalog: ok\n'
