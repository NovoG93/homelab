#!/usr/bin/env python3
"""Validate the producer Homepage catalog and render Homepage services YAML.

The generator intentionally reads source manifests from the same checkout as the
catalog.  It does not query a Kubernetes API and it emits only ordinary HTTPS
links, descriptions, and icons; runtime credentials and Homepage widgets are
outside this contract.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode


API_VERSION = "homelab.novotny.live/v1alpha1"
CATALOG_KIND = "HomepageCatalog"
GROUPS = {
    "virtualservers": "Kubernetes VirtualServers",
    "httproutes": "Kubernetes HTTPRoutes",
}
SOURCE_KINDS = {
    "virtualservers": "VirtualServer",
    "httproutes": "HTTPRoute",
}
SOURCE_API_VERSIONS = {
    "VirtualServer": "k8s.nginx.org/v1",
    "HTTPRoute": "gateway.networking.k8s.io/v1",
}
ROOT_KEYS = {"apiVersion", "kind", "entries"}
ENTRY_KEYS = {
    "id",
    "group",
    "displayName",
    "description",
    "icon",
    "weight",
    "enabled",
    "source",
    "metadata",
}
SOURCE_KEYS = {"path", "kind", "name", "expectedHostname"}
METADATA_KEYS = {"exposure", "restricted"}
EXPOSURES = {"public", "restricted-admin", "backing-admin"}
HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
FORBIDDEN_CATALOG_WORDS_RE = re.compile(
    r"(?:password|credential|kubeconfig|api[_-]?key|secret|token)", re.IGNORECASE
)
BACKEND_OR_API_RE = re.compile(r"(?:^|[-_/])(?:api|backend)(?:[-_.]|$)", re.IGNORECASE)


class CatalogError(ValueError):
    """A fail-closed catalog or source validation error."""


class UniqueKeyLoader(yaml.SafeLoader):
    """PyYAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a mapping", node.start_mark)

    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_documents(path: Path) -> list[Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return list(yaml.load_all(handle, Loader=UniqueKeyLoader))
    except FileNotFoundError as exc:
        raise CatalogError(f"source path does not exist: {path}") from exc
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogError(f"could not parse YAML at {path}: {exc}") from exc


def load_single_mapping(path: Path, label: str) -> dict[str, Any]:
    documents = load_documents(path)
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise CatalogError(f"{label} must contain exactly one YAML mapping: {path}")
    return documents[0]


def require_mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(f"{context} must be a mapping")
    return value


def reject_unknown_keys(mapping: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        names = ", ".join(repr(name) for name in unknown)
        raise CatalogError(f"{context} has unsupported field(s): {names}")


def require_keys(mapping: dict[str, Any], required: set[str], context: str) -> None:
    missing = sorted(required - set(mapping))
    if missing:
        names = ", ".join(repr(name) for name in missing)
        raise CatalogError(f"{context} is missing required field(s): {names}")


def require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\n" in value or "\r" in value:
        raise CatalogError(f"{context} must be a non-empty single-line string")
    if FORBIDDEN_CATALOG_WORDS_RE.search(value):
        raise CatalogError(f"{context} contains a credential-shaped value")
    return value


def ensure_safe_catalog_strings(value: Any, context: str = "catalog") -> None:
    """Reject credential-shaped scalar values even in future optional fields."""
    if isinstance(value, str):
        if FORBIDDEN_CATALOG_WORDS_RE.search(value):
            raise CatalogError(f"{context} contains a credential-shaped value")
    elif isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and FORBIDDEN_CATALOG_WORDS_RE.search(key):
                raise CatalogError(f"{context} has a credential-shaped field: {key!r}")
            ensure_safe_catalog_strings(child, f"{context}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            ensure_safe_catalog_strings(child, f"{context}[{index}]")


def validate_relative_source_path(raw_path: Any, repo_root: Path) -> Path:
    path_text = require_string(raw_path, "source.path")
    if "\\" in path_text:
        raise CatalogError("source.path must use POSIX separators")
    relative = PurePosixPath(path_text)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise CatalogError(f"source path must be relative to the repository: {path_text!r}")
    if relative.parts[0] == "kind":
        raise CatalogError("kind sources are not allowed in the Homepage catalog")
    if relative.suffix not in {".yaml", ".yml"}:
        raise CatalogError(f"source path must point to a YAML file: {path_text!r}")

    root = repo_root.resolve()
    source_path = (root / Path(*relative.parts)).resolve()
    try:
        source_path.relative_to(root)
    except ValueError as exc:
        raise CatalogError(f"source path escapes the repository: {path_text!r}") from exc
    if source_path.relative_to(root).parts[0] == "kind":
        raise CatalogError("kind sources are not allowed in the Homepage catalog")
    if not source_path.is_file():
        raise CatalogError(f"source path does not exist: {path_text!r}")
    return source_path


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return False


def find_implied_namespace(source_path: Path, repo_root: Path) -> str:
    """Find the namespace declared by the owning app descriptor or Kustomization."""
    root = repo_root.resolve()
    current = source_path.parent.resolve()
    while True:
        app_namespace: str | None = None
        app_descriptor = current / "app.yaml"
        if app_descriptor.is_file():
            descriptor = load_single_mapping(app_descriptor, "app descriptor")
            descriptor_path = descriptor.get("path")
            if isinstance(descriptor_path, str):
                descriptor_target = (root / Path(*PurePosixPath(descriptor_path).parts)).resolve()
                if _same_path(descriptor_target, current):
                    namespace = descriptor.get("namespace")
                    if isinstance(namespace, str) and namespace.strip():
                        app_namespace = namespace
                    else:
                        raise CatalogError(
                            f"app descriptor has no namespace for source path: {source_path}"
                        )

        kustomization_namespace: str | None = None
        kustomization = current / "kustomization.yaml"
        if not kustomization.is_file():
            kustomization = current / "Kustomization"
        if kustomization.is_file():
            document = load_single_mapping(kustomization, "Kustomization")
            namespace = document.get("namespace")
            if isinstance(namespace, str) and namespace.strip():
                kustomization_namespace = namespace

        if (
            app_namespace is not None
            and kustomization_namespace is not None
            and app_namespace != kustomization_namespace
        ):
            raise CatalogError(
                f"conflicting namespace declarations for {current}: "
                f"app descriptor {app_namespace!r}, Kustomization {kustomization_namespace!r}"
            )
        if app_namespace is not None:
            return app_namespace
        if kustomization_namespace is not None:
            return kustomization_namespace

        if _same_path(current, root):
            break
        if root not in current.parents:
            break
        current = current.parent

    raise CatalogError(
        f"could not determine namespace from app descriptor or Kustomization for: {source_path}"
    )


def find_source_object(
    source_path: Path, source_kind: str, source_name: str, repo_root: Path
) -> dict[str, Any]:
    namespace = find_implied_namespace(source_path, repo_root)
    candidates: list[dict[str, Any]] = []
    for document in load_documents(source_path):
        if not isinstance(document, dict):
            continue
        if document.get("kind") != source_kind:
            continue
        metadata = document.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("name") != source_name:
            continue
        object_namespace = metadata.get("namespace")
        if object_namespace is not None and object_namespace != namespace:
            continue
        candidates.append(document)

    if not candidates:
        raise CatalogError(
            f"source object not found: {source_kind}/{source_name} in {source_path} "
            f"(namespace {namespace})"
        )
    if len(candidates) != 1:
        raise CatalogError(
            f"source object is ambiguous: {source_kind}/{source_name} in {source_path}"
        )

    document = candidates[0]
    expected_api_version = SOURCE_API_VERSIONS[source_kind]
    if document.get("apiVersion") != expected_api_version:
        raise CatalogError(
            f"source object has unexpected apiVersion: {source_kind}/{source_name} "
            f"must use {expected_api_version}"
        )
    return document


def extract_hostname(document: dict[str, Any], source_kind: str) -> str:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        raise CatalogError(f"source object has no spec: {source_kind}/{document['metadata']['name']}")

    if source_kind == "VirtualServer":
        hostname = spec.get("host")
        if not isinstance(hostname, str) or not hostname:
            raise CatalogError(
                f"VirtualServer/{document['metadata']['name']} has no spec.host"
            )
        return hostname

    hostnames = spec.get("hostnames")
    if not isinstance(hostnames, list) or not hostnames:
        raise CatalogError(
            f"HTTPRoute/{document['metadata']['name']} has no spec.hostnames[]"
        )
    if any(not isinstance(hostname, str) or not hostname for hostname in hostnames):
        raise CatalogError(
            f"HTTPRoute/{document['metadata']['name']} has an invalid spec.hostnames[] value"
        )
    if len(set(hostnames)) != len(hostnames):
        raise CatalogError(
            f"HTTPRoute/{document['metadata']['name']} has duplicate spec.hostnames[] values"
        )
    # The catalog's expectedHostname selects the one Homepage endpoint below.
    return hostnames[0] if len(hostnames) == 1 else ""


def validate_hostname(hostname: Any, context: str) -> str:
    hostname = require_string(hostname, context)
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or any(
            len(label) > 63 or not HOSTNAME_LABEL_RE.fullmatch(label)
            for label in labels
        )
    ):
        raise CatalogError(f"{context} is not a valid hostname: {hostname!r}")
    return hostname


def validate_metadata(value: Any, context: str) -> dict[str, Any]:
    if value is None:
        return {}
    metadata = require_mapping(value, context)
    reject_unknown_keys(metadata, METADATA_KEYS, context)
    if "exposure" in metadata:
        exposure = require_string(metadata["exposure"], f"{context}.exposure")
        if exposure not in EXPOSURES:
            raise CatalogError(f"{context}.exposure is unsupported: {exposure!r}")
    if "restricted" in metadata and not isinstance(metadata["restricted"], bool):
        raise CatalogError(f"{context}.restricted must be a boolean")
    return metadata


def validate_entry(
    raw_entry: Any,
    index: int,
    repo_root: Path,
    ids: set[str],
    enabled_urls: dict[str, str],
    enabled_names: dict[tuple[str, str], str],
) -> dict[str, Any]:
    context = f"entries[{index}]"
    entry = require_mapping(raw_entry, context)
    reject_unknown_keys(entry, ENTRY_KEYS, context)
    require_keys(
        entry,
        {"id", "group", "displayName", "description", "icon", "weight", "enabled", "source"},
        context,
    )

    entry_id = require_string(entry["id"], f"{context}.id")
    if not ID_RE.fullmatch(entry_id):
        raise CatalogError(f"{context}.id is not a stable kebab-case identifier")
    if entry_id in ids:
        raise CatalogError(f"duplicate entry ID: {entry_id}")
    ids.add(entry_id)

    group = require_string(entry["group"], f"{context}.group")
    if group not in GROUPS:
        raise CatalogError(f"unknown Homepage group: {group!r}")

    display_name = require_string(entry["displayName"], f"{context}.displayName")
    description = require_string(entry["description"], f"{context}.description")
    icon = require_string(entry["icon"], f"{context}.icon")
    weight = entry["weight"]
    if isinstance(weight, bool) or not isinstance(weight, int) or weight < 0:
        raise CatalogError(f"{context}.weight must be a non-negative integer")
    enabled = entry["enabled"]
    if not isinstance(enabled, bool):
        raise CatalogError(f"{context}.enabled must be a boolean")

    source = require_mapping(entry["source"], f"{context}.source")
    reject_unknown_keys(source, SOURCE_KEYS, f"{context}.source")
    require_keys(source, SOURCE_KEYS, f"{context}.source")
    source_kind = require_string(source["kind"], f"{context}.source.kind")
    if source_kind != SOURCE_KINDS[group]:
        raise CatalogError(
            f"{context}.source.kind {source_kind!r} does not match group {group!r}"
        )
    source_name = require_string(source["name"], f"{context}.source.name")
    expected_hostname = validate_hostname(
        source["expectedHostname"], f"{context}.source.expectedHostname"
    )
    source_path = validate_relative_source_path(source["path"], repo_root)

    metadata = validate_metadata(entry.get("metadata"), f"{context}.metadata")
    source_object = find_source_object(source_path, source_kind, source_name, repo_root)
    actual_hostname = extract_hostname(source_object, source_kind)
    if len(actual_hostname) == 0 and source_kind == "HTTPRoute":
        hostnames = source_object["spec"]["hostnames"]
        if expected_hostname not in hostnames:
            raise CatalogError(
                f"hostname mismatch for {source_kind}/{source_name}: "
                f"expected {expected_hostname!r}, found {hostnames!r}"
            )
        actual_hostname = expected_hostname
    if actual_hostname != expected_hostname:
        raise CatalogError(
            f"hostname mismatch for {source_kind}/{source_name}: "
            f"expected {expected_hostname!r}, found {actual_hostname!r}"
        )

    if enabled:
        source_identity = f"{source_path}/{source_kind}/{source_name}"
        if BACKEND_OR_API_RE.search(source_name) or BACKEND_OR_API_RE.search(str(source["path"])):
            raise CatalogError(
                f"backend/API-only source must be explicitly disabled: {source_identity}"
            )
        url = f"https://{expected_hostname}/"
        previous = enabled_urls.get(url)
        if previous is not None:
            raise CatalogError(f"duplicate enabled URL: {url} ({previous} and {entry_id})")
        enabled_urls[url] = entry_id
        name_key = (group, display_name)
        previous_name = enabled_names.get(name_key)
        if previous_name is not None:
            raise CatalogError(
                f"duplicate enabled display name: {display_name!r} in {group} "
                f"({previous_name} and {entry_id})"
            )
        enabled_names[name_key] = entry_id

    return {
        "id": entry_id,
        "group": group,
        "displayName": display_name,
        "description": description,
        "icon": icon,
        "weight": weight,
        "enabled": enabled,
        "source": {
            "path": str(source["path"]),
            "kind": source_kind,
            "name": source_name,
            "expectedHostname": expected_hostname,
        },
        "metadata": metadata,
    }


def validate_catalog(catalog: Any, repo_root: Path) -> list[dict[str, Any]]:
    document = require_mapping(catalog, "catalog")
    reject_unknown_keys(document, ROOT_KEYS, "catalog")
    require_keys(document, ROOT_KEYS, "catalog")
    if document["apiVersion"] != API_VERSION:
        raise CatalogError(f"catalog.apiVersion must be {API_VERSION!r}")
    if document["kind"] != CATALOG_KIND:
        raise CatalogError(f"catalog.kind must be {CATALOG_KIND!r}")
    entries = document["entries"]
    if not isinstance(entries, list) or not entries:
        raise CatalogError("catalog.entries must be a non-empty list")

    ensure_safe_catalog_strings(document)
    ids: set[str] = set()
    enabled_urls: dict[str, str] = {}
    enabled_names: dict[tuple[str, str], str] = {}
    normalized = [
        validate_entry(entry, index, repo_root, ids, enabled_urls, enabled_names)
        for index, entry in enumerate(entries)
    ]
    if not any(entry["enabled"] and entry["group"] == "virtualservers" for entry in normalized):
        raise CatalogError("catalog must enable at least one VirtualServer")
    if not any(entry["enabled"] and entry["group"] == "httproutes" for entry in normalized):
        raise CatalogError("catalog must enable at least one HTTPRoute")
    return normalized


def homepage_description(entry: dict[str, Any]) -> str:
    description = entry["description"]
    exposure = entry["metadata"].get("exposure")
    labels = {
        "restricted-admin": "[Restricted/Admin]",
        "backing-admin": "[Backing/Admin]",
    }
    label = labels.get(exposure)
    return f"{label} {description}" if label else description


def render_services(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    enabled_entries = [entry for entry in entries if entry["enabled"]]
    rendered: list[dict[str, Any]] = []
    for group in ("virtualservers", "httproutes"):
        services = []
        for entry in sorted(
            (item for item in enabled_entries if item["group"] == group),
            key=lambda item: (item["weight"], item["id"]),
        ):
            services.append(
                {
                    entry["displayName"]: {
                        "description": homepage_description(entry),
                        "href": f"https://{entry['source']['expectedHostname']}/",
                        "icon": entry["icon"],
                    }
                }
            )
        rendered.append({GROUPS[group]: services})
    return rendered


def dump_yaml(document: Any) -> str:
    return yaml.safe_dump(
        document,
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
        width=120,
    )


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=script_root)
    parser.add_argument("--catalog", type=Path, default=script_root / "catalog/homepage.yaml")
    parser.add_argument(
        "--output", type=Path, default=script_root / "catalog/homepage-services.yaml"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate and render without changing output; fail when output is stale or absent",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = args.repo_root.resolve()
    catalog_path = args.catalog.resolve()
    output_path = args.output.resolve()
    try:
        catalog_documents = load_documents(catalog_path)
        if len(catalog_documents) != 1:
            raise CatalogError(f"catalog must contain exactly one YAML document: {catalog_path}")
        entries = validate_catalog(catalog_documents[0], repo_root)
        rendered = dump_yaml(render_services(entries))
        if args.check:
            if not output_path.is_file():
                raise CatalogError(f"generated artifact is missing: {output_path}")
            if output_path.read_text(encoding="utf-8") != rendered:
                raise CatalogError(f"generated artifact is stale: {output_path}")
        else:
            atomic_write(output_path, rendered)
    except (CatalogError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
