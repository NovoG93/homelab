#!/usr/bin/env bash
# Contract for Immich preparation-only local storage and import manifests.
set -Eeuo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
storage_class="$repo_dir/apps/immich/immich-local-storage-class.yaml"
postgres_pv="$repo_dir/apps/immich/immich-postgres-local-pv.yaml"
cnpg_cluster="$repo_dir/apps/immich/cloudnative-pg/pg-db.yaml"
kustomization="$repo_dir/apps/immich/kustomization.yaml"

fail() {
  printf 'immich storage preparation: FAIL: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

assert_yq() {
  local file=$1
  local expression=$2
  local message=$3
  yq -e "$expression" "$file" >/dev/null 2>&1 || fail "$message"
}

require_command helm
require_command kustomize
require_command yq

for file in "$storage_class" "$postgres_pv" "$cnpg_cluster" "$kustomization"; do
  [ -f "$file" ] || fail "missing $file"
done

assert_yq "$storage_class" \
  '.apiVersion == "storage.k8s.io/v1" and .kind == "StorageClass" and .metadata.name == "immich-local" and .provisioner == "kubernetes.io/no-provisioner" and .volumeBindingMode == "WaitForFirstConsumer" and .reclaimPolicy == "Retain" and .metadata.annotations["argocd.argoproj.io/sync-options"] == "Prune=false"' \
  'local StorageClass must be no-provisioner, WaitForFirstConsumer, Retain, and Prune=false'

assert_yq "$postgres_pv" \
  '.apiVersion == "v1" and .kind == "PersistentVolume" and .metadata.name == "immich-postgres-local" and .spec.capacity.storage == "20Gi" and (.spec.accessModes | length == 1) and .spec.accessModes[0] == "ReadWriteOnce" and .spec.volumeMode == "Filesystem" and .spec.persistentVolumeReclaimPolicy == "Retain" and .metadata.annotations["argocd.argoproj.io/sync-options"] == "Prune=false" and .spec.storageClassName == "immich-local" and .spec.local.path == "/var/lib/immich/postgres" and (.spec | has("hostPath") | not)' \
  'local PostgreSQL PV must be 20Gi RWO, Filesystem, Retain, Prune=false, local-path backed, and not hostPath-backed'
assert_yq "$postgres_pv" \
  '(.spec.nodeAffinity.required.nodeSelectorTerms | length == 1) and (.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions | length == 1) and .spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].key == "kubernetes.io/hostname" and .spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].operator == "In" and (.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values | length == 1) and .spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0] == "wp2"' \
  'local PostgreSQL PV must be required-affine to wp2'

assert_yq "$cnpg_cluster" \
  '.apiVersion == "postgresql.cnpg.io/v1" and .kind == "Cluster" and .metadata.name == "immich-postgres" and .spec.instances == 1 and .spec.storage.pvcTemplate.storageClassName == "immich-local" and .spec.storage.pvcTemplate.resources.requests.storage == "20Gi" and .spec.storage.pvcTemplate.volumeMode == "Filesystem" and (.spec.storage.pvcTemplate.accessModes | length == 1) and .spec.storage.pvcTemplate.accessModes[0] == "ReadWriteOnce"' \
  'CNPG skeleton must request the retained 20Gi immich-local RWO PVC'
assert_yq "$cnpg_cluster" \
  '.spec.bootstrap.initdb.import.type == "microservice" and (.spec.bootstrap.initdb.import.databases | length == 1) and .spec.bootstrap.initdb.import.databases[0] == "immich-db" and .spec.bootstrap.initdb.import.source.externalCluster == "immich-restore-source" and (.spec.bootstrap.initdb | has("postInitApplicationSQL") | not)' \
  'CNPG skeleton must use import.microservice for immich-db and must not retain fresh-initdb SQL'
assert_yq "$cnpg_cluster" \
  '(.spec.externalClusters | length == 1) and .spec.externalClusters[0].name == "immich-restore-source" and .spec.externalClusters[0].connectionParameters.host == "immich-restore-source.immich.svc.cluster.local" and .spec.externalClusters[0].connectionParameters.port == "5432" and (.spec.externalClusters[0].connectionParameters.port | tag) == "!!str" and .spec.externalClusters[0].connectionParameters.user == "immich-import" and .spec.externalClusters[0].connectionParameters.dbname == "postgres" and .spec.externalClusters[0].password.name == "immich-restore-source-credentials" and .spec.externalClusters[0].password.key == "password"' \
  'CNPG skeleton must use a named source Service and Secret with a string-valued source port'
assert_yq "$cnpg_cluster" \
  '.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key == "kubernetes.io/hostname" and (.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values | length == 1) and .spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0] == "wp2"' \
  'CNPG skeleton must remain placed on wp2'
assert_yq "$cnpg_cluster" \
  '(.spec | has("tolerations") | not) and (.spec.affinity.tolerations | length == 1) and .spec.affinity.tolerations[0].key == "apps" and .spec.affinity.tolerations[0].operator == "Exists" and .spec.affinity.tolerations[0].effect == "NoSchedule"' \
  'CNPG tolerations must be nested under spec.affinity, not at the Cluster spec root'

if grep -Fq 'immich-local-storage-class.yaml' "$kustomization" || \
  grep -Fq 'immich-postgres-local-pv.yaml' "$kustomization" || \
  grep -Fq 'cloudnative-pg/pg-db.yaml' "$kustomization"; then
  fail 'preparation-only storage/CNPG resources must remain excluded from the disabled Kustomization'
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/immich-storage-preparation.XXXXXX")
cleanup() {
  rm -f "$work_dir/default.yaml" "$work_dir/kustomize.err"
  rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT

default_render="$work_dir/default.yaml"
if ! kustomize build --enable-helm "$repo_dir/apps/immich" >"$default_render" 2>"$work_dir/kustomize.err"; then
  fail 'disabled Immich Kustomization did not render'
fi

object_count=$(yq eval-all '[select(has("kind"))] | length' "$default_render")
[ "$object_count" = "8" ] || fail "disabled default render must contain exactly eight objects (got $object_count)"

expected_inventory=$(printf '%s\n' \
  'ConfigMap immich-immich-config' \
  'ExternalSecret immich-database-credentials' \
  'ExternalSecret immich-postgres-credentials' \
  'ExternalSecret smb-creds' \
  'PersistentVolume immich-production-smb' \
  'PersistentVolumeClaim immich-production-smb-claim' \
  'PersistentVolume immich-smb' \
  'PersistentVolumeClaim immich-smb-claim' | sort)
actual_inventory=$(yq eval --no-doc 'select(has("kind")) | [.kind, .metadata.name] | join(" ")' "$default_render" | sort)
[ "$actual_inventory" = "$expected_inventory" ] || {
  printf 'expected disabled inventory:\n%s\nactual disabled inventory:\n%s\n' "$expected_inventory" "$actual_inventory" >&2
  fail 'disabled default render inventory changed'
}

if yq -e 'select(.kind == "Deployment" or .kind == "StatefulSet" or .kind == "DaemonSet" or .kind == "Job" or .kind == "CronJob" or .kind == "Cluster" or .kind == "HTTPRoute" or .kind == "VirtualServer" or .kind == "Ingress" or .kind == "StorageClass" or (.kind == "PersistentVolume" and .metadata.name == "immich-postgres-local"))' "$default_render" >/dev/null 2>&1; then
  fail 'disabled default render contains a workload, CNPG Cluster, route, or preparation-only local storage resource'
fi

printf 'immich storage preparation: ok (eight disabled objects; production media is staged and local storage/import resources remain excluded)\n'
