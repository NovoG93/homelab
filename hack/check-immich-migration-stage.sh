#!/usr/bin/env bash
# Contract for the migration-safe Immich staging revision.
set -Eeuo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
kustomization="$repo_dir/apps/immich/kustomization.yaml"
values="$repo_dir/apps/immich/values.yaml"
chart_dir="$repo_dir/helmCharts/immich-0.13.2/immich"

fail() {
  printf 'immich migration contract: FAIL: %s\n' "$*" >&2
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

workflow="$repo_dir/.github/workflows/helm-upgrade-test.yml"
[ -f "$workflow" ] || fail 'Helm CI workflow is missing'
yq -e '.' "$workflow" >/dev/null 2>&1 || fail 'Helm CI workflow is not valid YAML'
grep -Fq 'bash hack/check-immich-migration-stage.sh' "$workflow" || \
  fail 'Helm CI does not run the Immich migration contract'
grep -Fq '"helmCharts/immich-0.13.2/**"' "$workflow" || \
  fail 'vendored chart changes do not trigger Helm CI'
grep -Fq '"hack/check-immich-migration-stage.sh"' "$workflow" || \
  fail 'migration contract changes do not trigger Helm CI'
grep -Fq 'bash hack/tests/monitoring-render.sh' "$workflow" || \
  fail 'upstream monitoring render contract was lost'
grep -Fq -- '--skip-initial-deploy' "$workflow" || \
  fail 'upstream Kind cluster-only bootstrap was lost'
seen_prerequisites=false
validated_order=false
while IFS= read -r step; do
  if [ "$step" = 'Install Immich CI prerequisites' ]; then
    seen_prerequisites=true
  elif [ "$step" = 'Server-side validate changed applications' ]; then
    [ "$seen_prerequisites" = true ] || \
      fail 'Kind CI must install Immich prerequisites before server-side validation'
    validated_order=true
  fi
done < <(yq -r '.jobs.kind.steps[].name' "$workflow")
[ "$validated_order" = true ] || fail 'Kind CI prerequisites or server validation are missing'
prerequisite_commands=$(yq -r '.jobs.kind.steps[] | select(.name == "Install Immich CI prerequisites") | .run' "$workflow")
for required in \
  'kind/tools/external-secret-operator' \
  'kubectl create namespace external-secret-operator' \
  'condition=Established' \
  'select(.kind != "ClusterSecretStore")' \
  'kubectl create namespace immich'; do
  [[ "$prerequisite_commands" == *"$required"* ]] || \
    fail "Kind CI prerequisite step lost $required"
done

[ -f "$kustomization" ] || fail "missing $kustomization"
[ -f "$values" ] || fail "missing $values"

assert_yq "$kustomization" \
  '(.helmCharts | length == 1) and (.helmCharts[0].name == "immich") and (.helmCharts[0].version == "0.13.2")' \
  'kustomization does not pin Immich chart 0.13.2'
assert_yq "$kustomization" \
  '.helmGlobals.chartHome == "../../helmCharts/immich-0.13.2/"' \
  'chartHome must resolve to the tracked chart on a clean CI checkout'

[ -f "$chart_dir/Chart.yaml" ] || fail "missing vendored Immich chart at $chart_dir"
git -C "$repo_dir" ls-files --error-unmatch -- \
  helmCharts/immich-0.13.2/immich/Chart.yaml >/dev/null 2>&1 || \
  fail 'Immich chart is present locally but not staged/tracked in Git'
git -C "$repo_dir" ls-files --error-unmatch -- \
  helmCharts/immich-0.13.2/immich/charts/common/Chart.yaml >/dev/null 2>&1 || \
  fail 'common chart is present locally but not staged/tracked in Git'

chart_version=$(yq -r '.version // ""' "$chart_dir/Chart.yaml")
[ "$chart_version" = "0.13.2" ] || fail "vendored chart metadata is not version 0.13.2"
common_dependency_version=$(yq -r '[.dependencies[]? | select(.name == "common")][0].version // ""' "$chart_dir/Chart.yaml")
[ -n "$common_dependency_version" ] || fail 'vendored chart has no common dependency declaration'
common_chart_dir="$chart_dir/charts/common"
[ -f "$common_chart_dir/Chart.yaml" ] || fail 'vendored common dependency chart is missing'
common_chart_version=$(yq -r '.version // ""' "$common_chart_dir/Chart.yaml")
[ "$common_chart_version" = "$common_dependency_version" ] || \
  fail 'vendored common dependency does not match the chart dependency declaration'

assert_yq "$values" \
  '.server.enabled == false and .["machine-learning"].enabled == false and .valkey.enabled == false' \
  'server, machine-learning, and valkey must be disabled in the staging values'
assert_yq "$values" \
  '.server.controllers.main.containers.main.image.repository == "ghcr.io/immich-app/immich-server" and .server.controllers.main.containers.main.image.tag == "v3.2.4"' \
  'server image must use the chart 0.13.2 nested image path and tag v3.2.4'
assert_yq "$values" \
  '.["machine-learning"].controllers.main.containers.main.image.repository == "ghcr.io/immich-app/immich-machine-learning" and .["machine-learning"].controllers.main.containers.main.image.tag == "v3.2.4"' \
  'machine-learning image must use the chart 0.13.2 nested image path and tag v3.2.4'
assert_yq "$values" \
  '([.controllers.main.containers.main.env // {} | keys[]? | select(test("^DB_"))] | length) == 0' \
  'DB_* environment settings must not remain in the global controller values'
assert_yq "$values" \
  '(.valkey.persistence.data.type // null) == null and (.valkey.persistence.data.accessMode // null) == null' \
  'disabled valkey values must not carry invalid emptyDir persistence fields'

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/immich-migration-contract.XXXXXX")
cleanup() {
  rm -f "$work_dir/default.yaml" "$work_dir/active.yaml" "$work_dir/kustomize.err" "$work_dir/helm.err"
  rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT

default_render="$work_dir/default.yaml"
if ! kustomize build --enable-helm "$repo_dir/apps/immich" >"$default_render" 2>"$work_dir/kustomize.err"; then
  fail 'default Immich kustomization did not render'
fi

if yq -e 'select(.kind == "Deployment" or .kind == "StatefulSet" or .kind == "DaemonSet" or .kind == "Job" or .kind == "CronJob")' "$default_render" >/dev/null 2>&1; then
  fail 'default staging render contains an active application workload'
fi
if yq -e 'select(.kind == "Cluster" and .apiVersion == "postgresql.cnpg.io/v1")' "$default_render" >/dev/null 2>&1; then
  fail 'default staging render contains a CloudNativePG Cluster'
fi
if yq -e 'select(.kind == "HTTPRoute" or .kind == "VirtualServer" or .kind == "Ingress")' "$default_render" >/dev/null 2>&1; then
  fail 'default staging render contains an active route'
fi
if yq -e 'select(.kind != "PersistentVolume" and .metadata.namespace != "immich")' "$default_render" >/dev/null 2>&1; then
  fail 'staged namespaced resources must explicitly target the Immich namespace'
fi

assert_yq "$default_render" \
  'select(.kind == "PersistentVolume" and .metadata.name == "immich-smb") | .spec.persistentVolumeReclaimPolicy == "Retain" and .metadata.annotations["argocd.argoproj.io/sync-options"] == "Prune=false"' \
  'media PersistentVolume must be Retain and protected from Argo pruning'
assert_yq "$default_render" \
  'select(.kind == "PersistentVolumeClaim" and .metadata.name == "immich-smb-claim") | .spec.volumeName == "immich-smb"' \
  'media PersistentVolumeClaim must continue to bind the existing media volume'

active_render="$work_dir/active.yaml"
if ! helm template immich "$chart_dir" --namespace immich --values "$values" \
  --set server.enabled=true --set 'machine-learning.enabled=true' --set valkey.enabled=true \
  >"$active_render" 2>"$work_dir/helm.err"; then
  fail 'scratch-only all-components Immich Helm render did not succeed'
fi

assert_yq "$active_render" \
  'select((.kind == "Deployment" or .kind == "StatefulSet") and .metadata.name == "immich-server") | ([.spec.template.spec.containers[] | .env // [] | .[] | select(.name == "DB_USERNAME" and .valueFrom.secretKeyRef.name == "immich-database-credentials")] | length) == 1 and ([.spec.template.spec.containers[] | .env // [] | .[] | select(.name == "DB_PASSWORD" and .valueFrom.secretKeyRef.name == "immich-database-credentials")] | length) == 1' \
  'server must own the database secret references in the active scratch render'
assert_yq "$active_render" \
  'select((.kind == "Deployment" or .kind == "StatefulSet") and .metadata.name == "immich-server") | ([.spec.template.spec.containers[] | .env // [] | .[] | select(.name | test("^DB_")) | .name] | sort | join(",")) == "DB_DATABASE_NAME,DB_HOSTNAME,DB_PASSWORD,DB_USERNAME"' \
  'server must receive exactly the four unique DB_* connection settings'
assert_yq "$active_render" \
  'select((.kind == "Deployment" or .kind == "StatefulSet") and .metadata.name == "immich-server") | ([.spec.template.spec.containers[] | .env // [] | .[] | select(.name == "DB_USERNAME" or .name == "DB_PASSWORD") | select(has("value") or .valueFrom.secretKeyRef.name != "immich-database-credentials")] | length) == 0' \
  'server DB credentials must be secret references, never literals'
assert_yq "$active_render" \
  'select((.kind == "Deployment" or .kind == "StatefulSet") and .metadata.name == "immich-machine-learning") | ([.spec.template.spec.containers[] | .env // [] | .[] | select(.name | test("^DB_"))] | length) == 0' \
  'machine-learning must not receive DB_* environment settings'
assert_yq "$active_render" \
  'select((.kind == "Deployment" or .kind == "StatefulSet") and .metadata.name == "immich-valkey") | ([.spec.template.spec.containers[] | .env // [] | .[] | select(.name | test("^DB_"))] | length) == 0' \
  'valkey must render without DB_* environment settings'

printf 'immich migration contract: ok\n'
