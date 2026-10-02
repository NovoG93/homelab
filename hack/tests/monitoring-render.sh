#!/usr/bin/env bash
# Hermetic, cluster-free contract test for the monitoring Helm render.
set -euo pipefail

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/monitoring-render.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

remote_write_url='http://192.168.0.157:8428/api/v1/write'

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

grep -F 'Accepted transport risk' "${repo_dir}/tools/monitoring/README.md" >/dev/null || \
  fail 'the unauthenticated HTTP remote-write transport risk must be documented'

for command_name in kustomize jq yq; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is missing: ${command_name}"
done

render() {
  local source="$1"
  local output="$2"
  local json_output="$3"
  local -a build_flags=(--enable-helm)

  if [[ "${source}" == kind/tools/monitoring ]]; then
    build_flags+=(--load-restrictor LoadRestrictionsNone)
  fi

  kustomize build "${build_flags[@]}" "${repo_dir}/${source}" >"${output}" || \
    fail "kustomize render failed for ${source}"
  yq eval-all -o=json '[.]' "${output}" >"${json_output}" || \
    fail "YAML-to-JSON conversion failed for ${source}"
}

assert_json() {
  local json_file="$1"
  local filter="$2"
  local message="$3"

  jq -e "$filter" "${json_file}" >/dev/null || fail "${message}"
}

assert_json_with_remote() {
  local json_file="$1"
  local filter="$2"
  local message="$3"

  jq -e --arg remote_write_url "$remote_write_url" "$filter" "${json_file}" >/dev/null || \
    fail "${message}"
}

validate_custom_resources() {
  local json_file="$1"
  local label="$2"
  local schema_dir="${tmp_dir}/${label}-crd-schemas"
  local payload_file="${tmp_dir}/${label}-without-crds.yaml"

  command -v kubeconform >/dev/null 2>&1 || fail 'kubeconform is required for CRD-aware monitoring validation'
  mkdir -p "${schema_dir}"
  python3 - "${json_file}" "${schema_dir}" "${payload_file}" <<'PY'
import json
import pathlib
import sys

documents = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
schema_dir = pathlib.Path(sys.argv[2])
payload_path = pathlib.Path(sys.argv[3])

for document in documents:
    if document.get("kind") != "CustomResourceDefinition":
        continue
    group = document["spec"]["group"]
    kind = document["spec"]["names"]["kind"]
    for version in document["spec"]["versions"]:
        schema = version.get("schema", {}).get("openAPIV3Schema")
        if version.get("served") and schema:
            path = schema_dir / f"{group}_{kind}_{version['name']}.json"
            path.write_text(json.dumps(schema), encoding="utf-8")

with payload_path.open("w", encoding="utf-8") as handle:
    for document in documents:
        if document.get("kind") == "CustomResourceDefinition":
            continue
        json.dump(document, handle)
        handle.write("\n---\n")
PY

  kubeconform \
    -strict \
    -summary \
    -schema-location default \
    -schema-location "${schema_dir}/{{.Group}}_{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
    "${payload_file}"
}

assert_values() {
  local values_file="$1"
  local expression="$2"
  local message="$3"

  yq -e "$expression" "${values_file}" >/dev/null || fail "${message}"
}

production_yaml="${tmp_dir}/production.yaml"
production_json="${tmp_dir}/production.json"
kind_yaml="${tmp_dir}/kind.yaml"
kind_json="${tmp_dir}/kind.json"

assert_values "${repo_dir}/tools/monitoring/values.yaml" \
  '.prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues == false and .prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues == false and (.prometheus.prometheusSpec.serviceMonitorSelector | length == 0) and (.prometheus.prometheusSpec.podMonitorSelector | length == 0) and (.prometheus.prometheusSpec.serviceMonitorNamespaceSelector | length == 0) and (.prometheus.prometheusSpec.podMonitorNamespaceSelector | length == 0)' \
  'monitor selector values must explicitly select all monitors across namespaces'

render tools/monitoring "${production_yaml}" "${production_json}"
assert_json "${production_json}" \
  'map(select(.kind == "Namespace" and .metadata.name == "monitoring")) | length == 1' \
  'the production render must declare the monitoring namespace'

assert_json "${production_json}" \
  '[.[] | select(.kind == "Prometheus")] | length == 1' \
  'the production render must contain exactly one Prometheus resource'
assert_json "${production_json}" \
  'map(select(.kind == "Prometheus" and .spec.retention == "6h")) | length == 1' \
  'Prometheus retention must be 6h'
assert_json "${production_json}" \
  'map(select(.kind == "Prometheus" and .spec.externalLabels.cluster == "homelab")) | length == 1' \
  'Prometheus must carry externalLabels.cluster=homelab'
# shellcheck disable=SC2016
assert_json_with_remote "${production_json}" \
  '[.[] | select(.kind == "Prometheus") | (.spec.remoteWrite // [])[] | select(.url == $remote_write_url)] | length == 1' \
  'the production remote-write URL must occur exactly once'
assert_json "${production_json}" \
  'map(select(.kind == "Prometheus" and .spec.serviceMonitorSelector == {} and .spec.serviceMonitorNamespaceSelector == {} and .spec.podMonitorSelector == {} and .spec.podMonitorNamespaceSelector == {})) | length == 1' \
  'Prometheus must explicitly select all ServiceMonitors and PodMonitors across namespaces'
assert_json "${production_json}" \
  'map(select(.kind == "Prometheus") | .spec.resources) | length == 1 and all(.[]; .requests.cpu != null and .requests.memory != null and .limits.cpu != null and .limits.memory != null)' \
  'Prometheus must have explicit CPU and memory requests and limits'
assert_json "${production_json}" \
  'map(select(.kind == "Prometheus")) | length == 1 and .[0].spec.nodeSelector.tools == "true" and any(.[0].spec.tolerations[]?; .key == "tools" and .effect == "NoSchedule")' \
  'Prometheus must be scheduled on tools=true and tolerate the tools taint'

assert_json "${production_json}" \
  'map(select(.kind == "Deployment" and ((.metadata.name // "") | test("operator")))) | length == 1' \
  'the Prometheus Operator deployment must be present exactly once'
assert_json "${production_json}" \
  'map(select(.kind == "Deployment" and ((.metadata.name // "") | test("operator")))) | .[0].spec.template.spec.nodeSelector.tools == "true" and any(.[0].spec.template.spec.tolerations[]?; .key == "tools" and .effect == "NoSchedule")' \
  'the Prometheus Operator must be scheduled on tools=true and tolerate the tools taint'
assert_json "${production_json}" \
  'map(select(.kind == "Deployment" and ((.metadata.name // "") | test("operator"))) | .spec.template.spec.containers[]) | length >= 1 and all(.[]; .resources.requests.cpu != null and .resources.requests.memory != null and .resources.limits.cpu != null and .resources.limits.memory != null)' \
  'the Prometheus Operator must have explicit CPU and memory requests and limits'
assert_json "${production_json}" \
  '[.[] | select(.kind == "Job" and ((.metadata.name // "") | test("admission-(create|patch)$")))] | length == 2 and all(.[]; .spec.template.spec.nodeSelector.tools == "true" and any(.spec.template.spec.tolerations[]?; .key == "tools" and .operator == "Exists" and .effect == "NoSchedule") and all(.spec.template.spec.containers[]; .resources.requests.cpu != null and .resources.requests.memory != null and .resources.limits.cpu != null and .resources.limits.memory != null))' \
  'both admission Jobs must have tools scheduling, toleration, and explicit resources'
assert_json "${production_json}" \
  '[.[] | select(.kind == "Job" and ((.metadata.name // "") | test("admission-(create|patch)$")))] | length == 2 and all(.[]; .spec.ttlSecondsAfterFinished == 60 and (.metadata.annotations["helm.sh/hook"] | length > 0) and (.metadata.annotations["helm.sh/hook-delete-policy"] | length > 0))' \
  'both admission Jobs must retain TTL and Helm hook lifecycle metadata'

assert_json "${production_json}" \
  '[.[] | select(.kind == "Service" and ((.metadata.name // "") | test("kube-prometheus-(coredns|kube-controller-manager|kube-etcd|kube-proxy|kube-scheduler)$")))] | length == 5 and all(.[]; .metadata.namespace == "kube-system")' \
  'all five Kubernetes control-plane scrape Services must remain in kube-system'

assert_json "${production_json}" \
  'map(select(.kind == "Deployment" and .metadata.labels["app.kubernetes.io/name"] == "kube-state-metrics")) | length == 1' \
  'kube-state-metrics deployment must be present exactly once'
assert_json "${production_json}" \
  'map(select(.kind == "Deployment" and .metadata.labels["app.kubernetes.io/name"] == "kube-state-metrics")) | .[0].spec.template.spec.nodeSelector.tools == "true" and any(.[0].spec.template.spec.tolerations[]?; .key == "tools" and .effect == "NoSchedule")' \
  'kube-state-metrics must be scheduled on tools=true and tolerate the tools taint'
assert_json "${production_json}" \
  'map(select(.kind == "Deployment" and .metadata.labels["app.kubernetes.io/name"] == "kube-state-metrics") | .spec.template.spec.containers[]) | length >= 1 and all(.[]; .resources.requests.cpu != null and .resources.requests.memory != null and .resources.limits.cpu != null and .resources.limits.memory != null)' \
  'kube-state-metrics must have explicit CPU and memory requests and limits'

assert_json "${production_json}" \
  'map(select(.kind == "DaemonSet" and .metadata.labels["app.kubernetes.io/name"] == "prometheus-node-exporter")) | length == 1' \
  'node-exporter must be exactly one DaemonSet'
assert_json "${production_json}" \
  'map(select(.kind == "DaemonSet" and .metadata.labels["app.kubernetes.io/name"] == "prometheus-node-exporter")) | length == 1 and any(.[0].spec.template.spec.tolerations[]?; .key == "node-role.kubernetes.io/control-plane" and .operator == "Exists" and .effect == "NoSchedule")' \
  'node-exporter must tolerate the control-plane taint with Exists/NoSchedule'
assert_json "${production_json}" \
  'map(select(.kind == "DaemonSet" and .metadata.labels["app.kubernetes.io/name"] == "prometheus-node-exporter")) | length == 1 and any(.[0].spec.template.spec.tolerations[]?; .key == "tools" and .operator == "Exists" and .effect == "NoSchedule")' \
  'node-exporter must tolerate the tools taint with Exists/NoSchedule'
assert_json "${production_json}" \
  'map(select(.kind == "DaemonSet" and .metadata.labels["app.kubernetes.io/name"] == "prometheus-node-exporter")) | length == 1 and any(.[0].spec.template.spec.tolerations[]?; .key == "apps" and .operator == "Exists" and .effect == "NoSchedule")' \
  'node-exporter must tolerate the apps taint with Exists/NoSchedule'
assert_json "${production_json}" \
  'map(select(.kind == "DaemonSet" and .metadata.labels["app.kubernetes.io/name"] == "prometheus-node-exporter") | .spec.template.spec.containers[]) | length >= 1 and all(.[]; .resources.requests.cpu != null and .resources.requests.memory != null and .resources.limits.cpu != null and .resources.limits.memory != null)' \
  'node-exporter must have explicit CPU and memory requests and limits'

assert_json "${production_json}" \
  '[.[] | select((.kind == "Deployment" or .kind == "StatefulSet" or .kind == "DaemonSet") and (((.metadata.name // "") | ascii_downcase | contains("grafana")) or ((.metadata.name // "") | ascii_downcase | contains("alertmanager"))))] | length == 0' \
  'Grafana and Alertmanager workloads must be absent'
assert_json "${production_json}" \
  'map(select(.kind == "CustomResourceDefinition" and (.metadata.name | IN("prometheuses.monitoring.coreos.com", "servicemonitors.monitoring.coreos.com", "podmonitors.monitoring.coreos.com")))) | length == 3' \
  'Prometheus Operator monitoring CRDs must be included'
assert_json "${production_json}" \
  '[.[] | select(.metadata.name != null) | [(.apiVersion // ""), .kind, (.metadata.namespace // ""), .metadata.name] | join("|")] | sort | group_by(.) | map(select(length > 1)) | length == 0' \
  'the production render must not contain duplicate resource identities'
validate_custom_resources "${production_json}" production

render kind/tools/monitoring "${kind_yaml}" "${kind_json}"
assert_json "${kind_json}" \
  'map(select(.kind == "Namespace" and .metadata.name == "monitoring")) | length == 1' \
  'the Kind render must declare the monitoring namespace before direct apply'

assert_json "${kind_json}" \
  '[.[] | select(.kind == "Service" and ((.metadata.name // "") | test("kube-prometheus-(coredns|kube-controller-manager|kube-etcd|kube-proxy|kube-scheduler)$")))] | length == 5 and all(.[]; .metadata.namespace == "kube-system")' \
  'all five Kind control-plane scrape Services must remain in kube-system'
assert_json "${kind_json}" \
  '[.[] | select(.kind == "Job" and ((.metadata.name // "") | test("admission-(create|patch)$")))] | length == 2 and all(.[]; .spec.ttlSecondsAfterFinished == 60 and (.metadata.annotations["helm.sh/hook"] | length > 0) and (.metadata.annotations["helm.sh/hook-delete-policy"] | length > 0))' \
  'both Kind admission Jobs must retain TTL and Helm hook lifecycle metadata'

# shellcheck disable=SC2016
assert_json_with_remote "${kind_json}" \
  '[.[] | .. | strings | select(. == $remote_write_url or contains("192.168.0.157"))] | length == 0' \
  'the Kind render must not contain the production remote-write endpoint'
assert_json "${kind_json}" \
  '[.[] | select(.kind == "Prometheus") | (.spec.remoteWrite // [])[]] | length == 0' \
  'the Kind Prometheus must not configure remote-write'
assert_json "${kind_json}" \
  'map(select(.kind == "Prometheus" and .spec.externalLabels.cluster == "homelab")) | length == 0' \
  'the Kind overlay must not retain the production cluster label'
assert_json "${kind_json}" \
  'map(select(.kind == "Prometheus")) | length == 1 and .[0].spec.nodeSelector.tools == null and any(.[0].spec.tolerations[]?; .key == "tools") | not' \
  'the Kind Prometheus must not retain production tools scheduling'
assert_json "${kind_json}" \
  'map(select(.kind == "Deployment" and ((.metadata.name // "") | test("operator")))) | length == 1 and .[0].spec.template.spec.nodeSelector.tools == null' \
  'the Kind Prometheus Operator must not retain production tools scheduling'
assert_json "${kind_json}" \
  'map(select(.kind == "Deployment" and .metadata.labels["app.kubernetes.io/name"] == "kube-state-metrics")) | length == 1 and .[0].spec.template.spec.nodeSelector.tools == null' \
  'the Kind kube-state-metrics must not retain production tools scheduling'
# jq variables belong to jq, not the shell.
# shellcheck disable=SC2016
assert_json "${kind_json}" \
  'map(select(.kind == "DaemonSet" and .metadata.labels["app.kubernetes.io/name"] == "prometheus-node-exporter")) as $daemonsets | ($daemonsets | length) == 1 and all(["node-role.kubernetes.io/control-plane", "tools", "apps"][]; . as $key | any($daemonsets[0].spec.template.spec.tolerations[]?; .key == $key and .operator == "Exists" and .effect == "NoSchedule"))' \
  'the Kind node-exporter must tolerate every role taint so it covers every node'
assert_json "${kind_json}" \
  '[.[] | select((.kind == "Deployment" or .kind == "StatefulSet" or .kind == "DaemonSet") and (.spec.template.spec.containers? != null) and ((.metadata.name // "") | test("operator|prometheus|kube-state-metrics|node-exporter"))) | .spec.template.spec.containers[] | .resources // {}] | all(.[]; . == {})' \
  'the Kind overlay must not retain production resource requests or limits'
assert_json "${kind_json}" \
  '[.[] | select(.metadata.name != null) | [(.apiVersion // ""), .kind, (.metadata.namespace // ""), .metadata.name] | join("|")] | sort | group_by(.) | map(select(length > 1)) | length == 0' \
  'the Kind render must not contain duplicate resource identities'
validate_custom_resources "${kind_json}" kind

workflow="${repo_dir}/.github/workflows/helm-upgrade-test.yml"
directory_mapper="${repo_dir}/hack/ci/changed-application-directories.bash"
[[ -x "${directory_mapper}" ]] || fail 'the changed-application directory mapper must be executable'
mapped_directories="$({
  printf '%s\n' \
    'tools/monitoring/values.yaml' \
    'kind/tools/monitoring/values.yaml' \
    'kind/tools/kustomization.yaml'
} | (cd "${repo_dir}" && "${directory_mapper}"))"
[[ "${mapped_directories}" == $'kind/tools\nkind/tools/monitoring' ]] || \
  fail "the changed-application mapper returned unexpected directories: ${mapped_directories}"
# This is a literal workflow source assertion.
# shellcheck disable=SC2016
if [[ "$(grep -F -c 'kustomize build "${build_args[@]}" "$directory"' "${workflow}")" -lt 2 ]]; then
  fail 'both Kind server validation and deployment must pass overlay-specific Kustomize arguments'
fi
grep -F 'select(.kind == "Namespace" or .kind == "CustomResourceDefinition")' "${workflow}" >/dev/null || \
  fail 'the Kind server gate must install namespaces and CRDs before validating custom resources'
grep -F 'kubectl wait --for=condition=Established' "${workflow}" >/dev/null || \
  fail 'the Kind server gate must wait for CRD discovery before validating custom resources'
grep -F 'yq eval-all --no-doc' "${workflow}" >/dev/null || \
  fail 'the Kind server gate must not pass YAML document separators as CRD names'
# This is a literal workflow source assertion.
# shellcheck disable=SC2016
grep -F '[[ -s "$prerequisites" ]]' "${workflow}" >/dev/null || \
  fail 'the Kind server gate must skip kubectl apply when an overlay has no prerequisites'
# This is a literal workflow source assertion.
# shellcheck disable=SC2016
grep -F '"${crd_args[@]}"' "${workflow}" >/dev/null || \
  fail 'the Kind server gate must pass each CRD to kubectl wait as a separate argument'
# This is a literal workflow expression.
# shellcheck disable=SC2016
grep -F 'EVENT_NAME: ${{ github.event_name }}' "${workflow}" >/dev/null || \
  fail 'workflow_dispatch must select applications without PR-only SHA variables'
grep -F -- '-mindepth 3 -maxdepth 3' "${workflow}" >/dev/null || \
  fail 'workflow_dispatch must select leaf Kind application overlays'

printf 'monitoring-render: ok\n'
