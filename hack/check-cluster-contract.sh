#!/bin/sh
# Keeps cluster-contract.yaml honest: declared ApplicationSet names must exist,
# declared deferred kinds must be real kinds in the bootstrap payload, and every
# chart scheduling by a declared node role must carry a toleration.
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
contract="$repo_dir/cluster-contract.yaml"
appsets_dir="$repo_dir/tools/argocd/appSets"

yq -e '.kind == "ClusterContract"' "$contract" >/dev/null || {
  printf 'FAIL: %s is not a ClusterContract\n' "$contract" >&2; exit 1; }

# 1. Every declared ApplicationSet name is defined in the repo.
yq -r '.spec.bootstrap.applicationSets[]' "$contract" | while IFS= read -r name; do
  grep -q "^  name: $name$" "$appsets_dir"/*.yaml || {
    printf 'FAIL: ApplicationSet %s is declared but not defined\n' "$name" >&2; exit 1; }
done

# 2. Every declared deferred kind really appears in the bootstrap payload.
path=$(yq -r '.spec.bootstrap.path' "$contract")
rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT
kubectl kustomize --enable-helm "$repo_dir/$path" >"$rendered"
yq -r '.spec.bootstrap.deferredKinds[]' "$contract" | while IFS= read -r kind; do
  grep -q "^kind: $kind$" "$rendered" || {
    printf 'FAIL: deferred kind %s is declared but absent from the payload\n' "$kind" >&2; exit 1; }
done

# 3. Every chart scheduling by a declared node role declares a toleration.
yq -r '.spec.nodeRoles[].label' "$contract" | while IFS= read -r label; do
  for values in $(grep -rl "key: \"$label\"" "$repo_dir"/tools/*/values.yaml); do
    grep -qE "^[[:space:]]*tolerations:" "$values" || {
      printf 'FAIL: %s schedules by node role %s without a toleration\n' "$values" "$label" >&2; exit 1; }
  done
done

printf 'cluster-contract: ok\n'
