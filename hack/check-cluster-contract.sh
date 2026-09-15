#!/bin/sh
# Keeps cluster-contract.yaml honest: declared ApplicationSet names must exist,
# declared deferred kinds must be real kinds in the bootstrap payload, every
# chart scheduling by a declared node role must carry a toleration, and the
# handover order must be adoptable in the order it declares.
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
  # shellcheck disable=SC2013  # values files paths carry no whitespace, so the
  # word splitting here is intentional.
  for values in $(grep -rl "key: \"$label\"" "$repo_dir"/tools/*/values.yaml); do
    grep -qE "^[[:space:]]*tolerations:" "$values" || {
      printf 'FAIL: %s schedules by node role %s without a toleration\n' "$values" "$label" >&2; exit 1; }
  done
done

# 4. The handover order is phased, the platform comes first, and every named
# Application has an app descriptor. The consumer waits for the ApplicationSets to
# generate each name before syncing it, so a typo or a renamed directory here
# hangs a bootstrap instead of failing it.
first_phase=$(yq -r '.spec.handover.adoptionOrder[0].phase' "$contract")
[ "$first_phase" = "core" ] || {
  printf 'FAIL: the first adoption phase is %s, expected core before tools\n' "$first_phase" >&2; exit 1; }

empty_phases=$(yq -r '[.spec.handover.adoptionOrder[]
  | select((.applications // []) | length == 0)] | length' "$contract")
[ "$empty_phases" = "0" ] || {
  printf 'FAIL: %s adoptionOrder phase(s) declare no applications\n' "$empty_phases" >&2; exit 1; }

yq -r '.spec.handover.adoptionOrder[].applications[]' "$contract" | while IFS= read -r app; do
  find "$repo_dir/core" "$repo_dir/tools" "$repo_dir/apps" -maxdepth 2 -name app.yaml \
    -exec grep -l "^name: ${app}$" {} + 2>/dev/null | head -n 1 | grep -q . || {
      printf 'FAIL: adoptionOrder names %s, which has no app descriptor\n' "$app" >&2; exit 1; }
done

printf 'cluster-contract: ok\n'
