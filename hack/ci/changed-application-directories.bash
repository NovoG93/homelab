#!/usr/bin/env bash
# Map changed manifest paths to directly deployable Kustomizations.
set -euo pipefail

mode=${1:---kind}
[[ "$mode" == --kind || "$mode" == --native ]] || {
  printf 'usage: %s [--kind|--native]\n' "$0" >&2
  exit 2
}

while IFS= read -r file; do
  [[ -n "$file" ]] || continue
  IFS=/ read -r -a parts <<<"$file"
  directory=

  case "${parts[0]:-}" in
    kind)
      if [[ "${#parts[@]}" -ge 4 ]]; then
        directory="kind/${parts[1]}/${parts[2]}"
      elif [[ "${#parts[@]}" -ge 3 ]]; then
        directory="kind/${parts[1]}"
      fi
      ;;
    apps|core|tools)
      if [[ "${#parts[@]}" -ge 2 ]]; then
        directory="${parts[0]}/${parts[1]}"
      fi
      ;;
  esac

  [[ -n "$directory" ]] || continue
  if [[ "$mode" == --kind && "$directory" != kind/* && -f "kind/${directory}/kustomization.yaml" ]]; then
    directory="kind/${directory}"
  fi
  [[ -f "${directory}/kustomization.yaml" ]] && printf '%s\n' "$directory"
done | sort -u
