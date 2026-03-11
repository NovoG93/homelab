#!/bin/bash

set -eou pipefail

GIT_DIR="$(git rev-parse --show-toplevel)"
BASE_DIR="${GIT_DIR}/kind"
CLUSTER_NAME="homelab-dev"
INITIAL_CONTEXT="homelab"
RETRY_COUNT=6
RETRY_DELAY=30

usage() {
    cat <<'EOF'
Usage:
    ./kind/hack/initial_deploy.bash [--cluster-name <name>] [--context <name>]
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --cluster-name)
            CLUSTER_NAME="$2"
            shift 2
            ;;
        --context)
            INITIAL_CONTEXT="$2"
            shift 2
            ;;
        --retry-count)
            RETRY_COUNT="$2"
            shift 2
            ;;
        --retry-delay)
            RETRY_DELAY="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unexpected argument '$1'"
            usage
            exit 1
            ;;
    esac
done

if ! command -v kustomize >/dev/null 2>&1; then
    echo "ERROR: Missing required command: kustomize"
    exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
    echo "ERROR: Missing required command: kubectl"
    exit 1
fi

CONTEXT="kind-${CLUSTER_NAME}"

echo "=== Starting initial deployment for kind cluster '${CLUSTER_NAME}' (bootstrap context '${INITIAL_CONTEXT}') ==="


function apply() {
    for root_overlay in core tools apps; do
        local overlay_path; local OUT;
        overlay_path="${BASE_DIR}/${root_overlay}"
        echo "Applying ${overlay_path} to context ${CONTEXT}..."
        OUT=$(kustomize build "${overlay_path}" --enable-helm | kubectl --context "${CONTEXT}" apply --server-side --force-conflicts -f - 2>&1 || true)
        echo "${OUT}"
    done
}

apply
for i in $(seq 1 "${RETRY_COUNT}"); do
    delay=$((RETRY_DELAY * (RETRY_COUNT - i + 1)))
    echo "Checking cluster readiness (attempt ${i}/${RETRY_COUNT})..."
    if kubectl --namespace nginx-ingress --context "${CONTEXT}" get pods --field-selector=status.phase=Running 2>/dev/null | grep -q "1/1"; then
        echo "=== Initial deployment complete for kind cluster '${CLUSTER_NAME}' ==="
        break
    else
        echo "Cluster not ready yet. Retrying in ${delay} seconds..."
        sleep "${delay}"
        apply
    fi
    kubectl --namespace nginx-ingress --context "${CONTEXT}" rollout restart deployment nginx-ingress-controller
done

echo "=== Initial deployment failed due to timeout ==="
