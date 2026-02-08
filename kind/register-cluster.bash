#!/bin/bash
# register-cluster.bash
# Bootstraps the argocd-manager ServiceAccount in the kind cluster and
# prints the Vault command to store credentials for prod ArgoCD.

set -eou pipefail

GIT_DIR="$(git rev-parse --show-toplevel)"
BASE_DIR="${GIT_DIR}/kind"
CLUSTER_NAME="${1:-"homelab-dev"}"

CONTEXT="kind-${CLUSTER_NAME}"

echo "=== Registering kind cluster '${CLUSTER_NAME}' for ArgoCD ==="

# Apply argocd-manager SA, ClusterRole, ClusterRoleBinding, and token Secret
echo "Applying argocd-manager resources to kind cluster..."
kubectl --context "${CONTEXT}" apply -k "${BASE_DIR}/core/argocd-manager/"

# Wait for the token to be populated
echo "Waiting for argocd-manager token..."
for _ in $(seq 1 30); do
  TOKEN=$(kubectl --context "${CONTEXT}" -n kube-system get secret argocd-manager-token -o jsonpath='{.data.token}' 2>/dev/null | base64 -d 2>/dev/null || true)
  if [ -n "${TOKEN}" ]; then
    break
  fi
  sleep 1
done

if [ -z "${TOKEN}" ]; then
  echo "ERROR: Failed to retrieve argocd-manager token after 30 seconds"
  exit 1
fi

# Get the API server URL
SERVER=$(kubectl --context "${CONTEXT}" config view --minify -o jsonpath='{.clusters[0].cluster.server}')

echo ""
echo "=============================================="
echo "  Kind cluster credentials extracted"
echo "=============================================="
echo ""
echo "  Cluster Name: kind-dev"
echo "  API Server:   ${SERVER}"
echo "  Token:        ${TOKEN:0:20}..."
echo ""
echo "=============================================="
echo "  Run the following command to store in Vault:"
echo "=============================================="
echo ""
echo "  vault kv put dev/argocd-clusters/kind-dev \\"
echo "    server=\"${SERVER}\" \\"
echo "    token=\"${TOKEN}\""
echo ""
echo "=============================================="
echo ""
echo "After storing in Vault, prod ArgoCD will pick up the cluster"
echo "via the ExternalSecret and begin syncing ApplicationSets."
