#!/bin/bash
# register-cluster.bash
# Bootstraps the argocd-manager ServiceAccount in the kind cluster and
# prints the kubectl exec command to store credentials in the Prod Vault.

set -eou pipefail

GIT_DIR="$(git rev-parse --show-toplevel)"
BASE_DIR="${GIT_DIR}/kind"
CLUSTER_NAME="${1:-"homelab-dev"}"
INITIAL_CONTEXT="${2:-"homelab"}"

# Define the Host LAN IP (Ref: kind/cluster.yaml certSANs)
# This is required so Prod can reach Kind.
HOST_IP="192.168.0.81"
PORT="5510"

CONTEXT="kind-${CLUSTER_NAME}"

echo "=== Registering kind cluster '${CLUSTER_NAME}' for ArgoCD ==="

# 1. Apply argocd-manager SA, ClusterRole, ClusterRoleBinding, and token Secret
echo "Applying argocd-manager resources to kind cluster..."
kubectl --context "${CONTEXT}" apply -k "${BASE_DIR}/core/argocd-manager/"

# 2. Wait for the token to be populated
echo "Waiting for argocd-manager token..."
for _ in $(seq 1 30); do
  # We decode the token because Vault/ArgoCD expects the raw JWT string
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

# 3. Extract the CA Certificate
# We do NOT decode this. ArgoCD expects the CA data to be Base64 encoded.
CA_DATA=$(kubectl --context "${CONTEXT}" -n kube-system get secret argocd-manager-token -o jsonpath='{.data.ca\.crt}')

# 4. Construct the Server URL
SERVER="https://${HOST_IP}:${PORT}"

# 5. Read Vault root token from keys file (same pattern as operator-init.sh)
VAULT_ROOT_TOKEN="$(kubectl --context "${INITIAL_CONTEXT}" -n vault exec vault-0 -- cat /tmp/keys/keys.json 2>/dev/null | grep "Initial Root Token" | head -n 1 | awk -F': ' '{print $2}' || true)"
if [ -z "${VAULT_ROOT_TOKEN}" ]; then
  echo "No Vault root token found. Exiting ..."
  exit 1
fi

echo ""
echo "=============================================="
echo "  Kind cluster credentials extracted"
echo "=============================================="
echo ""
echo "  Cluster Name: ${CLUSTER_NAME}"
echo "  API Server:   ${SERVER}"
echo "  Token:        ${TOKEN:0:20}..."
echo "  CA Data:      (Captured)"
echo ""
echo "=============================================="
echo "  Pushing credentials to Prod Vault..."
echo "=============================================="
echo ""
if [ -n "${VAULT_ROOT_TOKEN}" ]; then
  kubectl --context "${INITIAL_CONTEXT}" -n vault exec -i vault-0 -- \
    env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put dev/argocd-clusters/kind-dev \
    server="${SERVER}" \
    bearerToken="${TOKEN}" \
    caData="${CA_DATA}"
  echo "✓ Credentials successfully pushed to Vault"
else
  echo "# WARNING: Could not read Vault root token from ${VAULT_KEYS_FILE}"
  echo "# Replace <VAULT_TOKEN> with your Vault token (root or admin user)"
  echo "kubectl --context homelab -n vault exec -i vault-0 -- \\"
  echo "  env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=\"<VAULT_TOKEN>\" \\"
  echo "  vault kv put dev/argocd-clusters/kind-dev \\"
  echo "  server=\"${SERVER}\" \\"
  echo "  bearerToken=\"${TOKEN}\" \\"
  echo "  caData=\"${CA_DATA}\""
fi
echo ""
echo "================================================"
echo "  Replacing the old ExternalSecret (if exists)  "
echo "================================================"
kubectl --context "${INITIAL_CONTEXT}" -n argocd delete -f "${GIT_DIR}/tools/argocd/clusters/kind-dev-secret.yaml" --ignore-not-found
kubectl --context "${INITIAL_CONTEXT}" -n argocd apply -f "${GIT_DIR}/tools/argocd/clusters/kind-dev-secret.yaml"
echo ""
echo "=============================================="
echo ""
echo "After running the above, Prod ArgoCD will sync the ExternalSecret"
echo "and connect to your Kind cluster."