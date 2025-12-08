#!/bin/bash
set -euo pipefail

# Ensure we are in the script's directory
cd "$(dirname "$0")"

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <username> <role> [namespace] [kind]"
    echo "Example: $0 georg admin"
    echo "Example: $0 elena reader harbor"
    echo "Example: $0 elena my-role harbor Role"
    exit 1
fi

NEW_USER="$1"
ROLE="$2"
NAMESPACE="${3:-}"
KIND="${4:-}"

# Define the group for the CSR
GROUP="homelab-users"

echo "------------------------------------------------"
echo "Initiating setup for user: ${NEW_USER}"
echo "Role: ${ROLE}"
if [ -n "$NAMESPACE" ]; then
    echo "Scope: Namespace '${NAMESPACE}'"
else
    echo "Scope: Cluster-wide"
fi
if [ -n "$KIND" ]; then
    echo "Kind: ${KIND}"
else
    echo "Kind: ClusterRole (default)"
fi
echo "------------------------------------------------"

# Update USERS.txt
USERS_FILE="users/USERS.txt"
mkdir -p users

# Construct the entry line
if [ -z "$NAMESPACE" ]; then
    ENTRY="${NEW_USER}:${ROLE}"
else
    if [ -n "$KIND" ]; then
        ENTRY="${NEW_USER}:${ROLE}:${NAMESPACE}:${KIND}"
    else
        ENTRY="${NEW_USER}:${ROLE}:${NAMESPACE}"
    fi
fi

# Check if exact entry exists to avoid duplicates
if grep -Fxq "$ENTRY" "$USERS_FILE"; then
    echo "Entry '$ENTRY' already exists in $USERS_FILE. Skipping append."
else
    echo "Adding '$ENTRY' to $USERS_FILE..."
    echo "$ENTRY" >> "$USERS_FILE"
fi

# Regenerate RBAC manifests
echo "Regenerating RBAC manifests..."
./generate_rbac.bash

# Generate Certificates and Kubeconfig
# Create a directory for the user's credentials to keep things clean
CRED_DIR="creds/${NEW_USER}"
mkdir -p "$CRED_DIR"

echo "Generating credentials in $CRED_DIR..."

# Generate Private Key and CSR
# Note: We use the username as the Common Name (CN)
openssl genrsa -out "${CRED_DIR}/${NEW_USER}.key" 2048 2>/dev/null
openssl req -new -key "${CRED_DIR}/${NEW_USER}.key" -out "${CRED_DIR}/${NEW_USER}.csr" -subj "/CN=${NEW_USER}/O=${GROUP}" 2>/dev/null

# Create Kubernetes CSR Object
# We use a unique name for the CSR to avoid conflicts
CSR_NAME="${NEW_USER}-csr-$(date +%s)"
CSR_CONTENT=$(cat "${CRED_DIR}/${NEW_USER}.csr" | base64 | tr -d "\n")

cat <<YAML | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${CSR_NAME}
spec:
  request: ${CSR_CONTENT}
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
YAML

# Approve CSR
echo "Approving CSR..."
kubectl certificate approve "${CSR_NAME}"

# Retrieve Signed Certificate
echo "Waiting for certificate to be issued..."
# Loop a few times to wait for the certificate
for _ in {1..10}; do
    CERT=$(kubectl get csr "${CSR_NAME}" -o jsonpath='{.status.certificate}')
    if [ -n "$CERT" ]; then
        break
    fi
    sleep 1
done

if [ -z "$CERT" ]; then
    echo "Error: Certificate was not issued in time."
    exit 1
fi

echo "$CERT" | base64 -d > "${CRED_DIR}/${NEW_USER}.crt"


# Create Kubeconfig
KUBE_CONFIG="${CRED_DIR}/${NEW_USER}.kubeconfig"
CLUSTER_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CLUSTER_CA=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

# Determine context namespace line
NS_LINE=""
if [ -n "$NAMESPACE" ]; then
    NS_LINE="    namespace: ${NAMESPACE}"
fi

cat << YAML > "${KUBE_CONFIG}"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: ${CLUSTER_SERVER}
    certificate-authority-data: ${CLUSTER_CA}
  name: homelab-cluster
contexts:
- context:
    cluster: homelab-cluster
    user: ${NEW_USER}
${NS_LINE}
  name: ${NEW_USER}-context
current-context: ${NEW_USER}-context
users:
- name: ${NEW_USER}
  user:
    client-certificate-data: $(cat "${CRED_DIR}/${NEW_USER}.crt" | base64 | tr -d "\n")
    client-key-data: $(cat "${CRED_DIR}/${NEW_USER}.key" | base64 | tr -d "\n")
YAML
