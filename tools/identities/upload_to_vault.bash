#!/bin/bash
set -euo pipefail

# Ensure we are in the script's directory
cd "$(dirname "$0")"

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

USER="$1"
CREDS_DIR="creds/${USER}"
VAULT_NAMESPACE="vault"
VAULT_POD="vault-0"
VAULT_ROOT_PATH="root"

if [ ! -d "$CREDS_DIR" ]; then
    echo "Error: Credentials directory for user '$USER' not found at $CREDS_DIR"
    exit 1
fi

echo "Uploading credentials for user '$USER' to Vault..."

# Check if Vault pod is running
if ! kubectl get pod -n "$VAULT_NAMESPACE" "$VAULT_POD" &>/dev/null; then
    echo "Error: Vault pod '$VAULT_POD' not found in namespace '$VAULT_NAMESPACE'."
    exit 1
fi

# Function to upload a single file
upload_file() {
    local file_path="$1"
    local filename
    filename=$(basename "$file_path")
    local vault_path="${VAULT_ROOT_PATH}/${USER}/${filename}"
    
    echo "  Processing $filename..."
    
    # 1. Copy file to Vault pod
    if ! kubectl cp "$file_path" "${VAULT_NAMESPACE}/${VAULT_POD}:/tmp/${filename}"; then
        echo "    Error: Failed to copy file to pod. Ensure 'tar' is installed in the Vault image."
        exit 1
    fi
    
    # 2. Write to Vault
    if output=$(kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- vault kv put "$vault_path" "${filename}=@/tmp/${filename}" 2>&1); then
        echo "    Successfully uploaded to $vault_path"
    else
        echo "    Failed to upload $filename"
        echo "    Vault Output: $output"
        exit 1
    fi
    
    # 3. Cleanup
    kubectl exec -n "$VAULT_NAMESPACE" "$VAULT_POD" -- rm -f "/tmp/${filename}"
}

# Upload CRT
if [ -f "${CREDS_DIR}/${USER}.crt" ]; then
    upload_file "${CREDS_DIR}/${USER}.crt"
else
    echo "Warning: ${USER}.crt not found"
fi

# Upload KEY
if [ -f "${CREDS_DIR}/${USER}.key" ]; then
    upload_file "${CREDS_DIR}/${USER}.key"
else
    echo "Warning: ${USER}.key not found"
fi

echo "Upload complete."
