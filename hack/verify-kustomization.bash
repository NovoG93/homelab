#!/bin/bash

set -eou pipefail
GIT_DIR="$(git rev-parse --show-toplevel)"
KUSTMOIZE_ACTION_VERSION="v0.1.0"
REPO_URL="https://github.com/NovoG93/kustomize-action"

ARCH="$(uname -m)"
OS="$(uname -s)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
fi

case "${OS}" in
    Linux*)     OS="linux";;
    Darwin*)    OS="darwin";;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac


# Download the kustomize-action binary
KUSTOMIZE_ACTION_URL="${REPO_URL}/releases/download/${KUSTMOIZE_ACTION_VERSION}/action-${OS}-${ARCH}"
KUSTOMIZE_ACTION_PATH="${GIT_DIR}/action"
echo "Downloading kustomize-action from ${KUSTOMIZE_ACTION_URL}..."
curl -Ls -o "${KUSTOMIZE_ACTION_PATH}" "${KUSTOMIZE_ACTION_URL}"
chmod +x "${KUSTOMIZE_ACTION_PATH}"

# Set a trap to clean up the binary whenever the script exits
trap 'rm -f "${KUSTOMIZE_ACTION_PATH}"' EXIT

echo "Verifying kustomization.yaml files..."

# Run validation
if CHANGED_ONLY=false FAIL_ON_ERROR=true "${KUSTOMIZE_ACTION_PATH}"; then
    echo "✅ All kustomization.yaml files are valid!"
else
    echo "❌ Validation failed for one or more kustomization.yaml files."
    exit 1
fi