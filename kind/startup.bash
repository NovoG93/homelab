#!/bin/bash

set -eou pipefail

GIT_DIR="$(git rev-parse --show-toplevel)"
BASE_DIR="${GIT_DIR}/kind"
ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
fi

UNAME="$(uname -s)"
case "${UNAME}" in
    Linux*)     IP_ADDR=$(hostname -I | awk '{print $1}');;
    Darwin*)    IP_ADDR=$(ipconfig getifaddr en0);;
    *)          echo "Unsupported OS: ${UNAME}"; exit 1;;
esac

KIND_VERSION="${1:-"0.30.0"}"
KUBECTL_VERSION="${2:-"1.35.0"}"
CLUSTER_NAME="${3:-"homelab-dev"}"


echo "Starting kind cluster setup with kind version ${KIND_VERSION} and kubectl version ${KUBECTL_VERSION}..."



# Install kind
echo "Checking kind installation..."
if [ -x "$(command -v kind)" ]; then
  echo "kind is already installed"
else
  echo "kind not found, installing..."
  curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/kind-linux-${ARCH}"
  chmod +x ./kind
  sudo mv ./kind /usr/local/bin/kind
fi

# Patching IP address in cluster configuration
export IP_ADDR
envsubst < "${BASE_DIR}/cluster.yaml.tmpl" > "${BASE_DIR}/cluster.yaml"

# Startup kind cluster
echo "Creating kind cluster ${CLUSTER_NAME}..."
kind delete cluster --name "${CLUSTER_NAME}" || true
kind create cluster --name "${CLUSTER_NAME}" --config "${BASE_DIR}/cluster.yaml"

# Register the kind cluster with prod ArgoCD
echo "Registering kind cluster with ArgoCD..."
"${BASE_DIR}/register-cluster.bash" "${CLUSTER_NAME}"
