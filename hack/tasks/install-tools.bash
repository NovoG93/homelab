#!/bin/bash

set -eou pipefail

YQ_VERSION="latest"
CURL_VERSION="latest"
ENVSUBST_VERSION="latest"
DOCKER_VERSION="latest"
KUBECTL_VERSION="v1.34.1"
KUSTOMIZE_VERSION="v5.0.0"
KIND_VERSION="v0.20.0"
HELM_VERSION="v3.12.0"
KUBECONFORM_VERSION="v0.6.7"
INSTALL_DIR="/usr/local/bin"
DRY_RUN="false"

# Script that installs the required tools for running a local kind cluster and managing Kubernetes resources.
# Usage: ${0} [--yq-version <version>] [--curl-version <version>] [--envsubst-version <version>] [--kubectl-version <version>] [--kustomize-version <version>] [--kind-version <version>] [--helm-version <version>] [--kubeconform-version <version>] [--docker-version <version>] [--install-dir <dir>] [--dry-run] [--help]
# 
# Options:
#   --yq-version <version>           Specify the version of yq to install (default: ${YQ_VERSION})
#   --curl-version <version>         Specify the version of curl to install (default: ${CURL_VERSION})
#   --envsubst-version <version>     Specify the version of envsubst to install (default: ${ENVSUBST_VERSION})
#   --kubectl-version <version>      Specify the version of kubectl to install (default: ${KUBECTL_VERSION})
#   --kustomize-version <version>   Specify the version of kustomize to install (default: ${KUSTOMIZE_VERSION})
#   --kind-version <version>         Specify the version of kind to install (default: ${KIND_VERSION})
#   --helm-version <version>         Specify the version of helm to install (default: ${HELM_VERSION})
#   --kubeconform-version <version>  Specify the version of kubeconform to install (default: ${KUBECONFORM_VERSION})
#   --docker-version <version>       Specify the version of docker to install (default: ${DOCKER_VERSION})
#   --install-dir <dir>              Directory to install binaries to (default: ${INSTALL_DIR})
#   --dry-run                        Perform a dry run without actually installing anything
#   --help, -h                       Show this help message and exit
# 

usage() {
  export YQ_VERSION CURL_VERSION ENVSUBST_VERSION DOCKER_VERSION KUBECTL_VERSION KUSTOMIZE_VERSION KIND_VERSION HELM_VERSION KUBECONFORM_VERSION INSTALL_DIR

  sed -n '1,35{ /^#!/d; s/^[[:space:]]*#[[:space:]]\{0,1\}//p; }' "${BASH_SOURCE[0]}"
  exit 0
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)       echo "${arch}" ;;
  esac
}

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)
      echo "ERROR: Unsupported OS $(uname -s)" >&2
      exit 1
      ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --yq-version)
      YQ_VERSION="$2"
      shift 2
      ;;
    --curl-version)
      CURL_VERSION="$2"
      shift 2
      ;;
    --envsubst-version)
      ENVSUBST_VERSION="$2"
      shift 2
      ;;
    --kubectl-version)
      KUBECTL_VERSION="$2"
      shift 2
      ;;
    --kustomize-version)
      KUSTOMIZE_VERSION="$2"
      shift 2
      ;;
    --kind-version)
      KIND_VERSION="$2"
      shift 2
      ;;
    --helm-version)
      HELM_VERSION="$2"
      shift 2
      ;;
    --kubeconform-version)
      KUBECONFORM_VERSION="$2"
      shift 2
      ;;
    --docker-version)
      DOCKER_VERSION="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift 1
      ;;
    --help|-h)
      usage
      ;;
    *)
      echo "ERROR: Unknown option '$1'" >&2
      usage
      ;;
  esac
done

OS="$(detect_os)"
ARCH="$(detect_arch)"

case "${OS}" in
  darwin) OS_CAP="Darwin" ;;
  linux)  OS_CAP="Linux" ;;
  *)      OS_CAP="${OS}" ;;
esac

case "${ARCH}" in
  amd64) ARCH_CAP="x86_64" ;;
  *)     ARCH_CAP="${ARCH}" ;;
esac

install_binary() {
  local tool_name="$1"
  local src_path="$2"

  if [ "${DRY_RUN}" = "true" ]; then
    echo "[DRY-RUN] Would install ${tool_name} from ${src_path} to ${INSTALL_DIR}/${tool_name}"
    return 0
  fi

  if [ ! -d "${INSTALL_DIR}" ]; then
    echo "Creating directory ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}" 2>/dev/null || sudo mkdir -p "${INSTALL_DIR}"
  fi

  chmod +x "${src_path}"
  if [ -w "${INSTALL_DIR}" ]; then
    mv "${src_path}" "${INSTALL_DIR}/${tool_name}"
  else
    echo "Elevated permissions required to write to ${INSTALL_DIR}. Using sudo..."
    sudo mv "${src_path}" "${INSTALL_DIR}/${tool_name}"
  fi
  echo "✅ Installed ${tool_name} to ${INSTALL_DIR}/${tool_name}"
}

download_and_install() {
  local tool_name="$1"
  local url="$2"
  local archive_subpath="${3:-}"

  if [ "${DRY_RUN}" = "true" ]; then
    echo "[DRY-RUN] Would download ${tool_name} from ${url}"
    return 0
  fi

  echo "Downloading ${tool_name} from ${url}..."
  if [[ "${url}" == *.tar.gz ]] || [[ "${url}" == *.tgz ]]; then
    local tmp_dir tmp_tar
    tmp_dir="$(mktemp -d)"
    tmp_tar="${tmp_dir}/archive.tar.gz"

    if ! curl -fsSL -o "${tmp_tar}" "${url}"; then
      rm -rf "${tmp_dir}"
      return 1
    fi

    tar -xzf "${tmp_tar}" -C "${tmp_dir}"
    local subpath="${archive_subpath:-${tool_name}}"
    install_binary "${tool_name}" "${tmp_dir}/${subpath}"
    rm -rf "${tmp_dir}"
  else
    local tmp_file
    tmp_file="$(mktemp)"
    if ! curl -fsSL -o "${tmp_file}" "${url}"; then
      rm -f "${tmp_file}"
      return 1
    fi
    install_binary "${tool_name}" "${tmp_file}"
    rm -f "${tmp_file}"
  fi
}

install_via_package_manager() {
  local tool_name="$1"
  local brew_pkg="${2:-$tool_name}"
  local apt_pkg="${3:-$tool_name}"
  local dnf_pkg="${4:-$tool_name}"

  if [ "${DRY_RUN}" = "true" ]; then
    echo "[DRY-RUN] Would install ${tool_name} via system package manager"
    return 0
  fi

  case "${OS}" in
    darwin)
      if command -v brew >/dev/null 2>&1; then
        echo "Installing ${tool_name} via Homebrew (${brew_pkg})..."
        brew install "${brew_pkg}"
      else
        echo "ERROR: Homebrew is required on macOS to install ${tool_name}." >&2
        return 1
      fi
      ;;
    linux)
      if command -v apt-get >/dev/null 2>&1; then
        echo "Installing ${tool_name} via apt-get (${apt_pkg})..."
        sudo apt-get update && sudo apt-get install -y "${apt_pkg}"
      elif command -v dnf >/dev/null 2>&1; then
        echo "Installing ${tool_name} via dnf (${dnf_pkg})..."
        sudo dnf install -y "${dnf_pkg}"
      else
        echo "ERROR: No supported package manager (apt-get/dnf) found on Linux." >&2
        return 1
      fi
      ;;
  esac
}

install_yq() {
  echo "---> Processing yq (version: ${YQ_VERSION})..."
  local ver="${YQ_VERSION}"
  [[ "${ver}" != "latest" && "${ver}" != v* ]] && ver="v${ver}"
  local download_path="$([ "${ver}" = "latest" ] && echo "latest/download" || echo "download/${ver}")"
  local url="https://github.com/mikefarah/yq/releases/${download_path}/yq_${OS}_${ARCH}"
  download_and_install "yq" "${url}"
}

install_curl() {
  echo "---> Processing curl..."
  if command -v curl >/dev/null 2>&1; then
    echo "curl is already installed: $(curl --version | head -n 1)"
    return 0
  fi
  install_via_package_manager "curl"
}

install_envsubst() {
  echo "---> Processing envsubst (version: ${ENVSUBST_VERSION})..."
  if command -v envsubst >/dev/null 2>&1 && [ "${ENVSUBST_VERSION}" = "latest" ]; then
    echo "envsubst is already installed: $(command -v envsubst)"
    return 0
  fi

  local ver="${ENVSUBST_VERSION}"
  [[ "${ver}" != "latest" && "${ver}" != v* ]] && ver="v${ver}"
  local download_path="$([ "${ver}" = "latest" ] && echo "latest/download" || echo "download/${ver}")"
  local url="https://github.com/a8m/envsubst/releases/${download_path}/envsubst-${OS_CAP}-${ARCH_CAP}"

  download_and_install "envsubst" "${url}" || install_via_package_manager "envsubst" "gettext" "gettext-base" "gettext"
}

install_kubectl() {
  echo "---> Processing kubectl (version: ${KUBECTL_VERSION})..."
  local ver="${KUBECTL_VERSION}"
  if [ "${ver}" = "latest" ]; then
    ver="$(curl -L -s https://dl.k8s.io/release/stable.txt)"
  elif [[ "${ver}" != v* ]]; then
    ver="v${ver}"
  fi
  local url="https://dl.k8s.io/release/${ver}/bin/${OS}/${ARCH}/kubectl"
  download_and_install "kubectl" "${url}"
}

install_kustomize() {
  echo "---> Processing kustomize (version: ${KUSTOMIZE_VERSION})..."
  local ver="${KUSTOMIZE_VERSION}"
  if [ "${ver}" = "latest" ]; then
    local redirect_url
    redirect_url="$(curl -fssIL -o /dev/null -w "%{url_effective}" https://github.com/kubernetes-sigs/kustomize/releases/latest)"
    ver="$(basename "${redirect_url}")"
  elif [[ "${ver}" != v* ]]; then
    ver="v${ver}"
  fi
  local url="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F${ver}/kustomize_${ver}_${OS}_${ARCH}.tar.gz"
  download_and_install "kustomize" "${url}" "kustomize"
}

install_kind() {
  echo "---> Processing kind (version: ${KIND_VERSION})..."
  local ver="${KIND_VERSION}"
  local url
  if [ "${ver}" = "latest" ]; then
    url="https://kind.sigs.k8s.io/dl/latest/kind-${OS}-${ARCH}"
  else
    [[ "${ver}" != v* ]] && ver="v${ver}"
    url="https://kind.sigs.k8s.io/dl/${ver}/kind-${OS}-${ARCH}"
  fi
  download_and_install "kind" "${url}"
}

install_helm() {
  echo "---> Processing helm (version: ${HELM_VERSION})..."
  local ver="${HELM_VERSION}"
  if [ "${ver}" = "latest" ]; then
    local redirect_url
    redirect_url="$(curl -fssIL -o /dev/null -w "%{url_effective}" https://github.com/helm/helm/releases/latest)"
    ver="$(basename "${redirect_url}")"
  elif [[ "${ver}" != v* ]]; then
    ver="v${ver}"
  fi
  local url="https://get.helm.sh/helm-${ver}-${OS}-${ARCH}.tar.gz"
  download_and_install "helm" "${url}" "${OS}-${ARCH}/helm"
}

install_kubeconform() {
  echo "---> Processing kubeconform (version: ${KUBECONFORM_VERSION})..."
  local ver="${KUBECONFORM_VERSION}"
  if [ "${ver}" = "latest" ]; then
    local redirect_url
    redirect_url="$(curl -fssIL -o /dev/null -w "%{url_effective}" https://github.com/yannh/kubeconform/releases/latest)"
    ver="$(basename "${redirect_url}")"
  elif [[ "${ver}" != v* ]]; then
    ver="v${ver}"
  fi
  local url="https://github.com/yannh/kubeconform/releases/download/${ver}/kubeconform-${OS}-${ARCH}.tar.gz"
  download_and_install "kubeconform" "${url}" "kubeconform"
}

install_docker() {
  echo "---> Processing docker..."
  if command -v docker >/dev/null 2>&1; then
    echo "docker is already installed: $(docker --version)"
    return 0
  fi

  if [ "${DRY_RUN}" = "true" ]; then
    echo "[DRY-RUN] Would install docker"
    return 0
  fi

  if [ "${OS}" = "darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      echo "Installing docker via Homebrew..."
      brew install --cask docker || brew install docker
    else
      echo "ERROR: Homebrew is required to install Docker on macOS." >&2
      return 1
    fi
  elif [ "${OS}" = "linux" ]; then
    echo "Installing docker via official get.docker.com script..."
    curl -fsSL https://get.docker.com | sh
  fi
}

main() {
  echo "========================================================"
  echo " Installing tools for Homelab Kubernetes environment"
  echo "========================================================"
  echo " Target Directory : ${INSTALL_DIR}"
  echo " OS / Arch        : ${OS} / ${ARCH}"
  echo " Dry Run          : ${DRY_RUN}"
  echo "========================================================"

  install_curl
  install_envsubst
  install_yq
  install_kubectl
  install_kustomize
  install_kind
  install_helm
  install_kubeconform
  install_docker

  echo "========================================================"
  echo " Tool installation task completed successfully!"
  echo "========================================================"
}

main "$@"
