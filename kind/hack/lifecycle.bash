#!/bin/bash
set -eou pipefail

GIT_DIR="$(git rev-parse --show-toplevel)"
KIND_DIR="${GIT_DIR}/kind"

DEFAULT_KIND_VERSION="0.30.0"
DEFAULT_K8S_VERSION="1.35.0"
DEFAULT_CLUSTER_NAME="homelab-dev"
DEFAULT_INITIAL_CONTEXT="homelab"

COMMAND="${1:-startup}"
if [ "$#" -gt 0 ]; then
	shift
fi

KIND_VERSION="${DEFAULT_KIND_VERSION}"
K8S_VERSION="${DEFAULT_K8S_VERSION}"
CLUSTER_NAME="${DEFAULT_CLUSTER_NAME}"
INITIAL_CONTEXT="${DEFAULT_INITIAL_CONTEXT}"
SYNC_MODE="local"
HOST_IP_OVERRIDE=""

usage() {
	cat <<'EOF'
Usage:
	./kind/hack/lifecycle.bash <command> [options]

Commands:
	startup         Create kind cluster (if not already running) and run initial deployment
	initial-deploy  Apply kind app/core/tools kustomizations
	register        Register the kind cluster with prod ArgoCD/Vault
	stop            Delete the kind cluster
	reset           Stop then startup using provided options

Options:
	--kind-version <version>      Kind CLI version (default: 0.30.0)
	--k8s-version <version>       Kubernetes node image version (default: 1.35.0)
	--cluster-name <name>         Kind cluster name (default: homelab-dev)
	--context <name>              Initial kubectl context (default: homelab)
	--sync-mode <local|prod>      Sync mode (default: local)
	--host-ip <ip>                Override host IP used in cluster/register templates
	-p, --prod-sync               Shortcut for --sync-mode prod
	-h, --help                    Show help

Legacy startup positional args are also supported:
	./kind/hack/lifecycle.bash startup [-p] [kind_version] [k8s_version] [cluster_name] [initial_context]
EOF
}

require_command() {
	local cmd="$1"
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "ERROR: Missing required command: ${cmd}"
		exit 1
	fi
}

detect_arch() {
	local arch
	arch="$(uname -m)"
	if [ "${arch}" = "x86_64" ]; then
		arch="amd64"
	fi
	echo "${arch}"
}

detect_os() {
	case "$(uname -s)" in
		Linux*)
			echo "linux"
			;;
		Darwin*)
			echo "darwin"
			;;
		*)
			echo "ERROR: Unsupported OS $(uname -s)" >&2
			exit 1
			;;
	esac
}

detect_host_ip() {
	if [ -n "${HOST_IP_OVERRIDE}" ]; then
		echo "${HOST_IP_OVERRIDE}"
		return
	fi

	case "$(uname -s)" in
		Linux*)
			hostname -I | awk '{print $1}'
			;;
		Darwin*)
			ipconfig getifaddr en0
			;;
		*)
			echo "ERROR: Unsupported OS $(uname -s)" >&2
			exit 1
			;;
	esac
}

ensure_kind_installed() {
	if command -v kind >/dev/null 2>&1; then
		echo "kind is already installed"
		return
	fi

	local os
	local arch
	local url
	local tmp_bin
	os="$(detect_os)"
	arch="$(detect_arch)"
	url="https://kind.sigs.k8s.io/dl/v${KIND_VERSION}/kind-${os}-${arch}"
	tmp_bin="${KIND_DIR}/kind"

	echo "kind not found, installing from ${url}..."
	curl -Lo "${tmp_bin}" "${url}"
	chmod +x "${tmp_bin}"
	sudo mv "${tmp_bin}" /usr/local/bin/kind
}

ensure_resource_present() {
	local resource="$1"
	local kustomization_file="$2"

	if yq e -e ".resources // [] | any_c(. == \"${resource}\")" "${kustomization_file}" >/dev/null 2>&1; then
		echo "Resource '${resource}' already present in ${kustomization_file}"
	else
		echo "Adding '${resource}' to ${kustomization_file}"
		yq e -i ".resources += [\"${resource}\"]" "${kustomization_file}"
	fi
}

check_running() {
	kind get clusters | grep -qx "${CLUSTER_NAME}"
}

ensure_resource_absent() {
	local resource="$1"
	local kustomization_file="$2"

	if yq e -e ".resources // [] | any_c(. == \"${resource}\")" "${kustomization_file}" >/dev/null 2>&1; then
		echo "Removing '${resource}' from ${kustomization_file}"
		yq e -i "del(.resources[] | select(. == \"${resource}\"))" "${kustomization_file}"
	else
		echo "Resource '${resource}' already absent in ${kustomization_file}"
	fi
}

configure_sync_mode() {
	local tools_kustomization
	tools_kustomization="${KIND_DIR}/tools/kustomization.yaml"

	require_command yq

	case "${SYNC_MODE}" in
		local)
			echo "Sync mode: local (deploy in-cluster ArgoCD)"
			ensure_resource_present "argocd" "${tools_kustomization}"
			;;
		prod)
			echo "Sync mode: prod (use prod ArgoCD and External Secrets)"
			ensure_resource_absent "argocd" "${tools_kustomization}"
			;;
		*)
			echo "ERROR: Invalid sync mode '${SYNC_MODE}'. Expected 'local' or 'prod'."
			exit 1
			;;
	esac
}

render_cluster_config() {
	local host_ip="$1"

	export IP_ADDR="${host_ip}"
	envsubst '$IP_ADDR' < "${KIND_DIR}/hack/cluster.yaml.tmpl" > "${KIND_DIR}/cluster.yaml"
}

run_initial_deploy() {
	"${KIND_DIR}/hack/initial_deploy.bash" --cluster-name "${CLUSTER_NAME}" --context "${INITIAL_CONTEXT}"
}

run_register_cluster() {
	local host_ip="$1"

	export IP_ADDR="${host_ip}"
	envsubst '$IP_ADDR' < "${KIND_DIR}/hack/register-cluster.bash.tmpl" > "${KIND_DIR}/hack/register-cluster.bash"
	chmod +x "${KIND_DIR}/hack/register-cluster.bash"
	"${KIND_DIR}/hack/register-cluster.bash" "${CLUSTER_NAME}" "${INITIAL_CONTEXT}"
}

startup_cluster() {
	local host_ip

	echo "Checking if kind cluster '${CLUSTER_NAME}' is already running..."
	if check_running; then
		echo "Cluster '${CLUSTER_NAME}' is already running, skipping startup"
		return
	fi

	require_command curl
	require_command envsubst
	require_command kubectl
	require_command kustomize

	echo "Starting kind cluster setup with kind version ${KIND_VERSION} and k8s version ${K8S_VERSION}..."

	configure_sync_mode
	ensure_kind_installed

	host_ip="$(detect_host_ip)"
	if [ -z "${host_ip}" ]; then
		echo "ERROR: Failed to detect host IP"
		exit 1
	fi

	echo "Using host IP '${host_ip}' for kind API server certificate SAN"
	render_cluster_config "${host_ip}"

	echo "Creating kind cluster ${CLUSTER_NAME}..."
	kind delete cluster --name "${CLUSTER_NAME}" || true
	kind create cluster --name "${CLUSTER_NAME}" --image "kindest/node:v${K8S_VERSION}" --config "${KIND_DIR}/cluster.yaml"

	echo "Performing initial deployment to kind cluster..."
	run_initial_deploy

	if [ "${SYNC_MODE}" = "prod" ]; then
		echo "Registering kind cluster with prod ArgoCD..."
		run_register_cluster "${host_ip}"
	fi
}

stop_cluster() {
	require_command kind
	echo "Deleting kind cluster '${CLUSTER_NAME}'..."
	kind delete cluster --name "${CLUSTER_NAME}" || true
}

parse_args() {
	require_option_value() {
		local option_name="$1"
		local option_value="${2:-}"
		if [ -z "${option_value}" ]; then
			echo "ERROR: Missing value for ${option_name}"
			usage
			exit 1
		fi
	}

	while [ "$#" -gt 0 ]; do
		case "$1" in
			-p|--prod-sync)
				SYNC_MODE="prod"
				shift
				;;
			--sync-mode=*)
				SYNC_MODE="${1#*=}"
				require_option_value "--sync-mode" "${SYNC_MODE}"
				shift
				;;
			--sync-mode)
				require_option_value "--sync-mode" "${2:-}"
				SYNC_MODE="$2"
				shift 2
				;;
			--kind-version=*)
				KIND_VERSION="${1#*=}"
				require_option_value "--kind-version" "${KIND_VERSION}"
				shift
				;;
			--kind-version)
				require_option_value "--kind-version" "${2:-}"
				KIND_VERSION="$2"
				shift 2
				;;
			--k8s-version=*)
				K8S_VERSION="${1#*=}"
				require_option_value "--k8s-version" "${K8S_VERSION}"
				shift
				;;
			--kubectl-version=*)
				K8S_VERSION="${1#*=}"
				require_option_value "--kubectl-version" "${K8S_VERSION}"
				shift
				;;
			--k8s-version|--kubectl-version)
				require_option_value "$1" "${2:-}"
				K8S_VERSION="$2"
				shift 2
				;;
			--cluster-name=*)
				CLUSTER_NAME="${1#*=}"
				require_option_value "--cluster-name" "${CLUSTER_NAME}"
				shift
				;;
			--cluster-name)
				require_option_value "--cluster-name" "${2:-}"
				CLUSTER_NAME="$2"
				shift 2
				;;
			--context=*)
				INITIAL_CONTEXT="${1#*=}"
				require_option_value "--context" "${INITIAL_CONTEXT}"
				shift
				;;
			--context)
				require_option_value "--context" "${2:-}"
				INITIAL_CONTEXT="$2"
				shift 2
				;;
			--host-ip=*)
				HOST_IP_OVERRIDE="${1#*=}"
				require_option_value "--host-ip" "${HOST_IP_OVERRIDE}"
				shift
				;;
			--host-ip)
				require_option_value "--host-ip" "${2:-}"
				HOST_IP_OVERRIDE="$2"
				shift 2
				;;
			-h|--help)
				usage
				exit 0
				;;
			*)
				usage
				exit 1
				;;
		esac
	done

}

main() {
	parse_args "$@"

	case "${COMMAND}" in
		startup)
			startup_cluster
			;;
		initial-deploy)
			configure_sync_mode
			run_initial_deploy
			;;
		register)
			run_register_cluster "$(detect_host_ip)"
			;;
		stop)
			stop_cluster
			;;
		reset)
			stop_cluster
			startup_cluster
			;;
		-h|--help|help)
			usage
			;;
		*)
			echo "ERROR: Unknown command '${COMMAND}'"
			usage
			exit 1
			;;
	esac
}

main "$@"