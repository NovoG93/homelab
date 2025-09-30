#!/bin/sh
set -o errexit
set -o nounset
set -o pipefail

Vault_Key_Shares_Env=1
Vault_Key_Threshold_Env=1
VAULT_ADDRESS="VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_OPTIONS="VAULT_SKIP_VERIFY=${VAULT_SKIP_VERIFY:-true}"
KEYS_PATH=""
PREFIX=""
# FORMAT="" # -format=json




wait_for_vault() {
    local SLEEP=5
    local START_TIME=$(date +%s)
    local TIMEOUT=60
    # wait until the API responds to status
    while true; do
        ${PREFIX} env VAULT_ADDR="${VAULT_ADDR}" vault status >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
            return 0
        fi
        local NOW=$(date +%s)
        if [ $(expr $NOW - $START_TIME) -ge $TIMEOUT ]; then
            break
        fi
        echo "vault status returned with error; retrying in ${SLEEP}s..." >&2
        sleep ${SLEEP}
    done
    return 1
}


init() {
    if [ -z "$PREFIX" ] && command -v kubectl >/dev/null 2>&1; then
        NAMESPACE="vault"
        POD_NAME="$(kubectl get po -n ${NAMESPACE} --selector=app.kubernetes.io/name=vault,app.kubernetes.io/instance=vault,component=server -ojsonpath='{.items[0].metadata.name}' 2>/dev/null)"
        if [ -n "$POD_NAME" ]; then
            PREFIX="kubectl -n ${NAMESPACE} exec ${POD_NAME} --"
            # Outside the pod: store/read keys from the repo folder
            KEYS_PATH="${KEYS_PATH:-$PWD/keys.json}"
        fi
    fi
    PREFIX="${PREFIX} env ${VAULT_ADDRESS} ${VAULT_OPTIONS}"
    # If not in kubectl mode (likely running inside the pod), use /tmp/keys.json
    if [ -z "$KEYS_PATH" ]; then
        KEYS_PATH="/tmp/keys/keys.json"
    fi
    # Normalize when a directory was provided
    if [ -d "$KEYS_PATH" ]; then
        KEYS_PATH="${KEYS_PATH%/}/keys.json"
    fi
}


# Reliable status check
vault_status_flags() {
    # Use jq if possible
    if command -v jq >/dev/null 2>&1; then
        if out="$(${PREFIX} vault status -format=json 2>/dev/null)"; then
            init=$(echo "$out" | jq -r '.initialized')
            sealed=$(echo "$out" | jq -r '.sealed')
            echo "${init}|${sealed}"
            return
        fi
    fi
    out="$(${PREFIX} vault status 2>/dev/null || true)"
    init=$(echo "$out" | awk '/^Initialized/ {print tolower($NF)}')
    sealed=$(echo "$out" | awk '/^Sealed/ {print tolower($NF)}')
    [ -z "$init" ] && init="false"
    [ -z "$sealed" ] && sealed="true"
    echo "${init}|${sealed}"
}

# Read first unseal key and root token from KEYS_PATH (supports human output; falls back to jq if file is JSON)
read_keys_file() {
    for file in "$KEYS_PATH" "$PWD/keys.json" "/tmp/keys.json"; do
        if [ -s "$file" ]; then
            if grep "Unseal Key" "$file" >/dev/null 2>&1; then
                unseal=$(grep "Unseal Key" "$file" | head -n 1 | awk -F': ' '{print $2}')
                root=$(grep "Initial Root Token" "$file" | head -n 1 | awk -F': ' '{print $2}')
                echo "${unseal}|${root}"
                return
            elif command -v jq >/dev/null 2>&1; then
                unseal=$(jq -r '.unseal_keys_b64[0]' "$file" 2>/dev/null)
                root=$(jq -r '.root_token' "$file" 2>/dev/null)
                if [ -n "$unseal" ] || [ -n "$root" ]; then
                    echo "${unseal}|${root}"
                    return
                fi
            fi
        fi
    done
    echo "|"
}

# Initialize Vault and save keys to KEYS_PATH
operator_init_and_save() {
    mkdir -p "$(dirname "$KEYS_PATH")"
    tmp="$(mktemp)"
    # capture both streams
    if ${PREFIX} vault operator init -key-shares="$Vault_Key_Shares_Env" -key-threshold="$Vault_Key_Threshold_Env" >"$tmp" 2>&1; then
        # Success path: stdout contains keys (human) unless -format=json used
        if grep -q "Unseal Key" "$tmp" || grep -q "Initial Root Token" "$tmp"; then
            cp "$tmp" "$KEYS_PATH"
            :
        elif command -v jq >/dev/null 2>&1 && jq -e '.unseal_keys_b64 and .root_token' "$tmp" >/dev/null 2>&1; then
            cp "$tmp" "$KEYS_PATH"
            :
        else
            echo "Init returned success but output not recognized; refusing to overwrite $KEYS_PATH" >&2
            rm -f "$tmp"
            return 1
        fi
    else
        # Error path: DO NOT overwrite keys file
        echo "vault operator init failed; not touching $KEYS_PATH. Output:" >&2
        sed 's/^/  /' "$tmp" >&2
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
    # Extract for return
    unseal=$(grep "Unseal Key" "$KEYS_PATH" | head -n 1 | awk -F': ' '{print $2}')
    root=$(grep "Initial Root Token" "$KEYS_PATH" | head -n 1 | awk -F': ' '{print $2}')
    echo "${unseal}|${root}"
}


unseal() {
    ${PREFIX} vault operator unseal "$1"
}

# Ensure a KV v2 secrets engine exists at a given path
ensure_secret_engine() {
    path="$1"
    if ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault secrets list 2>/dev/null | awk '{print $1}' | grep "^${path}/$" >/dev/null 2>&1; then
        return
    fi
    ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault secrets enable -path="${path}" -version=2 kv
}

# Create an 'admins' policy with broad permissions (always overwrite to ensure correctness)
ensure_admins_policy() {
    policy_name="admins"
    script_dir=$(dirname "$0")
    policy_file="${script_dir}/policies/admin.hcl"

    if [ ! -f "$policy_file" ]; then
        echo "Policy file not found at ${policy_file}" >&2
        return 1
    fi

    cat "$policy_file" | ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault policy write "${policy_name}" -
}

ensure_read_only_policy() {
    policy_name="read-only"
    script_dir=$(dirname "$0")
    policy_file="${script_dir}/policies/read-only.hcl"

    if [ ! -f "$policy_file" ]; then
        echo "Policy file not found at ${policy_file}" >&2
        return 1
    fi

    cat "$policy_file" | ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault policy write "${policy_name}" -
}


setupKubernetesAuth() {
    if ! ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault auth list 2>/dev/null | awk '{print $1}' | grep -q "^kubernetes/$"; then
        ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault auth enable kubernetes
    fi

    if [ "${PREFIX}" ]; then
        # Configure using in-cluster defaults (Vault >= 1.9.3 auto-reads SA token & CA)
        ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault write auth/kubernetes/config \
            kubernetes_host="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"

        # Create/overwrite a role for ESO
        # IMPORTANT: service account name here must match the SA you reference from your SecretStore.
        local ESO_SA_NAME="${ESO_SA_NAME:-eso-vault}"
        local ESO_NS="${ESO_NS:-external-secrets}"
        ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault write auth/kubernetes/role/eso \
            bound_service_account_names="${ESO_SA_NAME}" \
            bound_service_account_namespaces="${ESO_NS}" \
            policies="read-only" \
            ttl="1h"
    else
        # Outside the pod
        echo "Setting up Kubernetes auth method for Vault outside the pod is not supported." >&2
        echo "Please configure the Kubernetes host manually." >&2
        # local context="$(kubectl config current-context)"
        # local cluster="$(kubectl config view -o jsonpath="{.contexts[?(@.name=='${context}')].context.cluster}")"
        # local cluster_ip="$(kubectl config view -o jsonpath="{.clusters[?(@.name=='${cluster}')].cluster.server}")"
        # ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault write auth/kubernetes/config kubernetes_host="${cluster_ip}"
    fi
}

setUpUsers() {
    # Ensure userpass auth method is enabled
    if ! ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault auth list 2>/dev/null | awk '{print $1}' | grep "^userpass/$" >/dev/null 2>&1; then
        ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault auth enable userpass
    fi
    # Upsert users with 'default,admins' policies
    for user in $USERS; do
        user_lc=$(printf %s "$user" | tr '[:upper:]' '[:lower:]')
        ${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault write "auth/userpass/users/${user_lc}" \
            password=${USER_PASSWORD} \
            policies=default,admins
    done
}


#------------------------------------------#
#------------------ MAIN ------------------#

# set -x
init
wait_for_vault || echo "Vault API not up yet; continuing cautiously…" >&2


# Read status flags without here-strings; keep variables in the current shell
status="$(vault_status_flags)"
oldIFS=$IFS
IFS='|'; set -- $status; IFS=$oldIFS
INIT_FLAG="$1"
SEALED_FLAG="$2"

VAULT_UNSEAL_KEY=""
ROOT_TOKEN=""

if [ "$INIT_FLAG" != "true" ]; then
    echo "Vault is not initialized..." >&2
    res="$(operator_init_and_save)"
    oldIFS=$IFS
    IFS='|'; set -- $res; IFS=$oldIFS
    VAULT_UNSEAL_KEY="$1"
    ROOT_TOKEN="$2"
    echo "Vault initialized. Keys and root token saved to ${KEYS_PATH}" >&2
    unseal "$VAULT_UNSEAL_KEY"
else
    echo "Vault is initialized, reading keys..." >&2
    res="$(read_keys_file)"
    oldIFS=$IFS
    IFS='|'; set -- $res; IFS=$oldIFS
    VAULT_UNSEAL_KEY="$1"
    ROOT_TOKEN="$2"
    if [ "$SEALED_FLAG" = "true" ]; then
        if [ -z "$VAULT_UNSEAL_KEY" ]; then
            echo "Vault is sealed but no unseal key found at ${KEYS_PATH}. Aborting." >&2
            exit 1
        fi
        echo "Unsealing Vault..."
        unseal "$VAULT_UNSEAL_KEY"
    fi
fi

# Ensure secret engines exist (requires ROOT_TOKEN)
if [ -z "$ROOT_TOKEN" ]; then
    res="$(read_keys_file)"
    oldIFS=$IFS
    IFS='|'; set -- $res; IFS=$oldIFS
    ROOT_TOKEN="$2"
fi
if [ -n "$ROOT_TOKEN" ]; then
    echo "Creating root secret-engine..."
    ensure_secret_engine root
    echo "Creating dev secret-engine..."
    ensure_secret_engine dev
    echo "Creating prod secret-engine..."
    ensure_secret_engine prod

    echo "Creating admins policy..."
    ensure_admins_policy
    echo "Creating read-only policy..."
    ensure_read_only_policy

    echo "Enabling kubernetes auth method..."
    setupKubernetesAuth

    echo "Creating users..."
    setUpUsers
else
    echo "Root token not available; cannot manage secret engines." >&2
fi

# Store the Root Token and unseal key in the root kv
${PREFIX} env VAULT_TOKEN="${ROOT_TOKEN}" vault kv put root/keys unseal_key="$VAULT_UNSEAL_KEY" root_token="$ROOT_TOKEN"

# set +x