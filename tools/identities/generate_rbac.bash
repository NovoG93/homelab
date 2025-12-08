#!/bin/bash
set -e

# Ensure we are in the script's directory
cd "$(dirname "$0")"

mkdir -p bindings

# Initialize kustomization.yaml
cat <<YAML > kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
YAML

# Add all cluster roles found in clusterroles/
if [ -d "clusterroles" ]; then
  for role in clusterroles/*.yaml; do
    if [ -f "$role" ]; then
      echo "- $role" >> kustomization.yaml
    fi
  done
fi

# Add all roles found in roles/
if [ -d "roles" ]; then
  for role in roles/*.yaml; do
    if [ -f "$role" ]; then
      echo "- $role" >> kustomization.yaml
    fi
  done
fi

# Function to find namespace for a role
get_role_namespace() {
    local role_name="$1"
    if [ -d "roles" ]; then
        # Search for the role name in files and extract namespace
        # We look for "name: role_name" and then find "namespace: something" in the same file
        # This is a simple heuristic for simple YAML files
        grep -l "name: ${role_name}" roles/*.yaml | xargs grep "namespace:" | awk '{print $2}' | head -n 1
    fi
}

# Generate bindings based on USERS.txt
if [ -f "users/USERS.txt" ]; then
  while IFS=";" read -r user clusterrole role || [ -n "$user" ]; do
    # Skip empty lines and comments
    [[ -z "$user" || "$user" =~ ^# ]] && continue
    
    # Trim whitespace
    user=$(echo "$user" | xargs)
    clusterrole=$(echo "$clusterrole" | xargs)
    role=$(echo "$role" | xargs)
    
    # 1. Handle ClusterRole
    if [ -n "$clusterrole" ]; then
        # Replace colons with dashes for safe filenames/resource names
        safe_cr_name="${clusterrole//:/-}"
        binding_file="bindings/${user}-${safe_cr_name}-binding.yaml"
        
        cat <<YAML > "$binding_file"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${user}-${safe_cr_name}-binding
subjects:
- kind: User
  name: ${user}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: ${clusterrole}
  apiGroup: rbac.authorization.k8s.io
YAML
        echo "- $binding_file" >> kustomization.yaml
    fi

    # 2. Handle Role
    if [ -n "$role" ]; then
        namespace=$(get_role_namespace "$role")
        
        if [ -z "$namespace" ]; then
            echo "Warning: Could not find namespace for Role '$role' assigned to user '$user'. Skipping RoleBinding."
        else
            safe_role_name="${role//:/-}"
            binding_file="bindings/${user}-${safe_role_name}-${namespace}-binding.yaml"
            
            cat <<YAML > "$binding_file"
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${user}-${safe_role_name}-binding
  namespace: ${namespace}
subjects:
- kind: User
  name: ${user}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: ${role}
  apiGroup: rbac.authorization.k8s.io
YAML
            echo "- $binding_file" >> kustomization.yaml
        fi
    fi
    
  done < users/USERS.txt
fi

echo "RBAC manifests generated and kustomization.yaml updated."
