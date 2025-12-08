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

# Generate bindings based on USERS.txt
if [ -f "users/USERS.txt" ]; then
  while IFS=":" read -r user role namespace kind || [ -n "$user" ]; do
    # Skip empty lines and comments
    [[ -z "$user" || "$user" =~ ^# ]] && continue
    
    # Trim whitespace
    user=$(echo "$user" | xargs)
    role=$(echo "$role" | xargs)
    namespace=$(echo "$namespace" | xargs)
    kind=$(echo "$kind" | xargs)
    
    # Default kind to ClusterRole if not specified
    if [ -z "$kind" ]; then
      kind="ClusterRole"
    fi
    
    if [ -z "$namespace" ]; then
        # ClusterRoleBinding (Must reference a ClusterRole)
        if [ "$kind" != "ClusterRole" ]; then
            echo "Warning: User '$user' has no namespace but kind is '$kind'. ClusterRoleBindings must reference ClusterRoles. Forcing kind to ClusterRole."
            kind="ClusterRole"
        fi

        binding_file="bindings/${user}-${role}-binding.yaml"
        
        cat <<YAML > "$binding_file"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${user}-${role}-binding
subjects:
- kind: User
  name: ${user}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ${kind}
  name: ${role}
  apiGroup: rbac.authorization.k8s.io
YAML
    else
        # RoleBinding (scoped to namespace)
        binding_file="bindings/${user}-${role}-${namespace}-binding.yaml"
        
        cat <<YAML > "$binding_file"
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${user}-${role}-binding
  namespace: ${namespace}
subjects:
- kind: User
  name: ${user}
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ${kind}
  name: ${role}
  apiGroup: rbac.authorization.k8s.io
YAML
    fi
    
    echo "- $binding_file" >> kustomization.yaml
  done < users/USERS.txt
fi

echo "RBAC manifests generated and kustomization.yaml updated."
