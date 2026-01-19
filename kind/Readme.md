# Kind Configuration for Dev Cluster

This directory contains the kind cluster configuration and Kustomize overlays for running the homelab stack locally.

## Structure

```
kind/
├── cluster.yaml          # Kind cluster configuration
├── core/                  # Core infrastructure overlays
│   ├── calico/           # CNI (unchanged from prod)
│   ├── metallb-system/   # Load balancer with Docker subnet IPs
│   └── metrics-server/   # Metrics (unchanged from prod)
├── tools/                 # Tools overlays
│   ├── argocd/           # GitOps with kind-specific ApplicationSets
│   ├── cert-manager/     # Self-signed CA issuer
│   ├── local-storage/    # Local-path-provisioner (replaces NFS/SMB)
│   ├── nginx-ingress/    # Ingress controller
│   └── wildcard-tls/     # Wildcard cert for *.127.0.0.1.nip.io
└── apps/                  # Application overlays
    └── netshoot/         # Network debugging tool
```

## Key Differences from Production

| Component | Production | Kind (Dev) |
|-----------|-----------|------------|
| **IPs** | 192.168.0.210-221 | 172.18.0.200-210 (Docker) |
| **Certificates** | Let's Encrypt via Cloudflare | Self-signed CA |
| **Storage** | NFS/SMB | local-path-provisioner |
| **Domain** | *.novotny.live | *.127.0.0.1.nip.io |
| **VPN** | Tailscale | Disabled |
| **External DNS** | Cloudflare | Disabled |

## Quick Start

### 1. Create the Cluster

```bash
kind create cluster --config kind/cluster.yaml
```

### 2. Verify Docker Network (for MetalLB)

```bash
# Check the kind network subnet
docker network inspect kind | grep Subnet
# Expected: "Subnet": "172.18.0.0/16"
# If different, update kind/core/metallb-system/ipaddress-pool.yaml
```

### 3. Bootstrap with ArgoCD

```bash
# Install Calico CNI first (required before other workloads)
kubectl apply -k kind/core/calico

# Wait for Calico to be ready
kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n calico-system --timeout=300s

# Install MetalLB
kubectl apply -k kind/core/metallb-system

# Install cert-manager
kubectl apply -k kind/tools/cert-manager

# Wait for cert-manager webhook
kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=webhook -n cert-manager --timeout=300s

# Install ArgoCD
kubectl apply -k kind/tools/argocd

# ArgoCD will then sync all other components via ApplicationSets
```

### 4. Access ArgoCD

```bash
# Get the admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Port-forward to access UI
kubectl port-forward svc/argocd-server -n argocd 8080:80

# Open: http://localhost:8080
# Login: admin / <password from above>
```

### 5. Local DNS

Using `nip.io` avoids the need for `/etc/hosts` entries.
Access services via:
- `https://argocd.127.0.0.1.nip.io`
- `https://nginx.127.0.0.1.nip.io`

## Adding More Apps

To add a new app for kind:

1. Create overlay directory: `kind/apps/<app-name>/`
2. Create `kustomization.yaml` referencing base: `resources: [../../../apps/<app-name>]`
3. Create `app.yaml` with path pointing to `kind/apps/<app-name>`
4. Add patches as needed for kind-specific config

## Excluded Components

The following production components are not included in kind:
- `tailscale` - VPN not needed locally
- `nfs-provisioner` - Replaced by local-path-provisioner
- `smb-provisioner` - Replaced by local-path-provisioner
- `external-dns` - No external DNS for local dev
- `vault` - Can be added if needed (uses local storage)
- Heavy apps (immich, couchdb, postiz-app) - Require significant resources

## Cleanup

```bash
kind delete cluster --name homelab-dev
```
