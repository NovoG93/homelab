# Kind Configuration for Dev Cluster

This directory contains the kind cluster configuration and Kustomize overlays for running the homelab stack locally.

## Architecture

The kind dev cluster is **managed by the production ArgoCD** instance - there is no ArgoCD running inside the kind cluster itself. The prod ArgoCD discovers kind workloads via dedicated ApplicationSets that scan `kind/{core,tools,apps}/**/app.yaml` and target the `kind-dev` cluster.

```
┌──────────────────────┐         ┌───────────────────────┐
│   Prod Cluster       │         │   Kind Dev Cluster    │
│                      │         │                       │
│  ┌────────────────┐  │  HTTPS  │  ┌─────────────────┐  │
│  │    ArgoCD      │──┼────────►│  │  argocd-manager │  │
│  │                │  │  :5510  │  │ (ServiceAccount)│  │
│  │  ApplicationSets: │         │  └─────────────────┘  │
│  │  - core-appset-kind         │                       │
│  │  - tools-appset-kind        │  Managed workloads:   │
│  │  - apps-appset-kind         │  - calico             │
│  └────────────────┘  │         │  - metallb            │
│                      │         │  - cert-manager       │
│  ┌────────────────┐  │         │  - kyverno            │
│  │ ExternalSecret │  │         │  - nginx-ingress      │
│  │ (Vault → cluster  │         │  - wildcard-tls       │
│  │  credentials)  │  │         │  - netshoot           │
│  └────────────────┘  │         │  - nginx              │
└──────────────────────┘         └───────────────────────┘
```

Credentials flow: `kind cluster` → `register-cluster.bash` → **user stores in Vault** → `ExternalSecret` → ArgoCD cluster Secret.

## Structure

```
kind/
├── startup.bash           # Creates kind cluster + runs register-cluster.bash
├── register-cluster.bash  # Extracts credentials, prints vault kv put command
├── cluster.yaml.tmpl      # Kind cluster config template
├── core/                  # Core infrastructure overlays
│   ├── argocd-manager/    # SA + ClusterRole for prod ArgoCD access
│   ├── calico/            # CNI with kind-specific CIDR
│   ├── metallb-system/    # Load balancer with Docker subnet IPs
│   └── metrics-server/    # Metrics (unchanged from prod)
├── tools/                 # Tools overlays
│   ├── cert-manager/      # Self-signed CA issuer
│   ├── kyverno/           # Policy engine
│   ├── nginx-ingress/     # Ingress controller with HostPort
│   └── wildcard-tls/      # Wildcard cert for *.127.0.0.1.nip.io
└── apps/                  # Application overlays
    ├── netshoot/          # Network debugging tool
    └── nginx/             # Nginx test app
```

## Key Differences from Production

| Component | Production | Kind (Dev) |
|-----------|-----------|------------|
| **ArgoCD** | Runs in-cluster | Managed by prod ArgoCD remotely |
| **IPs** | 192.168.0.210-221 | 172.18.0.200-210 (Docker) |
| **Certificates** | Let's Encrypt via Cloudflare | Self-signed CA |
| **Storage** | NFS/SMB | local-path-provisioner |
| **Domain** | *.novotny.live | *.127.0.0.1.nip.io |
| **VPN** | Tailscale | Disabled |
| **External DNS** | PiHole | Disabled |
| **Sync Policy** | Automated (self-heal) | Manual sync |

## Quick Start

### 1. Create the Cluster

```bash
# This creates the kind cluster and extracts ArgoCD credentials
./kind/startup.bash
```

The script will:
1. Install `kind` if not present
2. Template `cluster.yaml` with your LAN IP
3. Create a 3-node kind cluster (`homelab-dev`)
4. Apply the `argocd-manager` ServiceAccount to the kind cluster
5. Print a `vault kv put` command with the extracted credentials

### 2. Store Credentials in Vault

Copy the `vault kv put` command printed by the script and run it against your Vault instance:

```bash
vault kv put dev/argocd-clusters/kind-dev \
  server="https://<your-ip>:5510" \
  token="<extracted-token>"
```

This populates the Vault path that the ExternalSecret (`tools/argocd/clusters/kind-dev-secret.yaml`) reads from to create the ArgoCD cluster Secret.

### 3. Verify Docker Network (for MetalLB)

```bash
# Check the kind network subnet
docker network inspect kind | grep Subnet
# Expected: "Subnet": "172.18.0.0/16"
# If different, update kind/core/metallb-system/ipaddress-pool.yaml
```

### 4. Sync via ArgoCD

Once the cluster secret is created, the kind ApplicationSets in prod ArgoCD will generate Applications targeting `kind-dev`. Since sync is **manual**, go to the ArgoCD UI and sync them in order:

1. **`calico-kind`** - CNI (must be first)
2. **`metallb-kind`** - Load balancer
3. **`argocd-manager-kind`** - Ensures the SA is managed by ArgoCD going forward
4. **`metrics-server-kind`** - Metrics
5. **`cert-manager-kind`** - Certificate management
6. **`kyverno-kind`** - Policy engine
7. **`nginx-ingress-kind`** - Ingress controller
8. **`wildcard-tls-kind`** - Wildcard certificate
9. **`netshoot-kind`**, **`nginx-kind`** - Apps

### 5. Local DNS

Using `nip.io` avoids the need for `/etc/hosts` entries.
Access services via:
- `https://nginx.127.0.0.1.nip.io`


## Excluded Components

The following production components are not included in kind:
- `tailscale` - VPN not needed locally
- `nfs-provisioner` - Replaced by local-path-provisioner
- `smb-provisioner` - Replaced by local-path-provisioner
- `external-dns` - No external DNS for local dev
- `vault` - TBD
- Heavy apps (immich, couchdb, postiz-app) - TBD

## Troubleshooting

### Prod ArgoCD can't reach kind cluster

- Ensure the kind API server is accessible from the prod cluster at `<host-ip>:5510`
- The kind cluster listens on `0.0.0.0:5510` with certSANs for the LAN IP
- Check firewall rules on the machine running kind

### Token expired or cluster recreated

After recreating the kind cluster, run `register-cluster.bash` again and update the Vault secret:

```bash
./kind/register-cluster.bash
# Then run the printed vault kv put command
```

### ApplicationSets show "cluster not found"

- Verify the ExternalSecret has synced: `kubectl -n argocd get externalsecret kind-dev-cluster`
- Check the generated Secret exists: `kubectl -n argocd get secret kind-dev-cluster`
- Verify the Secret has the correct label: `argocd.argoproj.io/secret-type: cluster`

## Cleanup

```bash
kind delete cluster --name homelab-dev
```
