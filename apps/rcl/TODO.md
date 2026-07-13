# TODO: Enhance mTLS Security with Vault PKI

## Current State
The `mtls-policy` currently uses a self-signed root CA where the private key is stored directly in a Kubernetes Secret (`mtls-ca-secret`) in the `rcl` namespace via `cert-manager`'s `SelfSigned` and `CA` issuers.

## Security Risk
Storing the Root CA private key in-cluster as a plain Kubernetes Secret means anyone (or any compromised controller/pod) with `Secret` read access in this namespace can extract the key and mint valid client certificates, bypassing the mTLS proxy.

## Proposed Action
Migrate the mTLS Certificate Authority to **HashiCorp Vault PKI** to keep the root private key out of the Kubernetes cluster.

### Steps
1. **Enable Vault PKI**: Configure the PKI secrets engine in the existing Vault deployment.
2. **Generate Root CA in Vault**: Create the Root CA entirely within Vault so the private key never leaves the secure enclave.
3. **Configure Vault Issuer**:
   - Replace the `selfsigned-issuer` and `mtls-ca-issuer` in `mtls-cert.yaml` with a `Vault` Issuer.
   - Set up the necessary Vault AppRole/Kubernetes authentication for `cert-manager` to securely communicate with Vault.
4. **Issue Certificates**: Have `cert-manager` issue the `admin-client-cert` directly via the Vault Issuer.
5. **Update NGINX Trust**: Ensure the NGINX `mtls-policy` trusts the public certificate of the Vault PKI Root CA.

*Note: Since Vault and External Secrets are already running in the cluster (`vault-dev`), this leverages existing infrastructure.*

## Trusted proxy address

`MTLS_TRUSTED_PROXY_CIDRS` currently pins the NGINX Ingress controller pod IP as a `/32`. This fails closed if that pod is replaced. Update the value after a controller rollout, or replace the address-based trust with a stable, independently authenticated proxy boundary before production.
