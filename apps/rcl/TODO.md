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

## Completed: staging email-outbox qualification

- Application release `staging-20260718-46147ef` is live with backend digest `ca9bbdd7` and frontend digest `d1bb115d`.
- The cached post-cover race and missing-author spinner were fixed and verified through Chrome DevTools using cached SPA navigation, hard reload, back/forward, and mobile rendering.
- The scheduled `email-outbox` worker is enabled with `concurrencyPolicy: Forbid` and `startingDeadlineSeconds: 60`.
- Manual and scheduled no-work runs completed with `0 sent, 0 requeued, 0 failed`; the MailLog baseline remains 64 `SENT` rows.
- Public health, missing/forged/mapped mTLS, SMTP, Kubernetes security, and MCP checks passed with fixtures cleaned.
- Homelab rollout revisions: images `35a9afe`, schedule enablement `a9df5b6`, missed-run safeguard `0df702e`.
- Roll back by disabling the CronJob first, then restore both images to `staging-20260718-c390c0c` (homelab revision `4147906`).
