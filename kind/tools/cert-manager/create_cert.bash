#!/bin/bash

# 1. Generate the Private Key (2048-bit RSA)
openssl genrsa -out tls.key 2048

# 2. Generate the Self-Signed CA Certificate (Valid for 10 years)
openssl req -x509 \
  -new -nodes \
  -key tls.key \
  -sha256 \
  -days 3650 \
  -out tls.crt \
  -subj "/CN=homelab-kind"

kubectl create secret tls kind-cert-manager-webhook-ca --cert=tls.crt --key=tls.key --dry-run=client -oyaml > kind-ca-secret.yaml