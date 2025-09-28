# Full admin across everything
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Explicit sys paths and UI helpers
path "sys/*"           { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/mounts"      { capabilities = ["read","list"] }
path "sys/mounts/*"    { capabilities = ["read","list"] }
path "sys/internal/*"  { capabilities = ["read","list"] }
path "sys/capabilities-self" { capabilities = ["create","read","update"] }

# Identity browsing for UI - requires sudo for listing
path "identity/*"      { capabilities = ["create","read","update","delete","list","sudo"] }
path "identity/entity/id"   { capabilities = ["read","list","sudo"] }
path "identity/entity/name" { capabilities = ["read","list","sudo"] }

# KV v2: dev
# Root mount path (needed for UI preflight on "dev/")
path "dev"             { capabilities = ["read","list"] }
# Data and metadata
path "dev/*"           { capabilities = ["create","read","update","delete","list"] }
path "dev/data/*"      { capabilities = ["create","read","update","delete","list"] }
path "dev/metadata/*"  { capabilities = ["create","read","update","delete","list"] }

# KV v2: prod
path "prod"            { capabilities = ["read","list"] }
path "prod/*"          { capabilities = ["create","read","update","delete","list"] }
path "prod/data/*"     { capabilities = ["create","read","update","delete","list"] }
path "prod/metadata/*" { capabilities = ["create","read","update","delete","list"] }