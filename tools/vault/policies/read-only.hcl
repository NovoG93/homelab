# Read-Only Policy for External-Secret-Operator
# KV v2: dev
path "dev/*"           { capabilities = ["read"] }

# KV v2: prod
path "prod/*"          { capabilities = ["read"] }
