#!/bin/sh

echo "Waiting for vault to become available"
for i in {1..100}; do sleep 1; if nc 127.0.0.1 8200 -z; then break; fi; done;

# Give vault a bit more time to fully initialize
sleep 3

role_name=dss
role_id=$(grep approle_id $GD_VAULT_CONF | cut -d= -f2)
secret_id=$(grep secret_id $GD_VAULT_CONF | cut -d= -f2)
token_path=$(grep token_path $GD_VAULT_CONF | cut -d= -f2)
mount_point=$(grep mount_point $GD_VAULT_CONF | cut -d= -f2)

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=$VAULT_DEV_ROOT_TOKEN_ID

# Enable approle auth (ignore error if already enabled)
vault auth enable approle 2>/dev/null || echo "approle already enabled"

# Configure approle
vault write -f auth/approle/role/$role_name || echo "Failed to create role"
vault write auth/approle/role/$role_name/role-id role_id=$role_id || echo "Failed to set role-id"
vault write auth/approle/role/$role_name/custom-secret-id secret_id=$secret_id || echo "Failed to set secret-id"

echo "enable path"
vault secrets enable -path=$mount_point kv 2>/dev/null || echo "kv already enabled at $mount_point"

echo "add policy for role $role_name"
vault policy write dss-policy -<<EOF
path "$mount_point/$token_path/*" {
  capabilities = ["create","read","update","delete","list"]
}
EOF

vault write auth/approle/role/$role_name token_policies="dss-policy" || echo "Failed to set token policies"

echo "Vault initialization complete"
