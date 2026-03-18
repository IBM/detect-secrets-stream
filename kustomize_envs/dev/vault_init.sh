#!/bin/sh

echo "Waiting for vault to become available"
for i in {1..100}; do sleep 1; if nc 127.0.0.1 8200 -z; then break; fi; done;

role_name=dss
role_id=$(grep approle_id $GD_VAULT_CONF | cut -d= -f2)
secret_id=$(grep secret_id $GD_VAULT_CONF | cut -d= -f2)
token_path=$(grep token_path $GD_VAULT_CONF | cut -d= -f2)
mount_point=$(grep mount_point $GD_VAULT_CONF | cut -d= -f2)

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=$VAULT_DEV_ROOT_TOKEN_ID

vault auth enable approle
vault write -f auth/approle/role/$role_name
vault write auth/approle/role/$role_name/role-id role_id=$role_id
vault write auth/approle/role/$role_name/custom-secret-id secret_id=$secret_id

echo "enable path"
vault secrets enable -path=$mount_point kv

echo "add policy for role $role_name"
vault policy write dss-policy -<<EOF
path "$mount_point/$token_path/*" {
  capabilities = ["create","read","update","delete","list"]
}
EOF
vault write auth/approle/role/$role_name token_policies="dss-policy"
