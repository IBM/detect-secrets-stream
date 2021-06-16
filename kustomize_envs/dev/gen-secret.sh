#!/bin/bash -e

cur_dir=$(cd "$(dirname "$0")" && pwd)
SECRET_DIR=${cur_dir}/secret_generated
GD_BASIC_AUTH_FILENAME=${SECRET_DIR}/basic_auth.conf
GD_VAULT_FILENAME=${SECRET_DIR}/vault.conf
GD_DB_FILENAME=${SECRET_DIR}/gd_db.conf

mkdir -p "${SECRET_DIR}"

make -f "${cur_dir}/../../Makefile" create-common-test-secrets TEST_SECRET_BASE_DIR="${SECRET_DIR}" TEST_SECRET_COMMENT="local test"

cat > "${GD_BASIC_AUTH_FILENAME}" << EOF
[basic_auth]
ingest = pre-receive:$(env LC_ALL=C tr -dc _A-Z-a-z-0-9 < /dev/urandom | head -c48)
revoker = revoker:$(env LC_ALL=C tr -dc _A-Z-a-z-0-9 < /dev/urandom | head -c48)
revoker-requires-auth = false
EOF

cat > "${GD_VAULT_FILENAME}" << EOF
[vault]
gd_vault_url=http://vault:8200
gd_vault_verify=True
gd_vault_approle_id=$(uuidgen)
gd_vault_secret_id=$(uuidgen)
mount_point=generic
token_path=project/detect-secrets-stream/token
EOF

cat > "${GD_DB_FILENAME}" << EOF
[db]
database = dss
hostname = postgres
password = postgres
port = 5432
username = postgres
EOF

echo "Populating manual secrets"

SECRET_MANUAL_DIR=${cur_dir}/secret_manual
mkdir -p "${SECRET_MANUAL_DIR}"

GD_GITHUB_APP_KEY_FILENAME=${SECRET_MANUAL_DIR}/app.key
test -s "${GD_GITHUB_APP_KEY_FILENAME}" || cat > "${GD_GITHUB_APP_KEY_FILENAME}" << EOF
<private ssh key here>
EOF

GD_DB2_LIC_FILENAME=${SECRET_MANUAL_DIR}/db2consv_zs.lic
# This should generate an empty license file
test -s "${GD_DB2_LIC_FILENAME}" || cat > "${GD_DB2_LIC_FILENAME}" << EOF
EOF

GD_EMAIL_CONF=${SECRET_MANUAL_DIR}/email.conf
test -s "${GD_EMAIL_CONF}" || cat > "${GD_EMAIL_CONF}" << EOF
[email]
# email matching my company
internal_email_regex = [A-Z0-9.\-_]+@([A-Z0-9]+\.)*(mycompany.com)$
EOF

GD_ENV_CONF=${SECRET_MANUAL_DIR}/env.txt
test -s "${GD_ENV_CONF}" || cat > "${GD_ENV_CONF}" << EOF
APP_ID=<GitHub App ID>
EOF

GD_GHE_REVOKE_TOKEN=${SECRET_MANUAL_DIR}/ghe_revocation.token
test -s "${GD_GHE_REVOKE_TOKEN}" || cat > "${GD_GHE_REVOKE_TOKEN}" << EOF
<Jenkins job trigger token to revoke GHE token>
EOF

GD_GHE_FILENAME=${SECRET_MANUAL_DIR}/github.conf
test -s "${GD_GHE_FILENAME}" || cat > "${GD_GHE_FILENAME}" << EOF
[github]
tokens = pat_for_public_repos
host = github.mycompany.com
admin_config = https://%(host)s/api/v3/repos/<org>/<repo>/contents/org_set_config
EOF

GD_IAM_FILENAME=${SECRET_MANUAL_DIR}/iam.conf
test -s "${GD_IAM_FILENAME}" || cat > "${GD_IAM_FILENAME}" << EOF
[iam]
admin_apikey = <iam_admin_key>
EOF

GD_KAFKA_FILENAME=${SECRET_MANUAL_DIR}/kafka.conf
test -s "${GD_KAFKA_FILENAME}" || cat > "${GD_KAFKA_FILENAME}" << EOF
[kafka]
brokers_sasl = broker-1:9093,broker-2:9093,broker-3:9093
api_key = kafka api key
EOF

GD_REVOKE_FILENAME=${SECRET_MANUAL_DIR}/revoker_urls.conf
test -s "${GD_REVOKE_FILENAME}" || cat > "${GD_REVOKE_FILENAME}" << EOF
[revoker-urls]
artifactory-revocation = https://artifactory/revoke
artifactory-owner-resolution = https://artifactory/artifactory/api/npm/auth
github-revocation = https://jenkins/generic-webhook-trigger/invoke
github-owner-resolution = https://github.mycompany.com/api/v3/user
EOF

echo ""
echo "Please review and edit secrets under ${SECRET_MANUAL_DIR} as needed."
