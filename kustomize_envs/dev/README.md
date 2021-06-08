# local end 2 end test

This doc describes how to use `skaffold` to run a detect-secrets-stream instance in a local kube env and run some end 2 end test.

## Dependencies

### provision ahead of time

- github-app:
  - `kustomize_envs/dev/secret_manual/app.key` stores the private key for this test Github App
  - `APP_ID` in `kustomize_envs/dev/secret_manual/env.txt` stores the Github App ID
- a kafka queue named `diff-scan`
  - You can request a free kafka instance in your own IBM Cloud account. Service link: https://cloud.ibm.com/catalog/services/event-streams. Once created, generate a queue named `diff-scan` in the kafka instance. **TODO** parameterize queue name

### ondemand provision

The resource below would be automatically provisioned when you run skaffold

- postgres
- vault

## Deploy a test instance

The steps below would deploy a test instance of detect-secrets-stream in a kube cluster you named. We are using [kind](https://kind.sigs.k8s.io/) to create a local cluster in the example below.

To install kind, run `brew install kind`.

```shell
# create a kube cluster using kind
kind create cluster
kubectl config current-context # make sure you are on the kind cluster

# create dev namespace
kubectl create ns dev

# generate local secret files
# refer to the Local Dev Secrets guide in the root project README to set up manually-entered secrets
kustomize_envs/dev/gen-secret.sh

# build image and deploy to dev cluster. "skaffold dev" would tail on log after image been deployed. In the meanwhile, you can use tools like k9s to monitor the status in your kube cluster
skaffold dev --port-forward -p dev

# Once you are done, you can delete your cluster
kind delete cluster
```

## Execute test

The ingest script reads payload from `kustomize_envs/dev/test/ingest.payload.json`, you can edit that file to customize the payload such as which repo and which commit to ingest.

```shell
# Ingest token by sending payload to ingest layer
kustomize_envs/dev/test/ingest.sh
```

You can inspect the captured token in vault and postgres

### Inspect vault

```shell
# Run in local env
# land into vault container first
kubectl exec -n dev -it $(kubectl get pods -n dev -l app=vault -o jsonpath="{.items[0].metadata.name}") -c vault-client -- /bin/sh

# Run inside of the container
# show captured token
vault kv list generic/project/detect-secrets-stream/token
vault kv get generic/project/detect-secrets-stream/token/<token_id>
```

### Inspect postgres

```shell
# Run in local env
# run psql in postgres container as user "postgres"
kubectl exec -n dev -it $(kubectl get pods -n dev -l app=postgres -o jsonpath="{.items[0].metadata.name}") -c postgres -- psql -U postgres
```

Allows running manual SQL commands against your postgresql database

```
# Run inside of the container
# connect to dss database and get all rows from "token" table
postgres=# \c dss
dss=# SELECT * FROM token;
```
