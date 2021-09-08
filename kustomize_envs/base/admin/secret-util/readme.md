# secret util

A long run deployment allows admin to interact with the system without needing to collect all secrets locally. It has exposed all secrets needed to run `secret_util`. Please make sure only authorized people can access this deployment.

You can run `secret_util` remotely like below

```shell
kubectl exec -it -n prod deploy/secret-util -- python -m detect_secrets_stream.util.secret_util decrypt-token-by-uuid <uuid_here>
```

You can also run any other commands within this admin container.

```shell
kubectl exec -it -n prod deploy/secret-util -- /bin/bash
```
