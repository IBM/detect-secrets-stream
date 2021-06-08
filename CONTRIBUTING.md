## Process for Supporting a New Secret Type in detect-secrets-stream

After a new secret detector has been developed in `IBM/detect-secrets` (see [instructions](https://github.com/IBM/detect-secrets/blob/master/CONTRIBUTING.md)), additional functionality must be developed in this repository in order to support the new secret type as part of the server side detection pipeline. This involves creating a validator class containing the functions `secret_type_name()`, `verify()`, `resolve_owner()` and `revoke()`, at a minumum.

First, be sure to run `pipenv update` to retrieve the new detector and any other recent changes from `detect-secrets`. Then, follow the steps below:

### Secret Validation
- In order to regularly validate whether or not a caught secret is still active, a "validator" for the new secret type must be developed. This validator should reuse functionality of the relevant `detect-secrets` detector.
- Using the secret validators in `detect_secrets_stream/validation` as examples, create a new Python file under that path. The file should contain a new validator class that inherits from `BaseValidator`.
- The new validator class must contain a static method called `secret_type_name()` which simply returns the `secret_type` attribute of the detector imported from `detect_secrets`.
- The new validator class should also contain a method called `validate()`, which accepts the `secret` and `other_factors` and passes them to the `verify()` function or other utility functions of the detector imported from `detect_secrets`. The return value of `validate()` is a boolean indicating if the secret is live, and should be compliant with the parent spec from `detect_secrets_stream.validation.base.BaseValidator.validate()`.
- Using the tests under `detect_secrets_stream/validation/tests` as examples, create a new test file under that directory with test cases to ensure that the new validator class functions as expected and failure cases are accounted for.

### Secret Owner Resolution
- There are a few ways of identifying the person responsible for remediating a leaked token. One could consider the responsible person to be the developer who pushed the commit, but another useful piece of information to store is the person to whom the token actually belongs, i.e. whose service account the token is from, or the person who created the token. We refer to this person as the token owner, which may or may not be the same as the pusher.
- Many service endpoints provide such owner metadata for keys, especially on successful verification. When possible, this owner information will be reported, preferably in the form of an email address.
- Identify a service endpoint for owner identification.
- In the same validator class developed above, add a function called `resolve_owner()` which accepts the `secret` and `other_factors` and returns an email address, if possible, or other identifying information about the token owner if not. If owner resolutions fails or is not possible, this function can return an empty string.
- Update the validator's test file under `detect_secrets_stream/validation/tests` to ensure that the owner resolution function works as expected. Use the other test files in that directory as examples.

### Secret Revocation
- The new validator class requires a function called `revoke()`, which must be compliant with the the parent spec from `detect_secrets_stream.validation.base.BaseValidator.revoke()`.
- If the relevant service owner to which the new secret type belongs has given their explicit permission, and a programmatic method for revoking the secret exists, `revoke()` should attempt to revoke the token and return a boolean indicating whether or not the revocation was successful.
- If the above preconditions for revoking a secret type are not true, the `revoke()` function must still be implemented, but will do nothing. See the parent spec for details.
- After implementing `revoke()`, update the validator's test file under `detect_secrets_stream/validation/tests` to ensure that the revocation function works as expected. Use the other test files in that directory as examples.
