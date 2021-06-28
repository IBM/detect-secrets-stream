# Adding a New Detector

Adding a new type of detector to detect-secrets-suite is a multi-stage process. You must:

- Understand the secret signature and use cases; What is it's format and how does it appear in code?
- Understand the secret verification, owner resolution, and revocation process.
- Develop a detector which becomes part of [`IBM/detect-secrets`](https://github.com/IBM/detect-secrets)
- Enable the new detector in [`IBM/detect-secrets-stream`](https://github.com/IBM/detect-secrets-stream) by supporting verification, owner resolution, and with the approval of the token type's internal service owner, revocation.
- [optional] Contribute the new detector to the upstream project `Yelp/detect-secrets` on github.com.

## Skills Required

- Python
- Python test frameworks
- Regular expressions
- Knowledge of the secret type, its specification & its usage
- Git

## Instructions

For detailed instructions on developing a new secret detector, see:

- [`IBM/detect-secrets` CONTRIBUTING.md - Process for Adding a New Secret Detector to whitewater-detect-secrets](https://github.com/IBM/detect-secrets/blob/master/CONTRIBUTING.md#process-for-adding-a-new-secret-detector-to-whitewater-detect-secrets)
- [`IBM/detect-secrets-stream` CONTRIBUTING.md - Process for Supporting a New Secret Type in detect-secrets-stream](../CONTRIBUTING.md#process-for-supporting-a-new-secret-type-in-detect-secrets-stream)

Please open one or more PRs using the instructions above.
