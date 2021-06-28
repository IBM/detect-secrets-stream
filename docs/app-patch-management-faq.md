# App-Level Patch Management FAQ

When images are generated in CI builds, [`trivy`](https://github.com/aquasecurity/trivy) and [`pyup`](https://pyup.io/) are run to scan for both OS and app-level vulnerabilities. This document focuses on vulnerabilities that appear after certain artifacts have been generated. The intended audience is GitHub Enterprise organization admins.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Artifact types](#artifact-types)
- [Tools](#tools)
  - [Detection](#detection)
  - [Fix](#fix)
- [Detection and fix matrix](#detection-and-fix-matrix)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Artifact types

1. Detect Secrets Stream Docker images, in [here](../Dockerfiles/Dockerfile.DSS)
1. Supporting Docker images
   - Images created by Detect Secrets Suite, such as `kafka-lag-exporter`
   - Images created by third parties, such as `logdna-agent` and `sysdig`
1. Dev tool Docker images
   - `detect-secrets`
   - `detect-secrets-hook`
1. Dev tool pip dependencies

## Tools

### Detection

- `trivy` reports both OS and app vulnerabilities.
- Vulnerability Advisor from IBM Cloud Container Registry. Vulnerability Advisor does not cover app-level vulnerabilities, it can be replaced with `trivy`.

### Fix

- `renovate bot`: runs a daily scan for app-level vulnerabilities based on Pipenv lockfile and Dockerfiles. It automatically opens PRs for vulnerability resolution.
- `detect-secrets-updater`: runs daily to scan for vulnerabilities in published Docker image with `latest` and latest version tag.

## Detection and fix matrix

| Artifacts                                                       | OS dep vulnerabilities                                                    | App dep vulnerabilities                                                   |
| --------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| server: dss images                                              | **detection**: trivy + issue<br/> **fix**: manual                         | **detection**: issue<br/>**fix**: renovate bot                            |
| server: support images(we don't manage)<br/><br/>sysdig, logdna | **detection**: trivy + issue<br/>**fix**: manual                          | **detection**: trivy + issue<br/>**fix**: manual                          |
| server: support images (we manage)<br/><br/>kafka-exporter      | same as "dss images"                                                      | same as "dss images"                                                      |
| dev tool: Docker images                                         | **detection**: detect-secrets-updater<br/>**fix**: detect-secrets-updater | **detection**: detect-secrets-updater<br/>**fix**: detect-secrets-updater |
| dev tool: pip pkg                                               | **n/a**                                                                   | **n/a**<br/>lib pkg always use latest dep                                 |
