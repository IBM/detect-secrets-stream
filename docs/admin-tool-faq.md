# Detect Secrets Suite Admin Tool FAQ

The Admin Tool is a companion app for `detect-secrets-stream` to allow it to scan private / internal repositories and add security personnel (security focals). This documentation is intended for GitHub Enterprise organization admins.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [As a GitHub organization admin, why have I been asked to install the Detect Secrets Admin Tool GitHub App and / or review a PR in `dss-config`?](#as-a-github-organization-admin-why-have-i-been-asked-to-install-the-detect-secrets-admin-tool-github-app-and--or-review-a-pr-in-dss-config)
- [As a GitHub organization admin, what should I look for when reviewing a PR in `dss-config`?](#as-a-github-organization-admin-what-should-i-look-for-when-reviewing-a-pr-in-dss-config)
- [How can I remove the Detect Secrets Admin Tool Github App from a single repository?](#how-can-i-remove-the-detect-secrets-admin-tool-github-app-from-a-single-repository)
- [How can I remove the Detect Secrets Admin Tool Github App from my organization?](#how-can-i-remove-the-detect-secrets-admin-tool-github-app-from-my-organization)
- [Does the Detect Secrets Admin Tool provide status checks on commits?](#does-the-detect-secrets-admin-tool-provide-status-checks-on-commits)
- [What does it mean if I can only request to install the Detect Secrets Admin Tool to a repository or organization?](#what-does-it-mean-if-i-can-only-request-to-install-the-detect-secrets-admin-tool-to-a-repository-or-organization)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## As a GitHub organization admin, why have I been asked to install the Detect Secrets Admin Tool GitHub App and / or review a PR in `dss-config`?

If you're a GitHub organization admin who has been asked to install the Detect Secrets Admin Tool GitHub to your organization and/or approve a PR in `dss-config`, this means that security focals associated with your GitHub organization have found it necessary to monitor for secret leaks within your organization via the Admin Tool GitHub app.

The Admin Tool provides security focals with a unified view of all secret leaks across a set of GitHub organizations, including both public and private repositories within those organizations.

In order for the Admin Tool to function, it needs to:

-   **Gain permission to scan private repositories**
-   **Associate security focals to organizations**, so the security focals can be subscribed to token leak communications, such as ServiceNow and email notifications.

> Why have I been asked to install the Detect Secrets Admin Tool GitHub App?

The Detect Secrets Admin Tool GitHub app grants the Admin Tool permission to scan private repositories. The GitHub app needs to be installed at the GitHub organization level, and only organization admins have permission to do so. This is why you, as an organization admin, have been asked to install the app.

> Why have I been asked to review a PR in `dss-config`?

The config files contributed by security focals in `dss-config` are used by the Admin Tool to build associations between security focals and GitHub organizations. Once the PR has been merged, it will allow the security focals listed in the file to be copied on all communications for tokens leaked within the organizations listed in the file.

## As a GitHub organization admin, what should I look for when reviewing a PR in `dss-config`?

When reviewing PRs in `dss-config`, it is important to verify that all the `security-focal-emails` listed in the PR's config file (in `dss-config/org_set_config/<filename>.yaml`) _should_ have access to Service Now tickets regarding secret leaks in your organization. You should also verify that your organization appears under `organizations` in that file, otherwise you should not need to review the PR.

## How can I remove the Detect Secrets Admin Tool Github App from a single repository?

Permission from an organization admin is required.

-   Go to `<github_host>/organizations/<org-name>/settings/installations`
-   In the Installed Github App list, click the `Configure` button next to `Detect Secrets Admin Tool`
-   Under `Repository access`, choose `Only select repositories`, then click the `x` next to the repository you want to remove the app from

## How can I remove the Detect Secrets Admin Tool Github App from my organization?

Permission from an organization admin is required.

-   Go to `<github_host>/organizations/<org-name>/settings/installations`
-   In the Installed Github App list, click the `Configure` button next to `Detect Secrets Admin Tool`
-   Under `Uninstall Detect Secrets Admin Tool`, click the `Uninstall` button

## Does the Detect Secrets Admin Tool provide status checks on commits?

No. The `Detect Secrets Admin Tool` runs entirely in the background, invisible to developers. It will only send a notification if it finds verified secrets in new commits, upon which the secrets will be reported to the remediation team.

## What does it mean if I can only request to install the Detect Secrets Admin Tool to a repository or organization?

This means that you do not have sufficient permissions to install the `Detect Secrets Admin Tool` app. If you encounter this problem, please contact the organization admin for the organization or repository.
