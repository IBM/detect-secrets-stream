# Welcome to `detect-secrets-suite`!

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [FAQ](#faq)
  - [What is detect-secrets-suite?](#what-is-detect-secrets-suite)
  - [What information do you track for each push?](#what-information-do-you-track-for-each-push)
  - [Do you also scan private repos?](#do-you-also-scan-private-repos)
  - [How does detect-secrets-suite affect my interaction with Github?](#how-does-detect-secrets-suite-affect-my-interaction-with-github)
  - [How does this affect the current detect-secrets app?](#how-does-this-affect-the-current-detect-secrets-app)
  - [What is a pre-receive hook?](#what-is-a-pre-receive-hook)
  - [Will my pushes and PR merges be blocked?](#will-my-pushes-and-pr-merges-be-blocked)
  - [Which of the pre-receive hooks should I use?](#which-of-the-pre-receive-hooks-should-i-use)
  - [As an org / repo owner, can I disable it?](#as-an-org--repo-owner-can-i-disable-it)
  - [Why is my pull request no longer triggering CI after enabling pre-receive hook?](#why-is-my-pull-request-no-longer-triggering-ci-after-enabling-pre-receive-hook)
  - [My push is timed out, what should I do?](#my-push-is-timed-out-what-should-i-do)
  - [My push has slowed down, what should I do?](#my-push-has-slowed-down-what-should-i-do)
  - [My push was made but my CI / CD didn't trigger or execute?](#my-push-was-made-but-my-ci--cd-didnt-trigger-or-execute)
  - [What token types do you scan?](#what-token-types-do-you-scan)
  - [What file content do you scan?](#what-file-content-do-you-scan)
  - [What's delta (diff) scan? are there any other scan types?](#whats-delta-diff-scan-are-there-any-other-scan-types)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## FAQ

### What is detect-secrets-suite?

`detect-secrets-suite` is the next generation of the Detect Secrets service. We are using [IBM Cloud](http://cloud.ibm.com)'s streaming & analysis capabilities to find secrets (tokens, keys, etc) in source code.

Under the hood, we use a non-blocking [pre-receive hook](#what-is-a-pre-receive-hook) to track [push information](#what-information-do-you-track-for-each-push). This queues an asynchronous scan request for potential secrets, for each commit in turn.

### What information do you track for each push?

The collected information includes who, what's been committed and the time of push to Github. The complete list of information we track can be found [here](https://help.github.com/en/enterprise/2.16/admin/developer-workflow/creating-a-pre-receive-hook-script#writing-a-pre-receive-hook-script.)

### Do you also scan private repos?

We only scan public repos by default. For private repos, we will ask for your permission through a Github App. Don't worry, we won't peek into your source code without asking.

Please note, the pre-receive trigger is in place enterprise-wide on _every_ repo. The scan code checks the privacy of a repo before scanning it. It does not scan a private repo unless the `detect-secrets-suite` GitHub App is in place to give permission to proceed.

### How does detect-secrets-suite affect my interaction with Github?

Each time you run `git push` to a pre-receive hook enabled repo, you will notice some additional text output as push metadata is collected. The design of the pre-receive hook is non blocking. Read question [`Will my pushes and pr merges be blocked?`](#will-my-pushes-and-pr-merges-be-blocked) for more details if your push is blocked.

```shell
$ git push
Warning: Permanently added '<REVOKED>' (ECDSA) to the list of known hosts.
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 999 bytes | 999.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0)
remote: Resolving deltas: 100% (2/2), completed with 2 local objects.
remote: detect-secrets-stream (beta) ver=<REVOKED>
remote:
remote: Successfully send push metadata.
remote: Push info collect pre-receive hook finished within 3 seconds.
To <REVOKED>.git
   ae785e1..37be0f6  master -> master
```

### How does this affect the current detect-secrets app?

This does _not_ affect the current Github app in any way. Both services follow different flows and can be run concurrently without any issues.

### What is a pre-receive hook?

Pre-receive hooks are designed to enforce rules before commits are pushed to a repository. They run tests to ensure commits meet repository or organization policy.

_\*Pre-receive hooks have a time limit. If the processing can't finish within 5 seconds, the push will fail._ It's not currently possible to complete a full scan of all a push's content in that time, so `detect-secrets-suite` queues a request for an asynchronous scan.

[more about pre-receive hooks](https://help.github.com/en/enterprise/2.16/admin/developer-workflow/about-pre-receive-hooks)

### Will my pushes and PR merges be blocked?

No, our pre-receive script is designed to ensure it will always finish successfully within 5 seconds, no matter the push info is sent successfully or not. It's intended not to block users from pushing due to server error. If you have any experiences to the contrary, please submit an issue.

### Which of the pre-receive hooks should I use?

The `detect-secrets-suite` pre-receive hook is preselected at the Enterprise level. Any additional hooks you select will be run consecutively.

### As an org / repo owner, can I disable it?

In this iteration of `detect-secrets-suite` it is designed to be non-disruptive and cannot be disabled individually.

### Why is my pull request no longer triggering CI after enabling pre-receive hook?

After the pre-receive hook is enabled on a repo, there is [one additional value: `has_hooks` in the `mergeable_state` field](https://developer.github.com/v4/enum/mergestatestatus/).

We have performed testing across the most common CI systems and applied patches for error conditions we found. However, if a CI system does not recognize this value, it might result in unexpected behaviors such as build not being triggered.

We've found the issue and applied an internal fix to Travis. We've also tested on Jenkins and verified the popular plugins such as Github Organizations and Multi-branches are not been affected.

If your CI system behaves strangely after enabling the pre-receive hook, check with your CI vendor to validate if the new value in field `mergeable_state` is the culprit. In any case, please raise the an issue with us.

### My push is timed out, what should I do?

If you have seen a message like :

```shell
remote: Push info collect pre-receive hook failed to finish within 3 seconds with error code 124
remote: push_info.sh: execution exceeded 5s timeout
To <REDACTED>/secret-corpus-db !
[remote rejected] gen-db-tool -> gen-db-tool (pre-receive hook declined)
```

We're sorry, the hook is designed to never fail. However, we have seen some rare circumstances where it does and we will be aware that it has timed out, you do not need to report it.

Please re-attempt the push unaltered. If it continues to fail, please open an issue.

### My push has slowed down, what should I do?

There should be minimal delay to your push introduced by triggering the detect-secrets asynchronous scan. If this is not the case for you, please open an issue in this repository.

### My push was made but my CI / CD didn't trigger or execute?

Please take care to distinguish between the `detect-secrets-suite` service and other CI/CD.
e.g.:

- your org / repo's CI/CD
- CI/CD secret checking
- GitHub Apps
- pre-commit hooks you have installed locally

For your own CI/CD issues please refer to your GitHub Organization owner.

### What token types do you scan?

Please view [this page](./developer-tool-faq.md#what-kind-of-tokens-does-detect-secrets-find) for details.

### What file content do you scan?

detect-secrets-suite server runs delta (diff) scan for each commit included in the git push. If many commits included, it will scan up to 250 commits per branch. For example, if your push only contains 4 commits, then all these 4 would be scanned. In another example, if you make a new branch of master which includes thousands of existing commits, then pushed the new branch, then 250 recent commits within that new branch would be scanned.

If your repo hasn't been pushed for long time, detect-secrets-suite server won't be able to catch old tokens in it.

### What's delta (diff) scan? are there any other scan types?

There are 3 different types of scans:

- Delta (diff) scan: scan the delta piece of any file modified or added by a commit. Suppose you have a file containing 1000 lines and your edits one line in it, it will only scan several lines surrounding the modified line. This is the behavior for detect-secrets-suite pre-receive scan.
- Shallow scan: scan all (non-binary) files at current commit. This is the default behavior for detect-secrets-suite developer tool.
- Deep scan: scan all (non-binary) files at all commit history. This can be done using script [here(not actively maintained)](https://github.ibm.com/xianjun/deep-scan).

TODO: do we want to include this ^ script?
