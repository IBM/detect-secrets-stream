# Detect Secrets Stream FAQ

This documentation is intended for GitHub Enterprise end users.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [FAQ](#faq)
  - [What is detect-secrets-suite?](#what-is-detect-secrets-suite)
  - [What information do you track for each push?](#what-information-do-you-track-for-each-push)
  - [Do you also scan private repositories?](#do-you-also-scan-private-repositories)
  - [How does `detect-secrets-suite` affect my interactions with Github?](#how-does-detect-secrets-suite-affect-my-interactions-with-github)
  - [What is a pre-receive hook?](#what-is-a-pre-receive-hook)
  - [Will my pushes and PR merges be blocked?](#will-my-pushes-and-pr-merges-be-blocked)
  - [Which of the pre-receive hooks should I use?](#which-of-the-pre-receive-hooks-should-i-use)
  - [As an org / repo owner, can I disable it?](#as-an-org--repo-owner-can-i-disable-it)
  - [Why is my pull request no longer triggering CI after I've enabled the pre-receive hook?](#why-is-my-pull-request-no-longer-triggering-ci-after-ive-enabled-the-pre-receive-hook)
  - [My push has timed out, what should I do?](#my-push-has-timed-out-what-should-i-do)
  - [My push has slowed down, what should I do?](#my-push-has-slowed-down-what-should-i-do)
  - [What token types do you scan?](#what-token-types-do-you-scan)
  - [What file contents do you scan?](#what-file-contents-do-you-scan)
  - [What is a delta (diff) scan? Are there any other scan types?](#what-is-a-delta-diff-scan-are-there-any-other-scan-types)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## FAQ

### What is detect-secrets-suite?

`detect-secrets-suite` is the next generation of the Detect Secrets service. It uses [IBM Cloud](http://cloud.ibm.com)'s streaming and analysis capabilities to find secrets (tokens, keys, etc) in source code.

Under the hood, it uses a non-blocking [pre-receive hook](#what-is-a-pre-receive-hook) to track [push information](#what-information-do-you-track-for-each-push). This queues an asynchronous scan request for potential secrets, for each commit in turn.

### What information do you track for each push?

The collected information includes information about the commit author, what has been committed, and the time of the push to Github. The complete list of tracked information can be found [here](https://help.github.com/en/enterprise/2.16/admin/developer-workflow/creating-a-pre-receive-hook-script#writing-a-pre-receive-hook-script).

### Do you also scan private repositories?

By default, this tool only scans public repositories. For private repositories, a GitHub app will request your permission. Don't worry, nobody will peek into your source code without asking.

Please note, the pre-receive trigger is in place enterprise-wide for _every_ repo. The scanning code checks a repository's privacy status before scanning it. It will not scan a private repository unless the `detect-secrets-suite` GitHub App is in place to give it permission to proceed.

### How does `detect-secrets-suite` affect my interactions with Github?

Each time you run `git push` to a pre-receive hook enabled repository, you will notice some additional text outputted as push metadata is collected. The design of the pre-receive hook is non-blocking. If your push is blocked, refer to [`Will my pushes and PR merges be blocked?`](#will-my-pushes-and-pr-merges-be-blocked) for more details.

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
   <REVOKED>..<REVOKED>  master -> master
```

### What is a pre-receive hook?

Pre-receive hooks are designed to enforce rules before commits are pushed to a repository. They run tests to ensure that commits meet repository or organization policies.

_\*Pre-receive hooks have a time limit. If the processing can't finish within 5 seconds, the push will fail._ It's not currently possible to complete a full scan of a push's entire contents in that time frame, so `detect-secrets-suite` will queue a request for an asynchronous scan.

You can find more information about pre-receive hooks [here](https://help.github.com/en/enterprise/2.16/admin/developer-workflow/about-pre-receive-hooks).

### Will my pushes and PR merges be blocked?

No, the pre-receive script is designed to ensure that it will always finish successfully within 5 seconds, no matter if the push info is sent successfully or not. It's intended not to block users from pushing due to server errors. If you have any experiences to the contrary, please submit an issue.

### Which of the pre-receive hooks should I use?

The `detect-secrets-suite` pre-receive hook is preselected at the Enterprise level. Any additional hooks you select will be run consecutively.

### As an org / repo owner, can I disable it?

`detect-secrets-suite` is designed to be non-disruptive and cannot be disabled individually.

### Why is my pull request no longer triggering CI after I've enabled the pre-receive hook?

After the pre-receive hook has been enabled for a repository, there is [one additional value: `has_hooks` in the `mergeable_state` field](https://developer.github.com/v4/enum/mergestatestatus/).

Testing has been performed across the most common CI systems and patches have been applied for error conditions that have been discovered. However, if a CI system does not recognize this value, it may result in unexpected behaviors such as the build not triggering.

Both Travis CI and Jenkins have been tested. Additionaly, it's been verified that popular plugins such as Github Organizations and Multi-branches have not been affected.

If your CI system behaves strangely after you've enabled the pre-receive hook, check with your CI vendor to validate if the new value in the `mergeable_state` field is the culprit. In any case, please open a GitHub issue.

### My push has timed out, what should I do?

If you're seeing a message such as:

```shell
remote: Push info collect pre-receive hook failed to finish within 3 seconds with error code 124
remote: push_info.sh: execution exceeded 5s timeout
To <REDACTED>/secret-corpus-db !
[remote rejected] gen-db-tool -> gen-db-tool (pre-receive hook declined)
```

Although the pre-receive hook should not fail by design, there have been rare instances where it does. If so, the development team will be aware that it has timed out; There is no need to report this.

Please re-attempt the push unaltered. If it continues to fail, please open a GitHub issue.

### My push has slowed down, what should I do?

There should be minimal delay to your push introduced by triggering the `detect-secrets` asynchronous scan. If this is not the case for you, please open a GitHub issue.
### What token types do you scan?

Please see [this](https://github.com/IBM/detect-secrets/blob/master/docs/developer-tool-faq.md) page for details.

### What file contents do you scan?

`detect-secrets-suite` server runs a delta (diff) scan for each commit included in the git push.

### What is a delta (diff) scan? Are there any other scan types?

The different types of scans are:

- Delta (diff) scan: scans the delta piece of any file modified or added by a commit. Suppose you have a file containing 1000 lines and you edit one line, only several lines surrounding the modified line will be scanned. This is the behavior for the `detect-secrets-suite` pre-receive scan.
- Shallow scan: scans all (non-binary) files at the current commit. This is the default behavior for the `detect-secrets-suite` [developer](https://github.com/IBM/detect-secrets) tool.
