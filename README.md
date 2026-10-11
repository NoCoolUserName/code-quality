# Shared code quality

Small, deterministic GitHub Actions checks for repositories owned by NoCoolUserName.
No Codex, GitHub Copilot, model calls, API keys, subscriptions or third-party Actions.

## Checks

- Gitleaks 8.24.3 scans the tracked snapshot, with its standard rules and fully redacted output. Its download has a fixed SHA-256 checksum; a fake-key self-test must pass before every scan. This is not a full Git history scan or a guarantee that every secret format is detected. Binary/archive contents and Git LFS payloads are not comprehensive coverage. Revoke real exposed credentials even after deleting them.
- Ruff 0.17.0 checks Python syntax, invalid comparisons/control flow, undefined names, mutable defaults, dangerous exception/finally patterns and other selected bug risks. Navimow opts into its broader established Ruff configuration. Repositories with comprehensive existing lint can disable duplicate lint.
- Optional mypy 2.4.0 checks selected typed modules after preflight validation. This is incremental coverage, not a claim that an entire repository is strictly typed. Type stubs are explicitly pinned when needed.
- Explicit offline Python tests and locked Node package scripts run when configured. Existing repository tests are preserved. Missing checks are visibly skipped in the run summary; configured commands that fail remain failures.

The job uses Ubuntu 24.04, a ten-minute timeout and only `contents: read`. Checkout does not retain Git credentials. No caller secrets are inherited, no privileged PR trigger is used, and nothing creates or approves PRs. No source or secret reports are uploaded. Dependencies and tests execute repository code on a disposable GitHub-hosted runner with the same limited token scope; review external contributions before approving them.

## Caller

Use `.github/workflows/code-quality.yml` with `pull_request`, default-branch `push`, and `workflow_dispatch` triggers. Pin the shared workflow to a verified full 40-character commit SHA. Add per-workflow concurrency with cancellation of superseded runs. Omit Python install/test commands when an existing workflow already covers them.

Do not add `secrets: inherit`. Never use `pull_request_target` for these checks.

For repositories containing large evidence or email archives, `checkout-paths` can limit checkout to code, configuration and documentation directories. Files outside those sparse paths are not scanned; the log reports the count. This keeps archival data out of routine code-quality jobs. The default is a complete tracked snapshot.

`use-secret-config: true` explicitly enables the caller's audited `.github/gitleaks.toml`. Extend default rules and restrict each exception to both its specific file and an exact verified public/synthetic value. Do not exclude whole test directories or accept arbitrary replacement keys. Every configuration still has to detect the fake-key self-test. Review changes to callers and scanner configuration before approving an external contribution.

## Failures

Open a repository's **Actions → Code quality → run → Lint, tests and secrets**, then the red step. The same result appears in a pull request's Checks tab and beside commits. The summary explains what ran or was skipped. Existing test/deploy jobs retain their separate results. Checks report failures without changing branch protection.

## Cost and maintenance

One short Linux job per relevant push/PR, no schedule, no new caches and no artifacts. These checks make no model calls; ordinary GitHub Actions usage applies, including the account's limits for private repositories. Avoid duplicate push and PR runs by pushing only the default branch trigger plus PR events. Existing workflows can still run their own matrices and uploads.

Dependabot is configured separately in `.github/dependabot.yml`. It checks GitHub Actions and applicable package manifests monthly, groups proposals, and allows one open version-update PR per ecosystem. Workbench's core package is maintained by its dedicated compatibility-tested updater to avoid two bots editing the same core dependency files. Dependabot does not need quality jobs to have write permissions, and no bot auto-merges these proposals.

Shared workflow versions are published with versioned tags after a successful volatility-mcp pilot; callers retain full SHA pins and version comments so Dependabot can propose new releases without manually editing every caller. Review the PR and its checks before merging. The initial configuration also causes Dependabot to check for available updates; a clean repository may produce no PR.

Review monthly grouped PRs when GitHub notifies you, and address security alerts promptly. Check the centrally pinned Ruff/mypy versions and Gitleaks release/checksum roughly quarterly, or sooner for a relevant advisory. These tool versions and the scanner checksum are deliberately verified together in the central workflow; Dependabot does not edit the hardcoded tool downloads. Verify updated pins/checksums, run the pilot successfully, then publish a new workflow release so Dependabot can propose caller updates. Missing optional checks are reported as skipped; an explicitly configured command that fails fails the job. Preserve branch protections and review permissions exceptions separately.
