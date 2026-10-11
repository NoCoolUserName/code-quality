# Shared code quality

Small, deterministic GitHub Actions checks for repositories owned by NoCoolUserName.
No Codex, Copilot, model calls, API keys, subscriptions or third-party Actions.

## Checks

- Gitleaks 8.24.3 scans the tracked snapshot, with its standard rules and fully redacted output. Its download has a fixed SHA-256 checksum; a fake-key self-test must pass before every scan. This is not a full Git history scan or a guarantee that every secret format is detected. Binary/archive contents and Git LFS payloads are not comprehensive coverage. Revoke real exposed credentials even after deleting them.
- Ruff 0.17.0 checks Python syntax, invalid comparisons/control flow and undefined names. This is a small correctness baseline, not a formatting or type-checking policy. Repositories with comprehensive existing lint can disable this duplicate step.
- Explicit offline Python tests and locked Node package scripts run when configured. Existing repository tests are preserved. Missing checks are visibly skipped in the run summary; configured commands that fail remain failures.

The job uses Ubuntu 24.04, a ten-minute timeout and only `contents: read`. Checkout does not retain Git credentials. No caller secrets are inherited, no privileged PR trigger is used, and nothing creates or approves PRs. No source or secret reports are uploaded. Dependencies and tests execute repository code on a disposable GitHub-hosted runner with the same limited token scope; review external contributions before approving them.

## Caller

Use `.github/workflows/code-quality.yml` with `pull_request`, default-branch `push`, and `workflow_dispatch` triggers. Pin the shared workflow to a verified full 40-character commit SHA. Add per-workflow concurrency with cancellation of superseded runs. Omit Python install/test commands when an existing workflow already covers them.

Do not add `secrets: inherit`. Never use `pull_request_target` for these checks.

## Failures

Open a repository's **Actions → Code quality → run → Lint, tests and secrets**, then the red step. The same result appears in a pull request's Checks tab and beside commits. The summary explains what ran or was skipped. Existing test/deploy jobs retain their separate results. Checks report failures without changing branch protection.

## Cost and maintenance

One short Linux job per relevant push/PR, no schedule, no new caches and no artifacts. These checks make no model calls; ordinary GitHub Actions usage applies, including the account's limits for private repositories. Avoid duplicate push and PR runs by pushing only the default branch trigger plus PR events. Existing workflows can still run their own matrices and uploads.

Pinned commits do not follow central updates automatically. When updating, verify upstream action SHAs and scanner checksums, test the shared workflow on a pilot first, and then update caller SHAs. Centralize tool updates here instead of adding recurring update bots. Preserve existing tests and deployment behavior; review any permissions exception separately.
