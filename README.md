# Shared code quality

Small, deterministic GitHub Actions checks shared across repositories.
The checks run without AI services, model API keys, or subscriptions and use no third-party Actions.

## Checks

- Gitleaks 8.24.3 scans the tracked snapshot, with its standard rules and fully redacted output. Its download has a fixed SHA-256 checksum; a fake-key self-test must pass before every scan. This is not a full Git history scan or a guarantee that every secret format is detected. Binary/archive contents and Git LFS payloads are not comprehensive coverage. Revoke real exposed credentials even after deleting them.
- Ruff 0.17.0 checks Python syntax, invalid comparisons/control flow, undefined names, mutable defaults, dangerous exception/finally patterns and other selected bug risks. Navimow opts into its broader established Ruff configuration. Repositories with comprehensive existing lint can disable duplicate lint.
- Optional mypy 2.4.0 checks selected typed modules after preflight validation. Type checking covers the selected modules only. Type stubs are explicitly pinned when needed.
- Explicit offline Python tests and Node package scripts run when configured. Existing repository tests are preserved. Missing optional checks are visibly skipped in the run summary; required scripts and configured commands that fail remain failures.

The job uses Ubuntu 24.04, a ten-minute timeout and only `contents: read`. Checkout does not retain Git credentials. No caller secrets are inherited, no privileged PR trigger is used, and the quality job never creates or approves PRs. No source or secret reports are uploaded. Dependencies and tests execute repository code on a disposable GitHub-hosted runner with the same limited token scope; review external contributions before approving them.

## Caller

Use `.github/workflows/code-quality.yml` with `pull_request`, default-branch `push`, and `workflow_dispatch` triggers. Pin the shared workflow to a verified full 40-character commit SHA. Add per-workflow concurrency with cancellation of superseded runs. Omit Python install/test commands when an existing workflow already covers them.

Do not add `secrets: inherit`. Never use `pull_request_target` for these checks.

### Required frontend validation

Set `node-directory` to the frontend directory and include `typecheck test build` in both `node-scripts` and `node-required-scripts`. Required scripts must exist and execute successfully; a missing package or script fails the job. Optional scripts retain their existing skip behavior. Scripts listed twice run once.

The default `node-lockfile-required: true` still requires `package-lock.json` and uses `npm ci`. A repository whose explicit policy prohibits committed lockfiles may set `node-lockfile-required: false`: the runner resolves a temporary lock with `npm install --package-lock-only --ignore-scripts`, then performs `npm ci`. This fixes versions within that run only; later runs can resolve different versions allowed by the manifest. `npm ls --depth=0` records the resolved direct versions and rejects invalid installations. Nothing commits or uploads the temporary lock.

The Node validation contract workflow exercises the actual Node shell for missing required scripts/packages, default lock enforcement, explicit temporary-lock resolution, required-script execution, duplicate scripts, and installation/test failures. It uses controlled npm results; consumers must also pass their real installs, tests, type checks and builds before merge.

For repositories containing large evidence or email archives, `checkout-paths` can limit checkout to code, configuration and documentation directories. Files outside those sparse paths are not scanned; the log reports the count. This keeps archival data out of routine code-quality jobs. The default is a complete tracked snapshot.

`use-secret-config: true` explicitly enables the caller's audited `.github/gitleaks.toml`. Extend default rules and restrict each exception to both its specific file and an exact verified public/synthetic value. Do not exclude whole test directories or accept arbitrary replacement keys. Every configuration still has to detect the fake-key self-test. Review changes to callers and scanner configuration before approving an external contribution.

## Failures

Open a repository's **Actions → Code quality → run → Lint, tests and secrets**, then the red step. The same result appears in a pull request's Checks tab and beside commits. The summary explains what ran or was skipped. Existing test/deploy jobs retain their separate results. Checks report failures without changing branch protection.

## Cost and maintenance

One short Linux job per relevant push/PR, no schedule, no new caches and no artifacts. These checks make no model calls; ordinary GitHub Actions usage applies, including the account's limits for private repositories. Avoid duplicate push and PR runs by pushing only the default branch trigger plus PR events. Existing workflows can still run their own matrices and uploads.

Dependabot is configured separately in `.github/dependabot.yml`. It checks GitHub Actions and applicable package manifests monthly, groups proposals, and allows one open version-update PR per ecosystem. Workbench's core package is maintained by its dedicated compatibility-tested updater to avoid two bots editing the same core dependency files. Dependabot does not need quality jobs to have write permissions, and the separate opt-in guarded controller can merge eligible proposals.

Shared workflow versions are published with versioned tags after a successful volatility-mcp pilot; callers retain full SHA pins and version comments so Dependabot can propose new releases without manually editing every caller. Review the PR and its checks before merging. The initial configuration also causes Dependabot to check for available updates; a clean repository may produce no PR.

Ineligible updates remain blocked for agent-assisted maintenance; address security alerts promptly. Check the centrally pinned Ruff/mypy versions and Gitleaks release/checksum roughly quarterly, or sooner for a relevant advisory. These tool versions and the scanner checksum are deliberately verified together in the central workflow; Dependabot does not edit the hardcoded tool downloads. Verify updated pins/checksums, run the pilot successfully, then publish a new workflow release so Dependabot can propose caller updates. Missing optional checks are reported as skipped; an explicitly configured command that fails fails the job. Preserve branch protections and review permissions exceptions separately.

## Guarded dependency automation (opt-in extension)

`dependency-merge.yml` adds a separate privileged control job; `quality.yml` is
unchanged. Trigger it through `workflow_run: completed` for every relevant check
workflow. Pin both the reusable workflow and `framework-ref` to the same verified
commit. The controller checks out **only the pinned public framework**, never a PR
branch, artifact, dependency or script. It uses only Python's standard library and
GitHub API data. No AI calls, approvals, deployments or migrations occur.

A caller's `.github/dependency-policy.json` is read from the PR's immutable base.
The dependency gate requires the actual Dependabot account ID, a same-repository
PR, only bot-authored commits, exact dependency-file allowlists, approved semantic
version changes, successful required workflow runs and exact GitHub Actions check
names on the current head, no other failing/pending checks, and native strict
required-check rules. GitHub must report a clean/up-to-date merge and the merge API
receives the expected head SHA. No admin bypass, force update or failed-check
exception exists. Unknown state, pagination limits, missing evidence and API
permission errors block merging. This controller never approves PRs.

The initial validated file formats are npm v3 lockfiles with existing package
membership, dependency-only package.json updates, and exact-pinned requirements
files. Stable patch upgrades are eligible. A repository may opt into **minor dev
updates** only after meaningful compatibility tests; production minors, majors,
prereleases, downgrades, added/removed dependencies, lifecycle-script edits,
workflow/policy changes and unsupported lock formats are blocked. uv/pyproject
updates continue to get proposals and checks but are not auto-merged by this
initial conservative parser. No repository with missing behavioral coverage should
set `enabled: true`. Group patch updates separately so one ineligible update does not block eligible
patch proposals.

`configure_ruleset.py REPOSITORY` previews an additive native ruleset from the
repository policy. `--apply` needs a separately authorized administrator session.
It requires the configured GitHub Actions checks, up-to-date branches, a PR and
resolved conversations; approving-review count is zero and bypass actors are empty.
It prevents force pushes and deletion without replacing unrelated protections.
Do not put administrator credentials in Actions. Private-repository rulesets may
require an appropriate GitHub plan. The controller stays blocked until protection
is actually enforced, even if its caller has `merge: true`.

## Security analysis

`codeql.yml` uses CodeQL's default queries for eligible public code repositories;
`security.yml` uses local Semgrep rules for private repositories. Do not run both on the same code.
CodeQL's high/critical security results fail the check in addition to uploading
results to GitHub. The pinned Semgrep engine uses six reviewed Python/JS/TS rules
covering shell execution, unsafe YAML, disabled TLS verification, dynamic JavaScript
execution and URL-to-HTML injection. It uses no hosted rule service, credentials,
telemetry, source uploads or paid features. These six rules provide
limited SAST coverage and complement behavioral and negative tests. Scanner
failure is a failed check. Existing tests, protocol contracts, frozen synthetic
evaluations and integration checks remain authoritative.

## Passive web scanning decision

Do not enable broad ZAP scans across repositories. A Baseline spider sends requests
and can follow links even though its vulnerability analysis is passive. Before
opting in, supply an isolated temporary local target with synthetic state, no
credentials, external egress denied, a strict local URL allowlist, pinned scanner
image digest, bounded crawl and cleanup. Do not point it at production, external
URLs, evidence services, live model APIs or device-control services. Pure CLI/MCP
repositories are ineligible; browser regression tests generally offer more value
for static local learning/portfolio applications. No ZAP scan is scheduled by this
extension until a repository-specific isolated-target pilot passes.

## Resource limits and recovery

Keep validation on PRs and default-branch pushes, with superseded-run cancellation.
Keep project-specific matrices where they validate supported Python/protocol
contracts. The merge controller has a five-minute limit, Semgrep eight minutes,
CodeQL fifteen minutes, and the original quality job ten minutes. No new caches,
source artifacts, nightly scan schedules or recurring AI services are required.
GitHub billing-budget alerts require account administration and must be configured
separately from per-job timeouts.

The extension builds on validated main revision `927052f6ef9ce21c1fec280dcc87affdee1ae87a`.
The extension retains the required Node validation inputs and contract tests from
PR #3; the central native-check policy includes those contract tests.
Disable a caller's `merge` input or set policy `enabled: false` to stop automatic
merges immediately. Revert individual dependency commits through a tested PR;
never erase history or relax checks. Caller pin changes and framework policy
updates are intentionally excluded from unattended dependency merging.

## License

Original project code and documentation are licensed under the [MIT License](LICENSE).
Third-party tools executed by these workflows retain their own licenses; this
license does not relicense their binaries, rules, or source code.
