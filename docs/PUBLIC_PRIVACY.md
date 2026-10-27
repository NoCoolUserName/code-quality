# Public attribution check

These owner-maintained repositories accept new attribution from the account
handle with its GitHub no-reply email, Dependabot's standard bot identity, and
GitHub's web committer. Other author, committer, and co-author identities fail
with values withheld. The scanner does not require Actions secrets or personal
identifiers. Names and emails in attribution fields must match the allowed
pairs; a bot-looking name alone does not grant an exception.

The guard checks tracked text for local home paths and at most 128 new commits,
including author/committer fields, full messages for home paths, and every
`Co-authored-by` line. It does not infer personal names or emails appearing in
ordinary prose. An optional private local aliases file can extend the content
check on your own machine; never upload or commit that file.

Before pushing, run:

```sh
python3 scripts/check_public_privacy.py \
  --owner NoCoolUserName --owner-id "$(gh api users/NoCoolUserName --jq .id)" \
  --base "$(git merge-base origin/main HEAD)"
```

Run after committing the intended files and immediately before publication.
For extra local content checks, append `--aliases-file` with a private file path
outside the repository, containing one name or email per line. CI does not use
that option. The tracked scan reads the current working tree; inspect untracked
files separately. Pull-request ranges use the merge base; main pushes use exact
before/after SHAs. Invalid or unavailable refs, a non-descendant direct push, or
more than 128 commits fail closed. Git history is fetched in full; the metadata
inspection is bounded. Manual dispatch requires a full starting SHA.

The PR workflow uses `pull_request_target` to load the scanner from trusted base
code, with a read-only token and credentials removed after checkout. Proposed
code is data only: never execute its scripts, tests, hooks, or dependencies in
this job. No personal alias list or repository secret is supplied. The first PR
installing the guard is a bootstrap exception: validate it locally, then verify
the new main-push job after merging.

Historical third-party attribution outside the selected new range is untouched.
For a genuine new upstream import, retain the original commit and independently
review its full SHA. The local `--preserve-third-party SHA` option exempts that
exact commit's identity checks while keeping path and optional local alias
checks. CI grants no automatic third-party exemption; accepting such imports
requires an explicit reviewed change to trusted policy. Never relabel another
person's contribution as the owner to satisfy this guard.

Local validation can catch a disclosure before pushing. PR checks run after the
branch is public and can block merging only when required by branch protection.
Main-push checks, including GitHub-generated merge/squash messages, detect after
publication. Review the final merge message before merging. No check removes
existing disclosures or rewrites history. Diagnostics show only field category,
commit prefix, file index, and line number.
