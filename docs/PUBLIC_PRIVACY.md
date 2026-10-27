# Public attribution check

The Public path privacy workflow checks tracked text files and at most 128 new
commits. It checks author and committer fields, complete commit messages,
`Co-authored-by` trailers, and local home paths. Owner attribution must be the
repository handle with either `HANDLE@users.noreply.github.com` or
`ACCOUNT_ID+HANDLE@users.noreply.github.com`. The GitHub web committer and
unrelated contributors retain their own identities.

Add the repository Actions secret `PUBLIC_PRIVACY_OWNER_ALIASES` in **each**
repository. Put one private owner name or email per line, including any identity
that has appeared in prior author, committer, or co-author fields. Never commit
this list. The check fails closed if the secret is absent.

Pull requests run through `pull_request_target`: the workflow and executed
scanner are loaded from the trusted base branch. The proposed checkout is only
read as data. Never run scripts, tests, hooks, dependencies, or build commands
from that checkout in this job. Its token has read-only contents permission,
checkout credentials are not persisted, and no secret is passed to checkout.
The first PR that installs this workflow is a bootstrap exception: the trusted
base still has the old tracked-file guard. Validate that PR locally before
publication and inspect its final merge message. Once merged, new PRs use the
trusted scanner. Keep a PR status required in branch protection if merge
blocking is desired.

Before publishing a branch, create a private aliases file outside the checkout
with the same one-per-line format, then run:

```sh
python3 scripts/check_public_privacy.py \
  --owner NoCoolUserName --owner-id "$(gh api users/NoCoolUserName --jq .id)" \
  --base "$(git merge-base origin/main HEAD)" --base-mode direct \
  --aliases-file "$HOME/.config/public-privacy-owner-aliases"
```

Run this again immediately before each push or install it as a local pre-push
hook. The command reads only the current tracked working tree and commits in the
range; stage your intended file changes first and inspect untracked files too.
For a local branch with a diverged target base, use `--base-mode merge-base` and
pass the target's full SHA. For a direct main push, pass the previous full SHA
and use `--base-mode direct`. The trusted PR workflow uses the target merge base;
the main push job uses GitHub's before/after SHAs. Manual dispatch
requires a full starting SHA. An unavailable ref, a non-descendant direct push,
an empty secret, or more than 128 commits fails closed. Diagnostic output shows
only field type, commit prefix, file index, and line number.

The local command can prevent publication when run before pushing. A PR check
starts after its branch is already visible; it can block a merge if configured
as a required check, but cannot undo that exposure. A main push check likewise
reports after publication. GitHub-generated squash/merge commit messages are
inspected only after creation by the main push check; review the proposed merge
message before clicking Merge. These checks do not erase previously published
commits or tags. Configure branch protection or a ruleset to require the PR
status if merge blocking is desired.
