#!/usr/bin/env python3
"""Check tracked content and bounded new Git metadata before publication.

CI needs no private data. Optional local aliases never enter diagnostics.
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys

HOME_PATHS = (
    re.compile(rb"/Users/[A-Za-z0-9._-]+/"),
    re.compile(rb"/home/[A-Za-z0-9._-]+/"),
    re.compile(rb"[A-Za-z]:\\Users\\(?!Public\\|Default\\)[A-Za-z0-9._-]+\\", re.I),
)
TRAILER = re.compile(r"^Co-authored-by:\s*(.*?)\s*<([^<>]+)>\s*$", re.I | re.M)
MAX_COMMITS = 128


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def owner_email(email, login, user_id):
    local, sep, domain = email.casefold().partition("@")
    if not sep or domain != "users.noreply.github.com":
        return False
    return local in (login.casefold(), f"{user_id}+{login}".casefold())


def load_aliases(args):
    if not args.aliases_file:
        return []
    content = pathlib.Path(args.aliases_file).read_text(encoding="utf-8")
    aliases = [line.strip().casefold() for line in content.splitlines() if line.strip()]
    if not aliases or any(len(alias) < 4 or "\x00" in alias for alias in aliases):
        raise ValueError("invalid optional local aliases")
    return aliases


def allowed_identity(name, email, login, user_id, role):
    if name == login and owner_email(email, login, user_id):
        return True
    if name == "dependabot[bot]" and email.casefold() in (
        "49699333+dependabot[bot]@users.noreply.github.com",
        "dependabot[bot]@users.noreply.github.com",
    ):
        return True
    return role == "committer" and name == "GitHub" and email == "noreply@github.com"


def contains_alias(value, aliases):
    folded = value.casefold()
    return any(alias in folded for alias in aliases)


def scan_files(aliases):
    findings = []
    for index, raw in enumerate(git("ls-files", "-z").split(b"\0"), 1):
        if not raw:
            continue
        path = pathlib.Path(os.fsdecode(raw))
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        for line_number, line in enumerate(data.splitlines(), 1):
            if any(p.search(line) for p in HOME_PATHS) or contains_alias(
                line.decode("utf-8", "replace"), aliases
            ):
                findings.append(f"tracked file #{index}, line {line_number}")
    return findings


def commit_range(base, head, mode):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head):
        raise ValueError("head must be a full commit SHA")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", base) or int(base, 16) == 0:
        raise ValueError("base must be a nonzero full commit SHA")
    git("cat-file", "-e", f"{base}^{{commit}}")
    git("cat-file", "-e", f"{head}^{{commit}}")
    if mode == "merge-base":
        base = git("merge-base", base, head).decode().strip()
    else:
        git("merge-base", "--is-ancestor", base, head)
    commits = git("rev-list", "--reverse", f"{base}..{head}").decode().splitlines()
    if len(commits) > MAX_COMMITS:
        raise ValueError("commit range exceeds the 128-commit limit")
    return commits


def metadata(sha):
    # NUL framing keeps fields separate even when a message contains newlines.
    fields = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha).split(b"\0", 4)
    if len(fields) != 5:
        raise ValueError("cannot parse commit metadata")
    return [field.decode("utf-8", "replace") for field in fields]


def scan_metadata(commits, login, user_id, aliases, preserved=()):
    findings = []
    if any(not re.fullmatch(r"[0-9a-f]{40}", sha) or sha not in commits for sha in preserved):
        raise ValueError("third-party approvals must name exact commits in the range")
    for sha in commits:
        author, author_email, committer, committer_email, message = metadata(sha)
        short = sha[:12]
        for role, name, email in (
            ("author", author, author_email),
            ("committer", committer, committer_email),
        ):
            if any(p.search(part.encode("utf-8")) for p in HOME_PATHS for part in (name, email)):
                findings.append(f"{short}: {role} contains a local home path")
            if contains_alias(name, aliases) or contains_alias(email, aliases):
                findings.append(f"{short}: {role} contains a private owner alias")
            if sha not in preserved and not allowed_identity(name, email, login, user_id, role):
                findings.append(f"{short}: unapproved {role} identity")
        if any(p.search(message.encode("utf-8")) for p in HOME_PATHS):
            findings.append(f"{short}: message contains a local home path")
        if contains_alias(message, aliases):
            findings.append(f"{short}: message contains a private owner alias")
        for line in message.splitlines():
            if re.match(r"\s*co-authored-by\s*:", line, re.I):
                match = TRAILER.fullmatch(line.strip())
                if not match:
                    findings.append(f"{short}: malformed co-author trailer")
                elif sha not in preserved and not allowed_identity(
                    *match.groups(), login, user_id, "co-author"
                ):
                    findings.append(f"{short}: unapproved co-author identity")
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--owner-id", required=True, type=int)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--base-mode", choices=("direct", "merge-base"), default="direct")
    parser.add_argument("--aliases-file", help="optional private local file; never required in CI")
    parser.add_argument("--preserve-third-party", action="append", default=[], metavar="SHA",
                        help="retain attribution of an independently reviewed exact commit")
    args = parser.parse_args()
    try:
        aliases = load_aliases(args)
        head = git("rev-parse", "--verify", args.head).decode().strip()
        commits = commit_range(args.base, head, args.base_mode)
        findings = scan_files(aliases) + scan_metadata(commits, args.owner, args.owner_id, aliases, args.preserve_third_party)
    except (OSError, subprocess.CalledProcessError, ValueError):
        print("Privacy check could not complete; verify bounded Git refs and optional local inputs (values withheld).")
        return 2
    if findings:
        print("Privacy check failed (values withheld):")
        print("\n".join(findings))
        return 1
    print(f"Privacy check passed: tracked files and {len(commits)} new commits.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
