"""Synthetic Git history tests; fixtures never contain a real identity."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "scripts/check_public_privacy.py"
HANDLE = "ExampleHandle"
OWNER_ID = "123456"
ALIAS_NAME = "Avery" + " Example"
ALIAS_EMAIL = "avery" + "@example.invalid"
GOOD_EMAIL = f"{OWNER_ID}+{HANDLE}@users.noreply.github.com"


class PrivacyCheck(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", HANDLE)
        self.git("config", "user.email", GOOD_EMAIL)
        (self.repo / "sample.txt").write_text("safe\n")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.aliases = self.repo / "private-aliases"
        self.aliases.write_text(ALIAS_NAME + "\n" + ALIAS_EMAIL + "\n")

    def git(self, *args, env=None):
        return subprocess.run(["git", *args], cwd=self.repo, text=True,
                              capture_output=True, check=True, env=env)

    def commit(self, subject, body="", author_name=HANDLE, author_email=GOOD_EMAIL,
               committer_name=HANDLE, committer_email=GOOD_EMAIL, merge=False):
        env = dict(os.environ, GIT_AUTHOR_NAME=author_name, GIT_AUTHOR_EMAIL=author_email,
                   GIT_COMMITTER_NAME=committer_name, GIT_COMMITTER_EMAIL=committer_email)
        if merge:
            self.git("branch", "side")
            self.git("commit", "-qm", "main side", "--allow-empty")
            self.git("switch", "-q", "side")
            self.git("commit", "-qm", "other side", "--allow-empty")
            self.git("switch", "-q", "main")
            self.git("merge", "--no-ff", "side", "-m", subject, "-m", body, env=env)
        else:
            self.git("commit", "--allow-empty", "-qm", subject, "-m", body, env=env)

    def check(self, base=None, aliases=True, mode="direct"):
        return subprocess.run(
            [sys.executable, str(SCANNER), "--owner", HANDLE, "--owner-id", OWNER_ID,
             "--base", base or self.base, "--base-mode", mode, "--aliases-file",
             str(self.aliases if aliases else self.repo / "missing")],
            cwd=self.repo, text=True, capture_output=True,
        )

    def test_allowed_owner_forms_and_third_party_attribution(self):
        self.commit("ordinary", "Co-authored-by: Dana Contributor <dana@example.invalid>",
                    committer_name="GitHub", committer_email="noreply@github.com")
        self.commit("legacy noreply", author_email=f"{HANDLE}@users.noreply.github.com")
        self.assertEqual(self.check().returncode, 0)

    def test_private_aliases_in_author_committer_and_coauthor(self):
        for kwargs in (
            {"author_name": ALIAS_NAME, "author_email": ALIAS_EMAIL},
            {"committer_name": ALIAS_NAME, "committer_email": ALIAS_EMAIL},
            {"body": f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>"},
        ):
            with self.subTest(kwargs=kwargs):
                self.commit("synthetic", **kwargs)
                result = self.check()
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(ALIAS_NAME, result.stdout + result.stderr)
                self.assertNotIn(ALIAS_EMAIL, result.stdout + result.stderr)
                self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def test_noncanonical_owner_and_malformed_trailer(self):
        self.commit("bad", "Co-authored-by: ExampleHandle <other@example.invalid>",
                    author_email="other@example.invalid")
        self.assertEqual(self.check().returncode, 1)
        self.commit("bad trailer", "Co-authored-by: ExampleHandle with no email")
        self.assertEqual(self.check(base=self.git("rev-parse", "HEAD^").stdout.strip()).returncode, 1)

    def test_merge_and_squash_messages(self):
        self.commit("Merge branch 'topic'", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>", merge=True)
        self.assertEqual(self.check().returncode, 1)
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.commit("Squash merged change", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>")
        self.assertEqual(self.check().returncode, 1)

    def test_range_only_new_commits_and_bounded_selection(self):
        self.commit("old", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>")
        old = self.git("rev-parse", "HEAD").stdout.strip()
        self.commit("new safe")
        self.assertEqual(self.check(base=old).returncode, 0)
        self.assertEqual(self.check().returncode, 1)
        self.assertEqual(self.check(base="0" * 40).returncode, 2)
        for _ in range(128):
            self.commit("more")
        self.assertEqual(self.check(base=old).returncode, 2)

    def test_pull_request_divergence_uses_merge_base(self):
        self.git("branch", "topic")
        self.commit("base branch moved")
        moved = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("switch", "-q", "topic")
        self.commit("topic change")
        self.assertEqual(self.check(base=moved).returncode, 2)
        self.assertEqual(self.check(base=moved, mode="merge-base").returncode, 0)

    def test_commit_message_home_path_redacted(self):
        self.commit("message", "See /" + "home/FabricatedPerson/private")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("FabricatedPerson", result.stdout + result.stderr)

    def test_proposed_checkout_cannot_replace_trusted_scanner(self):
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/check_public_privacy.py").write_text("raise SystemExit(0)\n")
        self.git("add", "scripts/check_public_privacy.py")
        self.commit("proposed scanner replacement", f"Co-authored-by: {ALIAS_NAME} <{ALIAS_EMAIL}>")
        self.assertEqual(self.check().returncode, 1)

    def test_tracked_paths_and_missing_private_aliases_redacted(self):
        (self.repo / "sample.txt").write_text("/" + "Users/FabricatedPerson/private\n")
        self.git("add", "sample.txt")
        self.commit("tracked")
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("FabricatedPerson", result.stdout + result.stderr)
        self.assertNotIn("sample.txt", result.stdout + result.stderr)
        self.assertEqual(self.check(aliases=False).returncode, 2)


if __name__ == "__main__":
    unittest.main()
