"""Exercise the actual reusable workflow's Node shell with controlled npm results."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/quality.yml"


def node_step():
    content = WORKFLOW.read_text()
    step = content.split("      - name: Run available Node checks\n", 1)[1]
    body = step.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
    return textwrap.dedent(body)


class NodeValidationTests(unittest.TestCase):
    def run_checks(self, *, lock=True, required="typecheck test build", scripts="typecheck test build", package=True, fail=""):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            project.mkdir()
            if package:
                (project / "package.json").write_text('{"scripts":{"typecheck":"x","test":"x","build":"x"}}')
            if lock:
                (project / "package-lock.json").write_text("{}")
            binary = root / "bin"
            binary.mkdir()
            npm = binary / "npm"
            npm.write_text('#!/bin/bash\nset -eu\necho "$*" >> "$CALLS"\nif [[ "${1:-}" == "$FAIL_COMMAND" || "$*" == "$FAIL_COMMAND" ]]; then exit 23; fi\nif [[ "${1:-}" == install ]]; then touch package-lock.json; fi\n')
            npm.chmod(0o755)
            script = root / "checks.sh"
            script.write_text(node_step())
            env = dict(os.environ, PATH=f"{binary}:{os.environ['PATH']}", NODE_DIRECTORY=str(project), NODE_SCRIPTS=scripts,
                       NODE_REQUIRED_SCRIPTS=required, NODE_LOCKFILE_REQUIRED=getattr(self, "lock_required", "true"),
                       GITHUB_STEP_SUMMARY=str(root / "summary"), CALLS=str(root / "calls"), FAIL_COMMAND=fail)
            result = subprocess.run(["bash", str(script)], env=env, text=True, capture_output=True, timeout=20)
            calls = (root / "calls").read_text().splitlines() if (root / "calls").exists() else []
            summary = (root / "summary").read_text() if (root / "summary").exists() else ""
            return result, calls, summary

    def test_default_requires_lock(self):
        result, calls, _ = self.run_checks(lock=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing an unlocked install", result.stdout)
        self.assertEqual(calls, [])

    def test_explicit_opt_in_resolves_lock_then_clean_installs(self):
        self.lock_required = "false"
        result, calls, summary = self.run_checks(lock=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["install --package-lock-only --ignore-scripts --no-audit --no-fund", "ci --no-audit --no-fund", "ls --depth=0", "run typecheck", "run test", "run build"])
        self.assertIn("not reproducible across runs", summary)

    def test_existing_lock_uses_ci_without_resolving(self):
        result, calls, _ = self.run_checks()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["ci --no-audit --no-fund", "ls --depth=0", "run typecheck", "run test", "run build"])

    def test_missing_required_script_fails_before_install(self):
        result, calls, _ = self.run_checks(required="typecheck test build removed")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Required Node script is missing: removed", result.stdout)
        self.assertEqual(calls, [])

    def test_required_scripts_run_even_when_omitted_from_optional_list(self):
        result, calls, summary = self.run_checks(scripts="lint")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-3:], ["run typecheck", "run test", "run build"])
        self.assertIn("Node lint: skipped", summary)

    def test_missing_configured_package_fails(self):
        result, calls, _ = self.run_checks(package=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no package.json", result.stdout)
        self.assertEqual(calls, [])

    def test_invalid_required_script_fails(self):
        result, calls, _ = self.run_checks(required="--if-present")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_invalid_optional_script_fails(self):
        result, _, _ = self.run_checks(scripts="--if-present")
        self.assertNotEqual(result.returncode, 0)

    def test_resolver_failure_stops_before_ci(self):
        self.lock_required = "false"
        result, calls, summary = self.run_checks(lock=False, fail="install")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("passed", summary)

    def test_failed_install_or_check_never_reports_success(self):
        for failure in ["ci", "ls", "run typecheck", "run test", "run build"]:
            with self.subTest(failure=failure):
                result, calls, summary = self.run_checks(fail=failure)
                self.assertEqual(result.returncode, 23)
                self.assertTrue(calls[-1].startswith(failure))
                if failure.startswith("run "):
                    self.assertNotIn(f"Node {failure[4:]}: passed", summary)
                else:
                    self.assertNotIn("passed", summary)


if __name__ == "__main__":
    unittest.main()
