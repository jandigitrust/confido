"""Exercise the publication gate against real Git history, without uploads."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from release_gate import release_decision


def release_needed(*args):
    return release_decision(*args)[1]


class ReleaseGateTests(unittest.TestCase):
    def test_moved_package_keeps_its_own_release_history(self):
        legacy = self.root / "bindings/client-python"
        legacy.mkdir(parents=True)
        (legacy / "pyproject.toml").write_text(
            '[project]\nname = "confido-client"\nversion = "0.2.0"\n'
        )
        (self.root / "bindings/python/pyproject.toml").write_text(
            '[project]\nname = "confido-verifier"\nversion = "0.2.0"\n'
        )
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Before layout change")
        before = self.git("rev-parse", "HEAD").strip()
        self.write_version("0.2.0")
        self.assertFalse(release_needed(self.root, "push", "refs/heads/main", before))
        self.write_version("0.3.0")
        self.assertTrue(release_needed(self.root, "push", "refs/heads/main", before))

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "bindings/python").mkdir(parents=True)
        self.write_version("0.2.0")
        self.git("init", "--quiet")
        self.git("config", "user.name", "CI Fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Initial version")
        self.before = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def write_version(self, version):
        for name, section in (("pyproject.toml", "project"), ("Cargo.toml", "package")):
            (self.root / "bindings/python" / name).write_text(
                f'[{section}]\nname = "confido-client"\nversion = "{version}"\n'
            )

    def test_main_version_change_is_required(self):
        self.assertFalse(release_needed(self.root, "push", "refs/heads/main", self.before))
        self.write_version("0.3.0")
        self.assertTrue(release_needed(self.root, "push", "refs/heads/main", self.before))

    def test_pr_tag_manual_and_other_branch_never_publish(self):
        self.write_version("0.3.0")
        for event, ref in (
            ("pull_request", "refs/pull/1/merge"),
            ("pull_request", "refs/heads/main"),
            ("push", "refs/heads/feature"),
            ("push", "refs/tags/pypi-v0.3.0"),
            ("workflow_dispatch", "refs/heads/main"),
        ):
            with self.subTest(event=event, ref=ref):
                self.assertFalse(release_needed(self.root, event, ref, ""))

    def test_missing_history_and_mismatched_versions_fail_closed(self):
        for before in ("", "0" * 40, "invalid"):
            with self.subTest(before=before), self.assertRaises(ValueError):
                release_needed(self.root, "push", "refs/heads/main", before)
        (self.root / "bindings/python/Cargo.toml").write_text('[package]\nversion = "0.4.0"\n')
        with self.assertRaisesRegex(ValueError, "versions"):
            release_needed(self.root, "pull_request", "refs/pull/1/merge", "")

    def test_cli_writes_decision_only_after_validation(self):
        script = Path(__file__).resolve().parents[1] / "scripts/release_gate.py"
        event = self.root / "event.json"
        event.write_text(json.dumps({"before": self.before}))
        output = self.root / "output.txt"
        self.write_version("0.3.0")
        env = dict(os.environ, GITHUB_EVENT_NAME="push", GITHUB_REF="refs/heads/main",
                   GITHUB_EVENT_PATH=str(event), GITHUB_OUTPUT=str(output))
        subprocess.run([sys.executable, str(script)], cwd=self.root, env=env,
                       check=True, capture_output=True)
        self.assertEqual(output.read_text(), "publish=true\nversion=0.3.0\n")
        output.unlink()
        event.write_text('{}')
        process = subprocess.run([sys.executable, str(script)], cwd=self.root, env=env,
                                 capture_output=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse(output.exists())

    def test_unavailable_previous_revision_cannot_select_publication(self):
        self.write_version("0.3.0")
        with self.assertRaises(subprocess.CalledProcessError):
            release_decision(self.root, "push", "refs/heads/main", "f" * 40)

    def test_cli_uses_its_own_version_history(self):
        (self.root / "cli").mkdir()
        manifest = self.root / "cli/Cargo.toml"
        manifest.write_text('[package]\nname = "confido-cli"\nversion = "0.2.0"\n')
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "CLI version")
        before = self.git("rev-parse", "HEAD").strip()
        self.assertEqual(release_decision(self.root, "push", "refs/heads/main", before, "cli"),
                         ("0.2.0", False))
        manifest.write_text('[package]\nname = "confido-cli"\nversion = "0.3.0"\n')
        self.assertEqual(release_decision(self.root, "push", "refs/heads/main", before, "cli"),
                         ("0.3.0", True))
        self.assertEqual(release_decision(self.root, "push", "refs/tags/v0.3.0", "", "cli"),
                         ("0.3.0", False))

        self.git("tag", "v0.3.0")
        with self.assertRaisesRegex(ValueError, "tag already exists"):
            release_decision(self.root, "push", "refs/heads/main", before, "cli")
