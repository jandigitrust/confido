"""Check caller policy selection, permission modes, and browser cleanup offline."""

import json
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from browser_extension import installed_page
from browser_live_checks import DATA_HOSTS, check_result, load_cases, prepare_extension, resolver_rules, run_checks
from browser_live_checks import main as browser_main


class LiveBrowserChecksTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text('{"schema_version": 2}')
        self.path = self.root / "cases.json"
        self.record = {
            "name": "stage-match", "origin": "https://evidence.example.test",
            "policy": "policy.json", "expected_status": "verified",
            "expected_reason": "reference_match",
        }
        self.source = self.root / "extension"
        self.source.mkdir()
        self.manifest = {
            "host_permissions": ["https://required.example.test/*"],
            "optional_host_permissions": [self.record["origin"] + "/*", *DATA_HOSTS, "https://unused.example.test/*"],
        }
        (self.source / "manifest.json").write_text(json.dumps(self.manifest))

    def cases(self):
        self.path.write_text(json.dumps([self.record]))
        return load_cases(self.path)

    def test_resolves_policy_against_case_file_and_snapshots_bytes(self):
        cases = self.cases()
        self.policy.write_text("changed after case loading")
        self.assertEqual(cases[0].policy_path, self.policy.resolve())
        self.assertEqual(cases[0].policy_bytes, b'{"schema_version": 2}')

    def test_invalid_case_fails_before_browser_startup(self):
        for field, value in (
            ("origin", "https://evidence.example.test/path"),
            ("origin", "https://user:secret@evidence.example.test"),
            ("origin", "https://evidence.example.test:99999"),
            ("origin", "https://evidence.example.test:443"),
            ("origin", "https://*.example.test"),
            ("origin", "\nhttps://evidence.example.test"),
            ("expected_status", "success"),
            ("expected_reason", None),
            ("name", "unsafe\nlabel"),
        ):
            original = dict(self.record)
            self.record[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.cases()
            self.record = original

    def test_duplicate_cases_and_oversized_policy_are_rejected(self):
        self.path.write_text(json.dumps([self.record, self.record]))
        with self.assertRaisesRegex(ValueError, "unique"):
            load_cases(self.path)
        self.policy.write_bytes(b" " * (64 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            self.cases()

    def test_cli_failure_has_nonzero_exit_without_echoing_input_contents(self):
        self.path.write_text('{"private-diagnostic-sentinel":')
        process = subprocess.run([
            sys.executable, str(Path(__file__).resolve().parents[1] / "scripts/browser_live_checks.py"),
            "--cases", str(self.path), "--extension-dir", str(self.source),
        ], capture_output=True, text=True)
        self.assertEqual(process.returncode, 1)
        self.assertIn("JSONDecodeError", process.stderr)
        self.assertNotIn("private-diagnostic-sentinel", process.stdout + process.stderr)
        self.assertNotIn("Traceback", process.stderr)

    def test_default_package_keeps_permissions_and_pregrant_is_explicit(self):
        original = (self.source / "manifest.json").read_bytes()
        for pregrant in (False, True):
            target = self.root / str(pregrant)
            prepare_extension(self.source, target, self.cases(), pregrant_hosts=pregrant)
            copied = json.loads((target / "manifest.json").read_text())
            expected = list(self.manifest["host_permissions"])
            if pregrant:
                expected += [self.record["origin"] + "/*", *DATA_HOSTS]
            self.assertEqual(copied["host_permissions"], expected)
            self.assertEqual(copied["optional_host_permissions"], self.manifest["optional_host_permissions"])
        self.assertEqual((self.source / "manifest.json").read_bytes(), original)

    def test_unconfigured_origin_is_rejected_without_copying_package(self):
        self.record["origin"] = "https://other.example.test"
        target = self.root / "copy"
        with self.assertRaisesRegex(ValueError, "optional host"):
            prepare_extension(self.source, target, self.cases(), pregrant_hosts=True)
        self.assertFalse(target.exists())

    def test_missing_data_host_is_rejected_before_copying(self):
        self.manifest["optional_host_permissions"].remove(DATA_HOSTS[0])
        (self.source / "manifest.json").write_text(json.dumps(self.manifest))
        target = self.root / "missing-host"
        with self.assertRaisesRegex(ValueError, "required collection host"):
            prepare_extension(self.source, target, self.cases(), pregrant_hosts=True)
        self.assertFalse(target.exists())

    def test_explicit_resolution_is_scoped_to_unique_case_hosts(self):
        cases = self.cases()
        self.assertIsNone(resolver_rules([], cases))
        for address, expected in (("127.0.0.1", "127.0.0.1"), ("::1", "[::1]")):
            self.assertEqual(resolver_rules([f"evidence.example.test={address}"], cases),
                             f"MAP evidence.example.test {expected}")
        for values in (
            ["evidence.example.test"], ["evidence.example.test=not-an-ip"],
            ["evidence.example.test=fe80::1%eth0"],
            ["*.example.test=127.0.0.1"], ["api.github.com=127.0.0.1"],
            ["evidence.example.test=127.0.0.1", "EVIDENCE.EXAMPLE.TEST=::1"],
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                resolver_rules(values, cases)
        self.record["origin"] = "https://api.github.com"
        with self.assertRaisesRegex(ValueError, "cannot override"):
            resolver_rules(["api.github.com=127.0.0.1"], self.cases())

    def test_evidence_result_must_not_claim_application_admission(self):
        case = self.cases()[0]
        good = {"status": "verified", "scope": "evidence_only", "reason": "reference_match"}
        check_result(case, good)
        for change in (
            {"status": "policy_mismatch"}, {"reason": "different"},
            {"scope": "application"}, {"application_admitted": False},
        ):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                check_result(case, dict(good, **change))

    def test_invalid_resolution_never_starts_browser(self):
        self.cases()
        args = ["browser_live_checks.py", "--cases", str(self.path),
                "--extension-dir", str(self.source), "--resolve", "other.example.test=127.0.0.1"]
        with (
            patch.object(sys, "argv", args),
            patch("browser_live_checks.run_checks") as run,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(browser_main(), 1)
        run.assert_not_called()

    def test_failed_extension_startup_closes_owned_browser_context(self):
        playwright = Mock()
        context = playwright.chromium.launch_persistent_context.return_value
        context.service_workers = []
        context.wait_for_event.side_effect = RuntimeError("worker failed")
        with self.assertRaisesRegex(RuntimeError, "worker failed"):
            installed_page(playwright, self.source, self.root / "profile")
        context.close.assert_called_once_with()

    def test_live_runner_uploads_snapshot_and_closes_context_on_all_outcomes(self):
        case = self.cases()[0]
        for disabled, status in ((False, "verified"), (False, "policy_mismatch"), (True, None)):
            with self.subTest(disabled=disabled, status=status):
                context, page = Mock(), Mock()
                page.locator.return_value.is_disabled.return_value = disabled
                page.locator.return_value.inner_text.return_value = json.dumps({
                    "scope": "evidence_only", "status": status, "reason": "reference_match",
                })
                with (
                    patch.dict(sys.modules, {"playwright.sync_api": MagicMock()}),
                    patch("browser_live_checks.installed_page", return_value=(context, page)) as opened,
                    redirect_stdout(io.StringIO()),
                ):
                    rules = "MAP evidence.example.test 127.0.0.1"
                    if disabled or status != "verified":
                        with self.assertRaises(AssertionError):
                            run_checks(self.source, [case], pregrant_hosts=True, host_resolver_rules=rules)
                    else:
                        run_checks(self.source, [case], pregrant_hosts=True, host_resolver_rules=rules)
                self.assertEqual(opened.call_args.kwargs["host_resolver_rules"], rules)
                context.close.assert_called_once_with()
                page.locator.return_value.set_input_files.assert_called_once_with({
                    "name": "policy.json", "mimeType": "application/json",
                    "buffer": case.policy_bytes,
                })
                page.locator.return_value.select_option.assert_called_once_with(case.origin)
                if disabled:
                    page.locator.return_value.inner_text.assert_not_called()

    def test_headed_startup_preserves_caller_ownership_of_context(self):
        playwright = Mock()
        context = playwright.chromium.launch_persistent_context.return_value
        context.service_workers = [Mock(url="chrome-extension://test-id/background.js")]
        actual_context, page = installed_page(
            playwright, self.source, self.root / "profile", headless=False,
            host_resolver_rules="MAP evidence.example.test 127.0.0.1",
        )
        self.assertIs(actual_context, context)
        self.assertFalse(playwright.chromium.launch_persistent_context.call_args.kwargs["headless"])
        args = playwright.chromium.launch_persistent_context.call_args.kwargs["args"]
        self.assertIn("--host-resolver-rules=MAP evidence.example.test 127.0.0.1", args)
        self.assertFalse(any("ignore-certificate-errors" in arg for arg in args))
        page.goto.assert_called_once_with("chrome-extension://test-id/index.html")
        context.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
