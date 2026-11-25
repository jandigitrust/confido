"""Keep browser-compatible version fields distinct from the displayed SDK prerelease."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from extension.build import write_browser_manifest


class ExtensionVersionTests(unittest.TestCase):
    def test_browser_manifests_preserve_alpha_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "bindings/wasm/Cargo.toml"
            manifest.parent.mkdir(parents=True)
            manifest.write_text('[package]\nversion = "0.4.2-alpha.3"\n')
            for browser in ("chromium", "firefox", "safari"):
                with self.subTest(browser=browser), patch("extension.build.PROJECT_ROOT", root):
                    write_browser_manifest(root, browser, [])
                    packaged = json.loads((root / "manifest.json").read_text())
                    self.assertEqual(packaged["version"], "0.4.2")
                    self.assertEqual(packaged["version_name"], "0.4.2-alpha.3")
