"""Build identity includes the pinned Evidence revision in Cargo.lock."""

import tempfile
import unittest
from pathlib import Path

from scripts.source_fingerprint import fingerprint


class SourceFingerprintTests(unittest.TestCase):
    def test_browser_identity_covers_javascript_and_build_entry_point(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = (
                "scripts/source_fingerprint.py", "build_support.rs",
                "bindings/wasm/js/confido.js", "bindings/wasm/js/collection.js",
                "bindings/wasm/build_sdk.py",
            )
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
            for name in names[2:]:
                with self.subTest(name=name):
                    original = fingerprint(root, "wasm")
                    (root / name).write_text("changed SDK input")
                    self.assertNotEqual(fingerprint(root, "wasm"), original)

    def test_client_python_identity_includes_python_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "confido"
            for name in (
                "scripts/source_fingerprint.py",
                "build_support.rs",
                "bindings/python/src/lib.rs",
                "bindings/python/python/confido_client/__init__.py",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)

            original = fingerprint(root, "python")
            (root / "bindings/python/python/confido_client/__init__.py").write_text(
                "changed public adapter"
            )
            self.assertNotEqual(fingerprint(root, "python"), original)

    def test_core_identity_uses_git_dependency_lock_without_sibling_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "confido"
            for name in (
                "scripts/source_fingerprint.py",
                "build_support.rs",
                "verifier/src/lib.rs",
                "verifier/Cargo.toml",
                "verifier/Cargo.lock",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)

            original = fingerprint(root, "core")
            (root / "../evidence/core/src/lib.rs").parent.mkdir(parents=True)
            (root / "../evidence/core/src/lib.rs").write_text("unrelated local checkout")
            self.assertEqual(fingerprint(root, "core"), original)

            (root / "verifier/Cargo.lock").write_text("updated Evidence commit")
            self.assertNotEqual(fingerprint(root, "core"), original)


if __name__ == "__main__":
    unittest.main()
