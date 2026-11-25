"""Build identity includes the pinned Evidence revision in Cargo.lock."""

import tempfile
import unittest
from pathlib import Path

from scripts.source_fingerprint import fingerprint


class SourceFingerprintTests(unittest.TestCase):
    def test_client_python_identity_includes_python_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "confido"
            for name in (
                "scripts/source_fingerprint.py",
                "build_support.rs",
                "bindings/client-python/src/lib.rs",
                "bindings/client-python/python/confido_client/__init__.py",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)

            original = fingerprint(root, "client-python")
            (root / "bindings/client-python/python/confido_client/__init__.py").write_text(
                "changed public adapter"
            )
            self.assertNotEqual(fingerprint(root, "client-python"), original)

    def test_core_identity_uses_git_dependency_lock_without_sibling_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "confido"
            for name in (
                "scripts/source_fingerprint.py",
                "build_support.rs",
                "lib/src/lib.rs",
                "lib/Cargo.toml",
                "lib/Cargo.lock",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)

            original = fingerprint(root, "core")
            (root / "../evidence/core/src/lib.rs").parent.mkdir(parents=True)
            (root / "../evidence/core/src/lib.rs").write_text("unrelated local checkout")
            self.assertEqual(fingerprint(root, "core"), original)

            (root / "lib/Cargo.lock").write_text("updated Evidence commit")
            self.assertNotEqual(fingerprint(root, "core"), original)


if __name__ == "__main__":
    unittest.main()
