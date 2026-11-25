"""Check the real Makefile's pip request after a package version change."""

import json
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WheelInstallTests(unittest.TestCase):
    def test_install_uses_manifest_version_and_delegates_compatibility_to_pip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                '[project]\nname = "confido-client"\nversion = "0.2.1a1"\n'
            )
            # Exercise the real wheel recipe with a compiler and pip test double.
            overrides = root / "skip-build.mk"
            overrides.write_text("licenses:\n\t@:\n")
            dist = root / "dist"
            dist.mkdir()
            (dist / "stale.whl").write_bytes(b"old build")
            (dist / "keep.txt").write_text("unrelated output")
            compiler = root / "compiler.py"
            compiler.write_text(
                "from pathlib import Path\n"
                "assert not Path('dist/stale.whl').exists()\n"
                "Path('dist/fresh.whl').write_bytes(b'new build')\n"
            )
            (root / "pip.py").write_text(
                "import json, sys\n"
                "from pathlib import Path\n"
                "Path('pip-arguments.json').write_text(json.dumps(sys.argv[1:]))\n"
            )
            subprocess.run(
                [
                    "make", "-f", str(ROOT / "bindings/python/Makefile"),
                    "-f", str(overrides), "install",
                    "PYTHON=" + shlex.quote(sys.executable),
                    "MATURIN=" + shlex.join([sys.executable, str(compiler)]),
                ],
                cwd=root, check=True, capture_output=True, text=True,
            )
            arguments = json.loads((root / "pip-arguments.json").read_text())
            self.assertEqual(arguments[0], "install")
            self.assertIn("confido-client==0.2.1a1", arguments)
            self.assertIn("--no-index", arguments)
            self.assertIn("--no-deps", arguments)
            self.assertEqual(arguments[arguments.index("--find-links") + 1], "dist")
            self.assertEqual(list(dist.glob("*.whl")), [dist / "fresh.whl"])
            self.assertEqual((dist / "keep.txt").read_text(), "unrelated output")
