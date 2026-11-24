"""Packaging keeps dependency notices without recursively including its own output."""

import hashlib
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from collect_licenses import collect
from prepare_attribution import prepare


class AttributionTests(unittest.TestCase):
    def test_downstream_supplement_is_bound_to_crate_revision_and_license(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependency = root / "registry" / "example-1.0.0"
            dependency.mkdir(parents=True)
            revision = "a" * 40
            (dependency / ".cargo_vcs_info.json").write_text(
                json.dumps({"git": {"sha1": revision}})
            )
            supplement = root / "third_party" / "example-1.0.0"
            supplement.mkdir(parents=True)
            notice = supplement / "LICENSE-NOTICE.md"
            notice.write_text("Published crate declares Apache-2.0.")
            provenance = supplement / "provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "crate": "example",
                        "version": "1.0.0",
                        "license": "Apache-2.0",
                        "commit": revision,
                        "files": [
                            {
                                "file": notice.name,
                                "sha256": hashlib.sha256(notice.read_bytes()).hexdigest(),
                            }
                        ],
                    }
                )
            )
            metadata = {
                "resolve": {"nodes": [{"id": "example"}]},
                "packages": [
                    {
                        "id": "example",
                        "name": "example",
                        "version": "1.0.0",
                        "license": "Apache-2.0",
                        "manifest_path": str(dependency / "Cargo.toml"),
                        "source": "registry+https://example.invalid/index",
                    }
                ],
            }
            output = root / "attribution.tar.gz"
            collect(metadata, output, supplement_root=root)
            with tarfile.open(output) as archive:
                self.assertTrue(
                    any(
                        name.endswith("supplement/LICENSE-NOTICE.md")
                        for name in archive.getnames()
                    )
                )
            metadata["packages"][0]["license"] = "MIT"
            with self.assertRaisesRegex(ValueError, "Attribution provenance differs"):
                collect(metadata, output, supplement_root=root)

    def test_downstream_package_uses_own_license_and_excludes_generated_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "native"
            output = package / "licenses"
            dependency = root / "dependency"
            output.mkdir(parents=True)
            dependency.mkdir()
            (root / "LICENSE").write_text("downstream project licence")
            (output / "third-party-licenses.tar.gz").write_bytes(b"old archive")
            (dependency / "LICENSE").write_text("dependency licence")
            metadata = {
                "workspace_members": ["project"],
                "resolve": {"nodes": [{"id": "project"}, {"id": "dependency"}]},
                "packages": [
                    {"id": "project", "manifest_path": str(package / "Cargo.toml")},
                    {
                        "id": "dependency",
                        "name": "dependency",
                        "version": "1.0.0",
                        "manifest_path": str(dependency / "Cargo.toml"),
                        "source": "registry+https://example.invalid/index",
                    },
                ],
            }
            with patch(
                "prepare_attribution.subprocess.check_output",
                return_value=json.dumps(metadata),
            ):
                prepare(
                    package / "Cargo.toml",
                    output,
                    root,
                    target="x86_64-unknown-linux-gnu",
                )
            self.assertEqual(
                (output / "LICENSE").read_text(), "downstream project licence"
            )
            with tarfile.open(output / "third-party-licenses.tar.gz") as archive:
                inventory = json.load(archive.extractfile("third-party/packages.json"))
                self.assertEqual([item["name"] for item in inventory], ["dependency"])
                self.assertFalse(
                    any(name.endswith(".tar.gz") for name in archive.getnames())
                )

    def test_git_workspace_notices_require_the_resolved_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / "core"
            crate.mkdir()
            (root / ".git").mkdir()
            (root / "LICENSE").write_text("workspace licence")
            revision = "a" * 40
            metadata = {
                "resolve": {"nodes": [{"id": "core"}]},
                "packages": [
                    {
                        "id": "core",
                        "name": "core",
                        "version": "0.2.0",
                        "manifest_path": str(crate / "Cargo.toml"),
                        "source": "git+https://example.invalid/evidence#" + revision,
                    }
                ],
            }
            output = root / "attribution.tar.gz"
            with patch(
                "collect_licenses.subprocess.check_output", return_value=revision
            ):
                collect(metadata, output)
            with tarfile.open(output) as archive:
                self.assertTrue(
                    any(
                        name.endswith("repository/LICENSE")
                        for name in archive.getnames()
                    )
                )
            with patch(
                "collect_licenses.subprocess.check_output", return_value="b" * 40
            ):
                with self.assertRaisesRegex(ValueError, "Git revision differs"):
                    collect(metadata, output)


if __name__ == "__main__":
    unittest.main()
