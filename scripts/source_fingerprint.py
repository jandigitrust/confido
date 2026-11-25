"""Deterministic fingerprints of explicit native build inputs (never credentials)."""

import hashlib
import os
import sys
from pathlib import Path


def files(root, scope):
    # `python` is the established verifier-wheel scope. The live client wheel
    # has its own scope and embeds the Rust verifier rather than importing it.
    scopes = {
        "core": [root / "lib"],
        "python": [root / "bindings/python"],
        "client-python": [root / "bindings/client-python"],
        "wasm": [root / "bindings/wasm"],
        "cli": [root / "client"],
    }
    paths = {
        root / "scripts/source_fingerprint.py",
        root / "build_support.rs",
    }
    directories = []
    for base in scopes[scope]:
        directories.append(base / "src")
        paths.update((base / "src").rglob("*.rs"))
        if (base / "python").is_dir():
            paths.update((base / "python").rglob("*.py"))
        paths.update(
            base / name
            for name in (
                "Cargo.toml",
                "Cargo.lock",
                "build.rs",
                "pyproject.toml",
                "Makefile",
            )
            if (base / name).is_file()
        )
    return sorted(paths), directories


def fingerprint(root, scope):
    digest = hashlib.sha256()
    for path in files(root, scope)[0]:
        # Cargo.lock pins the git-sourced Evidence commit. Relative labels keep
        # the digest independent of the checkout's absolute location.
        name = os.path.relpath(path, root).replace(os.sep, "/").encode()
        data = path.read_bytes()
        digest.update(
            len(name).to_bytes(8, "big") + name + len(data).to_bytes(8, "big") + data
        )
    return digest.hexdigest()


if __name__ == "__main__":
    root, scope = Path(sys.argv[1]).resolve(), sys.argv[2]
    print(fingerprint(root, scope))
    for path in [*files(root, scope)[0], *files(root, scope)[1]]:
        print(path)
