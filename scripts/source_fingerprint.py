"""Deterministic fingerprints of explicit native build inputs (never credentials)."""

import hashlib
import os
import sys
from pathlib import Path


def files(root, scope):
    scopes = {
        "core": [root / "verifier"],
        "python": [root / "bindings/python"],
        "wasm": [root / "bindings/wasm"],
        "client": [root / "client"],
        "cli": [root / "cli"],
    }
    paths = {
        root / "scripts/source_fingerprint.py",
        root / "build_support.rs",
    }
    directories = []
    for base in scopes[scope]:
        directories.append(base / "src")
        paths.update((base / "src").rglob("*.rs"))
        if (base / "js").is_dir():
            directories.append(base / "js")
            paths.update((base / "js").rglob("*.js"))
            paths.add(base / "build_sdk.py")
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
