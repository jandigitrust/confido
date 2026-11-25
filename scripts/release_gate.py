"""Gate Python and CLI releases on a package version change in a main push.

Run from the repository root after checkout with full history. GitHub event
metadata supplies the previous main revision. Invalid package metadata or an
unavailable previous revision fails before any publication output is written.
"""

import argparse
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

COMPONENTS = {
    "verifier": ("bindings/python/pyproject.toml", "project", "confido-verifier"),
    "cli": ("client/Cargo.toml", "package", "confido-cli"),
}


def release_decision(root, event_name, ref, before, component="verifier"):
    """Return (version, eligible), validating the selected package and history."""
    path, section, name = COMPONENTS[component]
    package = tomllib.loads((root / path).read_text())[section]
    version = package["version"]
    if package["name"] != name:
        raise ValueError("Unexpected release package name")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise ValueError("Invalid release version")
    if component == "verifier":
        crate = tomllib.loads((root / "bindings/python/Cargo.toml").read_text())["package"]
        if crate["version"] != version:
            raise ValueError("Python and crate versions must match")
    if event_name != "push" or ref != "refs/heads/main":
        return version, False
    if not re.fullmatch(r"[a-f0-9]{40}", before) or before == "0" * 40:
        raise ValueError("Publication requires a previous main revision")
    previous = subprocess.check_output(
        ["git", "show", f"{before}:{path}"], cwd=root, text=True, stderr=subprocess.PIPE,
    )
    old_package = tomllib.loads(previous)[section]
    if old_package["name"] != package["name"]:
        raise ValueError("Previous release package name differs")
    changed = old_package["version"] != version
    if changed and component == "cli":
        tag = f"refs/tags/v{version}"
        lookup = subprocess.run(["git", "show-ref", "--verify", "--quiet", tag], cwd=root)
        if lookup.returncode == 0:
            raise ValueError("CLI release tag already exists; choose an unused version")
        if lookup.returncode != 1:
            lookup.check_returncode()
    return version, changed


def main():
    """Write a bounded GitHub job output after validating the release decision."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=COMPONENTS, default="verifier")
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    version, publish = release_decision(
        Path.cwd(), os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"],
        event.get("before", ""), args.component,
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"publish={str(publish).lower()}\nversion={version}\n")
    print(f"{args.component} publication eligible: " + str(publish).lower())


if __name__ == "__main__":
    main()
