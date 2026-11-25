"""Package the local WASM verifier with optional live service origins."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit

EXTENSION_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = EXTENSION_ROOT.parent
AMD_KDS_ORIGIN = "https://kdsintf.amd.com/*"
GITHUB_API_ORIGIN = "https://api.github.com/*"

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from source_fingerprint import fingerprint
sys.path.insert(0, str(PROJECT_ROOT / "bindings/wasm"))
from build_sdk import build_sdk


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--browser", choices=("chromium", "firefox", "safari"), default="chromium"
    )
    parser.add_argument("--wasm-bindgen", default="wasm-bindgen")
    parser.add_argument(
        "--origins-config", type=Path, help="JSON with locally approved HTTPS origins"
    )
    return parser.parse_args()


def approved_origins(config_path):
    config = json.loads(config_path.read_bytes()) if config_path else {"origins": []}
    if (
        not isinstance(config, dict)
        or set(config) != {"origins"}
        or not isinstance(config["origins"], list)
        or len(config["origins"]) > 16
    ):
        raise SystemExit("Invalid origins configuration")

    origins = set()
    for origin in config["origins"]:
        if not isinstance(origin, str):
            raise SystemExit("Invalid origin")
        try:
            parsed = urlsplit(origin)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise SystemExit("Service origin must be a bare HTTPS DNS origin") from exc

        valid_host = host is not None and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in host.split(".")
        )
        if (
            parsed.scheme != "https"
            or not valid_host
            or port is not None
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or origin != f"https://{parsed.netloc}"
        ):
            raise SystemExit("Service origin must be a bare HTTPS DNS origin")
        if origin in origins:
            raise SystemExit("Duplicate origin")
        origins.add(origin)
    return sorted(origins)


def caller_fingerprint():
    source_files = [
        EXTENSION_ROOT / "build.py",
        *sorted((EXTENSION_ROOT / "src").glob("*")),
    ]
    digest = hashlib.sha256()
    for path in source_files:
        digest.update(path.relative_to(EXTENSION_ROOT).as_posix().encode() + b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def source_identity():
    return {
        "core_source_sha256": fingerprint(PROJECT_ROOT, "core"),
        "wrapper_source_sha256": fingerprint(PROJECT_ROOT, "wasm"),
    }


def write_browser_manifest(output, browser, origins):
    package = tomllib.loads((PROJECT_ROOT / "bindings/wasm/Cargo.toml").read_text())["package"]
    version = package["version"]
    manifest = {
        "manifest_version": 3,
        "name": "Confido Evidence Verifier",
        # Browser update metadata requires numeric components; display SemVer separately.
        "version": version.split("-", 1)[0],
        "version_name": version,
        "description": "Local evidence verification against your selected policy.",
        "action": {"default_title": "Verify evidence"},
        "optional_host_permissions": [
            *(origin + "/*" for origin in origins),
            AMD_KDS_ORIGIN,
            GITHUB_API_ORIGIN,
        ],
        "content_security_policy": {
            "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
        },
    }
    manifest["background"] = (
        {"service_worker": "background.js"}
        if browser == "chromium"
        else {"scripts": ["background.js"]}
    )
    if browser == "firefox":
        manifest["browser_specific_settings"] = {
            "gecko": {
                "id": "confido-verifier@genxt.network",
                "strict_min_version": "128.0",
            }
        }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def write_runtime_manifest(output, identity, caller_hash):
    asset_paths = [
        "background.js",
        "index.html",
        "style.css",
        "worker.js",
        "ui.js",
        "sdk/collection.js",
        "sdk/confido.js",
        "config.js",
        "sdk/_native.js",
        "sdk/_native_bg.wasm",
    ]
    assets = {
        path: hashlib.sha256((output / path).read_bytes()).hexdigest()
        for path in asset_paths
    }
    manifest = {
        "pipeline_revision": 2,
        **identity,
        "caller_source_sha256": caller_hash,
        "assets": assets,
    }
    (output / "runtime-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main():
    args = parse_args()
    config_bytes = args.origins_config.read_bytes() if args.origins_config else None
    origins = approved_origins(args.origins_config)
    identity = source_identity()
    caller_hash = caller_fingerprint()

    output = EXTENSION_ROOT / "dist" / args.browser
    # Avoid packaging files left behind by a previous version of the caller.
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(EXTENSION_ROOT / "src", output, dirs_exist_ok=True)
    (output / "config.js").write_text(
        "export const ORIGINS = " + json.dumps(origins, separators=(",", ":")) + ";\n"
    )
    build_sdk(output / "sdk", args.wasm_bindgen)
    write_browser_manifest(output, args.browser, origins)

    if (
        identity != source_identity()
        or caller_hash != caller_fingerprint()
        or (args.origins_config and args.origins_config.read_bytes() != config_bytes)
    ):
        raise SystemExit("Sources changed during extension build; rebuild required")
    write_runtime_manifest(output, identity, caller_hash)
    print(output)


if __name__ == "__main__":
    main()
