"""Build one distributable browser SDK with offline and live APIs."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SDK_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from prepare_attribution import prepare
from source_fingerprint import fingerprint


def build_native(bindgen, output):
    """Compile the locked portable verifier and generate its internal JS adapter."""
    manifest = PROJECT_ROOT / "bindings/wasm/Cargo.toml"
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--manifest-path",
            str(manifest),
        ],
        check=True,
    )
    wasm = (
        PROJECT_ROOT
        / "bindings/wasm/target/wasm32-unknown-unknown/release/confido_wasm.wasm"
    )
    subprocess.run(
        [
            bindgen,
            str(wasm),
            "--target",
            "web",
            "--out-dir",
            str(output),
            "--out-name",
            "_native",
        ],
        check=True,
    )


def build_sdk(output, bindgen="wasm-bindgen"):
    """Package the portable WASM verifier, JS client, and target attribution."""
    identity = (fingerprint(PROJECT_ROOT, "core"), fingerprint(PROJECT_ROOT, "wasm"))
    output.mkdir(parents=True, exist_ok=True)
    prepare(SDK_ROOT / "Cargo.toml", output / "licenses", target="wasm32-unknown-unknown")
    build_native(bindgen, output)
    for source in (SDK_ROOT / "js").glob("*.js"):
        shutil.copyfile(source, output / source.name)
    if identity != (fingerprint(PROJECT_ROOT, "core"), fingerprint(PROJECT_ROOT, "wasm")):
        raise RuntimeError("SDK sources changed during build; rebuild required")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=SDK_ROOT / "dist")
    parser.add_argument("--wasm-bindgen", default="wasm-bindgen")
    args = parser.parse_args()
    build_sdk(args.out_dir.resolve(), args.wasm_bindgen)
