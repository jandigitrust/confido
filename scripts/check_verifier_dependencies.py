"""Guard normal evidence-core and verifier graphs from native I/O crates."""

import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for manifest, target in [
    ("verifier/Cargo.toml", None),
    ("bindings/wasm/Cargo.toml", "wasm32-unknown-unknown"),
]:
    cmd = [
        "cargo",
        "tree",
        "--locked",
        "--manifest-path",
        str(root / manifest),
        "-e",
        "normal",
        "--prefix",
        "none",
    ]
    if target:
        cmd += ["--target", target]
    graph = subprocess.check_output(cmd, text=True)
    names = {line.split()[0] for line in graph.splitlines()}
    forbidden = names & {
        "openssl",
        "openssl-sys",
        "tss-esapi",
        "tss-esapi-sys",
        "reqwest",
        "tokio",
        "hyper",
        "rustls",
        "web-sys",
        "js-sys",
        "az-snp-vtpm",
    }
    if forbidden:
        raise SystemExit(
            f"{manifest}: forbidden verifier dependencies {sorted(forbidden)}"
        )
    print(manifest + ": portable dependency guard passed")
