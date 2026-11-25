include!("../../build_support.rs");

fn main() {
    stamp("python", "../..");

    // Embed the Python distribution spelling; Cargo uses SemVer prereleases.
    let python = std::env::var("PYO3_PYTHON").unwrap_or_else(|_| "python3".into());
    let output = std::process::Command::new(python)
        .current_dir(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .args([
            "-c",
            "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])",
        ])
        .output()
        .expect("Python 3.11+ is required to read Python package metadata");
    assert!(
        output.status.success(),
        "Could not read Python package version: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let version = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=CONFIDO_PYTHON_VERSION={}", version.trim());
    println!("cargo:rerun-if-env-changed=PYO3_PYTHON");
}
