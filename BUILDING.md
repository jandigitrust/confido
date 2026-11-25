# Building Confido 0.2

Use the pinned Rust toolchain in `rust-toolchain.toml`. Cargo fetches
`evidence-core` and `evidence-protocol` 0.2.0 from the Teraveri Git commit
pinned in the Confido manifests and lockfiles. No sibling Evidence checkout is
needed. Run commands from the Confido repository root.

```sh
cargo test --locked --manifest-path lib/Cargo.toml
cargo build --locked --manifest-path client/Cargo.toml
```

For a Python wheel, install maturin 1.15.0 and use the Makefile so that project and
dependency attribution are included:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'maturin==1.15.0' jsonschema
make -C bindings/python install PYTHON=python
python -m unittest discover -s lib/tests -v
python -m unittest discover -s tests -v
```

Attribution uses the locked dependency graph for the build target. The helper
defaults to `CARGO_BUILD_TARGET` or the Rust host; `--target` overrides it for
cross-target packaging. The browser build explicitly selects
`wasm32-unknown-unknown`. The example application packages its own transport
licences and consumes the published Confido verifier wheel.

The [PyPI publishing workflow](.github/workflows/publish-pypi.yml) builds
CPython 3.10 and 3.13 Linux x86_64 wheels and CPython 3.13 macOS arm64 and
x86_64 wheels. It requires a `pypi-v0.2.0` tag on `main` and the repository's
`PYPI_API_TOKEN` secret. Merge and validate the workflow before tagging;
creating that tag publishes the resulting artifacts to PyPI. The example pins
the `confido-verifier` distribution version and records the exact downloaded
wheel hash in its runtime manifest.

Rust tests that need private functions live in the owning module: short tests
stay inline, while larger suites use a `tests.rs` child module. Installed-wheel
API tests and fixtures live in `lib/tests`; evidence parser and quote tests live
in the [Evidence core repository](https://github.com/teraveri/evidence/blob/900d420b0928c4693e1143aa33a33ab670147e3c/core/src/formats/tests.rs).
Repository-wide build checks live in `tests`. Browser and replay checks are
explicit integration commands under `scripts`; collector tests live in
[Attestor](https://github.com/jandigitrust/attestor).

`PROFILE=dev` selects a development wheel. Release builds use `PROFILE=release`.
Browser packaging instructions are in [extension/README.md](extension/README.md).
The CLI remains a Confido caller; Attestor is a separate source and build tree.
