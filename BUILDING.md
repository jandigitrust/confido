# Building Confido 0.2

Use the pinned Rust toolchain in `rust-toolchain.toml`. Cargo fetches
`evidence-core` and `evidence-protocol` 0.2.0 from the Teraveri Git commit
pinned in the Confido manifests and lockfiles. No sibling Evidence checkout is
needed. Run commands from the Confido repository root.

```sh
cargo test --locked --manifest-path lib/Cargo.toml
cargo build --locked --manifest-path client/Cargo.toml
cargo test --locked --manifest-path client/Cargo.toml
```

Both Python wheels support CPython 3.15; CI pins 3.15.2 in `.python-version`.
Python 3.10–3.14 and 3.16 are outside the declared support range. Create a new
3.15 environment when migrating an existing installation, then reinstall the
wheel and application dependencies. Native Rust and WASM callers do not require
Python 3.15 at runtime.

For a Python wheel, install maturin 1.15.0 and use the Makefile so that project
and dependency attribution are included:

```sh
python3.15 -m venv .venv
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
CPython 3.15 Linux x86_64 and macOS arm64/x86_64 wheels. The client wheel workflow
uses the same interpreter and platforms. This configuration does not establish
that all platform builds have passed. Publication requires a `pypi-v0.2.0` tag
on `main` and the repository's
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
The client library also has a separate Python wheel. It builds from the same
Rust client crate as the CLI:

```sh
make -C bindings/client-python wheel PYTHON=python
python -m pip install --no-index --no-deps bindings/client-python/dist/confido_client-0.2.0-cp315-*.whl
python -m unittest discover -s bindings/client-python/tests -v
```

The client wheel embeds the Rust verifier and does not require the separate
`confido-verifier` wheel. Its optional `httpx` adapter is installed with
`confido-client[httpx]` when consuming a published distribution.
