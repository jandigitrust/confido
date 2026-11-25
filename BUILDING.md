# Building Confido 0.2

Run commands from the repository root. Use the Rust toolchain in
`rust-toolchain.toml`. Cargo fetches the Evidence crates at the revision pinned
in each manifest and lockfile; no sibling Evidence checkout is needed.

```sh
cargo test --locked --manifest-path verifier/Cargo.toml
cargo test --locked --manifest-path client/Cargo.toml
cargo build --locked --manifest-path cli/Cargo.toml
```

The portable verifier has no network runtime. The native client and Python SDK
include rustls and certificate inspection; native test fixtures compile vendored
OpenSSL. The CLI is a separate consumer of the client library.

## Python SDK

One wheel, `confido-client`, provides offline verification and live APIs through
`import confido_client`. CPython 3.15 is required; CI pins 3.15.2 in
`.python-version`. Create a fresh environment when migrating from older Python.
Native Rust and browser callers do not require Python at runtime.

```sh
python3.15 -m venv .venv
. .venv/bin/activate
python -m pip install 'maturin==1.15.0' jsonschema 'httpx==0.28.1'
make -C bindings/python install PYTHON=python
python -m unittest discover -s verifier/tests -v
python -m unittest discover -s bindings/python/tests -v
python -m unittest discover -s tests -v
```

Use the Makefile so that project and dependency attribution are included.
`PROFILE=dev` selects a development wheel; the default is `PROFILE=release`.
The helper uses the locked build-target dependency graph, defaulting to
`CARGO_BUILD_TARGET` or the Rust host. Its `--target` option supports explicit
cross-target attribution. The optional synchronous HTTP adapter is included in
the wheel; consuming applications install `confido-client[httpx]` to obtain its
`httpx` dependency.

The [Python SDK workflow](.github/workflows/client-wheel.yml) builds and tests
Linux x86_64 and macOS arm64/x86_64 wheels for PRs targeting `main` and pushes to
`main`. Successful main builds upload `client-wheel-*` artifacts for existing
consumers. These artifact names and the distribution/import names are retained.
The standalone `confido-verifier` wheel and its publication workflow are removed.

PyPI publication requires a push to `main` that changes the SDK version in both
`bindings/python/pyproject.toml` and `bindings/python/Cargo.toml`. Update the
lockfile in the same release PR. All matrix jobs must succeed. The publish job
requires the `pypi` environment and `PYPI_API_TOKEN` secret. PRs, tags and manual
runs cannot publish; a manual main run can check token connectivity without
uploading a file. Unchanged versions produce CI artifacts only. Moving the SDK
from `bindings/client-python/` preserves its previous version history in the
release gate and does not itself trigger publication.

## Browser SDK

Install clang, the Rust `wasm32-unknown-unknown` target and `wasm-bindgen-cli`
0.2.100. Build the WASM verifier and JavaScript client as one directory:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.100 --locked
python3 bindings/wasm/build_sdk.py
```

Serve `bindings/wasm/dist/` as static assets and import `confido.js` from that
directory. The SDK build includes target-specific attribution. The
[extension build](extension/README.md#build) packages this same SDK and adds its
UI, permissions and runtime manifest. Browser acceptance is documented in the
[extension guide](extension/README.md#tests).

## CLI releases

The [RPM workflow](.github/workflows/release.yml) builds and publishes only when
a push to `main` changes the package version in `cli/Cargo.toml`. Choose an unused
version and update the lockfile in the release PR. The workflow creates
`v<version>` at that main revision. Tags and manual runs do not release an RPM;
existing release assets are not overwritten. RPM and Python versions are
independent.

The existing self-hosted Fedora 39 x86_64 runner must support Node 24 actions,
Python 3.11+ and rustup; dependency installation uses `sudo dnf`. The package
split does not establish support on additional platforms.

## Verification ownership

Rust tests live in their owning modules. Installed-wheel offline tests and
fixtures live in `verifier/tests`; live API, transport and console tests live in
`bindings/python/tests`. Build helper tests live in `tests`. Browser and replay
checks are explicit commands in `scripts`. Evidence parser tests live in
[Evidence](https://github.com/teraveri/evidence), and collector tests live in
[Attestor](https://github.com/jandigitrust/attestor).
