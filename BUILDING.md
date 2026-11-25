# Building Confido

Confido is in alpha development for staging. Rust packages use SemVer
`0.2.1-alpha.1`; the Python distribution uses the equivalent PEP 440 spelling
`0.2.1a1`. Keep these formats distinct from evidence wire and schema versions.

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
`make install` reads the SDK version from `pyproject.toml` and lets pip select a
compatible wheel from `dist/`. Older versions in that directory are not selected.
The helper uses the locked build-target dependency graph, defaulting to
`CARGO_BUILD_TARGET` or the Rust host. Its `--target` option supports explicit
cross-target attribution. The optional synchronous HTTP adapter is included in
the wheel; install `httpx` alongside CI artifacts as shown above. The
`confido-client[httpx]` extra declares this dependency for published packages.

The [Python SDK workflow](.github/workflows/client-wheel.yml) builds and tests
Linux x86_64 and macOS arm64/x86_64 wheels for PRs targeting `main` and pushes to
`main`. Successful main builds upload `client-wheel-*` artifacts for existing
consumers. These artifact names and the distribution/import names are retained.
The standalone `confido-verifier` wheel and its publication workflow are removed.

Alpha, beta and release-candidate builds remain CI artifacts for staging.
PyPI publication requires a final version change on a push to `main`. Set the
equivalent versions in `bindings/python/pyproject.toml` and
`bindings/python/Cargo.toml`. Update the lockfile in the same release PR.
All matrix jobs must succeed. The publish job
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
a push to `main` changes the package to a final version in `cli/Cargo.toml`.
Prereleases do not create an RPM or GitHub Release. The RPM spec uses
`0.2.1~alpha.1` for the current prerelease. Choose an unused
version and update the lockfile in the release PR. The workflow creates
`v<version>` at that main revision. Tags and manual runs do not release an RPM;
existing release assets are not overwritten. RPM and Python versions are
independent.

The existing self-hosted Fedora 39 x86_64 runner must support Node 24 actions,
Python 3.11+ and rustup; dependency installation uses `sudo dnf`. The package
split does not establish support on additional platforms.

## Verification ownership

Rust tests that need private functions live in the owning module: short tests
stay inline, while larger suites use a `tests.rs` child module.
Installed-wheel offline tests and fixtures live in `verifier/tests`;
live API, transport and console tests live in `bindings/python/tests`.
Build helper tests live in `tests`. Browser and replay
checks are explicit commands in `scripts`. Evidence parser and quote tests live in
[Evidence core](https://github.com/teraveri/evidence/blob/900d420b0928c4693e1143aa33a33ab670147e3c/core/src/formats/tests.rs).
Collector tests live in
[Attestor](https://github.com/jandigitrust/attestor).
