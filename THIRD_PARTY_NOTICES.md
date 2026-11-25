# Third-party material

The root LICENSE applies to Confido's project-authored material. It does not
replace the licences, copyright notices, or attribution requirements of dependencies.

## Preserved source material

- The [Teraveri Evidence core](https://github.com/teraveri/evidence/blob/900d420b0928c4693e1143aa33a33ab670147e3c/core/src/formats.rs) retains attribution for adapted SNP/HCL layouts. Its repository carries the relevant upstream licence material.
- Cargo lockfiles identify additional Rust dependencies. Confido has no TPM2-TSS or OpenSSL runtime dependency. Dependencies retain their authors' terms.

## Dependencies included in binary releases

- `ring` includes material derived from BoringSSL, OpenSSL, and other contributors.
  Its complete LICENSE and nested third-party licence files must be retained;
  Confido's Apache-2.0 declaration does not replace them.
- Native test fixtures use vendored OpenSSL; a release must review the locked
  graph of the artifact actually distributed.
- Other Rust dependencies keep their own terms, including applicable MIT, BSD,
  ISC, Apache, and other licences. The examples above are not a complete inventory.

The CLI RPM workflow creates a third-party licence archive from its locked Cargo
metadata after compilation. It includes the resolved package
inventory and verbatim licence, copyright, author, and notice files found in those
packages, including nested bundled components. For path and Git workspace
dependencies, repository root attribution files are also included. The inventory
conservatively includes resolved build and Linux-target dependencies as well
as runtime dependencies;
it is not a claim that every listed dependency is linked into the binary.

The CLI RPM installs this document, the root LICENSE, and the archive's contents
under `/usr/share/licenses/confido-cli/`. Upstream NOTICE files, when present, are
preserved in the corresponding dependency directory. No project-level NOTICE
file is added because the inspected Confido sources establish no requirement
for one.

## Release review

The collector preserves identified files; it does not establish ownership or
licence compatibility. Before publishing a release, review the resolved inventory
and any file-specific terms, and check the aggregate RPM licence expression
against the code actually included. Use the release's locked dependency inventory for this review. Python wheels and other binary formats
also require their own third-party attribution packaging review before publication.

## SDK distributions

The Python Makefile prepares `licenses/` before building a wheel. The wheel
includes the project licence, this document, and a dependency attribution archive
from the locked Python binding graph for the build target. Browser packages carry
the same materials for the `wasm32-unknown-unknown` graph under `sdk/licenses/`.
The standalone browser SDK uses `licenses/` at its package root.
Internal Confido crates are covered by the
project licence and are excluded from the third-party inventory.

The unified Python wheel contains native HTTPS and certificate inspection
dependencies, including rustls and `x509-parser`. OpenSSL is used only by
native test fixtures. Its macOS graph includes
reviewed supplements for the `system-configuration` crates whose published
packages omit standalone licence files.

`third_party/` contains reviewed attribution supplements for identified omissions
in upstream packages. It is not a copy of all dependency licences; the build
collector assembles those from the actual resolved graph. Neither source alone
establishes a complete legal review of a distributed artifact.
