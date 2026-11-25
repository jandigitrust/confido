# Agent guidance

Confido 0.2 verifies caller-supplied evidence against caller-selected policy and
reference bytes. Start with `README.md`; for revision work, use
`docs/revision-0.2.md` and `docs/revision/coverage.md`. Read other documents only
when relevant to the task.
For serialized contracts, start with `schemas/README.md`.

- `lib/` is the portable verifier. The version-pinned Teraveri
  `evidence-protocol` Git dependency defines wire structures, and
  `evidence-core` checks bounded formats and snapshot consistency.
  `bindings/python/` and `bindings/wasm/` expose the verifier. `client/` owns
  reusable native collection, appraisal and peer checking;
  `bindings/client-python/` exposes that client. `extension/` remains a browser
  caller.
  [JAN Attestor](https://github.com/jandigitrust/attestor) owns native collection
  and the report endpoint.
- The sibling `confidential-ai-example` owns demo policies and application
  admission. Its existing transport will migrate to the Confido client.
  Reference creation, approval, and
  publication belong to separate tooling and registries.

## Context and private data

- Scope searches to relevant source, tests, schemas, and documentation. Exclude
  `target/`, `dist/`, `pkg/`, `.venv/`, `.artifacts/`, caches, and logs from broad
  searches.
- Build and test tools may use generated files locally. Do not print, attach,
  or paste caches, binaries, private keys, credentials, or raw live evidence
  into model context, issues, or PRs. For diagnosis, report only necessary
  metadata, counts, hashes, or redacted fields.
- `.gitignore` limits accidental Git staging; it does not control what an
  agent reads or sends to a model. Check tool output before exposing it.

## Verification

Use the focused build and test commands in `README.md` for affected packages.
Before handing off, check `git status --short` and `git diff --check`; keep test
output free of raw evidence.
