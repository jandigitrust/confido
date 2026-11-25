# Repository build checks

These Python tests exercise build and packaging helpers without TPM hardware:

- `test_release_gate.py` checks the publication gate against real Git history;
  prereleases, PR, tag, manual and non-main events cannot select an upload.
- `test_extension_version.py` checks browser-compatible version metadata and
  the displayed SemVer prerelease.
- `test_wheel_install.py` checks that installation selects the manifest version
  through pip after a version change, without compiling native code.
- `test_source_fingerprint.py` checks that the locked Evidence revision affects
  build identity and an unrelated sibling checkout does not.
- `test_browser_live_checks.py` checks caller-selected cases, bounded inputs,
  explicit pregrants, scoped DNS mappings, verdicts, and context cleanup without
  live services.
- `test_attribution.py` checks Git revision consistency, inherited workspace
  notices, and downstream packaging without recursive attribution archives.

Run `python3 -m unittest discover -s tests -v` from the repository root.
Installed-wheel API tests live in `verifier/tests` and `bindings/python/tests`; hardware/browser integration
checks live in `scripts`; deployment cases belong to the cooperating application. Collector launcher
tests live in [Attestor](https://github.com/jandigitrust/attestor).
