# Repository build checks

These Python tests exercise build and packaging helpers without TPM hardware:

- `test_source_fingerprint.py` checks that the locked Evidence revision affects
  build identity and an unrelated sibling checkout does not.
- `test_browser_live_checks.py` checks caller-selected cases, bounded inputs,
  explicit pregrants, verdicts, and context cleanup without live services.
- `test_attribution.py` checks Git revision consistency, inherited workspace
  notices, and downstream packaging without recursive attribution archives.

Run `python3 -m unittest discover -s tests -v` from the repository root.
Installed-wheel API tests live in `lib/tests`, and hardware/browser integration
checks live in `scripts`; deployment cases belong to the cooperating application. Collector launcher
tests live in [Attestor](https://github.com/jandigitrust/attestor).
