# Repository support scripts

Run these scripts from the Confido repository root unless a command documents
otherwise. They support builds, packaging, and explicit checks; they are not
part of the portable verifier runtime.

| Script | Purpose |
| --- | --- |
| [`archive_inputs.py`](archive_inputs.py) | Adapts legacy saved archives for caller-side replay. |
| [`browser_checks.py`](browser_checks.py) | Compares Python, CLI, and browser WASM behavior using local inputs. |
| [`check_verifier_dependencies.py`](check_verifier_dependencies.py) | Guards the portable verifier's normal dependency graph. |
| [`replay_checks.py`](replay_checks.py) | Runs offline negative-case replay over a supplied evidence bundle. |
| [`source_fingerprint.py`](source_fingerprint.py) | Hashes explicit source and build inputs for artifact identity. |
| [`prepare_attribution.py`](prepare_attribution.py) | Copies project notices and prepares dependency attribution for a package. |
| [`collect_licenses.py`](collect_licenses.py) | Creates the dependency attribution archive from resolved Cargo metadata. |

If a published crate declares a licence but omits attribution files, place a
reviewed `third_party/<crate>-<version>/provenance.json` and its referenced files
in the owning project. The collector verifies their digests and the crate's
published VCS revision; downstream projects use their own `third_party/` tree.

See the [build guide](../BUILDING.md) for routine commands, the
[extension guide](../extension/README.md#tests) for browser checks, and the
[rerun guide](../docs/revision/rerun.md) for evidence replay.
