# Confido browser extension

All evidence verification runs in a local Worker using packaged Rust/WASM.
There is no native messaging host, remote verifier, content script or chat client.

`src/index.html`, `src/style.css`, and `src/ui.js` form the page and its
file-input/Worker UI. `src/collection.js` retrieves live inputs with explicit
origin, size and time limits. `src/worker.js` checks the packaged runtime and
invokes the shared verifier; `src/background.js` opens the verifier page when
the extension action is clicked. `build.py` packages those sources with the
Rust/WASM binding and browser manifests.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.100 --locked
python3 extension/build.py --browser chromium
python3 extension/build.py --browser firefox
python3 extension/build.py --browser safari
# Optional GENXT live-demo build, using application-owned host configuration:
python3 extension/build.py --browser chromium --origins-config ../confidential-ai-example/profiles/extension-origins.json
```

Run from the repository root with clang installed. Outputs are under
`extension/dist/<browser>` and are ignored by Git. WASM and JS are bundled;
CSP permits WASM compilation and forbids remotely hosted scripts.

- Chromium: enable developer mode at `chrome://extensions`, choose **Load unpacked**.
- Firefox: `about:debugging` → **This Firefox** → **Load Temporary Add-on**, choose
  the generated manifest. Manifest targets Firefox 128+; test your release channel.
- Safari: on macOS run `xcrun safari-web-extension-converter extension/dist/safari`
  and build/sign the generated Xcode project. Native packaging is required by
  Safari; the verifier itself remains WASM. Safari acceptance is pending macOS.

Without `--origins-config`, the extension supports local historical replay.
For live collection, supply an approved origin list at build time and select
a caller-owned verifier policy, such as the adjacent
`confidential-ai-example/profiles/verifier-match.json`. The build places only
those configured origins in the optional host permissions and runtime
allowlist. The extension does not infer trust policy from the service.
Replay requires a v2 archive and an explicit evaluation timestamp; old embedded
results are ignored and all raw inputs are reverified. Convert v1 archives with
the CLI's `migrate-archive` command. Imported policies are explicitly user-selected
trust configuration and are not obtained from the service.

Live collection requests optional permission only for the selected configured hostname,
AMD KDS and GitHub. Credentials/cookies are omitted; redirects, oversized inputs
and expired requests are rejected. A closed/restarted page loses pending challenges.
The configured endpoints must have HTTPS certificates accepted by the browser.
No certificate-error bypass is implemented. Private GitHub references need a
separate explicit credential design; the initial extension uses public references.

The UI displays evidence status, checks and limitations. It does not say a TLS peer
was matched or an application was admitted. Saving/reopening a result creates a
historical replay, never a fresh live challenge.

## Tests

```sh
python -m pip install playwright
python -m playwright install --with-deps chromium firefox
python scripts/browser_checks.py
# Optional privately retained real hardware corpus:
python scripts/browser_checks.py --bundle /private/archive-v1.json --at UNIX_SECONDS
```

The harness compares Python and worker results in Chromium/Firefox and loads the
actual Chromium MV3 extension to verify CSP and archive UI. Real Safari and public
HTTPS delivery require separate environment acceptance. Linux Firefox worker
coverage alone is not a claim of signed Firefox store-package acceptance.

### Opt-in live Chromium acceptance

The deployment-neutral runner lives in `scripts/browser_live_checks.py`.
It requires Playwright/Chromium and a packaged extension built with the
operator-approved origins. It does not require the Python verifier or CLI.
Run these commands from the Confido repository root:

```sh
python3 extension/build.py --browser chromium --origins-config ../confidential-ai-example/profiles/extension-origins.json
python scripts/browser_live_checks.py \
  --extension-dir extension/dist/chromium \
  --cases ../confidential-ai-example/profiles/browser-live-cases-genoa.json \
  --pregrant-hosts
```

The example case file targets the Genoa stage deployment. Use it only when that
is the intended deployment; it is not evidence of a currently promoted public
service. Other consumers provide their own case files and origin configuration.
Policy paths are resolved relative to the case file, and their bytes are read
before browser startup. The runner does not fetch or select trust policy.

A case file is a JSON list of one to 32 records:

```json
[
  {
    "name": "stage-match",
    "origin": "https://evidence.example.test",
    "policy": "policies/approved.json",
    "expected_status": "verified",
    "expected_reason": "reference_match"
  }
]
```

`expected_reason` is optional and must be a string when supplied; other fields
are required. The exact origin must
be among the packaged extension's optional hosts. Results must have scope
`evidence_only` and must not claim application admission. Failures return a
nonzero exit status without dumping server/browser errors or raw evidence.

The default browser uses system name resolution, including hosts-file entries.
A public-looking hostname alone does not prove a public route was tested.
To select a route explicitly, repeat `--resolve HOST=IP` for selected evidence
hosts. For example, `--resolve evidence.example.test=203.0.113.10` shows the
syntax with documentation-only addresses. Hostnames are case-insensitive;
duplicate, unselected, wildcard, or non-IP mappings are rejected before browser
startup. IPv4, IPv6, and local/private destinations are supported; scoped IPv6
addresses are rejected.
Mappings apply only to this Chromium context. They preserve the original URL,
HTTPS hostname validation and policy bytes, and do not override AMD/GitHub DNS.

`--pregrant-hosts` explicitly grants the selected case hosts, AMD KDS and GitHub in a
**temporary copy**, preserving the original package. This mode checks live
collection and WASM delivery with existing permissions. It does **not** test the
production permission-consent UI, denial, or revocation. Without the flag the
package's permissions are unchanged; unattended browser permission prompts may
fail or time out. Use `--headed` on a desktop to allow operator-driven consent.
Native consent-flow acceptance remains a separate environment check. The
[2026-11-25 record](../docs/revision/acceptance-browser-live-20261125.md) covers
public Genoa match/mismatch and a real Linux/Chromium grant/deny dialog. Repeat
that acceptance for the browser and deployment being released.

The offline harness stubs the permission API to decline a request and checks
the real UI's requested scopes, absence of collection, and disabled save button.
This covers denial handling, not the browser's native permission dialog.

Live checks contact the configured services, AMD KDS and GitHub. They are opt-in
and do not run in default CI. No credentials, chat requests or certificate-error
bypasses are used. This does not establish evidence-to-connection binding.
Offline tests for case validation, permissions and browser cleanup run with:

```sh
python -m unittest discover -s tests -p test_browser_live_checks.py -v
```

## Runtime identity

The bundle includes `runtime-manifest.json` with pipeline revision 2, source
fingerprints and SHA-256 values for its page, JS, CSS and WASM assets. The Worker verifies these
and checks the loaded WASM build metadata before inspecting or verifying evidence.
A mixed bundle fails with a rebuild message; installing a new JS caller alongside
an old WASM artifact is not supported. Metadata is separate from the result JSON.
