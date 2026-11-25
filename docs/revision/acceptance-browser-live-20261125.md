# Public browser acceptance — 2026-11-25 UTC

The configured GENXT stage passed Chromium live match/mismatch with explicitly
selected Genoa policies, including a separate route check against published DNS
addresses. A separate headed run exercised Chromium's native
optional-host permission dialog without pregrants or a stubbed permissions API.
These observations concern the tested evidence delivery and browser build.
They do not establish application admission or authenticate the browser's TLS
peer against the certificate in the evidence.

## Source and environment

- Extension/verifier build source: `1315a22fa927f0c70dbc59396489a509c8791b91`
  (JAN `main`). The native-dialog run used that source too.
- Supported `--resolve` runner: `9a9cb51a5009a7b60213046b53e2b5cefa63688a`.
  Only harness code changed; the extension package stayed the same.
- Linux x86_64; Chrome for Testing `159.0.8154.6`; Playwright `1.65.2`.
- Rust `1.98.0 (88d9e12ae 2026-08-18)`; wasm-bindgen `0.2.100`.
- Packaged Chromium MV3 extension, pipeline revision 2, built with the
  example-owned `profiles/extension-origins.json`.
- Verifier policy bytes were caller-selected snapshots. No policy was obtained
  from the evidence service, and no Milan fallback was used.

| Build/configuration input | SHA-256 |
| --- | --- |
| Packaged `manifest.json` | `42a97ee0addb7042d6d1f1942c48b29fd1be74caa560a8b1ff35f8487940061d` |
| `runtime-manifest.json` | `53b7034ebf0bfab2d942a057c368451fc909b60f12b7c04f417b183adfec18f6` |
| Core source identity | `e11f34a7e508b0b2b5fc8ba0f065c99091c9046a1538840fa400c779b85affcc` |
| WASM wrapper source identity | `9b285be770924e94f7605c103df3e5ffc8ccdc0574bfdd048537284aaafcbe51` |
| Extension caller source identity | `d3b18ec0f0c51eed5e043e5a037a1a422e838b9e3080d07f50bf6427e3774b3c` |
| Example `profiles/extension-origins.json` | `6eb79b4be57881dfb813eb582599943d762372690360ae27b9acc6fc6a276057` |
| Example `profiles/browser-live-cases-genoa.json` | `f27aa023ca55779e6772013e9d7a75636d8345dd83fe8f8392c18a00a0e8fc68` |

The example profiles were local working-tree inputs; the hashes identify the
selected configuration independently of its checkout revision.

The manifest fingerprints identify the tested package; they are not publisher
authentication or a provenance attestation. Raw live evidence was not retained
in this record, so it does not provide an offline replay corpus.

## Live delivery: system resolver and published addresses

The system-resolver snapshot run started at `16:22:43 UTC` and completed at
`16:22:57 UTC`.
The runner loaded an installed extension, selected each policy and origin,
invoked live collection, and checked its local WASM result. Both cases passed
their configured status and reason assertions with scope `evidence_only` and
without an application-admission claim.

A later route check found hosts-file overrides for both names and non-global
addresses in system resolution. That initial run therefore does not establish
a public route, even though it used public-looking HTTPS names.

| Case | Origin | Policy in example `profiles/` | Observed status / reason |
| --- | --- | --- | --- |
| `genoa-match` | `https://match.demo.genxt.network` | `verifier-genoa-stage-registry.json` | `verified` / `reference_match` |
| `genoa-mismatch` | `https://mismatch.demo.genxt.network` | `verifier-genoa-stage-mismatch.json` | `policy_mismatch` / `measurement_mismatch` |

Hashes of the actual policy snapshots passed to the runner:

- Positive: `7d3cf06255a691ecec351bfbeaa147317eb2de272a96969d437b051e8aceb3c1`.
- Negative: `394eef80e44b19c5c7a121b3335d0c6be80accf09285432d7930e226c1f8434d`.

The pregrant mode changed host permissions only in a temporary package copy.
The original package and runtime manifests remained byte-for-byte unchanged.
Requests used browser TLS without certificate-error bypasses. No user token,
chat request, or LLM invocation was involved.

### Separate published-address check

A separate check at `16:27:50–16:27:56 UTC` obtained A records from the public
`dns.google` DNS-over-HTTPS resolver and supplied explicit Chromium hostname
mappings. Each `/tee-report` response was HTTP 200, and Chromium's reported
server address matched the selected published A record. Both evidence cases
passed the same status/reason assertions. URLs, policy bytes and ordinary
browser TLS validation were preserved; these address selectors were not trust
policy.

| Hostname | Published A record used |
| --- | --- |
| `match.demo.genxt.network` | `4.180.9.14` |
| `mismatch.demo.genxt.network` | `172.201.106.172` |

The maintained CLI was then exercised with these mappings from `16:32:52` to
`16:33:06 UTC`, using harness revision `9a9cb51`. Both cases passed and the
process exited 0. This second stage used `--resolve`; it did not change the
system hosts file. The test browser ran on the VM test host, so reachability
from an independent external network was not established.

To repeat the live run, install the build tools and Playwright/Chromium from the
[extension guide](../../extension/README.md). Place the example checkout beside
Confido with the listed case/policy files. From the Confido root, run:

```sh
python extension/build.py --browser chromium --origins-config ../confidential-ai-example/profiles/extension-origins.json
python scripts/browser_live_checks.py \
  --extension-dir extension/dist/chromium \
  --cases ../confidential-ai-example/profiles/browser-live-cases-genoa.json \
  --pregrant-hosts \
  --resolve match.demo.genxt.network=4.180.9.14 \
  --resolve mismatch.demo.genxt.network=172.201.106.172
```

The listed addresses are dated observations. For another deployment or DNS
state, explicitly select its intended addresses and retain that configuration.
A run without `--resolve` uses the system resolver, including hosts overrides.

The expected result is two passing case lines and exit status 0. A network or
verdict failure is a failed acceptance run; do not substitute a different policy
or relax TLS validation to obtain a pass. Services and their dependencies may
change after the recorded interval.

## Native Chromium permission flow

A separate headed Chromium ran on an isolated Xvfb display with a fresh temporary
profile and the original package manifest. This native-dialog run used system
name resolution; the published-address run above used pregrants. The package had
no required `host_permissions`. A one-off controller supplied the positive policy and used
X11 pointer input on the visible native dialog. It did not replace
`chrome.permissions.request`, `fetch`, or the verifier. This was environment
acceptance, not an additional default-CI native-dialog test.

1. With no granted origins, click **Retrieve and verify evidence**. Chromium
   displayed its native permission dialog for the selected match origin,
   `kdsintf.amd.com`, and `api.github.com`.
2. Click **Deny**. The page reported that retrieval permission was declined.
   The browser context observed zero HTTP(S) requests, saving stayed disabled,
   and `chrome.permissions.contains` confirmed that the requested hosts were
   absent.
3. Click **Retrieve and verify evidence** again, then **Allow** in the native
   dialog. Collection completed with `verified/reference_match`.
   `chrome.permissions.getAll` contained exactly the three selected host patterns;
   the other configured evidence origin was not granted.

These steps can also be repeated manually after loading the built extension in
a fresh Chromium profile. A profile with prior consent is unsuitable for the
initial denial test. The live runner's `--headed` mode supports operator consent
for successful cases; declining a required permission makes that runner fail.

An additional API-level probe removed those hosts with `permissions.remove` and
confirmed `permissions.contains == false`. On a subsequent explicit request,
this Chromium build silently restored previously approved hosts and verified
again. API removal therefore did not demonstrate that Chromium forgot prior
consent. Revocation through the browser's extension-settings UI was not tested.

## Limits

- Native-dialog acceptance covers this Linux/Chromium build and the positive
  origin. Firefox extension consent, Safari, store packages, macOS, and Windows
  were not exercised by this live run.
- The public negative case was checked with explicit pregrants. Its native
  additional-host dialog was not separately tested.
- Passing evidence does not establish TLS peer binding, relay resistance,
  application/model/GPU integrity, external inference, or application admission.
- Default CI retains deterministic local browser checks; these network- and
  environment-dependent acceptance steps remain opt-in.
