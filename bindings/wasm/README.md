# Browser SDK

One SDK combines the portable WASM verifier with JavaScript collection.
Offline verification accepts caller-supplied evidence, policy, nonce and time.
Live appraisal uses an explicit per-client origin allowlist, credentialless
fetches, bounded responses and deadlines. Policy bytes are copied before any
asynchronous work. The browser authenticates ordinary HTTPS; it cannot inspect
the connection's certificate to authenticate the attested peer. The SDK makes
no application admission decision.

| File | Role |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | Browser-callable verification, requirement inspection, and build metadata. |
| [`Cargo.toml`](Cargo.toml), `Cargo.lock` | WASM crate dependencies and the locked build graph. |
| [`build.rs`](build.rs) | Stamps wrapper source identity and build metadata. |
| [`js/confido.js`](js/confido.js) | Public initialization, offline verification and `createClient` API. |
| [`js/collection.js`](js/collection.js) | Reusable browser evidence, endorsement and reference retrieval. |
| [`build_sdk.py`](build_sdk.py) | Packages the WASM module, JavaScript modules and attribution together. |

Build with `python3 bindings/wasm/build_sdk.py` from the repository root;
see [prerequisites](../../BUILDING.md#browser-sdk). Serve the resulting `dist/`
directory and import its entry point:

```javascript
import initialize, {createClient} from './confido.js';

await initialize();
const client = createClient({origins: ['https://evidence.example.test']});
const archive = await client.appraise('https://evidence.example.test', policyBytes);
```

The module exports synchronous `verify(report, amdChain, vcek, reference,
policy, nonce, unixSeconds)` and `inspect_requirements(report)` after initialization.
Both return objects. `createClient().verify(input)` and `.inspect_requirements(report)`
return promises. `input` uses the keys `report`, `amd_chain`, `vcek`, `reference`,
`policy`, `nonce` and `at`. `capabilities.attestedPeerAuthentication` is `false`.

A caller that owns a worker can pass `rpc(operation, input)` to `createClient`.
It must dispatch `inspect` and `verify` to this SDK's offline functions and
return their objects. The [extension](../../extension/README.md#build) uses
this adapter and owns permissions, worker lifecycle and presentation.
Live RPC calls receive an optional third argument `{signal}`. Appraisal stops
waiting when its deadline expires; adapters can use the signal to cancel work
they own. A local timeout does not establish that worker execution stopped.
Browser behavior is checked by `scripts/browser_checks.py` from the
repository root.
