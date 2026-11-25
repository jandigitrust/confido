"""Compare browser WASM, Python and CLI verification using local inputs.

An optional private hardware archive stays on localhost. Without ``--bundle``,
this checks invalid-input parity, CSP, worker startup and WASM imports.
"""

import argparse
import functools
import hashlib
import json
import shutil
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import confido_client
from archive_inputs import arguments, encode, migrate
from browser_extension import installed_page
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "extension/dist/chromium"
EVIDENCE_KEYS = ("report", "amd_chain", "vcek", "reference")
WORKER_INPUT_KEYS = (*EVIDENCE_KEYS, "policy", "nonce")

WORKER_METADATA = """() => new Promise((resolve, reject) => {
  const worker = new Worker('./worker.js', {type: 'module'});
  worker.onmessage = ({data}) => {
    worker.terminate();
    data.error ? reject(Error(data.error)) : resolve(data.result);
  };
  worker.postMessage({id: 1, operation: 'metadata', input: {}});
})"""

WASM_IMPORTS = """async () => {
  const response = await fetch('./sdk/_native_bg.wasm');
  const module = await WebAssembly.compile(await response.arrayBuffer());
  return WebAssembly.Module.imports(module).map(item => item.name);
}"""

WORKER_VERIFY = """input => new Promise((resolve, reject) => {
  const worker = new Worker('./worker.js', {type: 'module'});
  const timer = setTimeout(() => {
    worker.terminate();
    reject(Error('timeout'));
  }, 30000);
  worker.onerror = event => {
    clearTimeout(timer);
    worker.terminate();
    reject(Error(event.message));
  };
  worker.onmessage = ({data}) => {
    clearTimeout(timer);
    worker.terminate();
    data.error ? reject(Error(data.error)) : resolve(data.result);
  };
  for (const key of ['report', 'amd_chain', 'vcek', 'reference', 'policy', 'nonce']) {
    input[key] = Uint8Array.from(atob(input[key]), character => character.charCodeAt(0));
  }
  worker.postMessage({id: 1, operation: 'verify', input});
})"""

SDK_VERIFY = """async input => {
  const sdk = await import('./sdk/confido.js');
  await sdk.default();
  for (const key of ['report', 'amd_chain', 'vcek', 'reference', 'policy', 'nonce']) {
    input[key] = sdk.decode(input[key]);
  }
  return await sdk.createClient().verify(input);
}"""

COLLECTION_CONTRACT = """async () => {
  const module = await import('./sdk/confido.js');
  const origin = 'https://evidence.example.test';
  const requests = [];
  const originalFetch = globalThis.fetch;
  let cacheControl = 'no-store';

  globalThis.fetch = async (url, options) => {
    requests.push({url, method: options.method, credentials: options.credentials});
    policy.fill(0);  // Caller mutation after dispatch must not change verified policy.
    const headers = url === origin + '/tee-report'
      ? {'cache-control': cacheControl}
      : {};
    return new Response(new TextEncoder().encode('synthetic input'), {
      status: 200, headers,
    });
  };

  const policy = new TextEncoder().encode(JSON.stringify({
    schema_version: 2,
    profile: 'azure-snp-vtpm-ima/1',
    platform: {product: 'Genoa'},
    reference: {repository: 'org/repo', commit: 'a'.repeat(40), path: 'values.json'},
  }));
  const originalPolicy = policy.slice();
  let policySnapshotPreserved = false;
  const rpc = async (operation, input) => {
    if (operation === 'inspect') {
      return {trusted: false, product: 'Genoa', chip_id: 'b'.repeat(128), tcb: [1, 2, 3, 4]};
    }
    policySnapshotPreserved = input.policy.every((byte, i) => byte === originalPolicy[i]);
    return {status: 'verified', expected_nonce_base64: module.encode(input.nonce)};
  };

  const origins = [origin];
  const client = module.createClient({origins, rpc});
  origins.length = 0;  // Mutating caller configuration must not change this client.
  try {
    let rejectedUnconfiguredOrigin = false;
    try {
      await module.createClient({rpc}).appraise(origin, policy);
    } catch (error) {
      rejectedUnconfiguredOrigin = String(error).includes('Unconfigured');
    }
    const requestsBeforeAppraisal = requests.length;
    const result = await client.appraise(origin, policy);
    cacheControl = '';
    let rejectedWithoutNoStore = false;
    try {
      await client.appraise(origin, originalPolicy);
    } catch (error) {
      rejectedWithoutNoStore = String(error).includes('Missing no-store');
    }
    return {
      status: result.verification.status,
      mode: result.mode,
      requests: requests.map(request => request.url),
      credentialless: requests.every(request => request.credentials === 'omit'),
      reportMethod: requests[0].method,
      rejectedWithoutNoStore,
      rejectedUnconfiguredOrigin,
      requestsBeforeAppraisal,
      policySnapshotPreserved,
      attestedPeerAuthentication: client.capabilities.attestedPeerAuthentication,
    };
  } finally {
    globalThis.fetch = originalFetch;
  }
}"""


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--at", type=int)
    parser.add_argument("--policy", type=Path)
    args = parser.parse_args()
    if args.bundle and not args.policy:
        parser.error("--bundle requires --policy matching the archive")
    if args.bundle and args.at is None:
        parser.error("--bundle requires --at")
    return args


def reference_mutation(values, policy, edit):
    changed = values.copy()
    reference = json.loads(changed[3])
    edit(reference)
    changed[3] = json.dumps(reference).encode()
    changed_policy = json.loads(policy)
    changed_policy["reference"]["sha256"] = hashlib.sha256(changed[3]).hexdigest()
    changed[4] = json.dumps(changed_policy).encode()
    return changed


def verification_cases(args, policy):
    empty = [b"", b"", b"", b"", policy, bytes(32), 1750000000]
    cases = [("missing_input", empty)]
    if not args.bundle:
        return cases

    archive = migrate(json.loads(args.bundle.read_text()), args.at)
    values = arguments(archive, policy)
    cases.append(("hardware", values))

    wrong_nonce = values.copy()
    wrong_nonce[5] = bytes(32)
    cases.append(("wrong_nonce", wrong_nonce))

    changed_reference = values.copy()
    changed_reference[3] += b" "
    cases.append(("reference_mutation", changed_reference))

    changed_quote = values.copy()
    report = json.loads(changed_quote[0])
    report["evidence"]["quote"]["signature"][0] ^= 1
    changed_quote[0] = json.dumps(report).encode()
    cases.append(("quote_mutation", changed_quote))

    cases.append(
        (
            "ima_reference_mismatch",
            reference_mutation(
                values,
                policy,
                lambda reference: reference["ima_measurements"][1].update(
                    filedata_hash="0" * 64
                ),
            ),
        )
    )
    cases.append(
        (
            "pcr10_mismatch",
            reference_mutation(
                values,
                policy,
                lambda reference: reference.update(pcr10_sha256="0" * 64),
            ),
        )
    )
    return cases


def check_cli(cases):
    cli = ROOT / "cli/target/debug/confido-cli"
    metadata = json.loads(subprocess.check_output([str(cli), "--build-info"]))
    assert (
        metadata["core"]["source_sha256"]
        == confido_client.build_info()["core"]["source_sha256"]
    )
    assert metadata["core"]["pipeline_revision"] == 2

    with tempfile.TemporaryDirectory() as directory:
        folder = Path(directory)
        for name, values in cases:
            expected = confido_client.verify(*values)
            archive = {
                "schema_version": 2,
                "mode": "historical_replay",
                "inputs": {
                    key: encode(value) for key, value in zip(EVIDENCE_KEYS, values[:4])
                },
                "context": {
                    "expected_nonce_base64": encode(values[5]),
                    "evaluation_unix_seconds": values[6],
                },
            }
            (folder / "archive.json").write_text(json.dumps(archive))
            (folder / "policy.json").write_bytes(values[4])
            process = subprocess.run(
                [
                    str(cli),
                    "replay",
                    str(folder / "policy.json"),
                    str(folder / "archive.json"),
                    str(values[6]),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert process.returncode == (
                0 if expected["status"] == "verified" else 2
            ), (
                name,
                process.stderr,
            )
            assert json.loads(process.stdout) == expected, ("cli", name)
    print(f"CLI: {len(cases)} identical installed Python results")


@contextmanager
def local_extension_server():
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        functools.partial(QuietHandler, directory=str(EXTENSION)),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/index.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def check_worker(browser_type, browser_name, url, cases):
    browser = browser_type.launch(headless=True)
    try:
        page = browser.new_page()
        page.goto(url)
        metadata = page.evaluate(WORKER_METADATA)
        assert metadata["core"]["pipeline_revision"] == 2
        assert (
            metadata["core"]["source_sha256"]
            == confido_client.build_info()["core"]["source_sha256"]
        )
        imports = page.evaluate(WASM_IMPORTS)
        assert not any(
            forbidden in str(imports).lower()
            for forbidden in ("fetch", "random", "socket", "date_now")
        ), imports

        for name, values in cases:
            expected = confido_client.verify(*values)
            payload = {
                key: encode(value) for key, value in zip(WORKER_INPUT_KEYS, values[:6])
            }
            payload["at"] = values[6]
            actual = page.evaluate(WORKER_VERIFY, payload)
            assert actual == expected, (browser_name, name)
            assert page.evaluate(SDK_VERIFY, payload) == expected, (browser_name, "sdk", name)
        check_collection_contract(page)
        print(
            f"{browser_name}: {len(cases)} identical Python/WASM results; no network/RNG/clock WASM imports"
        )
    finally:
        browser.close()


def check_collection_contract(page):
    result = page.evaluate(COLLECTION_CONTRACT)
    assert result["status"] == "verified"
    assert result["mode"] == "live_collection"
    assert result["reportMethod"] == "POST"
    assert result["credentialless"] and result["rejectedWithoutNoStore"]
    assert result["rejectedUnconfiguredOrigin"] and result["requestsBeforeAppraisal"] == 0
    assert result["policySnapshotPreserved"]
    assert result["attestedPeerAuthentication"] is False
    assert result["requests"][0] == "https://evidence.example.test/tee-report"
    assert result["requests"][1].endswith("/vcek/v1/Genoa/cert_chain")
    assert "/repos/org/repo/contents/values.json?ref=" in result["requests"][3]


def check_installed_replay(playwright, policy_path):
    with tempfile.TemporaryDirectory() as profile:
        context, page = installed_page(playwright, EXTENSION, profile)
        try:
            page.locator("#policy").set_input_files(policy_path)
            empty_archive = {
                "schema_version": 2,
                "inputs": {key: "" for key in EVIDENCE_KEYS},
                "context": {"expected_nonce_base64": encode(bytes(32))},
            }
            page.locator("#archive").set_input_files(
                {
                    "name": "input.json",
                    "mimeType": "application/json",
                    "buffer": json.dumps(empty_archive).encode(),
                }
            )
            page.locator("#time").fill("1750000000")
            page.locator("#replay").click()
            expect(page.locator("#status")).to_contain_text(
                "incomplete_input", timeout=30000
            )
            assert not page.locator("#save").is_disabled()
        finally:
            context.close()
    print("Chromium installed MV3 extension: worker, CSP and local replay passed")


def check_mixed_assets(playwright):
    # A stale asset or source identity must fail before any evidence call.
    for mismatch in ("asset", "core_identity"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extension = root / "extension"
            shutil.copytree(EXTENSION, extension)
            if mismatch == "asset":
                with (extension / "sdk/collection.js").open("a") as output:
                    output.write("\n// deliberately stale asset\n")
            else:
                path = extension / "runtime-manifest.json"
                manifest = json.loads(path.read_text())
                manifest["core_source_sha256"] = "0" * 64
                path.write_text(json.dumps(manifest))

            context, page = installed_page(playwright, extension, root / "profile")
            try:
                page.locator("#replay").click()
                expect(page.locator("#status")).to_contain_text("diff", timeout=30000)
                assert page.locator("#save").is_disabled()
            finally:
                context.close()
    print(
        "Chromium rejects mixed JS/WASM assets and mismatched embedded source identity"
    )


def check_permission_denial(playwright):
    """Exercise the real UI's denial branch with a stubbed permissions API.

    This checks requested scopes and absence of collection after denial; the
    browser's own permission dialog still requires separate acceptance.
    """
    with tempfile.TemporaryDirectory() as profile:
        context, page = installed_page(playwright, EXTENSION, profile)
        try:
            page.evaluate("""async () => {
                const {ORIGINS} = await import('./config.js');
                const origin = 'https://evidence.example.test';
                ORIGINS.push(origin);  // Configure the caller; SDK state remains private.
                const select = document.querySelector('#origin');
                select.add(new Option(origin, origin));
                select.value = origin;
                document.querySelector('#live').disabled = false;
                globalThis.permissionProbe = {requests: [], fetches: 0};
                chrome.permissions.request = async request => {
                    permissionProbe.requests.push(request.origins);
                    return false;
                };
                globalThis.fetch = async () => {
                    permissionProbe.fetches++;
                    throw Error('Collection must not run after permission denial');
                };
            }""")
            page.locator("#live").click()
            expect(page.locator("#status")).to_contain_text("permission was declined")
            assert page.locator("#save").is_disabled()
            probe = page.evaluate("permissionProbe")
            assert probe["requests"] == [[
                "https://evidence.example.test/*",
                "https://kdsintf.amd.com/*",
                "https://api.github.com/*",
            ]]
            assert probe["fetches"] == 0
        finally:
            context.close()
    print("Chromium UI: stubbed permission denial prevents collection and saving")


def main():
    args = parse_args()
    policy_path = args.policy or ROOT / "verifier/tests/fixtures/verifier-policy-v2.json"
    cases = verification_cases(args, policy_path.read_bytes())
    check_cli(cases)
    with local_extension_server() as url, sync_playwright() as playwright:
        for browser_name in ("chromium", "firefox"):
            check_worker(getattr(playwright, browser_name), browser_name, url, cases)
        check_installed_replay(playwright, policy_path)
        check_mixed_assets(playwright)
        check_permission_denial(playwright)


if __name__ == "__main__":
    main()
