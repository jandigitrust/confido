import init, {verify, inspect_requirements, build_info} from './sdk/confido.js';

const EXPECTED_PIPELINE = 2;
let ready;

async function loadRuntime() {
  const manifestUrl = new URL('./runtime-manifest.json', import.meta.url);
  const manifestResponse = await fetch(manifestUrl);
  if (!manifestResponse.ok) throw Error('Missing bundled runtime manifest');
  const manifest = await manifestResponse.json();
  if (manifest.pipeline_revision !== EXPECTED_PIPELINE) {
    throw Error('Incompatible verifier pipeline; rebuild extension');
  }

  let wasm;
  for (const [path, expectedHash] of Object.entries(manifest.assets)) {
    const response = await fetch(new URL(path, import.meta.url));
    if (!response.ok) throw Error('Missing bundled verifier asset');
    const bytes = await response.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    const actualHash = [...new Uint8Array(digest)]
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
    if (actualHash !== expectedHash) {
      throw Error('Bundled JS/WASM assets differ from build manifest; rebuild extension');
    }
    if (path.endsWith('.wasm')) wasm = bytes;
  }
  if (!wasm) throw Error('Missing bundled WASM');

  await init({module_or_path: wasm});
  const info = build_info();
  if (info.core.pipeline_revision !== EXPECTED_PIPELINE
    || info.core.source_sha256 !== manifest.core_source_sha256
    || info.wrapper.source_sha256 !== manifest.wrapper_source_sha256) {
    throw Error('Loaded WASM build differs from caller manifest');
  }
  return info;
}

self.onmessage = async ({data: {id, operation, input}}) => {
  try {
    const info = await (ready ??= loadRuntime());
    if (operation === 'metadata') {
      self.postMessage({id, result: info});
      return;
    }
    if (!['inspect', 'verify'].includes(operation)) {
      throw Error('Unsupported verifier operation');
    }

    const result = operation === 'inspect'
      ? inspect_requirements(input.report)
      : verify(
        input.report,
        input.amd_chain,
        input.vcek,
        input.reference,
        input.policy,
        input.nonce,
        input.at,
      );
    self.postMessage({id, result});
  } catch (error) {
    self.postMessage({id, error: String(error)});
  }
};
