/** Confido browser SDK: offline appraisal and live evidence collection.
 * Fetch authenticates ordinary browser TLS. Exact attested-certificate peer
 * authentication and application admission are not provided in this runtime.
 */
import initialize, {
  verify as nativeVerify,
  inspect_requirements as nativeInspect,
  build_info as nativeBuildInfo,
} from './_native.js';
import {createCollector} from './collection.js';

export {decode, encode, DATA_ORIGINS} from './collection.js';
export default initialize;

export const capabilities = Object.freeze({
  offlineVerification: true,
  liveAppraisal: true,
  attestedPeerAuthentication: false,
});

/** Verify caller-supplied bytes and explicit context after WASM initialization. */
export function verify(report, amdChain, vcek, reference, policy, nonce, at) {
  return JSON.parse(nativeVerify(report, amdChain, vcek, reference, policy, nonce, at));
}

export function inspect_requirements(report) {
  return JSON.parse(nativeInspect(report));
}

export function build_info() {
  return JSON.parse(nativeBuildInfo());
}

async function localVerifier(operation, input) {
  if (operation === 'inspect') return inspect_requirements(input.report);
  if (operation === 'verify') {
    return verify(input.report, input.amd_chain, input.vcek, input.reference,
      input.policy, input.nonce, input.at);
  }
  throw Error('Unsupported verifier operation');
}

/** Use local WASM or a caller-owned worker RPC for both offline and live work. */
export function createClient({origins = [], rpc = localVerifier} = {}) {
  const collect = createCollector(origins);
  return Object.freeze({
    capabilities,
    verify: async input => rpc('verify', input),
    inspect_requirements: async report => rpc('inspect', {report}),
    appraise: (origin, policy) => collect(origin, policy, rpc),
  });
}
