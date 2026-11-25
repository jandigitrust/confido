/** Bounded credentialless collection for caller-approved evidence origins. */
const AMD_KDS_ORIGIN = 'https://kdsintf.amd.com';
const GITHUB_API_ORIGIN = 'https://api.github.com';
const REQUEST_TIMEOUT_MS = 30_000;
const COLLECTION_TIMEOUT_MS = 120_000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export const DATA_ORIGINS = Object.freeze([AMD_KDS_ORIGIN, GITHUB_API_ORIGIN]);

/** Bound local waiting even when a caller-owned RPC does not support cancellation. */
async function runWithSignal(operation, signal) {
  signal.throwIfAborted();
  let onAbort;
  const aborted = new Promise((resolve, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener('abort', onAbort, {once: true});
  });
  try {
    return await Promise.race([
      Promise.resolve().then(() => {
        signal.throwIfAborted();
        return operation();
      }),
      aborted,
    ]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

async function waitForRetry(delay, signal) {
  let timer;
  try {
    await runWithSignal(() => new Promise(resolve => {
      timer = setTimeout(resolve, delay);
    }), signal);
  } finally {
    clearTimeout(timer);
  }
}

export function decode(value) {
  return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

export function encode(bytes) {
  let text = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    text += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(text);
}

/** Each client owns its immutable origin allowlist; no extension configuration is imported. */
export function createCollector(origins) {
  if (!Array.isArray(origins)) throw Error('Expected an array of HTTPS origins');
  for (const origin of origins) {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:' || parsed.origin !== origin) {
      throw Error('Expected explicit bare HTTPS origins');
    }
  }
  const ORIGINS = Object.freeze([...origins]);
  async function fetchBytes(url, {body, limit = MAX_RESPONSE_BYTES, signal} = {}) {
    const origin = new URL(url).origin;
    if (![...ORIGINS, ...DATA_ORIGINS].includes(origin)) {
      throw Error('Origin is not in the configured allowlist');
    }

    const requestSignal = AbortSignal.any([
      ...(signal ? [signal] : []),
      AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    ]);
    const response = await fetch(url, {
      method: body ? 'POST' : 'GET',
      body: body && JSON.stringify(body),
      headers: {
        'Accept': origin === GITHUB_API_ORIGIN
          ? 'application/vnd.github.raw+json'
          : 'application/json',
        ...(body && {'Content-Type': 'application/json'}),
      },
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
      signal: requestSignal,
    });

    if (!response.ok) {
      await response.body?.cancel();
      const error = Error(`HTTP ${response.status}`);
      error.status = response.status;
      error.retryAfter = response.headers.get('retry-after');
      throw error;
    }

    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > limit) throw Error('Response exceeds size limit');
        chunks.push(value);
      }
    } finally {
      await reader.cancel();
    }

    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return {bytes, headers: response.headers};
  }

  function retryDelay(error, attempt) {
    if (error.retryAfter === null) return 1000 * 2 ** attempt;
    if (/^\d+$/.test(error.retryAfter)) return Number(error.retryAfter) * 1000;
    return Math.max(0, Date.parse(error.retryAfter) - Date.now());
  }

  async function fetchKds(url, signal) {
    const deadline = performance.now() + 60_000;
    const requestSignal = AbortSignal.any([signal, AbortSignal.timeout(60_000)]);

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await fetchBytes(url, {limit: 65_536, signal: requestSignal});
      } catch (error) {
        if (![429, 500, 502, 503, 504].includes(error.status) || attempt === 2) {
          throw error;
        }
        const delay = retryDelay(error, attempt);
        if (!Number.isFinite(delay) || delay >= deadline - performance.now()) {
          throw Error('KDS retry deadline exceeded');
        }
        await waitForRetry(delay, requestSignal);
      }
    }
  }

  function readPolicy(policyBytes) {
    const json = new TextDecoder('utf-8', {fatal: true}).decode(policyBytes);
    const policy = JSON.parse(json);
    const reference = policy?.reference;
    const validPath = typeof reference?.path === 'string'
      && reference.path.split('/').every(segment =>
        /^[\w.-]+$/.test(segment) && !['.', '..'].includes(segment));

    if (policy?.schema_version !== 2
      || policy?.profile !== 'azure-snp-vtpm-ima/1'
      || !/^[\w.-]+\/[\w.-]+$/.test(reference?.repository)
      || !/^[a-f0-9]{40}$/.test(reference?.commit)
      || !validPath) {
      throw Error('Invalid immutable local policy');
    }
    return policy;
  }

  function kdsSelectors(hints, policy) {
    if (!hints || typeof hints !== 'object') throw Error('Invalid KDS selectors');
    const product = hints.product ?? policy.platform?.product;
    const validTcb = Array.isArray(hints.tcb)
      && hints.tcb.length === 4
      && hints.tcb.every(value => Number.isInteger(value) && value >= 0 && value <= 255);

    if (hints.trusted !== false
      || !['Milan', 'Genoa'].includes(product)
      || product !== policy.platform?.product
      || !/^[a-f0-9]{128}$/.test(hints.chip_id)
      || !validTcb) {
      throw Error('Invalid KDS selectors');
    }
    return product;
  }

  async function fetchAmdCertificates(product, hints, signal) {
    const baseUrl = `${AMD_KDS_ORIGIN}/vcek/v1/${product}`;
    const chain = await fetchKds(`${baseUrl}/cert_chain`, signal);
    const query = ['blSPL', 'teeSPL', 'snpSPL', 'ucodeSPL']
      .map((key, index) => `${key}=${String(hints.tcb[index]).padStart(2, '0')}`)
      .join('&');
    const vcek = await fetchKds(`${baseUrl}/${hints.chip_id}?${query}`, signal);
    return {chain: chain.bytes, vcek: vcek.bytes};
  }

  async function collect(endpoint, policyBytes, rpc) {
    if (!ORIGINS.includes(endpoint)) throw Error('Unconfigured evidence origin');
    const policySnapshot = Uint8Array.from(policyBytes);
    const policy = readPolicy(policySnapshot);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), COLLECTION_TIMEOUT_MS);
    const {signal} = controller;

    try {
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const expectedNonce = encode(nonce);
      const report = await fetchBytes(`${endpoint}/tee-report`, {
        body: {nonce: expectedNonce}, signal,
      });
      const noStore = report.headers.get('cache-control')
        ?.split(',').some(value => value.trim().toLowerCase() === 'no-store');
      if (!noStore) throw Error('Missing no-store');

      // Inspect only untrusted selectors here; the verifier authenticates them later.
      const hints = await runWithSignal(
        () => rpc('inspect', {report: report.bytes}, {signal}), signal,
      );
      const product = kdsSelectors(hints, policy);
      const certificates = await fetchAmdCertificates(product, hints, signal);
      const {reference} = policy;
      const referenceUrl = `${GITHUB_API_ORIGIN}/repos/${reference.repository}`
        + `/contents/${reference.path}?ref=${reference.commit}`;
      const referenceBytes = await fetchBytes(referenceUrl, {signal});
      if (signal.aborted) throw Error('Challenge expired');

      const input = {
        report: report.bytes,
        amd_chain: certificates.chain,
        vcek: certificates.vcek,
        reference: referenceBytes.bytes,
        policy: policySnapshot,
        nonce,
        at: Math.floor(Date.now() / 1000),
      };
      const result = await runWithSignal(() => rpc('verify', input, {signal}), signal);
      if (signal.aborted || result.expected_nonce_base64 !== expectedNonce) {
        throw Error('Challenge expired/mismatched');
      }

      return {
        schema_version: 2,
        mode: 'live_collection',
        origin: endpoint,
        inputs: Object.fromEntries(
          ['report', 'amd_chain', 'vcek', 'reference']
            .map(key => [key, encode(input[key])]),
        ),
        context: {
          expected_nonce_base64: expectedNonce,
          evaluation_unix_seconds: input.at,
        },
        verification: result,
      };
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  }
  return collect;
}
