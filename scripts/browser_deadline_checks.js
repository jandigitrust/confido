/** Exercise collection cancellation with controlled timers, transport and RPC. */
(async phase => {
  const {createClient} = await import('./sdk/confido.js');
  const original = {fetch, setTimeout, clearTimeout};
  const timers = new Map();
  let nextId = 0;
  let blocked;
  const ready = new Promise(resolve => { blocked = resolve; });
  globalThis.setTimeout = (callback, delay) => {
    const id = ++nextId;
    timers.set(id, {callback, delay});
    if (delay === 50_000) blocked();
    return id;
  };
  globalThis.clearTimeout = id => timers.delete(id);
  const origin = 'https://evidence.example.test';
  let requests = 0;
  let rpcSignal;
  globalThis.fetch = async url => {
    requests++;
    if (phase === 'retry' && url.includes('/cert_chain')) {
      return new Response('', {status: 503, headers: {'retry-after': '50'}});
    }
    return new Response('synthetic input', {
      headers: {'cache-control': 'no-store'},
    });
  };
  const policy = new TextEncoder().encode(JSON.stringify({
    schema_version: 2, profile: 'azure-snp-vtpm-ima/1',
    platform: {product: 'Genoa'},
    reference: {repository: 'org/repo', commit: 'a'.repeat(40), path: 'values.json'},
  }));
  const rpc = async (operation, input, options) => {
    if (operation === phase) {
      rpcSignal = options?.signal;
      blocked();
      return new Promise(() => {});
    }
    return {trusted: false, product: 'Genoa', chip_id: 'b'.repeat(128), tcb: [1, 2, 3, 4]};
  };
  let watchdog;
  try {
    const outcome = createClient({origins: [origin], rpc}).appraise(origin, policy)
      .then(() => { throw Error('Expired collection unexpectedly succeeded'); }, error => error);
    // A real timer bounds the test even if the implementation ignores cancellation.
    const failed = new Promise((resolve, reject) => {
      watchdog = original.setTimeout.call(
        globalThis, () => reject(Error('Deadline did not settle appraisal')), 2000,
      );
    });
    await Promise.race([ready, failed]);
    const beforeAbort = requests;
    const [id, timer] = [...timers].find(([, value]) => value.delay === 120_000);
    timers.delete(id);
    timer.callback();
    const error = await Promise.race([outcome, failed]);
    await Promise.resolve();
    if (error.name !== 'AbortError') throw error;
    if (requests !== beforeAbort) throw Error('Request sent after cancellation');
    if (timers.size) throw Error('Collection timers were not cleaned up');
    if (phase !== 'retry' && !rpcSignal?.aborted) throw Error('RPC cancellation signal missing');
    return true;
  } finally {
    original.clearTimeout.call(globalThis, watchdog);
    Object.assign(globalThis, original);
  }
})
