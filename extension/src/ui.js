import {createClient, decode, DATA_ORIGINS} from './sdk/confido.js';
import {ORIGINS} from './config.js';

const EVIDENCE_KEYS = ['report', 'amd_chain', 'vcek', 'reference'];
const WORKER_TIMEOUT_MS = 30_000;
const POLICY_FILE_LIMIT = 65_536;
const ARCHIVE_FILE_LIMIT = 16_777_216;
const element = id => document.getElementById(id);

let busy = false;
let record;

for (const origin of ORIGINS) {
  const option = document.createElement('option');
  option.value = origin;
  option.textContent = origin;
  element('origin').append(option);
}
if (ORIGINS.length === 0) element('live').disabled = true;

function createWorkerRpc() {
  const worker = new Worker(new URL('./worker.js', import.meta.url), {type: 'module'});
  const pending = new Map();
  let sequence = 0;

  function failPending(error) {
    for (const task of pending.values()) {
      clearTimeout(task.timer);
      task.reject(error);
    }
    pending.clear();
    worker.terminate();
  }

  worker.onmessage = ({data}) => {
    const task = pending.get(data.id);
    if (!task) return;
    clearTimeout(task.timer);
    pending.delete(data.id);
    if (data.error) task.reject(Error(data.error));
    else task.resolve(data.result);
  };
  worker.onerror = event => failPending(Error(event.message));

  return {
    call(operation, input) {
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(
          () => failPending(Error('Verifier timed out')),
          WORKER_TIMEOUT_MS,
        );
        pending.set(id, {resolve, reject, timer});
        worker.postMessage({id, operation, input});
      });
    },
    close() {
      worker.terminate();
    },
  };
}

async function readFile(id, limit) {
  const selected = element(id).files[0];
  if (!selected || selected.size > limit) {
    throw Error('Select a file within the size limit');
  }
  return new Uint8Array(await selected.arrayBuffer());
}

async function verifyLive(rpc) {
  const endpoint = element('origin').value;
  if (!ORIGINS.includes(endpoint)) throw Error('Unconfigured evidence service');

  const origins = [endpoint, ...DATA_ORIGINS].map(origin => `${origin}/*`);
  if (!await chrome.permissions.request({origins})) {
    throw Error('Retrieval permission was declined');
  }
  await rpc.call('metadata', {});
  const policy = await readFile('policy', POLICY_FILE_LIMIT);
  return createClient({origins: ORIGINS, rpc: rpc.call}).appraise(endpoint, policy);
}

async function replayArchive(rpc) {
  await rpc.call('metadata', {});
  const policy = await readFile('policy', POLICY_FILE_LIMIT);
  const archiveBytes = await readFile('archive', ARCHIVE_FILE_LIMIT);
  const archive = JSON.parse(new TextDecoder().decode(archiveBytes));
  if (archive.schema_version !== 2) {
    throw Error('Archive schema 2 required; use the CLI to migrate a legacy archive');
  }

  const timeInput = element('time').value;
  const evaluationTime = Number(timeInput);
  if (!timeInput || !Number.isSafeInteger(evaluationTime) || evaluationTime < 0) {
    throw Error('Choose an independent evaluation time');
  }

  const input = Object.fromEntries(
    EVIDENCE_KEYS.map(key => [key, decode(archive.inputs[key])]),
  );
  const result = await rpc.call('verify', {
    ...input,
    policy,
    nonce: decode(archive.context.expected_nonce_base64),
    at: evaluationTime,
  });
  return {
    schema_version: 2,
    mode: 'historical_replay',
    inputs: archive.inputs,
    context: {...archive.context, evaluation_unix_seconds: evaluationTime},
    verification: result,
  };
}

async function run(operation) {
  if (busy) return;
  busy = true;
  record = null;
  element('save').disabled = true;
  element('result').textContent = '';
  element('status').textContent = 'Verifying…';
  const rpc = createWorkerRpc();

  try {
    record = operation === 'live'
      ? await verifyLive(rpc)
      : await replayArchive(rpc);
    const kind = record.mode === 'historical_replay'
      ? 'Historical evidence'
      : 'Evidence';
    element('status').textContent = `${kind}: ${record.verification.status}. `
      + 'Connection authentication and admission are not evaluated.';
    element('result').textContent = JSON.stringify(record.verification, null, 2);
    element('save').disabled = false;
  } catch (error) {
    element('status').textContent = String(error);
  } finally {
    rpc.close();
    busy = false;
  }
}

element('live').addEventListener('click', () => run('live'));
element('replay').addEventListener('click', () => run('replay'));
element('save').addEventListener('click', () => {
  if (!record) return;
  const json = JSON.stringify(record, null, 2);
  const url = URL.createObjectURL(new Blob([json], {type: 'application/json'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'confido-verification.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
