import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const cwd = new URL('..', import.meta.url);
const verifierPort = await freePort();
const apiPort = await freePort();
const verifierUrl = `http://127.0.0.1:${verifierPort}/voice-id/verifier/`;
const apiUrl = `http://127.0.0.1:${apiPort}`;
const processes = [];

try {
  processes.push(
    spawnForSmoke('verifier', ['run', 'dev:verifier'], {
      VOICEID_VERIFIER_BACKEND: 'placeholder',
      VOICEID_VERIFIER_PORT: String(verifierPort),
    }),
  );
  await waitForOk(`http://127.0.0.1:${verifierPort}/health`);

  processes.push(
    spawnForSmoke('api', ['run', 'dev:server'], {
      PORT: String(apiPort),
      VOICEID_VERIFIER_TRANSPORT: 'python-http',
      VOICEID_PYTHON_VERIFIER_URL: verifierUrl,
      VOICEID_VERIFIER_TIMEOUT_MS: '5000',
    }),
  );
  await waitForOk(`${apiUrl}/health`);

  const enrollment = await postJson('/voice-id/enrollment/start', {
    userId: 'owner',
    phrase: 'Walking on clouds',
  });
  const enrollmentId = enrollment.record.enrollmentId;

  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    const sample = await postSample('/voice-id/enrollment/sample', {
      fields: {
        userId: 'owner',
        enrollmentId,
        expectedPhrase: 'Walking on clouds',
        spokenPhrase: 'Walking on clouds',
        attemptNumber,
      },
    });
    assertEqual(sample.quality.kind, 'accepted', 'enrollment sample quality');
  }

  const finalized = await postJson('/voice-id/enrollment/finalize', {
    userId: 'owner',
    enrollmentId,
  });
  assertEqual(finalized.state, 'enrolled', 'finalized enrollment state');

  const verification = await postJson('/voice-id/verification/start', {
    userId: 'owner',
    enrollmentId,
    phrase: 'Walking on clouds',
  });
  const verificationId = verification.record.verificationId;

  const result = await postSample('/voice-id/verification/sample', {
    fields: {
      userId: 'owner',
      enrollmentId,
      verificationId,
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    },
  });
  assertEqual(result.kind, 'accepted', 'verification result');

  console.log(`VoiceID python-http API smoke passed on API ${apiUrl} and verifier ${verifierUrl}`);
} catch (error) {
  printChildOutput();
  throw error;
} finally {
  shutdown();
}

function spawnForSmoke(name, args, env) {
  const child = spawn('pnpm', args, {
    cwd,
    env: {
      ...process.env,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const output = [];
  child.stdout.on('data', (chunk) => output.push(`[${name}] ${chunk.toString('utf8')}`));
  child.stderr.on('data', (chunk) => output.push(`[${name}] ${chunk.toString('utf8')}`));
  child.on('exit', (code, signal) => {
    if (code !== null && code !== 0) {
      output.push(`[${name}] exited with code ${code}`);
    }
    if (signal !== null) {
      output.push(`[${name}] exited with signal ${signal}`);
    }
  });
  child.output = output;
  return child;
}

async function waitForOk(url) {
  const startedAt = Date.now();
  let lastError = null;
  while (Date.now() - startedAt < 10_000) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
      lastError = new Error(`${url} returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await delay(100);
  }
  throw new Error(`timed out waiting for ${url}: ${lastError instanceof Error ? lastError.message : String(lastError)}`);
}

async function postJson(path, body) {
  const response = await fetch(`${apiUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return await readOkValue(response, path);
}

async function postSample(path, input) {
  const bytes = new Uint8Array([1, 2, 3, 4, 5]);
  const form = new FormData();
  form.set('audio', new Blob([bytes], { type: 'audio/webm' }));
  form.set('metadata', JSON.stringify(buildMetadata(bytes.byteLength)));
  form.set('fields', JSON.stringify(input.fields));

  const response = await fetch(`${apiUrl}${path}`, {
    method: 'POST',
    body: form,
  });
  return await readOkValue(response, path);
}

async function readOkValue(response, path) {
  const body = await response.json();
  if (response.status !== 200 || body.kind !== 'ok') {
    throw new Error(`${path} failed with HTTP ${response.status}: ${JSON.stringify(body)}`);
  }
  return body.value;
}

function buildMetadata(byteLength) {
  return {
    mimeType: 'audio/webm',
    durationMs: 1800,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength,
    capturedAt: new Date('2026-06-13T00:00:00.000Z').toISOString(),
    recorder: 'smoke',
    fixtureBehavior: { kind: 'speaker_label', speakerLabel: 'owner' },
  };
}

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => {
        if (address !== null && typeof address === 'object') {
          resolve(address.port);
          return;
        }
        reject(new Error('failed to allocate a free port'));
      });
    });
  });
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} expected ${expected}, got ${actual}`);
  }
}

function shutdown() {
  for (const child of processes) {
    child.kill('SIGTERM');
  }
}

function printChildOutput() {
  for (const child of processes) {
    for (const line of child.output ?? []) {
      process.stderr.write(line);
    }
  }
}
