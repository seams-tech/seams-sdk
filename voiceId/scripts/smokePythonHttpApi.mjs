import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const cwd = new URL('..', import.meta.url);
const verifierPort = await freePort();
const apiPort = await freePort();
const verifierUrl = `http://127.0.0.1:${verifierPort}/voice-id/verifier/`;
const apiUrl = `http://127.0.0.1:${apiPort}`;
const tsxCli = fileURLToPath(import.meta.resolve('tsx/cli'));
const processes = [];

try {
  processes.push(
    spawnForSmoke('verifier', 'python3', ['verifier/voiceid_verifier/app.py', 'serve_http'], {
      PYTHONPATH: 'verifier',
      VOICEID_VERIFIER_BACKEND: 'placeholder',
      VOICEID_VERIFIER_PORT: String(verifierPort),
    }),
  );
  await waitForOk(`http://127.0.0.1:${verifierPort}/health`);

  processes.push(
    spawnForSmoke('api', process.execPath, [tsxCli, 'server/src/devServer.ts'], {
      PORT: String(apiPort),
      VOICEID_VERIFIER_TRANSPORT: 'python-http',
      VOICEID_TRANSCRIPT_PROVIDER: 'fake',
      VOICEID_PYTHON_VERIFIER_URL: verifierUrl,
      VOICEID_VERIFIER_TIMEOUT_MS: '5000',
    }),
  );
  await waitForOk(`${apiUrl}/health`);

  const enrollment = await postJson('/voice-id/evidence/enrollment/start', {
    userId: 'owner',
  });
  const enrollmentId = enrollment.enrollmentId;

  const enrolled = await postRecording('/voice-id/evidence/enrollment/recording', {
    fields: { userId: 'owner', enrollmentId },
    durationMs: 18_000,
  });
  assertEqual(enrolled.kind, 'enrolled', 'enrollment result');

  const verification = await postJson('/voice-id/evidence/verification/start', {
    userId: 'owner',
    enrollmentId,
  });
  const verificationId = verification.verificationId;

  const result = await postRecording('/voice-id/evidence/verification/recording', {
    fields: {
      userId: 'owner',
      enrollmentId,
      verificationId,
    },
    durationMs: 4_000,
  });
  assertEqual(result.kind, 'evidence_observed', 'verification result');

  console.log(`VoiceID python-http API smoke passed on API ${apiUrl} and verifier ${verifierUrl}`);
} catch (error) {
  printChildOutput();
  throw error;
} finally {
  await shutdown();
}

function spawnForSmoke(name, command, args, env) {
  const child = spawn(command, args, {
    cwd,
    env: {
      ...process.env,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const output = [];
  child.stdout.on('data', captureProcessOutput.bind(undefined, output, name));
  child.stderr.on('data', captureProcessOutput.bind(undefined, output, name));
  child.on('exit', captureProcessExit.bind(undefined, output, name));
  child.output = output;
  return child;
}

function captureProcessOutput(output, name, chunk) {
  output.push(`[${name}] ${chunk.toString('utf8')}`);
}

function captureProcessExit(output, name, code, signal) {
  if (code !== null && code !== 0) {
    output.push(`[${name}] exited with code ${code}`);
  }
  if (signal !== null) {
    output.push(`[${name}] exited with signal ${signal}`);
  }
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
  throw new Error(
    `timed out waiting for ${url}: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}

async function postJson(path, body) {
  const response = await fetch(`${apiUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return await readOkValue(response, path);
}

async function postRecording(path, input) {
  const bytes = input.durationMs === 18_000
    ? makeWav([
        [210, 4_000], [null, 500], [270, 4_000], [null, 500],
        [330, 4_000], [null, 500], [410, 4_000], [null, 500],
      ])
    : makeWav([[240, input.durationMs]]);
  const form = new FormData();
  form.set('audio', new Blob([bytes], { type: 'audio/wav' }));
  form.set('metadata', JSON.stringify(buildMetadata(bytes.byteLength, input.durationMs)));
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

function buildMetadata(byteLength, durationMs) {
  return {
    mimeType: 'audio/wav',
    durationMs,
    sampleRate: { kind: 'known', hertz: 16000 },
    channelCount: { kind: 'known', count: 1 },
    byteLength,
    capturedAt: new Date('2026-06-13T00:00:00.000Z').toISOString(),
    recorder: 'smoke',
  };
}

function makeWav(segments) {
  const sampleRateHz = 16_000;
  const sampleCount = segments.reduce(
    (total, segment) => total + Math.round(sampleRateHz * segment[1] / 1000),
    0,
  );
  const buffer = Buffer.alloc(44 + sampleCount * 2);
  writeWavHeader(buffer, sampleCount, sampleRateHz);
  let sampleOffset = 0;
  for (const [frequencyHz, durationMs] of segments) {
    const segmentSampleCount = Math.round(sampleRateHz * durationMs / 1000);
    for (let index = 0; index < segmentSampleCount; index += 1) {
      const seconds = index / sampleRateHz;
      const phase = frequencyHz === null
        ? 0
        : 2 * Math.PI * (frequencyHz * seconds + 15 * seconds * seconds);
      const sample = frequencyHz === null ? 0 : Math.round(0.2 * 32767 * Math.sin(phase));
      buffer.writeInt16LE(sample, 44 + sampleOffset * 2);
      sampleOffset += 1;
    }
  }
  return buffer;
}

function writeWavHeader(buffer, sampleCount, sampleRateHz) {
  buffer.write('RIFF', 0, 'ascii');
  buffer.writeUInt32LE(36 + sampleCount * 2, 4);
  buffer.write('WAVE', 8, 'ascii');
  buffer.write('fmt ', 12, 'ascii');
  buffer.writeUInt32LE(16, 16);
  buffer.writeUInt16LE(1, 20);
  buffer.writeUInt16LE(1, 22);
  buffer.writeUInt32LE(sampleRateHz, 24);
  buffer.writeUInt32LE(sampleRateHz * 2, 28);
  buffer.writeUInt16LE(2, 32);
  buffer.writeUInt16LE(16, 34);
  buffer.write('data', 36, 'ascii');
  buffer.writeUInt32LE(sampleCount * 2, 40);
}

async function freePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  const closed = once(server, 'close');
  server.close();
  await closed;
  if (address !== null && typeof address === 'object') {
    return address.port;
  }
  throw new Error('failed to allocate a free port');
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} expected ${expected}, got ${actual}`);
  }
}

async function shutdown() {
  const shutdowns = [];
  for (const child of processes) {
    shutdowns.push(stopProcess(child));
  }
  await Promise.all(shutdowns);
}

async function stopProcess(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  const gracefulExit = once(child, 'exit');
  child.kill('SIGTERM');
  const gracefulResult = await Promise.race([gracefulExit, delay(2_000, null)]);
  if (gracefulResult !== null || child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  const forcedExit = once(child, 'exit');
  child.kill('SIGKILL');
  await Promise.race([forcedExit, delay(2_000, null)]);
}

function printChildOutput() {
  for (const child of processes) {
    for (const line of child.output ?? []) {
      process.stderr.write(line);
    }
  }
}
