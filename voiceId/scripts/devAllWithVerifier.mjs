import { spawn } from 'node:child_process';

const cwd = new URL('..', import.meta.url);
const apiPort = process.env.PORT ?? '8787';
const verifierPort = process.env.VOICEID_VERIFIER_PORT ?? '8797';
const verifierBackend = process.env.VOICEID_VERIFIER_BACKEND ?? 'placeholder';
const speakerScoreThreshold =
  process.env.VOICEID_SPEAKER_SCORE_THRESHOLD ?? (verifierBackend === 'ecapa' ? '0.6352' : undefined);
const verifierUrl =
  process.env.VOICEID_PYTHON_VERIFIER_URL ?? `http://127.0.0.1:${verifierPort}/voice-id/verifier/`;

const children = [
  spawnNamed('verifier', ['run', 'dev:verifier'], {
    VOICEID_VERIFIER_PORT: verifierPort,
    VOICEID_VERIFIER_BACKEND: verifierBackend,
  }),
  spawnNamed('api', ['run', 'dev:server'], {
    PORT: apiPort,
    VOICEID_VERIFIER_TRANSPORT: 'python-http',
    VOICEID_VERIFIER_BACKEND: verifierBackend,
    VOICEID_PYTHON_VERIFIER_URL: verifierUrl,
    ...(speakerScoreThreshold !== undefined ? { VOICEID_SPEAKER_SCORE_THRESHOLD: speakerScoreThreshold } : {}),
  }),
  spawnNamed('demo', ['run', 'dev'], {}),
];

let shuttingDown = false;

for (const child of children) {
  child.on('exit', (code, signal) => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    shutdown(signal ?? 'SIGTERM');
    process.exitCode = code ?? 1;
  });
}

function spawnNamed(name, args, env) {
  const child = spawn('pnpm', args, {
    cwd,
    env: {
      ...process.env,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  child.stdout.on('data', (chunk) => {
    process.stdout.write(prefixLines(name, chunk));
  });
  child.stderr.on('data', (chunk) => {
    process.stderr.write(prefixLines(name, chunk));
  });

  return child;
}

function shutdown(signal) {
  for (const child of children) {
    child.kill(signal);
  }
}

function prefixLines(name, chunk) {
  return chunk
    .toString('utf8')
    .split('\n')
    .map((line, index, lines) => {
      if (index === lines.length - 1 && line.length === 0) {
        return '';
      }
      return `[${name}] ${line}`;
    })
    .join('\n');
}

process.on('SIGINT', () => {
  shuttingDown = true;
  shutdown('SIGINT');
});
process.on('SIGTERM', () => {
  shuttingDown = true;
  shutdown('SIGTERM');
});
