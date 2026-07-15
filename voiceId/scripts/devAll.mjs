import { spawn } from 'node:child_process';

const children = [
  spawn('pnpm', ['run', 'dev:server'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      VOICEID_VERIFIER_TRANSPORT: 'fake',
      VOICEID_TRANSCRIPT_PROVIDER: 'fake',
    },
    stdio: 'inherit',
  }),
  spawn('pnpm', ['run', 'dev'], {
    cwd: new URL('..', import.meta.url),
    stdio: 'inherit',
  }),
];

function shutdown(signal) {
  for (const child of children) {
    child.kill(signal);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
