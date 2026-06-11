import { spawn } from 'node:child_process';

const children = [
  spawn('pnpm', ['run', 'dev:server'], {
    cwd: new URL('..', import.meta.url),
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
