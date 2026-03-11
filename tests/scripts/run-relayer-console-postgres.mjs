import { spawn } from 'node:child_process';

function normalizeEnvValue(value) {
  return typeof value === 'string' ? value.trim() : '';
}

const candidates = [
  { key: 'BILLING_POSTGRES_URL', value: normalizeEnvValue(process.env.BILLING_POSTGRES_URL) },
  { key: 'CONSOLE_POSTGRES_URL', value: normalizeEnvValue(process.env.CONSOLE_POSTGRES_URL) },
  { key: 'POSTGRES_URL', value: normalizeEnvValue(process.env.POSTGRES_URL) },
];

const selected = candidates.find((entry) => entry.value.length > 0) || null;
if (!selected) {
  console.error(
    '[test:relayer:console-postgres] Missing Postgres URL. Set BILLING_POSTGRES_URL, CONSOLE_POSTGRES_URL, or POSTGRES_URL.',
  );
  process.exit(1);
}

if (selected.key !== 'POSTGRES_URL') {
  console.log(
    `[test:relayer:console-postgres] using ${selected.key} as POSTGRES_URL for relayer console billing suites.`,
  );
}

const forwardedArgs = process.argv.slice(2);
if (forwardedArgs[0] === '--') {
  forwardedArgs.shift();
}

const args = [
  'exec',
  'playwright',
  'test',
  '-c',
  'playwright.relayer.config.ts',
  './relayer/console-billing.postgres.test.ts',
  './relayer/console-router.test.ts',
  './relayer/console-tenant-isolation.postgres.test.ts',
  '--reporter=line',
  ...forwardedArgs,
];

const child = spawn('pnpm', args, {
  stdio: 'inherit',
  env: {
    ...process.env,
    POSTGRES_URL: selected.value,
  },
});

child.on('error', (error) => {
  console.error(
    `[test:relayer:console-postgres] failed to start playwright process: ${
      error instanceof Error ? error.message : String(error)
    }`,
  );
  process.exit(1);
});

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
