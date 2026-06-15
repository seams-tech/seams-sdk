import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const crateRoot = join(scriptDir, '..');

const roles = [
  {
    label: 'router',
    config: 'wrangler.router.toml',
    outDir: 'bundled/startup/router',
  },
  {
    label: 'deriver-a',
    config: 'wrangler.signer-a.toml',
    outDir: 'bundled/startup/deriver-a',
  },
  {
    label: 'deriver-b',
    config: 'wrangler.signer-b.toml',
    outDir: 'bundled/startup/deriver-b',
  },
  {
    label: 'signing-worker',
    config: 'wrangler.signing-worker.toml',
    outDir: 'bundled/startup/signing-worker',
  },
];

const roleVarKeys = {
  router: [
    'ROUTER_JWT_ISSUER',
    'ROUTER_JWT_AUDIENCE',
    'ROUTER_JWT_JWKS_URL',
    'SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY',
    'SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY',
    'SIGNER_A_PEER_VERIFYING_KEY_HEX',
    'SIGNER_B_PEER_VERIFYING_KEY_HEX',
    'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
  ],
  'deriver-a': [
    'SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY',
    'SIGNER_A_PEER_VERIFYING_KEY_HEX',
    'SIGNER_B_PEER_VERIFYING_KEY_HEX',
  ],
  'deriver-b': [
    'SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY',
    'SIGNER_A_PEER_VERIFYING_KEY_HEX',
    'SIGNER_B_PEER_VERIFYING_KEY_HEX',
  ],
  'signing-worker': ['SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY'],
};

const argv = process.argv.slice(2).filter((arg) => arg !== '--');
const upload = argv.includes('--upload');
const dryRun = argv.includes('--dry-run');
const selectedRole = readOption('--role');
const envName = readOption('--env');
const reportPath = resolveReportPath(
  readOption('--out') ??
    join(
      'reports',
      'startup-latencies',
      `startup-latencies-${new Date().toISOString().replace(/[:.]/g, '-')}.json`,
    ),
);

if (!upload && !dryRun) {
  console.log(`Usage:
  pnpm -C crates/router-ab-cloudflare measure:startup-latencies -- --upload
  pnpm -C crates/router-ab-cloudflare measure:startup-latencies -- --dry-run

Options:
  --upload       Run wrangler versions upload and parse startup_time_ms.
  --dry-run      Validate build/upload shape without creating Worker versions.
  --role <role>  Limit to one role: router, deriver-a, deriver-b, signing-worker.
  --env <env>    Target a Wrangler environment, usually staging or production.
  --out <path>   Write JSON report to a custom path.

Dry-run output does not emit startup_time_ms. Use --upload for release evidence.`);
  process.exit(0);
}

const selectedRoles = selectedRole ? roles.filter((role) => role.label === selectedRole) : roles;

if (selectedRoles.length === 0) {
  throw new Error(`unknown role '${selectedRole}'`);
}

const report = {
  generatedAt: new Date().toISOString(),
  mode: upload ? 'versions_upload' : 'dry_run',
  env: envName ?? null,
  measurements: [],
};

let failed = false;
for (const role of selectedRoles) {
  const args = [
    'versions',
    'upload',
    '--config',
    role.config,
    '--outdir',
    role.outDir,
    '--message',
    `Router A/B startup latency capture for ${role.label}`,
  ];
  if (envName) {
    args.push('--env', envName);
  }
  for (const [key, value] of roleVars(role.label)) {
    args.push('--var', `${key}:${value}`);
  }
  if (dryRun) {
    args.push('--dry-run');
  }

  console.log(`\n== ${role.label}: wrangler ${args.join(' ')} ==`);
  const child = spawnSync('wrangler', args, {
    cwd: crateRoot,
    encoding: 'utf8',
    env: process.env,
  });
  process.stdout.write(child.stdout ?? '');
  process.stderr.write(child.stderr ?? '');

  const output = `${child.stdout ?? ''}\n${child.stderr ?? ''}`;
  const measurement = {
    role: role.label,
    config: role.config,
    status: child.status,
    startupTimeMs: parseStartupTimeMs(output),
    upload: parseUploadSize(output),
  };
  report.measurements.push(measurement);
  if (child.status !== 0) {
    failed = true;
  }
}

mkdirSync(dirname(reportPath), { recursive: true });
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(`\nWrote ${reportPath}`);

if (failed) {
  process.exit(1);
}

function readOption(name) {
  const index = argv.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function roleVars(label) {
  const keys = roleVarKeys[label] ?? [];
  return keys
    .map((key) => [key, process.env[key]])
    .filter((entry) => entry[1] !== undefined && entry[1] !== '');
}

function parseStartupTimeMs(output) {
  const clean = stripAnsi(output);
  for (const pattern of [
    /startup_time_ms["'\s:=]+([0-9]+(?:\.[0-9]+)?)/i,
    /startup\s*time\s*:?\s*([0-9]+(?:\.[0-9]+)?)\s*ms/i,
  ]) {
    const match = clean.match(pattern);
    if (match) {
      return Number(match[1]);
    }
  }
  return null;
}

function parseUploadSize(output) {
  const clean = stripAnsi(output);
  const match = clean.match(
    /Total Upload:\s*([0-9]+(?:\.[0-9]+)?)\s*KiB\s*\/\s*gzip:\s*([0-9]+(?:\.[0-9]+)?)\s*KiB/i,
  );
  if (!match) {
    return null;
  }
  return {
    totalKiB: Number(match[1]),
    gzipKiB: Number(match[2]),
  };
}

function stripAnsi(value) {
  return value.replace(/\x1b\[[0-9;]*m/g, '');
}

function resolveReportPath(path) {
  return isAbsolute(path) ? path : join(crateRoot, path);
}
