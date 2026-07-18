import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import dotenv from 'dotenv';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const buildEnvPath = `${repoRoot}/.env.router-ab.ecdsa-commitment-policy.build.local`;
const requiredKeys = [
  'ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX',
  'ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX',
  'ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH',
];
const [command, ...args] = process.argv.slice(2);

if (!command) {
  throw new Error('commitment-policy build command is required');
}

const buildEnv = dotenv.parse(readFileSync(buildEnvPath));
for (const key of requiredKeys) {
  if (!buildEnv[key]) {
    throw new Error(`local commitment-policy build environment is missing ${key}`);
  }
}

const child = spawnSync(command, args, {
  cwd: repoRoot,
  env: { ...process.env, ...buildEnv },
  stdio: 'inherit',
});
process.exit(child.status ?? 1);
