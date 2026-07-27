import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { gatewaySecretNames, readDeploymentTarget } from '../../../scripts/deployment-targets.mjs';

const OPTIONAL_SECRET_NAMES = [
  'STRIPE_WEBHOOK_SECRET',
  'RELAYER_PRIVATE_KEY',
  'SPONSORED_EVM_EXECUTORS_JSON',
];

function main() {
  const outputPath = readOutputPath(process.argv.slice(2));
  const targetName = readTargetName();
  const target = readDeploymentTarget(targetName);
  const secrets = readRequiredSecrets(gatewaySecretNames(target));
  addOptionalSecrets(secrets);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(secrets)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  process.stdout.write(`${outputPath}\n`);
}

function readOutputPath(args) {
  if (args.length !== 2 || args[0] !== '--output') {
    throw new Error('usage: write-gateway-secrets-file.mjs --output <path>');
  }
  const value = String(args[1] || '').trim();
  if (!value) {
    throw new Error('--output requires a value');
  }
  return path.resolve(process.cwd(), value);
}

function readTargetName() {
  const target = String(process.env.DEPLOY_TARGET || '').trim();
  if (!target) throw new Error('DEPLOY_TARGET is required');
  return target;
}

function addOptionalSecrets(secrets) {
  for (const name of OPTIONAL_SECRET_NAMES) {
    const value = readEnvironmentValue(name);
    if (value) secrets[name] = value;
  }
}

function readRequiredSecrets(names) {
  const secrets = {};
  for (const name of names) {
    secrets[name] = requireEnvironmentValue(name);
  }
  return secrets;
}

function requireEnvironmentValue(name) {
  const value = readEnvironmentValue(name);
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function readEnvironmentValue(name) {
  return String(process.env[name] || '').trim();
}

main();
