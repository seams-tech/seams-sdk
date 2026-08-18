import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { gatewaySecretNames, readBackendLane } from '../../../scripts/deployment-targets.mjs';

const OPTIONAL_SECRET_NAMES = [
  'GITHUB_OAUTH_CALLBACK_URL',
  'GITHUB_OAUTH_CLIENT_ID',
  'GITHUB_OAUTH_CLIENT_SECRET',
  'STRIPE_WEBHOOK_SECRET',
  'RELAYER_PRIVATE_KEY',
  'SPONSORED_EVM_EXECUTORS_JSON',
];

const CONSOLE_REQUIRED_SECRET_NAMES = [
  'CONSOLE_INITIAL_OWNER_EMAIL',
  'CONSOLE_SESSION_HMAC_SECRET',
  'STRIPE_API_SK',
];

function main() {
  const { outputPath, profile } = readArguments(process.argv.slice(2));
  const laneId = readLaneId();
  const lane = readBackendLane(laneId);
  requireProvisionedLane(laneId, lane.provisioning);
  const secrets =
    profile === 'console'
      ? readRequiredSecrets(CONSOLE_REQUIRED_SECRET_NAMES)
      : readRequiredSecrets(['CONSOLE_INITIAL_OWNER_EMAIL', ...gatewaySecretNames(lane)]);
  addOptionalSecrets(secrets);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(secrets)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  process.stdout.write(`${outputPath}\n`);
}

function readArguments(args) {
  let output = '';
  let profile = 'gateway';
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--output') {
      output = String(args[index + 1] || '').trim();
      index += 1;
      continue;
    }
    if (args[index] === '--profile') {
      profile = String(args[index + 1] || '').trim();
      index += 1;
      continue;
    }
    throw new Error('usage: write-gateway-secrets-file.mjs --output <path> [--profile gateway|console]');
  }
  if (!output) throw new Error('--output requires a value');
  if (profile !== 'gateway' && profile !== 'console') {
    throw new Error('--profile must be gateway or console');
  }
  return { outputPath: path.resolve(process.cwd(), output), profile };
}

function readLaneId() {
  const lane = String(process.env.DEPLOYMENT_LANE || '').trim();
  if (!lane) throw new Error('DEPLOYMENT_LANE is required');
  return lane;
}

function requireProvisionedLane(laneId, provisioning) {
  if (provisioning.kind !== 'provisioned') {
    throw new Error(`lane ${laneId} is pending provisioning; Gateway secrets cannot be written`);
  }
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
