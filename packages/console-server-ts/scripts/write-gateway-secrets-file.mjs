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

function main() {
  const outputPath = readOutputPath(process.argv.slice(2));
  const laneId = readLaneId();
  const lane = readBackendLane(laneId);
  requireProvisionedLane(laneId, lane.provisioning);
  const secrets = readRequiredSecrets([
    'CONSOLE_INITIAL_OWNER_EMAIL',
    ...gatewaySecretNames(lane),
  ]);
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
