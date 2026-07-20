import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const REQUIRED_SECRET_NAMES = [
  'RELAY_SESSION_HMAC_SECRET',
  'ACCOUNT_ID_DERIVATION_SECRET',
  'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
  'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
];
const OPTIONAL_SECRET_NAMES = ['RELAYER_PRIVATE_KEY', 'SPONSORED_EVM_EXECUTORS_JSON'];
const SIGNING_SESSION_SECRET_NAMES = [
  'SIGNING_SESSION_SEAL_KEY_VERSION',
  'SIGNING_SESSION_SHAMIR_P_B64U',
  'SIGNING_SESSION_SEAL_E_S_B64U',
  'SIGNING_SESSION_SEAL_D_S_B64U',
];

function main() {
  const outputPath = readOutputPath(process.argv.slice(2));
  const secrets = readRequiredSecrets();
  addOptionalSecrets(secrets);
  addSigningSessionSecrets(secrets);
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

function readRequiredSecrets() {
  return Object.fromEntries(
    REQUIRED_SECRET_NAMES.map((name) => [name, requireEnvironmentValue(name)]),
  );
}

function addOptionalSecrets(secrets) {
  for (const name of OPTIONAL_SECRET_NAMES) {
    const value = readEnvironmentValue(name);
    if (value) {
      secrets[name] = value;
    }
  }
}

function addSigningSessionSecrets(secrets) {
  const values = SIGNING_SESSION_SECRET_NAMES.map((name) => [name, readEnvironmentValue(name)]);
  const configuredCount = values.filter(([, value]) => Boolean(value)).length;
  if (configuredCount !== 0 && configuredCount !== values.length) {
    throw new Error('all signing-session seal secrets must be configured together');
  }
  for (const [name, value] of values) {
    if (value) {
      secrets[name] = value;
    }
  }
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
