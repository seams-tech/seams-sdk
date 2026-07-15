import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign, verify } from 'node:crypto';

const argv = process.argv.slice(2).filter((arg) => arg !== '--');
const envName = readOption('--env');
const apply = argv.includes('--apply');
const showSecrets = argv.includes('--show-secrets');
const json = argv.includes('--json');
const repo = readOption('--repo');

if (argv.includes('--help') || !envName) {
  console.log(`Usage:
  pnpm router:deploy:keygen -- --env staging
  pnpm router:deploy:keygen -- --env staging --show-secrets
  pnpm router:deploy:keygen -- --env staging --apply

Options:
  --env <name>      GitHub Environment name to target.
  --apply           Write generated values with gh variable set and gh secret set.
  --show-secrets    Print generated secret values for manual copy.
  --json            Print a machine-readable JSON document.
  --repo <owner/repo>
                    Pass an explicit repository to gh.

This command generates deployment identity keys only. It does not generate
DERIVER_A_ROOT_SHARE_WIRE_SECRET or DERIVER_B_ROOT_SHARE_WIRE_SECRET.`);
  process.exit(envName ? 0 : 1);
}

const deriverAEnvelope = generateX25519KeyPair();
const deriverBEnvelope = generateX25519KeyPair();
const signingWorkerServerOutput = generateX25519KeyPair();
const deriverAPeer = generateEd25519KeyPair();
const deriverBPeer = generateEd25519KeyPair();

const variables = {
  ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY: deriverAEnvelope.publicKey,
  ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY: deriverBEnvelope.publicKey,
  ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: signingWorkerServerOutput.publicKey,
  ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX: deriverAPeer.publicKeyHex,
  ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX: deriverBPeer.publicKeyHex,
};

const secrets = {
  DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverAEnvelope.privateKeyHex}`,
  DERIVER_A_PEER_SIGNING_KEY: deriverAPeer.signingSeedB64u,
  DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverBEnvelope.privateKeyHex}`,
  DERIVER_B_PEER_SIGNING_KEY: deriverBPeer.signingSeedB64u,
  SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY: `hpke-x25519-server-output-private-v1:${signingWorkerServerOutput.privateKeyHex}`,
};

const output = {
  environment: envName,
  generatedAt: new Date().toISOString(),
  variables,
  secrets: showSecrets ? secrets : redactObject(secrets),
  notGenerated: ['DERIVER_A_ROOT_SHARE_WIRE_SECRET', 'DERIVER_B_ROOT_SHARE_WIRE_SECRET'],
};

if (apply) {
  applyGithubEnvironmentValues(envName, variables, secrets, repo);
}

if (json) {
  console.log(JSON.stringify(output, null, 2));
} else {
  printHumanOutput(output, { showSecrets, apply });
}

function generateX25519KeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicBytes = decodeBase64UrlFixed(publicJwk.x, 32, 'X25519 public key');
  const privateBytes = decodeBase64UrlFixed(privateJwk.d, 32, 'X25519 private key');
  if (publicJwk.x !== privateJwk.x) {
    throw new Error('generated X25519 public/private JWK values do not match');
  }
  return {
    publicKey: `x25519:${publicBytes.toString('hex')}`,
    privateKeyHex: privateBytes.toString('hex'),
  };
}

function generateEd25519KeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicBytes = decodeBase64UrlFixed(publicJwk.x, 32, 'Ed25519 public key');
  const seedBytes = decodeBase64UrlFixed(privateJwk.d, 32, 'Ed25519 signing seed');
  if (publicJwk.x !== privateJwk.x) {
    throw new Error('generated Ed25519 public/private JWK values do not match');
  }
  const message = Buffer.from('router-ab-deployment-keygen-self-test-v1');
  const signature = sign(null, message, privateKey);
  if (!verify(null, message, publicKey, signature)) {
    throw new Error('generated Ed25519 key pair failed self-test verification');
  }
  return {
    publicKeyHex: publicBytes.toString('hex'),
    signingSeedB64u: encodeBase64Url(seedBytes),
  };
}

function applyGithubEnvironmentValues(environmentName, vars, secretValues, repoName) {
  for (const [name, value] of Object.entries(vars)) {
    runGh([
      'variable',
      'set',
      name,
      '--env',
      environmentName,
      '--body',
      value,
      ...repoArgs(repoName),
    ]);
  }
  for (const [name, value] of Object.entries(secretValues)) {
    runGh([
      'secret',
      'set',
      name,
      '--env',
      environmentName,
      '--body',
      value,
      ...repoArgs(repoName),
    ]);
  }
}

function runGh(args) {
  const child = spawnSync('gh', args, { stdio: 'inherit', encoding: 'utf8' });
  if (child.status !== 0) {
    throw new Error(`gh ${args.join(' ')} failed with status ${child.status}`);
  }
}

function repoArgs(repoName) {
  return repoName ? ['--repo', repoName] : [];
}

function printHumanOutput(data, options) {
  console.log(`Router A/B deployment keys for GitHub Environment: ${data.environment}`);
  if (options.apply) {
    console.log('Applied generated values with gh.');
  }
  console.log('\nGitHub Environment variables:');
  for (const [name, value] of Object.entries(data.variables)) {
    console.log(`${name}=${value}`);
  }
  console.log('\nGitHub Environment secrets:');
  for (const [name, value] of Object.entries(data.secrets)) {
    console.log(`${name}=${value}`);
  }
  if (!options.showSecrets) {
    console.log('\nPass --show-secrets to print private values for manual copy.');
  }
  console.log('\nNot generated by this command:');
  for (const name of data.notGenerated) {
    console.log(`- ${name}`);
  }
}

function redactObject(values) {
  return Object.fromEntries(
    Object.entries(values).map(([name, value]) => [name, redactSecret(value)]),
  );
}

function redactSecret(value) {
  const prefix = value.includes(':') ? `${value.split(':', 1)[0]}:` : '';
  return `${prefix}<redacted>`;
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

function decodeBase64UrlFixed(value, expectedLength, label) {
  if (!value) {
    throw new Error(`${label} is missing`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes`);
  }
  return bytes;
}

function encodeBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}
