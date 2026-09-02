import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { readBackendLane } from '../../../scripts/deployment-targets.mjs';

const argv = process.argv.slice(2).filter((arg) => arg !== '--');
assertNoLegacyIdentityFlags();
const apply = argv.includes('--apply');
const laneId = readOption('--lane');
const lane = laneId ? readBackendLane(laneId) : undefined;
if (apply && lane?.provisioning.kind === 'pending') {
  throw new Error(`${lane.id} is pending provisioning; deployment key generation is blocked`);
}
const environmentName = lane
  ? lane.resources.router.deploymentEnvironment.kind === 'named'
    ? lane.resources.router.deploymentEnvironment.name
    : lane.release
  : undefined;
const showSecrets = argv.includes('--show-secrets');
const json = argv.includes('--json');
const repo = readOption('--repo');

if (argv.includes('--help') || !laneId) {
  console.log(`Usage:
  pnpm router:deploy:keygen -- --lane staging-testnet
  pnpm router:deploy:keygen -- --lane staging-testnet --show-secrets
  pnpm router:deploy:keygen -- --lane staging-testnet --apply

Options:
  --lane <id>       Backend lane: staging-testnet, production-testnet, or production-mainnet.
  --apply           Write generated values with gh variable set and gh secret set.
  --show-secrets    Print generated secret values for manual copy.
  --json            Print a machine-readable JSON document.
  --repo <owner/repo>
                    Pass an explicit repository to gh.

This command generates deployment identity, operational-encryption,
tenant-root control-plane issuer, and Deriver role creation signing keys. It
does not generate
DERIVER_A_ROOT_SHARE_WIRE_SECRET, DERIVER_B_ROOT_SHARE_WIRE_SECRET, or
ROUTER_AB_TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON: the
tenant-root creation grant authority is external to the deployment, and a
command that could mint it would defeat the separation it exists for.

--apply does not place the tenant-root control-plane issuer values: it applies
to one generic environment, and the issuer seed must reach only the
*-tenant-root-control-plane environment. generate-github-env-values.mjs places
them per Worker.`);
  process.exit(laneId ? 0 : 1);
}

const deriverAEnvelope = generateX25519KeyPair();
const deriverBEnvelope = generateX25519KeyPair();
const deriverARolePrivateD1Kek = generateX25519KeyPair();
const deriverBRolePrivateD1Kek = generateX25519KeyPair();
const deriverATenantRootOnline = generateX25519KeyPair();
const deriverATenantRootManagedBackup = generateX25519KeyPair();
const deriverBTenantRootOnline = generateX25519KeyPair();
const deriverBTenantRootManagedBackup = generateX25519KeyPair();
const signingWorkerServerOutput = generateX25519KeyPair();
const signingWorkerPrivateD1Kek = generateX25519KeyPair();
const deriverAPeer = generateEd25519KeyPair();
const deriverBPeer = generateEd25519KeyPair();
// R120: one versioned issuer key per deployment environment. The private seed
// is held only by the tenant-root control-plane Worker; the public keyset is
// the trust anchor for Router, Deriver A, and Deriver B. The id carries the
// complete public-key hex, so it names exactly one key: 85 characters, inside
// the 256-character issuer key id limit.
const controlPlaneIssuer = generateEd25519KeyPair();
const controlPlaneIssuerKeyId = `control-plane-issuer-${controlPlaneIssuer.publicKeyHex}`;
// R120 Deriver role creation signing keys: each Deriver signs its own public
// commitments and installation evidence. Distinct from the A/B peer signing
// keys (the Rust loader rejects reuse) and role-local: A's seed reaches only
// the deriver-a environment, B's only deriver-b.
const deriverATenantRootCreation = generateEd25519KeyPair();
const deriverBTenantRootCreation = generateEd25519KeyPair();
const deriverATenantRootCreationKeyId = `deriver-a-tenant-root-creation-${deriverATenantRootCreation.publicKeyHex}`;
const deriverBTenantRootCreationKeyId = `deriver-b-tenant-root-creation-${deriverBTenantRootCreation.publicKeyHex}`;

const variables = {
  ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY: deriverAEnvelope.publicKey,
  ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY: deriverBEnvelope.publicKey,
  ROUTER_AB_DERIVER_A_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY: deriverARolePrivateD1Kek.publicKey,
  ROUTER_AB_DERIVER_A_ROLE_PRIVATE_D1_KEK_VERSION: 'epoch-1',
  ROUTER_AB_DERIVER_B_ROLE_PRIVATE_D1_KEK_PUBLIC_KEY: deriverBRolePrivateD1Kek.publicKey,
  ROUTER_AB_DERIVER_B_ROLE_PRIVATE_D1_KEK_VERSION: 'epoch-1',
  ROUTER_AB_DERIVER_A_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF:
    'cloudflare-worker-secret/deriver-a/tenant-root-online/key-1',
  ROUTER_AB_DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY: deriverATenantRootOnline.publicKey,
  ROUTER_AB_DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID:
    'cloudflare-worker-secret-operational-v1',
  ROUTER_AB_DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION: 'deriver-a-key-1',
  ROUTER_AB_DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY:
    deriverATenantRootManagedBackup.publicKey,
  ROUTER_AB_DERIVER_B_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF:
    'cloudflare-worker-secret/deriver-b/tenant-root-online/key-1',
  ROUTER_AB_DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY: deriverBTenantRootOnline.publicKey,
  ROUTER_AB_DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID:
    'cloudflare-worker-secret-operational-v1',
  ROUTER_AB_DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION: 'deriver-b-key-1',
  ROUTER_AB_DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY:
    deriverBTenantRootManagedBackup.publicKey,
  ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: signingWorkerServerOutput.publicKey,
  ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY: signingWorkerPrivateD1Kek.publicKey,
  ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_KEK_VERSION: 'epoch-1',
  ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX: deriverAPeer.publicKeyHex,
  ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX: deriverBPeer.publicKeyHex,
  ROUTER_AB_DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID: deriverATenantRootCreationKeyId,
  ROUTER_AB_DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID: deriverBTenantRootCreationKeyId,
  // Exact wire shape of TenantRootCreationRoleVerifyingKeySetWireV1 (deny_unknown_fields).
  ROUTER_AB_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON: JSON.stringify({
    keys: [
      {
        role: 'deriver_a',
        signing_key_id: deriverATenantRootCreationKeyId,
        verifying_key_hex: deriverATenantRootCreation.publicKeyHex,
      },
      {
        role: 'deriver_b',
        signing_key_id: deriverBTenantRootCreationKeyId,
        verifying_key_hex: deriverBTenantRootCreation.publicKeyHex,
      },
    ],
  }),
  ROUTER_AB_TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID: controlPlaneIssuerKeyId,
  // Exact wire shape of TenantRootCreationIssuerKeySetWireV1 (deny_unknown_fields).
  ROUTER_AB_TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON: JSON.stringify({
    keys: [
      {
        issuer_key_id: controlPlaneIssuerKeyId,
        verifying_key_hex: controlPlaneIssuer.publicKeyHex,
      },
    ],
  }),
};

const secrets = {
  DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverAEnvelope.privateKeyHex}`,
  DERIVER_A_ROLE_PRIVATE_D1_KEK: `hpke-x25519-role-private-d1-private-v1:${deriverARolePrivateD1Kek.privateKeyHex}`,
  DERIVER_A_PEER_SIGNING_KEY: deriverAPeer.signingSeedB64u,
  DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverATenantRootOnline.privateKeyHex}`,
  DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverATenantRootManagedBackup.privateKeyHex}`,
  DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverBEnvelope.privateKeyHex}`,
  DERIVER_B_ROLE_PRIVATE_D1_KEK: `hpke-x25519-role-private-d1-private-v1:${deriverBRolePrivateD1Kek.privateKeyHex}`,
  DERIVER_B_PEER_SIGNING_KEY: deriverBPeer.signingSeedB64u,
  DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverBTenantRootOnline.privateKeyHex}`,
  DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY: `hpke-x25519-private-v1:${deriverBTenantRootManagedBackup.privateKeyHex}`,
  SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY: `hpke-x25519-server-output-private-v1:${signingWorkerServerOutput.privateKeyHex}`,
  SIGNING_WORKER_PRIVATE_D1_KEK: `hpke-x25519-server-output-private-v1:${signingWorkerPrivateD1Kek.privateKeyHex}`,
  // base64url 32-byte Ed25519 seeds, the same encoding as the peer signing keys.
  DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY: deriverATenantRootCreation.signingSeedB64u,
  DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY: deriverBTenantRootCreation.signingSeedB64u,
  TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY: controlPlaneIssuer.signingSeedB64u,
};

// R120 control-plane values are NOT applied by this low-level generator.
// The issuer private seed must reach only the *-tenant-root-control-plane
// GitHub Environment, and this script derives one generic environment name for
// every value it applies. generate-github-env-values.mjs is topology-aware and
// places these into the correct per-Worker environments.
// The Deriver role creation seeds are role-local for the same reason: this
// script applies every value to one environment, which would place A's and
// B's seeds together.
const CONTROL_PLANE_OUTPUT_ONLY_VARIABLES = [
  'ROUTER_AB_DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY_ID',
  'ROUTER_AB_DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY_ID',
  'ROUTER_AB_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON',
  'ROUTER_AB_TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID',
  'ROUTER_AB_TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON',
];
const CONTROL_PLANE_OUTPUT_ONLY_SECRETS = [
  'DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY',
  'DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY',
  'TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY',
];

const output = {
  lane: laneId,
  environment: environmentName,
  generatedAt: new Date().toISOString(),
  variables,
  secrets: showSecrets ? secrets : redactObject(secrets),
  notGenerated: [
    'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
    'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
    // Deliberately not generated here: the grant authority is external to the
    // deployment, so this command must not be able to mint one.
    'ROUTER_AB_TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON',
  ],
  notApplied: [...CONTROL_PLANE_OUTPUT_ONLY_VARIABLES, ...CONTROL_PLANE_OUTPUT_ONLY_SECRETS],
};

if (apply) {
  applyGithubEnvironmentValues(
    environmentName,
    omitKeys(variables, CONTROL_PLANE_OUTPUT_ONLY_VARIABLES),
    omitKeys(secrets, CONTROL_PLANE_OUTPUT_ONLY_SECRETS),
    repo,
  );
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

function omitKeys(values, omitted) {
  return Object.fromEntries(Object.entries(values).filter(([name]) => !omitted.includes(name)));
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
  console.log(
    `Router A/B deployment keys for lane ${data.lane} (GitHub Environment: ${data.environment})`,
  );
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
  console.log('\nNot applied by --apply (placed per-Worker by generate-github-env-values.mjs;');
  console.log('the issuer seed belongs only in the tenant-root-control-plane environment):');
  for (const name of data.notApplied) {
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
  if (index !== -1) {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`${name} requires a value`);
    }
    return value;
  }
  const prefix = `${name}=`;
  const assignment = argv.find((argument) => argument.startsWith(prefix));
  if (!assignment) {
    return undefined;
  }
  const value = assignment.slice(prefix.length).trim();
  if (!value) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function assertNoLegacyIdentityFlags() {
  const legacyFlag = argv.find(
    (argument) =>
      argument === '--env' ||
      argument.startsWith('--env=') ||
      argument === '--target' ||
      argument.startsWith('--target='),
  );
  if (legacyFlag) {
    throw new Error(`${legacyFlag} is retired; use --lane <backend-lane-id>`);
  }
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
