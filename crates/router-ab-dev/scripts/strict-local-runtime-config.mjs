import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { resolveLocalConsoleOrganizationId } from './local-console-identity.mjs';
import {
  localPeerSigningKeyBase64Url,
  localPeerVerifyingKeyHex,
} from './router-ab-local-key-material.mjs';

const STRICT_WORKER_ROLES = Object.freeze([
  { role: 'router', port: 4102 },
  {
    role: 'deriver-a',
    port: 4103,
    privateD1: {
      databaseName: 'router-ab-deriver-a-private',
      migrationsDirectory: 'deriver-a',
      localDatabaseId: '00000000-0000-0000-0000-0000000094a1',
    },
  },
  {
    role: 'deriver-b',
    port: 4104,
    privateD1: {
      databaseName: 'router-ab-deriver-b-private',
      migrationsDirectory: 'deriver-b',
      localDatabaseId: '00000000-0000-0000-0000-0000000094b1',
    },
  },
  {
    role: 'signing-worker',
    port: 4105,
    privateD1: {
      databaseName: 'router-ab-signing-worker-private',
      migrationsDirectory: 'signing-worker',
      localDatabaseId: '00000000-0000-0000-0000-0000000094c1',
    },
  },
  { role: 'tenant-root-control-plane', port: 4106 },
]);
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function prepareRouterAbStrictLocalRuntimeConfigs(input) {
  const repoRoot = path.resolve(input.repoRoot);
  const localEnvRoot = path.resolve(input.localEnvRoot ?? repoRoot);
  const outputRoot = path.resolve(
    input.outputRoot ?? path.join(localEnvRoot, '.runtime', 'router-ab-strict'),
  );
  const routerEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.router.local'));
  const deriverAEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.deriver-a.local'));
  const deriverBEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.deriver-b.local'));
  const signingWorkerEnv = readEnvMap(
    path.join(localEnvRoot, '.env.router-ab.signing-worker.local'),
  );
  const tenantRootKeys = resolveLocalTenantRootKeyMaterial({
    repoRoot,
    localEnvRoot,
  });
  const localConsoleOrganizationId = resolveLocalConsoleOrganizationId({ localEnvRoot });
  const privateD1Keys = Object.freeze({
    deriverA: deriveLocalPrivateD1KeyPair(
      requiredEnv(deriverAEnv, 'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY'),
      'deriver-a',
    ),
    deriverB: deriveLocalPrivateD1KeyPair(
      requiredEnv(deriverBEnv, 'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY'),
      'deriver-b',
    ),
    signingWorker: deriveLocalPrivateD1KeyPair(
      requiredEnv(signingWorkerEnv, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY'),
      'signing-worker',
    ),
  });
  const ceremonyJwksJson = requireNonEmptyInput(input.ceremonyJwksJson, 'ceremonyJwksJson');
  const sdkRouterUrl = requiredEnv(routerEnv, 'GATEWAY_PUBLIC_URL');
  const mpcRouterUrl = `http://127.0.0.1:${STRICT_WORKER_ROLES[0].port}`;

  mkdirSync(outputRoot, { recursive: true });

  const configs = [];
  for (const { role, port, privateD1 = null } of STRICT_WORKER_ROLES) {
    const sourcePath = path.join(
      repoRoot,
      'crates',
      'router-ab-cloudflare',
      `wrangler.${role}.toml`,
    );
    const outputPath = path.join(outputRoot, `wrangler.${role}.toml`);
    const mainPath = path
      .relative(
        outputRoot,
        path.join(repoRoot, 'crates', 'router-ab-cloudflare', 'build', role, 'worker', 'shim.mjs'),
      )
      .split(path.sep)
      .join('/');
    let config = stripBuildSection(readFileSync(sourcePath, 'utf8'));
    config = replaceTomlAssignment(config, 'main', mainPath);
    config = applyRoleVars(config, role, {
      sdkRouterUrl,
      routerEnv,
      deriverAEnv,
      deriverBEnv,
      signingWorkerEnv,
      localConsoleOrganizationId,
      ceremonyJwksJson,
      privateD1Keys,
      tenantRootKeys,
    });
    if (privateD1) {
      config = setPrivateD1MigrationsDirectory(config, repoRoot, privateD1.migrationsDirectory);
      config = setPrivateD1LocalDatabaseId(config, privateD1.localDatabaseId);
    }
    writeFileSync(outputPath, config);
    const secretPath = path.join(outputRoot, `.dev.vars.${role}`);
    writeFileSync(
      secretPath,
      strictRoleSecretFile(role, {
        routerEnv,
        deriverAEnv,
        deriverBEnv,
        signingWorkerEnv,
        privateD1Keys,
        tenantRootKeys,
      }),
      { mode: 0o600 },
    );
    chmodSync(secretPath, 0o600);
    configs.push(
      Object.freeze({
        role,
        port,
        url: `http://127.0.0.1:${port}`,
        configPath: outputPath,
        secretPath,
        privateD1,
      }),
    );
  }

  return Object.freeze({
    outputRoot,
    mpcRouterUrl,
    workerUrls: Object.freeze({
      mpcRouter: configs[0].url,
      deriverA: configs[1].url,
      deriverB: configs[2].url,
      signingWorker: configs[3].url,
    }),
    configs: Object.freeze(configs),
    localConsoleOrganizationId,
  });
}

function setPrivateD1MigrationsDirectory(source, repoRoot, migrationsDirectory) {
  const expected = `migrations_dir = "migrations/${migrationsDirectory}"`;
  const matches = source.split(/\r?\n/).filter((line) => line === expected).length;
  if (matches === 0) {
    throw new Error(`strict local Wrangler config must define ${expected}`);
  }
  const absoluteDirectory = path.join(
    repoRoot,
    'crates',
    'router-ab-cloudflare',
    'migrations',
    migrationsDirectory,
  );
  return source.replaceAll(expected, `migrations_dir = ${JSON.stringify(absoluteDirectory)}`);
}

/**
 * Pin the top-level [[d1_databases]] id to a role-stable local value.
 *
 * Miniflare keys its on-disk D1 storage by database_id, so the id IS the local
 * database's identity: if the rendered id tracked the base config's deploy
 * placeholders, every placeholder rename would silently orphan all local
 * signing/derivation state (wallet activations included) on the next stack
 * start. The pinned ids predate the placeholder scheme, which also keeps
 * existing local state files reachable. Only the first database_id line is
 * rewritten — the [env.*] sections are never exercised by local dev.
 */
function setPrivateD1LocalDatabaseId(source, localDatabaseId) {
  if (!/^[0-9a-f-]{36}$/.test(localDatabaseId || '')) {
    throw new Error('strict local private D1 requires a pinned localDatabaseId');
  }
  const assignment = /^database_id\s*=.*$/m;
  if (!assignment.test(source)) {
    throw new Error('strict local Wrangler config must define database_id');
  }
  return source.replace(assignment, `database_id = ${JSON.stringify(localDatabaseId)}`);
}

function applyRoleVars(source, role, env) {
  const internalSecretBinding = 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET';
  let config = setTomlSectionAssignment(
    source,
    'vars',
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING',
    internalSecretBinding,
  );
  switch (role) {
    case 'router':
      config = setTomlSectionAssignment(config, 'vars', 'ROUTER_JWT_ISSUER', env.sdkRouterUrl);
      config = setTomlSectionAssignment(config, 'vars', 'ROUTER_JWT_AUDIENCE', 'router-ab');
      config = setTomlSectionAssignment(
        config,
        'vars',
        'ROUTER_JWT_JWKS_JSON',
        env.ceremonyJwksJson,
      );
      return setTenantRootPublicKeys(replaceTopologyPublicVars(config, env), env);
    case 'deriver-a':
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
        requiredEnv(env.routerEnv, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
        requiredEnv(env.routerEnv, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
      );
      return setTenantRootDeriverVars(
        setPrivateD1Vars(config, 'DERIVER_ROLE_PRIVATE_D1', env.privateD1Keys.deriverA),
        'A',
        env,
      );
    case 'deriver-b':
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
        requiredEnv(env.routerEnv, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
        requiredEnv(env.routerEnv, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
      );
      return setTenantRootDeriverVars(
        setPrivateD1Vars(config, 'DERIVER_ROLE_PRIVATE_D1', env.privateD1Keys.deriverB),
        'B',
        env,
      );
    case 'signing-worker':
      config = setTomlSectionAssignment(
        config,
        'vars',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
        requiredEnv(env.signingWorkerEnv, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY'),
      );
      return setPrivateD1Vars(config, 'SIGNING_WORKER_PRIVATE_D1', env.privateD1Keys.signingWorker);
    case 'tenant-root-control-plane':
      config = setTomlSectionAssignment(
        config,
        'vars',
        'TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID',
        env.tenantRootKeys.issuer.keyId,
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'TENANT_ROOT_CONTROL_PLANE_GRANT_AUTHORITY_VERIFYING_KEYS_JSON',
        env.tenantRootKeys.grantAuthority.verifyingKeysJson,
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'OPERATIONS_INCIDENT_VERIFYING_KEY_HEX',
        env.tenantRootKeys.operationsIncidentVerifyingKeyHex,
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_A_CUSTODY_AUTHORITY_VERIFYING_KEY_HEX',
        env.tenantRootKeys.deriverACustodyAuthorityVerifyingKeyHex,
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_B_CUSTODY_AUTHORITY_VERIFYING_KEY_HEX',
        env.tenantRootKeys.deriverBCustodyAuthorityVerifyingKeyHex,
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
      );
      config = setTomlSectionAssignment(
        config,
        'vars',
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
      );
      return setTenantRootPublicKeys(config, env);
    default:
      throw new Error(`unsupported strict local worker role ${role}`);
  }
}

function setTenantRootPublicKeys(source, env) {
  let config = setTomlSectionAssignment(
    source,
    'vars',
    'TENANT_ROOT_CONTROL_PLANE_ISSUER_VERIFYING_KEYS_JSON',
    env.tenantRootKeys.issuer.verifyingKeysJson,
  );
  return setTomlSectionAssignment(
    config,
    'vars',
    'ROUTER_TENANT_ROOT_CREATION_ROLE_VERIFYING_KEYS_JSON',
    env.tenantRootKeys.roleVerifyingKeysJson,
  );
}

function setTenantRootDeriverVars(source, suffix, env) {
  const role = suffix === 'A' ? env.tenantRootKeys.deriverA : env.tenantRootKeys.deriverB;
  let config = setTenantRootPublicKeys(source, env);
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_CREATION_SIGNING_KEY_BINDING`,
    `DERIVER_${suffix}_TENANT_ROOT_CREATION_SIGNING_KEY`,
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_CREATION_SIGNING_KEY_ID`,
    role.creationSigningKeyId,
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_ONLINE_EPOCH_WRAPPING_KEY_REF`,
    role.onlineEpochWrappingKeyRef,
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_ONLINE_HPKE_PUBLIC_KEY`,
    role.onlineKey.publicKey,
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY_BINDING`,
    `DERIVER_${suffix}_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY`,
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_MANAGED_BACKUP_PROVIDER_ID`,
    role.managedBackupProviderId,
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION`,
    role.managedBackupKeyVersion,
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_MANAGED_BACKUP_HPKE_PUBLIC_KEY`,
    role.managedBackupKey.publicKey,
  );
  return setTomlSectionAssignment(
    config,
    'vars',
    `DERIVER_${suffix}_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY_BINDING`,
    `DERIVER_${suffix}_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY`,
  );
}

function replaceTopologyPublicVars(source, env) {
  let config = setTomlSectionAssignment(
    source,
    'vars',
    'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
    requiredEnv(env.routerEnv, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
    requiredEnv(env.routerEnv, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    'DERIVER_A_PEER_VERIFYING_KEY_HEX',
    localPeerVerifyingKeyHex(requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
  );
  config = setTomlSectionAssignment(
    config,
    'vars',
    'DERIVER_B_PEER_VERIFYING_KEY_HEX',
    localPeerVerifyingKeyHex(requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
  );
  return setTomlSectionAssignment(
    config,
    'vars',
    'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
    requiredEnv(env.signingWorkerEnv, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY'),
  );
}

function strictRoleSecretFile(role, env) {
  const internalAuthSecret = `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET=${requiredEnv(
    env.routerEnv,
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
  )}`;
  switch (role) {
    case 'router':
      return `${internalAuthSecret}\n`;
    case 'deriver-a':
      return [
        internalAuthSecret,
        `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY=${versionedHexSecret(
          requiredEnv(env.deriverAEnv, 'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY'),
          'hpke-x25519-private-v1:',
          'Deriver A envelope HPKE private key',
        )}`,
        `DERIVER_A_PEER_SIGNING_KEY=${localPeerSigningKeyBase64Url(
          requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY'),
        )}`,
        `DERIVER_A_ROLE_PRIVATE_D1_KEK=hpke-x25519-role-private-d1-private-v1:${env.privateD1Keys.deriverA.privateKeyHex}`,
        `DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY=${env.tenantRootKeys.deriverA.creationSigningSeedB64u}`,
        `DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:${env.tenantRootKeys.deriverA.onlineKey.privateKeyHex}`,
        `DERIVER_A_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:${env.tenantRootKeys.deriverA.managedBackupKey.privateKeyHex}`,
        '',
      ].join('\n');
    case 'deriver-b':
      return [
        internalAuthSecret,
        `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY=${versionedHexSecret(
          requiredEnv(env.deriverBEnv, 'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY'),
          'hpke-x25519-private-v1:',
          'Deriver B envelope HPKE private key',
        )}`,
        `DERIVER_B_PEER_SIGNING_KEY=${localPeerSigningKeyBase64Url(
          requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY'),
        )}`,
        `DERIVER_B_ROLE_PRIVATE_D1_KEK=hpke-x25519-role-private-d1-private-v1:${env.privateD1Keys.deriverB.privateKeyHex}`,
        `DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY=${env.tenantRootKeys.deriverB.creationSigningSeedB64u}`,
        `DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:${env.tenantRootKeys.deriverB.onlineKey.privateKeyHex}`,
        `DERIVER_B_TENANT_ROOT_MANAGED_BACKUP_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:${env.tenantRootKeys.deriverB.managedBackupKey.privateKeyHex}`,
        '',
      ].join('\n');
    case 'signing-worker':
      return [
        internalAuthSecret,
        `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY=${versionedHexSecret(
          requiredEnv(env.signingWorkerEnv, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY'),
          'hpke-x25519-server-output-private-v1:',
          'SigningWorker server-output HPKE private key',
        )}`,
        `SIGNING_WORKER_PRIVATE_D1_KEK=hpke-x25519-server-output-private-v1:${env.privateD1Keys.signingWorker.privateKeyHex}`,
        '',
      ].join('\n');
    case 'tenant-root-control-plane':
      return [
        internalAuthSecret,
        `TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY=${env.tenantRootKeys.issuer.signingSeedB64u}`,
        '',
      ].join('\n');
    default:
      throw new Error(`unsupported strict local worker role ${role}`);
  }
}

function setPrivateD1Vars(source, prefix, keyPair) {
  let config = setTomlSectionAssignment(
    source,
    'vars',
    `${prefix}_KEK_PUBLIC_KEY`,
    keyPair.publicKey,
  );
  config = setTomlSectionAssignment(config, 'vars', `${prefix}_KEK_VERSION`, 'local-epoch-1');
  return setTomlSectionAssignment(config, 'vars', `${prefix}_ENVIRONMENT`, 'local');
}

function deriveLocalPrivateD1KeyPair(seedHex, role) {
  return deriveLocalX25519KeyPair(
    seedHex,
    `private-d1/${role}`,
    `seams/router-ab/private-d1/local/v1/${role}\0`,
  );
}

function deriveLocalX25519KeyPair(
  seedHex,
  purpose,
  derivationDomain = `seams/router-ab/local/v1/${purpose}\0`,
) {
  if (!/^[0-9a-f]{64}$/.test(seedHex)) {
    throw new Error(`${purpose} local key seed must be 32 lowercase hexadecimal bytes`);
  }
  const privateKey = createHash('sha256')
    .update(derivationDomain, 'utf8')
    .update(Buffer.from(seedHex, 'hex'))
    .digest();
  const privateKeyDer = Buffer.concat([X25519_PKCS8_PREFIX, privateKey]);
  const publicKeyDer = createPublicKey(
    createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' }),
  ).export({ format: 'der', type: 'spki' });
  if (!publicKeyDer.subarray(0, X25519_SPKI_PREFIX.length).equals(X25519_SPKI_PREFIX)) {
    throw new Error(`${purpose} local X25519 public key encoding is invalid`);
  }
  return Object.freeze({
    privateKeyHex: privateKey.toString('hex'),
    publicKey: `x25519:${publicKeyDer.subarray(X25519_SPKI_PREFIX.length).toString('hex')}`,
  });
}

function deriveLocalEd25519KeyPair(seedInput, purpose, derive = true) {
  const sourceSeed = localSeedBytes(seedInput, purpose);
  const seed = derive
    ? createHash('sha256')
        .update(`seams/router-ab/local/v1/${purpose}\0`, 'utf8')
        .update(sourceSeed)
        .digest()
    : sourceSeed;
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKeyDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  if (!publicKeyDer.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error(`${purpose} local Ed25519 public key encoding is invalid`);
  }
  return Object.freeze({
    signingSeedB64u: seed.toString('base64url'),
    verifyingKeyHex: publicKeyDer.subarray(ED25519_SPKI_PREFIX.length).toString('hex'),
  });
}

export function resolveLocalTenantRootKeyMaterial(input) {
  const repoRoot = path.resolve(input.repoRoot);
  const localEnvRoot = path.resolve(input.localEnvRoot ?? repoRoot);
  const controlPlaneEnv = readEnvMap(
    path.join(repoRoot, 'crates', 'router-ab-dev', 'env', 'tenant-root-control-plane.local.example'),
  );
  const deriverAEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.deriver-a.local'));
  const deriverBEnv = readEnvMap(path.join(localEnvRoot, '.env.router-ab.deriver-b.local'));
  const issuerKeyId = requiredEnv(
    controlPlaneEnv,
    'TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY_ID',
  );
  const issuerSeedHex = requiredEnv(
    controlPlaneEnv,
    'TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY',
  );
  const issuer = deriveLocalEd25519KeyPair(issuerSeedHex, 'tenant-root/issuer', false);
  const grantAuthority = deriveLocalEd25519KeyPair(
    issuerSeedHex,
    'tenant-root/grant-authority',
  );
  const operationsIncident = deriveLocalEd25519KeyPair(
    issuerSeedHex,
    'tenant-root/operations-incident',
  );
  const deriverACustodyAuthority = deriveLocalEd25519KeyPair(
    issuerSeedHex,
    'tenant-root/deriver-a-custody-authority',
  );
  const deriverBCustodyAuthority = deriveLocalEd25519KeyPair(
    issuerSeedHex,
    'tenant-root/deriver-b-custody-authority',
  );
  const deriverA = localTenantRootDeriverKeyMaterial(
    'A',
    requiredEnv(deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY'),
    requiredEnv(deriverAEnv, 'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY'),
  );
  const deriverB = localTenantRootDeriverKeyMaterial(
    'B',
    requiredEnv(deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY'),
    requiredEnv(deriverBEnv, 'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY'),
  );
  return Object.freeze({
    issuer: Object.freeze({
      keyId: issuerKeyId,
      signingSeedB64u: issuer.signingSeedB64u,
      verifyingKeysJson: issuerVerifyingKeysJson(issuerKeyId, issuer.verifyingKeyHex),
    }),
    grantAuthority: Object.freeze({
      keyId: 'local-tenant-root-grant-authority-v1',
      signingSeedB64u: grantAuthority.signingSeedB64u,
      verifyingKeysJson: issuerVerifyingKeysJson(
        'local-tenant-root-grant-authority-v1',
        grantAuthority.verifyingKeyHex,
      ),
    }),
    deriverA,
    deriverB,
    roleVerifyingKeysJson: JSON.stringify({
      active_deriver_a_signing_key_id: deriverA.creationSigningKeyId,
      active_deriver_b_signing_key_id: deriverB.creationSigningKeyId,
      keys: [
        {
          role: 'deriver_a',
          signing_key_id: deriverA.creationSigningKeyId,
          verifying_key_hex: deriverA.creationVerifyingKeyHex,
        },
        {
          role: 'deriver_b',
          signing_key_id: deriverB.creationSigningKeyId,
          verifying_key_hex: deriverB.creationVerifyingKeyHex,
        },
      ],
    }),
    operationsIncidentVerifyingKeyHex: operationsIncident.verifyingKeyHex,
    deriverACustodyAuthorityVerifyingKeyHex: deriverACustodyAuthority.verifyingKeyHex,
    deriverBCustodyAuthorityVerifyingKeyHex: deriverBCustodyAuthority.verifyingKeyHex,
  });
}

function localTenantRootDeriverKeyMaterial(suffix, signingSeed, hpkeSeedHex) {
  const lower = suffix.toLowerCase();
  const creation = deriveLocalEd25519KeyPair(
    signingSeed,
    `tenant-root/${lower}/creation-signing`,
  );
  return Object.freeze({
    creationSigningKeyId: `local-deriver-${lower}-tenant-root-creation-v1`,
    creationSigningSeedB64u: creation.signingSeedB64u,
    creationVerifyingKeyHex: creation.verifyingKeyHex,
    onlineEpochWrappingKeyRef: `local-deriver-${lower}-tenant-root-online-epoch-v1`,
    onlineKey: deriveLocalX25519KeyPair(hpkeSeedHex, `tenant-root/${lower}/online`),
    managedBackupProviderId: `local-deriver-${lower}-tenant-root-managed-backup`,
    managedBackupKeyVersion: `local-deriver-${lower}-tenant-root-backup-v1`,
    managedBackupKey: deriveLocalX25519KeyPair(
      hpkeSeedHex,
      `tenant-root/${lower}/managed-backup`,
    ),
  });
}

function localSeedBytes(value, purpose) {
  if (/^[0-9a-f]{64}$/.test(value)) return Buffer.from(value, 'hex');
  if (/^[A-Za-z0-9_-]{43}$/.test(value)) {
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.length === 32) return decoded;
  }
  throw new Error(`${purpose} local key seed must encode exactly 32 bytes`);
}

function issuerVerifyingKeysJson(keyId, verifyingKeyHex) {
  return JSON.stringify({
    keys: [{ issuer_key_id: keyId, verifying_key_hex: verifyingKeyHex }],
  });
}

function stripBuildSection(source) {
  return source.replace(/\n\[build\]\ncommand = [^\n]+\n/, '\n');
}

function replaceTomlAssignment(source, key, value) {
  const assignment = new RegExp(`^${escapeRegExp(key)}\\s*=.*$`, 'gm');
  const matches = source.match(assignment) ?? [];
  if (matches.length === 0) throw new Error(`strict local Wrangler config must define ${key}`);
  return source.replace(assignment, `${key} = ${JSON.stringify(value)}`);
}

function setTomlSectionAssignment(source, section, key, value) {
  const lines = source.split('\n');
  const header = `[${section}]`;
  const sectionIndexes = lines
    .map((line, index) => (line.trim() === header ? index : -1))
    .filter((index) => index >= 0);
  if (sectionIndexes.length !== 1) {
    throw new Error(`strict local Wrangler config must define exactly one ${header} section`);
  }

  const sectionStart = sectionIndexes[0] + 1;
  const nextSectionOffset = lines
    .slice(sectionStart)
    .findIndex((line) => line.trim().startsWith('['));
  const sectionEnd = nextSectionOffset === -1 ? lines.length : sectionStart + nextSectionOffset;
  const assignment = new RegExp(`^${escapeRegExp(key)}\\s*=`);
  const assignmentIndexes = [];
  for (let index = sectionStart; index < sectionEnd; index += 1) {
    if (assignment.test(lines[index].trim())) assignmentIndexes.push(index);
  }
  if (assignmentIndexes.length > 1) {
    throw new Error(`strict local Wrangler ${header} defines duplicate ${key} assignments`);
  }

  const rendered = `${key} = ${JSON.stringify(value)}`;
  if (assignmentIndexes.length === 1) {
    lines[assignmentIndexes[0]] = rendered;
  } else {
    lines.splice(sectionEnd, 0, rendered);
  }
  return lines.join('\n');
}

function requireNonEmptyInput(value, name) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`Router A/B strict local runtime is missing ${name}`);
  }
  return value.trim();
}

function readEnvMap(filePath) {
  const env = new Map();
  for (const rawLine of readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) throw new Error(`invalid env entry in ${filePath}`);
    env.set(line.slice(0, separator), line.slice(separator + 1));
  }
  return env;
}

function requiredEnv(env, key) {
  const value = env.get(key);
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`strict local runtime env is missing ${key}`);
  }
  return value.trim();
}

function versionedHexSecret(value, prefix, label) {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return `${prefix}${value}`;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
