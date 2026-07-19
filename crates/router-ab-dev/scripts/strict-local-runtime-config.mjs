import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import {
  localPeerSigningKeyBase64Url,
  localPeerVerifyingKeyHex,
} from './router-ab-local-key-material.mjs';

const STRICT_WORKER_ROLES = Object.freeze([
  { role: 'router', port: 9100 },
  { role: 'deriver-a', port: 9101 },
  { role: 'deriver-b', port: 9102 },
  { role: 'signing-worker', port: 9103 },
]);

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
  const sdkRouterUrl = requiredEnv(routerEnv, 'GATEWAY_PUBLIC_URL');
  const mpcRouterUrl = `http://127.0.0.1:${STRICT_WORKER_ROLES[0].port}`;

  mkdirSync(outputRoot, { recursive: true });

  const configs = [];
  for (const { role, port } of STRICT_WORKER_ROLES) {
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
    });
    writeFileSync(outputPath, config);
    const secretPath = path.join(outputRoot, `.dev.vars.${role}`);
    writeFileSync(
      secretPath,
      strictRoleSecretFile(role, { routerEnv, deriverAEnv, deriverBEnv, signingWorkerEnv }),
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
  });
}

function applyRoleVars(source, role, env) {
  const internalSecretBinding = 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET';
  let config = replaceTomlAssignment(
    source,
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING',
    internalSecretBinding,
  );
  switch (role) {
    case 'router':
      config = replaceTomlAssignment(config, 'ROUTER_JWT_ISSUER', env.sdkRouterUrl);
      config = replaceTomlAssignment(config, 'ROUTER_JWT_AUDIENCE', 'router-ab');
      config = replaceTomlAssignment(
        config,
        'ROUTER_JWT_JWKS_URL',
        `${env.sdkRouterUrl}/.well-known/router-ab-ceremony-jwks.json`,
      );
      config = replaceTopologyPublicVars(config, env);
      return replaceTomlAssignment(
        config,
        'ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON',
        JSON.stringify({
          org_id: 'local-smoke-org',
          project_id: 'local-smoke-project',
          environment: 'local',
          allowed_work_kinds: [
            'registration_prepare',
            'key_export',
            'recovery',
            'server_share_refresh',
          ],
          allow_normal_signing: true,
          rejected_retry_after_ms: 1000,
        }),
      );
    case 'deriver-a':
      config = replaceTomlAssignment(
        config,
        'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
        requiredEnv(env.routerEnv, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
      );
      config = replaceTomlAssignment(
        config,
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
      );
      return replaceTomlAssignment(
        config,
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
      );
    case 'deriver-b':
      config = replaceTomlAssignment(
        config,
        'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
        requiredEnv(env.routerEnv, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
      );
      config = replaceTomlAssignment(
        config,
        'DERIVER_A_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
      );
      return replaceTomlAssignment(
        config,
        'DERIVER_B_PEER_VERIFYING_KEY_HEX',
        localPeerVerifyingKeyHex(requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
      );
    case 'signing-worker':
      config = replaceTomlAssignment(
        config,
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
        requiredEnv(env.signingWorkerEnv, 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY'),
      );
      return config;
    default:
      throw new Error(`unsupported strict local worker role ${role}`);
  }
}

function replaceTopologyPublicVars(source, env) {
  let config = replaceTomlAssignment(
    source,
    'DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY',
    requiredEnv(env.routerEnv, 'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY'),
  );
  config = replaceTomlAssignment(
    config,
    'DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY',
    requiredEnv(env.routerEnv, 'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY'),
  );
  config = replaceTomlAssignment(
    config,
    'DERIVER_A_PEER_VERIFYING_KEY_HEX',
    localPeerVerifyingKeyHex(requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY')),
  );
  config = replaceTomlAssignment(
    config,
    'DERIVER_B_PEER_VERIFYING_KEY_HEX',
    localPeerVerifyingKeyHex(requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY')),
  );
  return replaceTomlAssignment(
    config,
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
        `DERIVER_A_ROOT_SHARE_WIRE_SECRET=${requiredEnv(env.deriverAEnv, 'DERIVER_A_ROOT_SHARE_WIRE_SECRET')}`,
        `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY=${versionedHexSecret(
          requiredEnv(env.deriverAEnv, 'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY'),
          'hpke-x25519-private-v1:',
          'Deriver A envelope HPKE private key',
        )}`,
        `DERIVER_A_PEER_SIGNING_KEY=${localPeerSigningKeyBase64Url(
          requiredEnv(env.deriverAEnv, 'DERIVER_A_PEER_SIGNING_KEY'),
        )}`,
        '',
      ].join('\n');
    case 'deriver-b':
      return [
        internalAuthSecret,
        `DERIVER_B_ROOT_SHARE_WIRE_SECRET=${requiredEnv(env.deriverBEnv, 'DERIVER_B_ROOT_SHARE_WIRE_SECRET')}`,
        `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY=${versionedHexSecret(
          requiredEnv(env.deriverBEnv, 'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY'),
          'hpke-x25519-private-v1:',
          'Deriver B envelope HPKE private key',
        )}`,
        `DERIVER_B_PEER_SIGNING_KEY=${localPeerSigningKeyBase64Url(
          requiredEnv(env.deriverBEnv, 'DERIVER_B_PEER_SIGNING_KEY'),
        )}`,
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
        '',
      ].join('\n');
    default:
      throw new Error(`unsupported strict local worker role ${role}`);
  }
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
