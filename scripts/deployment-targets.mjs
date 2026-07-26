import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseGatewayDeploymentConfig } from '../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_TARGETS_PATH = path.join(SCRIPT_DIRECTORY, '..', 'deployment', 'targets.json');

export const TARGET_NAMES = Object.freeze(['staging', 'production']);
export const BACKEND_COMPONENTS = Object.freeze([
  'signing-worker',
  'deriver-a',
  'deriver-b',
  'router',
  'gateway',
]);

const CAPABILITY_NAMES = Object.freeze(['billing', 'sponsoredExecution', 'signingSessionSeal']);
const CAPABILITY_OWNER_NAMES = new Set(['gateway']);
const DEPLOYMENT_RESOURCE_NAMES = Object.freeze([
  'gateway',
  'router',
  'deriverA',
  'deriverB',
  'signingWorker',
  'frontend',
]);
const GATEWAY_BASE_SECRET_NAMES = Object.freeze([
  'RELAY_SESSION_HMAC_SECRET',
  'ACCOUNT_ID_DERIVATION_SECRET',
  'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
  'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
]);

export function readDeploymentTargets(targetsPath = DEFAULT_TARGETS_PATH) {
  const absolutePath = path.resolve(targetsPath);
  let source;
  try {
    source = JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to read deployment targets ${absolutePath}: ${formatError(error)}`);
  }
  return parseDeploymentTargets(source, absolutePath);
}

export function readDeploymentTarget(targetName, targetsPath = DEFAULT_TARGETS_PATH) {
  const targets = readDeploymentTargets(targetsPath);
  if (!TARGET_NAMES.includes(targetName)) {
    throw new Error(`target must be ${TARGET_NAMES.join(' or ')}`);
  }
  return targets[targetName];
}

export function parseDeploymentTargets(value, sourceName = 'deployment targets') {
  const root = requireObject(value, sourceName);
  requireExactKeys(root, TARGET_NAMES, sourceName);
  const targets = {};
  for (const targetName of TARGET_NAMES) {
    targets[targetName] = parseDeploymentTarget(root[targetName], targetName);
  }
  return Object.freeze(targets);
}

export function gatewaySecretNames(target) {
  const names = [...GATEWAY_BASE_SECRET_NAMES];
  for (const capabilityName of CAPABILITY_NAMES) {
    const capability = target.capabilities[capabilityName];
    if (capability.enabled) names.push(...capability.secrets);
  }
  return unique(names, 'gateway secret requirements');
}

export function componentSecretNames(target, component) {
  switch (component) {
    case 'gateway':
      return gatewaySecretNames(target);
    case 'signing-worker':
      return [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      ];
    case 'deriver-a':
      return [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_A_PEER_SIGNING_KEY',
      ];
    case 'deriver-b':
      return [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_B_PEER_SIGNING_KEY',
      ];
    case 'router':
      return ['ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET'];
    default:
      throw new Error(`Unsupported backend component: ${component}`);
  }
}

function parseDeploymentTarget(value, targetName) {
  const target = requireObject(value, targetName);
  requireExactKeys(
    target,
    ['branch', 'origins', 'resources', 'capabilities', 'gatewayDeploymentConfig'],
    targetName,
  );
  const branch = requirePattern(target.branch, /^[a-z0-9._/-]+$/u, `${targetName}.branch`);
  const origins = parseOrigins(target.origins, `${targetName}.origins`);
  const resources = parseResources(target.resources, `${targetName}.resources`);
  const capabilities = parseCapabilities(target.capabilities, `${targetName}.capabilities`);
  const gatewayDeploymentConfig = parseGatewayDeploymentConfig(
    JSON.stringify(target.gatewayDeploymentConfig),
    targetName,
  );
  assertGatewayDeploymentConfigMatchesTarget(
    targetName,
    origins,
    resources,
    gatewayDeploymentConfig,
  );
  return Object.freeze({ branch, origins, resources, capabilities, gatewayDeploymentConfig });
}

function assertGatewayDeploymentConfigMatchesTarget(targetName, origins, resources, config) {
  if (
    config.resources.workerName !== resources.gateway.workerName ||
    config.resources.consoleD1.name !== resources.gateway.consoleD1Name ||
    config.resources.signerD1.name !== resources.gateway.signerD1Name ||
    config.origins.gateway !== origins.gateway ||
    config.serviceNames.mpcRouter !== resources.router.workerName ||
    config.serviceNames.deriverA !== resources.deriverA.workerName ||
    config.serviceNames.deriverB !== resources.deriverB.workerName ||
    config.serviceNames.signingWorker !== resources.signingWorker.workerName
  ) {
    throw new Error(`gatewayDeploymentConfig does not match deployment target ${targetName}`);
  }
}

function parseOrigins(value, pathName) {
  const origins = requireObject(value, pathName);
  requireExactKeys(origins, ['gateway', 'site', 'wallet'], pathName);
  return Object.freeze({
    gateway: requireHttpsUrl(origins.gateway, `${pathName}.gateway`),
    site: requireHttpsUrl(origins.site, `${pathName}.site`),
    wallet: requireHttpsUrl(origins.wallet, `${pathName}.wallet`),
  });
}

function parseResources(value, pathName) {
  const resources = requireObject(value, pathName);
  requireExactKeys(resources, DEPLOYMENT_RESOURCE_NAMES, pathName);
  return Object.freeze({
    gateway: parseGatewayResource(resources.gateway, `${pathName}.gateway`),
    router: parseWorkerResource(resources.router, `${pathName}.router`),
    deriverA: parseWorkerResource(resources.deriverA, `${pathName}.deriverA`),
    deriverB: parseWorkerResource(resources.deriverB, `${pathName}.deriverB`),
    signingWorker: parseWorkerResource(resources.signingWorker, `${pathName}.signingWorker`),
    frontend: parseFrontendResource(resources.frontend, `${pathName}.frontend`),
  });
}

function parseGatewayResource(value, pathName) {
  const resource = requireObject(value, pathName);
  requireExactKeys(resource, ['workerName', 'consoleD1Name', 'signerD1Name'], pathName);
  return Object.freeze({
    workerName: requireResourceName(resource.workerName, `${pathName}.workerName`),
    consoleD1Name: requireResourceName(resource.consoleD1Name, `${pathName}.consoleD1Name`),
    signerD1Name: requireResourceName(resource.signerD1Name, `${pathName}.signerD1Name`),
  });
}

function parseWorkerResource(value, pathName) {
  const resource = requireObject(value, pathName);
  requireExactKeys(resource, ['workerName', 'configPath', 'deploymentEnvironment'], pathName);
  return Object.freeze({
    workerName: requireResourceName(resource.workerName, `${pathName}.workerName`),
    configPath: requireRelativePath(resource.configPath, `${pathName}.configPath`),
    deploymentEnvironment: parseDeploymentEnvironment(
      resource.deploymentEnvironment,
      `${pathName}.deploymentEnvironment`,
    ),
  });
}

function parseFrontendResource(value, pathName) {
  const resource = requireObject(value, pathName);
  requireExactKeys(resource, ['pagesBranch', 'appProjectEnv', 'walletProjectEnv'], pathName);
  return Object.freeze({
    pagesBranch: requirePattern(
      resource.pagesBranch,
      /^[a-z0-9._/-]+$/u,
      `${pathName}.pagesBranch`,
    ),
    appProjectEnv: requireEnvironmentName(resource.appProjectEnv, `${pathName}.appProjectEnv`),
    walletProjectEnv: requireEnvironmentName(
      resource.walletProjectEnv,
      `${pathName}.walletProjectEnv`,
    ),
  });
}

function parseDeploymentEnvironment(value, pathName) {
  const environment = requireObject(value, pathName);
  const kind = requireString(environment.kind, `${pathName}.kind`);
  if (kind === 'default') {
    requireExactKeys(environment, ['kind'], pathName);
    return Object.freeze({ kind });
  }
  if (kind === 'named') {
    requireExactKeys(environment, ['kind', 'name'], pathName);
    return Object.freeze({
      kind,
      name: requirePattern(environment.name, /^[a-z0-9._/-]+$/u, `${pathName}.name`),
    });
  }
  throw new Error(`${pathName}.kind must be default or named`);
}

function parseCapabilities(value, pathName, requireAllCapabilities = true) {
  const capabilities = requireObject(value, pathName);
  const capabilityNames = Object.keys(capabilities);
  if (requireAllCapabilities) {
    requireExactKeys(capabilities, CAPABILITY_NAMES, pathName);
  } else if (capabilityNames.some((name) => !CAPABILITY_NAMES.includes(name))) {
    throw new Error(`${pathName} contains an unknown capability`);
  }
  const parsed = {};
  const ownedSecrets = new Map();
  const namesToParse = requireAllCapabilities ? CAPABILITY_NAMES : capabilityNames;
  for (const capabilityName of namesToParse) {
    const capabilityPath = `${pathName}.${capabilityName}`;
    const capability = requireObject(capabilities[capabilityName], capabilityPath);
    requireExactKeys(capability, ['enabled', 'owner', 'secrets'], capabilityPath);
    if (typeof capability.enabled !== 'boolean') {
      throw new Error(`${capabilityPath}.enabled must be a boolean`);
    }
    const owner = requireString(capability.owner, `${capabilityPath}.owner`);
    if (!CAPABILITY_OWNER_NAMES.has(owner)) {
      throw new Error(`${capabilityPath}.owner must be gateway`);
    }
    const secrets = parseSecretNames(capability.secrets, `${capabilityPath}.secrets`);
    for (const secret of secrets) {
      const previousOwner = ownedSecrets.get(secret);
      if (previousOwner !== undefined) {
        throw new Error(`secret ${secret} has duplicate ownership: ${previousOwner} and ${owner}`);
      }
      ownedSecrets.set(secret, owner);
    }
    parsed[capabilityName] = Object.freeze({ enabled: capability.enabled, owner, secrets });
  }
  return Object.freeze(parsed);
}

function parseSecretNames(value, pathName) {
  if (!Array.isArray(value)) throw new Error(`${pathName} must be an array`);
  return Object.freeze(
    unique(
      value.map((item, index) => requireSecretName(item, `${pathName}[${index}]`)),
      pathName,
    ),
  );
}

function requireExactKeys(value, keys, pathName) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${pathName} must contain exactly: ${keys.join(', ')}`);
  }
}

function requireObject(value, pathName) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${pathName} must be an object`);
  }
  return value;
}

function requireString(value, pathName) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${pathName} must be a non-empty string`);
  }
  return value.trim();
}

function requirePattern(value, pattern, pathName) {
  const string = requireString(value, pathName);
  if (!pattern.test(string)) throw new Error(`${pathName} has an invalid value`);
  return string;
}

function requireHttpsUrl(value, pathName) {
  const string = requireString(value, pathName);
  let url;
  try {
    url = new URL(string);
  } catch {
    throw new Error(`${pathName} must be an HTTPS URL`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error(`${pathName} must be an HTTPS origin`);
  }
  return url.origin;
}

function requireResourceName(value, pathName) {
  return requirePattern(value, /^[a-z0-9][a-z0-9-]{0,62}$/u, pathName);
}

function requireRelativePath(value, pathName) {
  const string = requireString(value, pathName);
  if (path.isAbsolute(string) || string.includes('..')) {
    throw new Error(`${pathName} must be a repository-relative path`);
  }
  return string;
}

function requireEnvironmentName(value, pathName) {
  return requirePattern(value, /^[A-Z][A-Z0-9_]*$/u, pathName);
}

function requireSecretName(value, pathName) {
  return requirePattern(value, /^[A-Z][A-Z0-9_]*$/u, pathName);
}

function unique(values, pathName) {
  const result = [];
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) throw new Error(`${pathName} must not contain duplicate values`);
    seen.add(value);
    result.push(value);
  }
  return result;
}

function formatError(error) {
  return error instanceof Error ? error.message : String(error);
}
