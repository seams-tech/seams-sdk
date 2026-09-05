import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseGatewayDeploymentConfig } from '../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_TARGETS_PATH = path.join(SCRIPT_DIRECTORY, '..', 'deployment', 'targets.json');

const RELEASE_IDS = Object.freeze(['staging', 'production']);
const RELEASE_NETWORKS = Object.freeze({
  staging: Object.freeze(['testnet']),
  production: Object.freeze(['testnet', 'mainnet']),
});
const BACKEND_LANE_IDS = Object.freeze([
  'staging-testnet',
  'production-testnet',
  'production-mainnet',
]);
const FRONTEND_SITE_IDS = Object.freeze(['staging', 'production']);

export const BACKEND_COMPONENTS = Object.freeze([
  'signing-worker',
  'deriver-a',
  'deriver-b',
  'router',
  'tenant-root-control-plane',
  'wallet-runtime',
  'gateway',
  'console',
]);

const CAPABILITY_NAMES = Object.freeze(['billing', 'sponsoredExecution', 'signingSessionSeal']);
const CAPABILITY_OWNER_NAMES = new Set(['gateway']);
const DEPLOYMENT_RESOURCE_NAMES = Object.freeze([
  'gateway',
  'router',
  'deriverA',
  'deriverB',
  'signingWorker',
  'tenantRootControlPlane',
]);
const GATEWAY_BASE_SECRET_NAMES = Object.freeze([
  'ACCOUNT_ID_DERIVATION_SECRET',
  'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
  'LINKED_DEVICE_TARGET_DESCRIPTOR_HMAC_SECRET',
  'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
]);
const AMAZON_SES_SECRET_NAMES = Object.freeze([
  'EMAIL_OTP_SES_ACCESS_KEY_ID',
  'EMAIL_OTP_SES_SECRET_ACCESS_KEY',
]);

export function backendLaneIds() {
  return BACKEND_LANE_IDS;
}

export function frontendSiteIds() {
  return FRONTEND_SITE_IDS;
}

export function readDeploymentTargets(targetsPath = DEFAULT_TARGETS_PATH) {
  const absolutePath = path.resolve(targetsPath);
  let source;
  try {
    source = JSON.parse(fs.readFileSync(absolutePath, 'utf8'));
  } catch (error) {
    throw new Error(
      'Unable to read deployment targets ' + absolutePath + ': ' + formatError(error),
    );
  }
  return parseDeploymentTargets(source, absolutePath);
}

export function readBackendLane(laneId, targetsPath = DEFAULT_TARGETS_PATH) {
  if (!BACKEND_LANE_IDS.includes(laneId)) {
    throw new Error('backend lane must be ' + BACKEND_LANE_IDS.join(' or '));
  }
  return readDeploymentTargets(targetsPath).backendLanes[laneId];
}

export function readFrontendSite(siteId, targetsPath = DEFAULT_TARGETS_PATH) {
  if (!FRONTEND_SITE_IDS.includes(siteId)) {
    throw new Error('frontend site must be ' + FRONTEND_SITE_IDS.join(' or '));
  }
  return readDeploymentTargets(targetsPath).frontendSites[siteId];
}

export function parseDeploymentTargets(value, sourceName = 'deployment targets') {
  const root = requireObject(value, sourceName);
  requireExactKeys(root, RELEASE_IDS, sourceName);
  const releases = {};
  const backendLanes = {};
  const frontendSites = {};
  for (const releaseId of RELEASE_IDS) {
    const release = parseRelease(root[releaseId], releaseId);
    releases[releaseId] = release;
    frontendSites[releaseId] = release.site;
    for (const lane of Object.values(release.lanes)) backendLanes[lane.id] = lane;
  }
  assertUniqueSiteOrigins(Object.values(frontendSites));
  assertUniqueLaneOrigins(Object.values(backendLanes));
  assertUniqueResourceNames(Object.values(backendLanes));
  assertUniqueProvisionedIdentities(Object.values(backendLanes));
  return Object.freeze({
    releases: Object.freeze(releases),
    backendLanes: Object.freeze(backendLanes),
    frontendSites: Object.freeze(frontendSites),
  });
}

export function gatewaySecretNames(lane) {
  const names = [...GATEWAY_BASE_SECRET_NAMES];
  if (
    lane.release === 'production' &&
    (lane.emailOtpDelivery.kind === 'demo_code_response' ||
      lane.emailOtpDelivery.provider.kind !== 'resend')
  ) {
    names.push('RESEND_API_KEY');
  }
  if (lane.emailOtpDelivery.kind !== 'demo_code_response') {
    names.push(...emailOtpProviderSecretNames(lane.emailOtpDelivery.provider));
  }
  for (const capabilityName of CAPABILITY_NAMES) {
    const capability = lane.capabilities[capabilityName];
    if (capability.enabled) names.push(...capability.secrets);
  }
  return unique(names, 'gateway secret requirements');
}

export function consoleSecretNames(lane) {
  const names = [
    'CONSOLE_INITIAL_OWNER_EMAIL',
    'CONSOLE_SESSION_HMAC_SECRET',
    'CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U',
    'CONSOLE_WEBHOOK_SECRET_KEY_B64U',
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
    'TENANT_ROOT_GRANT_AUTHORITY_SIGNING_KEY_ID',
    'TENANT_ROOT_GRANT_AUTHORITY_SIGNING_SEED',
    'STRIPE_API_SK',
    'STRIPE_WEBHOOK_SECRET',
  ];
  if (lane.release === 'production') names.push('RESEND_API_KEY');
  return unique(names, 'console secret requirements');
}

export function tenantRootManagedBackupConfig(lane, role) {
  const prefix = {
    a: 'DERIVER_A',
    b: 'DERIVER_B',
  }[role];
  if (!prefix) throw new Error('tenant-root deriver role must be a or b');

  const stem = `${prefix}_TENANT_ROOT_MANAGED_BACKUP`;
  const common = {
    providerIdEnvironmentName: `${stem}_PROVIDER_ID`,
    keyVersionEnvironmentName: `${stem}_KEY_VERSION`,
  };
  if (lane.network === 'mainnet') {
    return Object.freeze({
      ...common,
      kind: 'google_cloud_kms',
      expectedProviderId: `google-cloud-kms-deriver-${role}-v1`,
      credentialsSecretName: `${stem}_GOOGLE_CREDENTIALS_JSON`,
      credentialsBindingEnvironmentName: `${stem}_GOOGLE_CREDENTIALS_JSON`,
    });
  }
  return Object.freeze({
    ...common,
    kind: 'hpke',
    privateSecretName: `${stem}_HPKE_PRIVATE_KEY`,
    publicEnvironmentName: `${stem}_HPKE_PUBLIC_KEY`,
    privateBindingEnvironmentName: `${stem}_HPKE_PRIVATE_KEY_BINDING`,
  });
}

export function tenantRootManagedBackupSecretNames(lane, role) {
  const config = tenantRootManagedBackupConfig(lane, role);
  return config.kind === 'google_cloud_kms'
    ? [config.credentialsSecretName]
    : [config.privateSecretName];
}

function emailOtpProviderSecretNames(provider) {
  switch (provider.kind) {
    case 'resend':
      return ['RESEND_API_KEY'];
    case 'amazon_ses':
      return AMAZON_SES_SECRET_NAMES;
    default:
      throw new Error('Unsupported Email OTP provider: ' + provider.kind);
  }
}

export function componentSecretNames(lane, component) {
  switch (component) {
    case 'gateway':
    case 'wallet-runtime':
      return gatewaySecretNames(lane);
    case 'console':
      return consoleSecretNames(lane);
    case 'signing-worker':
      return [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
        'SIGNING_WORKER_PRIVATE_D1_KEK',
      ];
    case 'deriver-a':
      return [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_A_PEER_SIGNING_KEY',
        'DERIVER_A_ROLE_PRIVATE_D1_KEK',
        'DERIVER_A_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY',
        ...tenantRootManagedBackupSecretNames(lane, 'a'),
        'DERIVER_A_TENANT_ROOT_CREATION_SIGNING_KEY',
      ];
    case 'deriver-b':
      return [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_B_PEER_SIGNING_KEY',
        'DERIVER_B_ROLE_PRIVATE_D1_KEK',
        'DERIVER_B_TENANT_ROOT_ONLINE_HPKE_PRIVATE_KEY',
        ...tenantRootManagedBackupSecretNames(lane, 'b'),
        'DERIVER_B_TENANT_ROOT_CREATION_SIGNING_KEY',
      ];
    case 'router':
      return ['ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET'];
    case 'tenant-root-control-plane':
      // Sole holder of the R120 issuer private signing key.
      return [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'TENANT_ROOT_CONTROL_PLANE_ISSUER_SIGNING_KEY',
      ];
    default:
      throw new Error('Unsupported backend component: ' + component);
  }
}

function parseRelease(value, releaseId) {
  const releasePath = releaseId;
  const release = requireObject(value, releasePath);
  requireExactKeys(release, ['branch', 'site', 'lanes'], releasePath);
  const branch = requirePattern(release.branch, /^[a-z0-9._/-]+$/u, releasePath + '.branch');
  const expectedBranch = releaseId === 'staging' ? 'dev' : 'main';
  if (branch !== expectedBranch) {
    throw new Error(releasePath + '.branch must be ' + expectedBranch);
  }
  const site = parseSite(release.site, releaseId, branch);
  const laneRoot = requireObject(release.lanes, releasePath + '.lanes');
  const networks = RELEASE_NETWORKS[releaseId];
  requireExactKeys(laneRoot, networks, releasePath + '.lanes');
  const lanes = {};
  for (const network of networks) {
    const laneId = releaseId + '-' + network;
    lanes[network] = parseBackendLane(laneRoot[network], laneId, releaseId, network, branch, site);
  }
  const frontendSite = Object.freeze({
    ...site,
    lanes: Object.freeze(Object.values(lanes)),
  });
  return Object.freeze({
    id: releaseId,
    branch,
    site: frontendSite,
    lanes: Object.freeze(lanes),
  });
}

function parseSite(value, releaseId, branch) {
  const sitePath = releaseId + '.site';
  const site = requireObject(value, sitePath);
  requireExactKeys(
    site,
    [
      'origin',
      'docsOrigin',
      'googleOidcClientId',
      'defaultNetwork',
      'availableNetworks',
      'pagesProjectEnv',
      'docsPagesProjectEnv',
    ],
    sitePath,
  );
  const availableNetworks = parseNetworkNames(
    site.availableNetworks,
    sitePath + '.availableNetworks',
  );
  const expectedNetworks = RELEASE_NETWORKS[releaseId];
  requireExactArrayValues(availableNetworks, expectedNetworks, sitePath + '.availableNetworks');
  const defaultNetwork = requireString(site.defaultNetwork, sitePath + '.defaultNetwork');
  if (!availableNetworks.includes(defaultNetwork)) {
    throw new Error(sitePath + '.defaultNetwork must be one of ' + availableNetworks.join(', '));
  }
  return Object.freeze({
    id: releaseId,
    release: releaseId,
    branch,
    origin: requireHttpsOrigin(site.origin, sitePath + '.origin'),
    docsOrigin: requireHttpsOrigin(site.docsOrigin, sitePath + '.docsOrigin'),
    googleOidcClientId: requirePattern(
      site.googleOidcClientId,
      /^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$/u,
      sitePath + '.googleOidcClientId',
    ),
    defaultNetwork,
    availableNetworks: Object.freeze(availableNetworks),
    pagesProjectEnv: requireEnvironmentName(site.pagesProjectEnv, sitePath + '.pagesProjectEnv'),
    docsPagesProjectEnv: requireEnvironmentName(
      site.docsPagesProjectEnv,
      sitePath + '.docsPagesProjectEnv',
    ),
  });
}

function parseBackendLane(value, laneId, releaseId, network, branch, site) {
  const lanePath = releaseId + '.lanes.' + network;
  const lane = requireObject(value, lanePath);
  requireExactKeys(
    lane,
    [
      'gatewayOrigin',
      'walletOrigin',
      'walletPagesProjectEnv',
      'emailOtpDelivery',
      'resources',
      'capabilities',
      'provisioning',
    ],
    lanePath,
  );
  const parsed = Object.freeze({
    id: laneId,
    release: releaseId,
    network,
    branch,
    site,
    gatewayOrigin: requireHttpsOrigin(lane.gatewayOrigin, lanePath + '.gatewayOrigin'),
    walletOrigin: requireHttpsOrigin(lane.walletOrigin, lanePath + '.walletOrigin'),
    walletPagesProjectEnv: requireEnvironmentName(
      lane.walletPagesProjectEnv,
      lanePath + '.walletPagesProjectEnv',
    ),
    emailOtpDelivery: parseEmailOtpDelivery(lane.emailOtpDelivery, lanePath + '.emailOtpDelivery'),
    resources: parseResources(lane.resources, lanePath + '.resources'),
    capabilities: parseCapabilities(lane.capabilities, lanePath + '.capabilities'),
    provisioning: parseProvisioning(lane.provisioning, laneId, network, lanePath + '.provisioning'),
  });
  assertLaneOrigins(parsed);
  if (parsed.provisioning.kind === 'provisioned') {
    assertGatewayDeploymentConfigMatchesLane(parsed);
  }
  return parsed;
}

function parseProvisioning(value, laneId, network, provisioningPath) {
  const provisioning = requireObject(value, provisioningPath);
  const expectedRuntimeProfile = network === 'mainnet' ? 'mainnet_service' : 'testnet_live_demo';
  const kind = requireString(provisioning.kind, provisioningPath + '.kind');
  if (kind === 'provisioned') {
    requireExactKeys(provisioning, ['kind', 'gatewayDeploymentConfig'], provisioningPath);
    const gatewayDeploymentConfig = parseGatewayDeploymentConfig(
      JSON.stringify(provisioning.gatewayDeploymentConfig),
      laneId,
    );
    if (gatewayDeploymentConfig.runtimeProfile.kind !== expectedRuntimeProfile) {
      throw new Error(
        provisioningPath +
          '.gatewayDeploymentConfig runtime profile must be ' +
          expectedRuntimeProfile,
      );
    }
    return Object.freeze({ kind, gatewayDeploymentConfig });
  }
  if (kind === 'pending') {
    requireExactKeys(
      provisioning,
      ['kind', 'runtimeProfileKind', 'requiredValues'],
      provisioningPath,
    );
    const runtimeProfileKind = requireString(
      provisioning.runtimeProfileKind,
      provisioningPath + '.runtimeProfileKind',
    );
    if (runtimeProfileKind !== expectedRuntimeProfile) {
      throw new Error(provisioningPath + '.runtimeProfileKind must be ' + expectedRuntimeProfile);
    }
    return Object.freeze({
      kind,
      runtimeProfileKind,
      requiredValues: parseRequiredValues(
        provisioning.requiredValues,
        provisioningPath + '.requiredValues',
      ),
    });
  }
  throw new Error(provisioningPath + '.kind must be provisioned or pending');
}

function assertLaneOrigins(lane) {
  if (lane.provisioning.kind !== 'provisioned') return;
  const configOrigins = lane.provisioning.gatewayDeploymentConfig.origins;
  const expectedCors = [lane.site.origin, lane.walletOrigin].sort();
  const actualCors = [...configOrigins.allowedCors].sort();
  if (
    configOrigins.gateway !== lane.gatewayOrigin ||
    actualCors.length !== expectedCors.length ||
    actualCors.some((origin, index) => origin !== expectedCors[index])
  ) {
    throw new Error('Gateway origins do not match backend lane ' + lane.id);
  }
}

function assertGatewayDeploymentConfigMatchesLane(lane) {
  const config = lane.provisioning.gatewayDeploymentConfig;
  const resources = lane.resources;
  if (config.runtimeProfile.emailOtpDelivery.kind !== lane.emailOtpDelivery.kind) {
    throw new Error('Gateway email OTP delivery does not match backend lane ' + lane.id);
  }
  if (config.optional.googleOidcClientId !== lane.site.googleOidcClientId) {
    throw new Error('Gateway Google OIDC client does not match frontend site ' + lane.site.id);
  }
  if (
    config.resources.workerName !== resources.gateway.workerName ||
    config.resources.consoleD1.name !== resources.gateway.consoleD1Name ||
    config.resources.signerD1.name !== resources.gateway.signerD1Name ||
    config.serviceNames.mpcRouter !== resources.router.workerName ||
    config.serviceNames.deriverA !== resources.deriverA.workerName ||
    config.serviceNames.deriverB !== resources.deriverB.workerName ||
    config.serviceNames.signingWorker !== resources.signingWorker.workerName
  ) {
    throw new Error('gatewayDeploymentConfig does not match backend lane ' + lane.id);
  }
}

function parseEmailOtpDelivery(value, pathName) {
  const delivery = requireObject(value, pathName);
  const kind = requireString(delivery.kind, pathName + '.kind');
  if (kind === 'demo_code_response') {
    requireExactKeys(delivery, ['kind'], pathName);
    return Object.freeze({ kind });
  }
  if (kind === 'email_provider' || kind === 'provider_and_demo_code') {
    requireExactKeys(delivery, ['kind', 'provider'], pathName);
    return Object.freeze({
      kind,
      provider: parseEmailOtpProvider(delivery.provider, pathName + '.provider'),
    });
  }
  throw new Error(
    pathName + '.kind must be demo_code_response, email_provider, or provider_and_demo_code',
  );
}

function parseEmailOtpProvider(value, pathName) {
  const provider = requireObject(value, pathName);
  const kind = requireString(provider.kind, pathName + '.kind');
  if (kind === 'resend') {
    requireExactKeys(provider, ['kind', 'fromAddress'], pathName);
    return Object.freeze({
      kind,
      fromAddress: requireEmailAddress(provider.fromAddress, pathName + '.fromAddress'),
    });
  }
  if (kind === 'amazon_ses') {
    requireExactKeys(provider, ['kind', 'region', 'fromAddress'], pathName);
    return Object.freeze({
      kind,
      region: requirePattern(
        provider.region,
        /^[a-z]{2}(?:-gov)?-[a-z]+-\d+$/u,
        pathName + '.region',
      ),
      fromAddress: requireEmailAddress(provider.fromAddress, pathName + '.fromAddress'),
    });
  }
  throw new Error(pathName + '.kind must be resend or amazon_ses');
}

function requireEmailAddress(value, pathName) {
  return requirePattern(value, /^[^\s@]+@[^\s@]+\.[^\s@]+$/u, pathName);
}

function parseResources(value, pathName) {
  const resources = requireObject(value, pathName);
  requireExactKeys(resources, DEPLOYMENT_RESOURCE_NAMES, pathName);
  return Object.freeze({
    gateway: parseGatewayResource(resources.gateway, pathName + '.gateway'),
    router: parseWorkerResource(resources.router, pathName + '.router'),
    deriverA: parseWorkerResource(resources.deriverA, pathName + '.deriverA'),
    deriverB: parseWorkerResource(resources.deriverB, pathName + '.deriverB'),
    signingWorker: parseWorkerResource(resources.signingWorker, pathName + '.signingWorker'),
    tenantRootControlPlane: parseWorkerResource(
      resources.tenantRootControlPlane,
      pathName + '.tenantRootControlPlane',
    ),
  });
}

function parseGatewayResource(value, pathName) {
  const resource = requireObject(value, pathName);
  requireExactKeys(resource, ['workerName', 'consoleD1Name', 'signerD1Name'], pathName);
  return Object.freeze({
    workerName: requireResourceName(resource.workerName, pathName + '.workerName'),
    consoleD1Name: requireResourceName(resource.consoleD1Name, pathName + '.consoleD1Name'),
    signerD1Name: requireResourceName(resource.signerD1Name, pathName + '.signerD1Name'),
  });
}

function parseWorkerResource(value, pathName) {
  const resource = requireObject(value, pathName);
  requireExactKeys(resource, ['workerName', 'configPath', 'deploymentEnvironment'], pathName);
  return Object.freeze({
    workerName: requireResourceName(resource.workerName, pathName + '.workerName'),
    configPath: requireRelativePath(resource.configPath, pathName + '.configPath'),
    deploymentEnvironment: parseDeploymentEnvironment(
      resource.deploymentEnvironment,
      pathName + '.deploymentEnvironment',
    ),
  });
}

function parseDeploymentEnvironment(value, pathName) {
  const environment = requireObject(value, pathName);
  const kind = requireString(environment.kind, pathName + '.kind');
  if (kind === 'default') {
    requireExactKeys(environment, ['kind'], pathName);
    return Object.freeze({ kind });
  }
  if (kind === 'named') {
    requireExactKeys(environment, ['kind', 'name'], pathName);
    return Object.freeze({
      kind,
      name: requirePattern(environment.name, /^[a-z0-9._/-]+$/u, pathName + '.name'),
    });
  }
  throw new Error(pathName + '.kind must be default or named');
}

function parseCapabilities(value, pathName) {
  const capabilities = requireObject(value, pathName);
  requireExactKeys(capabilities, CAPABILITY_NAMES, pathName);
  const parsed = {};
  const ownedSecrets = new Map();
  for (const capabilityName of CAPABILITY_NAMES) {
    const capabilityPath = pathName + '.' + capabilityName;
    const capability = requireObject(capabilities[capabilityName], capabilityPath);
    requireExactKeys(capability, ['enabled', 'owner', 'secrets'], capabilityPath);
    if (typeof capability.enabled !== 'boolean') {
      throw new Error(capabilityPath + '.enabled must be a boolean');
    }
    const owner = requireString(capability.owner, capabilityPath + '.owner');
    if (!CAPABILITY_OWNER_NAMES.has(owner)) {
      throw new Error(capabilityPath + '.owner must be gateway');
    }
    const secrets = parseSecretNames(capability.secrets, capabilityPath + '.secrets');
    for (const secret of secrets) {
      const previousOwner = ownedSecrets.get(secret);
      if (previousOwner !== undefined) {
        throw new Error(
          'secret ' + secret + ' has duplicate ownership: ' + previousOwner + ' and ' + owner,
        );
      }
      ownedSecrets.set(secret, owner);
    }
    parsed[capabilityName] = Object.freeze({ enabled: capability.enabled, owner, secrets });
  }
  return Object.freeze(parsed);
}

function parseSecretNames(value, pathName) {
  if (!Array.isArray(value)) throw new Error(pathName + ' must be an array');
  return Object.freeze(
    unique(
      value.map((item, index) => requireSecretName(item, pathName + '[' + index + ']')),
      pathName,
    ),
  );
}

function parseRequiredValues(value, pathName) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(pathName + ' must be a non-empty array');
  }
  return Object.freeze(
    unique(
      value.map((item, index) => requireEnvironmentName(item, pathName + '[' + index + ']')),
      pathName,
    ),
  );
}

function assertUniqueSiteOrigins(sites) {
  assertUnique(
    sites.flatMap((site) => [site.origin, site.docsOrigin]),
    'frontend site and docs origins',
  );
}

function assertUniqueLaneOrigins(lanes) {
  const origins = [];
  for (const lane of lanes) origins.push(lane.gatewayOrigin, lane.walletOrigin);
  assertUnique(origins, 'backend lane origins');
  const siteOrigins = new Set(lanes.flatMap((lane) => [lane.site.origin, lane.site.docsOrigin]));
  for (const origin of origins) {
    if (siteOrigins.has(origin)) {
      throw new Error('backend origin ' + origin + ' must not equal a frontend site origin');
    }
  }
}

function assertUniqueResourceNames(lanes) {
  const names = [];
  for (const lane of lanes) {
    names.push(
      lane.resources.gateway.workerName,
      lane.resources.gateway.consoleD1Name,
      lane.resources.gateway.signerD1Name,
      lane.resources.router.workerName,
      lane.resources.deriverA.workerName,
      lane.resources.deriverB.workerName,
      lane.resources.signingWorker.workerName,
      lane.resources.tenantRootControlPlane.workerName,
    );
  }
  assertUnique(names, 'backend resource names');
}

function assertUniqueProvisionedIdentities(lanes) {
  const provisioned = lanes.filter((lane) => lane.provisioning.kind === 'provisioned');
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.resources.consoleD1.id),
    'console D1 identities',
  );
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.resources.signerD1.id),
    'signer D1 identities',
  );
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.tenant.namespace),
    'tenant namespaces',
  );
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.tenant.orgId),
    'tenant organizations',
  );
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.tenant.projectId),
    'tenant projects',
  );
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.tenant.environmentId),
    'tenant environments',
  );
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.session.issuer),
    'session issuers',
  );
  assertUnique(
    provisioned.map(
      (lane) => lane.provisioning.gatewayDeploymentConfig.signingSessionSeal.currentKeyVersion,
    ),
    'signing session seal identities',
  );
  assertUnique(
    provisioned.map((lane) => lane.provisioning.gatewayDeploymentConfig.routerAb.ceremonyJwtKeyId),
    'Router ceremony identities',
  );
  assertUnique(
    provisioned.map(
      (lane) =>
        lane.provisioning.gatewayDeploymentConfig.routerAb.registrationTopology.signerSet
          .signer_set_id,
    ),
    'Router signer-set identities',
  );
}

function assertUnique(values, pathName) {
  if (new Set(values).size !== values.length) {
    throw new Error(pathName + ' must be unique across deployment lanes');
  }
}

function parseNetworkNames(value, pathName) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(pathName + ' must be a non-empty array');
  }
  return value.map((item, index) => {
    const network = requireString(item, pathName + '[' + index + ']');
    if (!['testnet', 'mainnet'].includes(network)) {
      throw new Error(pathName + ' must contain only testnet or mainnet');
    }
    return network;
  });
}

function requireExactArrayValues(actual, expected, pathName) {
  if (
    actual.length !== expected.length ||
    actual.some((value, index) => value !== expected[index])
  ) {
    throw new Error(pathName + ' must contain exactly: ' + expected.join(', '));
  }
}

function requireExactKeys(value, keys, pathName) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(pathName + ' must contain exactly: ' + keys.join(', '));
  }
}

function requireObject(value, pathName) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(pathName + ' must be an object');
  }
  return value;
}

function requireString(value, pathName) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(pathName + ' must be a non-empty string');
  }
  return value.trim();
}

function requirePattern(value, pattern, pathName) {
  const string = requireString(value, pathName);
  if (!pattern.test(string)) throw new Error(pathName + ' has an invalid value');
  return string;
}

function requireHttpsOrigin(value, pathName) {
  const string = requireString(value, pathName);
  let url;
  try {
    url = new URL(string);
  } catch {
    throw new Error(pathName + ' must be an HTTPS origin');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new Error(pathName + ' must be an HTTPS origin');
  }
  return url.origin;
}

function requireResourceName(value, pathName) {
  return requirePattern(value, /^[a-z0-9][a-z0-9-]{0,62}$/u, pathName);
}

function requireRelativePath(value, pathName) {
  const string = requireString(value, pathName);
  if (path.isAbsolute(string) || string.includes('..')) {
    throw new Error(pathName + ' must be a repository-relative path');
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
    if (seen.has(value)) throw new Error(pathName + ' must not contain duplicate values');
    seen.add(value);
    result.push(value);
  }
  return result;
}

function formatError(error) {
  return error instanceof Error ? error.message : String(error);
}
