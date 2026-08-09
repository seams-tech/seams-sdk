import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type Capability = {
  readonly enabled: boolean;
  readonly owner: string;
  readonly secrets: readonly string[];
};

type BackendResources = {
  readonly gateway: {
    readonly workerName: string;
    readonly consoleD1Name: string;
    readonly signerD1Name: string;
  };
  readonly router: Readonly<Record<string, unknown>>;
  readonly deriverA: Readonly<Record<string, unknown>>;
  readonly deriverB: Readonly<Record<string, unknown>>;
  readonly signingWorker: Readonly<Record<string, unknown>>;
};

type GatewayDeploymentConfig = {
  readonly resources: {
    readonly consoleD1: { readonly id: string };
    readonly signerD1: { readonly id: string };
  };
  readonly tenant: { readonly namespace: string };
  readonly session: { readonly issuer: string };
};

type BackendLane = {
  readonly id: 'staging-testnet' | 'production-testnet' | 'production-mainnet';
  readonly release: 'staging' | 'production';
  readonly network: 'testnet' | 'mainnet';
  readonly branch: string;
  readonly site: {
    readonly origin: string;
    readonly defaultNetwork: string;
    readonly availableNetworks: readonly string[];
  };
  readonly gatewayOrigin: string;
  readonly walletOrigin: string;
  readonly resources: BackendResources;
  readonly capabilities: Readonly<Record<string, Capability>>;
  readonly provisioning:
    | {
        readonly kind: 'provisioned';
        readonly gatewayDeploymentConfig: GatewayDeploymentConfig;
      }
    | {
        readonly kind: 'pending';
        readonly runtimeProfileKind: string;
        readonly requiredValues: readonly string[];
      };
};

type FrontendSite = {
  readonly id: 'staging' | 'production';
  readonly branch: string;
  readonly origin: string;
  readonly defaultNetwork: string;
  readonly availableNetworks: readonly string[];
  readonly pagesProjectEnv: string;
  readonly lanes: readonly BackendLane[];
};

type DeploymentTopology = {
  readonly backendLanes: Readonly<Record<BackendLane['id'], BackendLane>>;
  readonly frontendSites: Readonly<Record<FrontendSite['id'], FrontendSite>>;
};

type DeploymentTargetsModule = {
  readonly backendLaneIds: () => readonly string[];
  readonly frontendSiteIds: () => readonly string[];
  readonly parseDeploymentTargets: (value: unknown) => DeploymentTopology;
  readonly readBackendLane: (laneId: string, targetsPath?: string) => BackendLane;
  readonly readFrontendSite: (siteId: string, targetsPath?: string) => FrontendSite;
  readonly componentSecretNames: (lane: BackendLane, component: string) => readonly string[];
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const deploymentTargetsModule = import(
  pathToFileURL(path.join(repoRoot, 'scripts/deployment-targets.mjs')).href
) as Promise<DeploymentTargetsModule>;

function validTargets(): Record<string, unknown> {
  return JSON.parse(readFileSync(path.join(repoRoot, 'deployment/targets.json'), 'utf8')) as Record<
    string,
    unknown
  >;
}

function stagingLane(targets: Record<string, unknown>): Record<string, unknown> {
  const staging = targets.staging as Record<string, unknown>;
  const lanes = staging.lanes as Record<string, unknown>;
  return lanes.testnet as Record<string, unknown>;
}

function withStaging(targets: Record<string, unknown>, lane: Record<string, unknown>) {
  const staging = targets.staging as Record<string, unknown>;
  return {
    ...targets,
    staging: {
      ...staging,
      lanes: { ...(staging.lanes as Record<string, unknown>), testnet: lane },
    },
  };
}

function withProduction(targets: Record<string, unknown>, lanes: Record<string, unknown>) {
  const production = targets.production as Record<string, unknown>;
  return {
    ...targets,
    production: {
      ...production,
      lanes: { ...(production.lanes as Record<string, unknown>), ...lanes },
    },
  };
}

test('deployment topology exposes exact lane and site identities', async () => {
  const module = await deploymentTargetsModule;
  expect(module.backendLaneIds()).toEqual([
    'staging-testnet',
    'production-testnet',
    'production-mainnet',
  ]);
  expect(module.frontendSiteIds()).toEqual(['staging', 'production']);

  const targets = module.parseDeploymentTargets(validTargets());
  expect(Object.keys(targets.backendLanes)).toEqual([
    'staging-testnet',
    'production-testnet',
    'production-mainnet',
  ]);
  expect(Object.keys(targets.frontendSites)).toEqual(['staging', 'production']);
});

test('deployment topology enforces release branches and network availability', async () => {
  const module = await deploymentTargetsModule;
  const targets = module.parseDeploymentTargets(validTargets());
  const staging = targets.frontendSites.staging;
  const production = targets.frontendSites.production;

  expect(staging.branch).toBe('dev');
  expect(staging.availableNetworks).toEqual(['testnet']);
  expect(production.branch).toBe('main');
  expect(production.availableNetworks).toEqual(['testnet', 'mainnet']);
  expect(targets.backendLanes['staging-testnet'].network).toBe('testnet');
  expect(targets.backendLanes['production-mainnet'].network).toBe('mainnet');
});

test('deployment topology keeps staging provisioning and isolates production origins/resources', async () => {
  const module = await deploymentTargetsModule;
  const targets = module.parseDeploymentTargets(validTargets());
  const staging = targets.backendLanes['staging-testnet'];
  const productionTestnet = targets.backendLanes['production-testnet'];
  const productionMainnet = targets.backendLanes['production-mainnet'];

  expect(staging.provisioning.kind).toBe('provisioned');
  expect(productionTestnet.provisioning.kind).toBe('provisioned');
  expect(productionMainnet.provisioning.kind).toBe('pending');
  expect(staging.gatewayOrigin).toBe('https://staging.api.seams.sh');
  expect(productionTestnet.gatewayOrigin).toBe('https://test.api.seams.sh');
  expect(productionMainnet.gatewayOrigin).toBe('https://api.seams.sh');
  expect(productionTestnet.walletOrigin).toBe('https://test.sign.seams.sh');
  expect(productionMainnet.walletOrigin).toBe('https://sign.seams.sh');
  expect(productionTestnet.resources.gateway.workerName).toBe('seams-sdk-d1-gateway-testnet');
  expect(productionMainnet.resources.gateway.workerName).toBe('seams-sdk-d1-gateway');
});

test('deployment topology preserves staging operational identities', async () => {
  const module = await deploymentTargetsModule;
  const lane = module.readBackendLane('staging-testnet');
  if (lane.provisioning.kind !== 'provisioned') throw new Error('staging must be provisioned');

  expect(lane.provisioning.gatewayDeploymentConfig.resources.consoleD1.id).toBe(
    '572d1147-bc66-4f0a-9030-8c1cdd8752e7',
  );
  expect(lane.provisioning.gatewayDeploymentConfig.resources.signerD1.id).toBe(
    'c68fdf27-ced3-464a-ad40-c3acf8727f8e',
  );
  expect(lane.provisioning.gatewayDeploymentConfig.tenant.namespace).toBe('seams-staging');
  expect(lane.provisioning.gatewayDeploymentConfig.session.issuer).toBe('seams-gateway-staging');
});

test('deployment target parsing rejects malformed capability records', async () => {
  const module = await deploymentTargetsModule;
  const targets = validTargets();
  const lane = stagingLane(targets);
  const capabilities = { ...(lane.capabilities as Record<string, unknown>) };
  capabilities.billing = { enabled: 'false', owner: 'gateway', secrets: ['STRIPE_API_SK'] };
  expect(() =>
    module.parseDeploymentTargets(withStaging(targets, { ...lane, capabilities })),
  ).toThrow(/enabled/u);
});

test('deployment target parsing rejects unknown capability owners', async () => {
  const module = await deploymentTargetsModule;
  const targets = validTargets();
  const lane = stagingLane(targets);
  const capabilities = { ...(lane.capabilities as Record<string, unknown>) };
  capabilities.billing = { enabled: true, owner: 'backend', secrets: ['STRIPE_API_SK'] };
  expect(() =>
    module.parseDeploymentTargets(withStaging(targets, { ...lane, capabilities })),
  ).toThrow(/owner/u);
});

test('deployment target parsing rejects duplicate capability secrets', async () => {
  const module = await deploymentTargetsModule;
  const targets = validTargets();
  const lane = stagingLane(targets);
  const capabilities = { ...(lane.capabilities as Record<string, unknown>) };
  capabilities.billing = { enabled: true, owner: 'gateway', secrets: ['SHARED_SECRET'] };
  capabilities.sponsoredExecution = {
    enabled: true,
    owner: 'gateway',
    secrets: ['SHARED_SECRET'],
  };
  expect(() =>
    module.parseDeploymentTargets(withStaging(targets, { ...lane, capabilities })),
  ).toThrow(/duplicate|ownership/u);
});

test('deployment target parsing rejects Gateway configuration drift', async () => {
  const module = await deploymentTargetsModule;
  const targets = validTargets();
  const lane = stagingLane(targets);
  const provisioning = lane.provisioning as Record<string, unknown>;
  const config = structuredClone(provisioning.gatewayDeploymentConfig as Record<string, unknown>);
  const origins = config.origins as Record<string, unknown>;
  origins.gateway = 'https://wrong-gateway.example';
  expect(() =>
    module.parseDeploymentTargets(
      withStaging(targets, {
        ...lane,
        provisioning: { ...provisioning, gatewayDeploymentConfig: config },
      }),
    ),
  ).toThrow(/origins|gatewayDeploymentConfig|lane/u);
});

test('deployment target parsing rejects a production branch drift', async () => {
  const module = await deploymentTargetsModule;
  const targets = validTargets();
  const production = targets.production as Record<string, unknown>;
  expect(() =>
    module.parseDeploymentTargets({
      ...targets,
      production: { ...production, branch: 'dev' },
    }),
  ).toThrow(/branch must be main/u);
});

test('deployment target parsing rejects cross-lane origin reuse', async () => {
  const module = await deploymentTargetsModule;
  const targets = validTargets();
  const lane = targets.production as Record<string, unknown>;
  const lanes = lane.lanes as Record<string, unknown>;
  const testnet = lanes.testnet as Record<string, unknown>;
  expect(() =>
    module.parseDeploymentTargets(
      withProduction(targets, {
        testnet: { ...testnet, gatewayOrigin: 'https://staging.api.seams.sh' },
      }),
    ),
  ).toThrow(/origin/u);
});

test('deployment target parsing rejects duplicate pending values', async () => {
  const module = await deploymentTargetsModule;
  const targets = validTargets();
  const lane = targets.production as Record<string, unknown>;
  const lanes = lane.lanes as Record<string, unknown>;
  const pending = lanes.mainnet as Record<string, unknown>;
  const provisioning = pending.provisioning as Record<string, unknown>;
  expect(() =>
    module.parseDeploymentTargets(
      withProduction(targets, {
        mainnet: {
          ...pending,
          provisioning: {
            ...provisioning,
            requiredValues: ['STRIPE_API_SK', 'STRIPE_API_SK'],
          },
        },
      }),
    ),
  ).toThrow(/duplicate/u);
});

test('lane and site readers reject retired or unknown identities', async () => {
  const module = await deploymentTargetsModule;
  expect(() => module.readBackendLane('production')).toThrow(/backend lane/u);
  expect(() => module.readFrontendSite('production-testnet')).toThrow(/frontend site/u);
});

test('required secrets are derived from enabled capabilities', async () => {
  const module = await deploymentTargetsModule;
  const targets = module.parseDeploymentTargets(validTargets());
  const staging = targets.backendLanes['staging-testnet'];
  expect(module.componentSecretNames(staging, 'gateway')).toEqual([
    'RELAY_SESSION_HMAC_SECRET',
    'ACCOUNT_ID_DERIVATION_SECRET',
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
    'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
    'STRIPE_API_SK',
    'SIGNING_SESSION_SEAL_ROOT_SECRET_B64U',
  ]);
  expect(module.componentSecretNames(staging, 'deriver-a')).toEqual([
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
    'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
    'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
    'DERIVER_A_PEER_SIGNING_KEY',
    'DERIVER_A_ROLE_PRIVATE_D1_KEK',
  ]);
});
