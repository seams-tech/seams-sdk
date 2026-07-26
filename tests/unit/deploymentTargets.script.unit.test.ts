import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type DeploymentTarget = {
  readonly capabilities: Readonly<Record<string, Capability>>;
};

type Capability = {
  readonly enabled: boolean;
  readonly owner: string;
  readonly secrets: readonly string[];
};

type DeploymentTargets = Readonly<Record<'staging' | 'production', DeploymentTarget>>;

type DeploymentTargetsModule = {
  readonly parseDeploymentTargets: (value: unknown) => DeploymentTargets;
  readonly componentSecretNames: (target: DeploymentTarget, component: string) => readonly string[];
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

function malformedTargets(): Record<string, unknown> {
  const targets = structuredClone(validTargets());
  return {
    ...targets,
    staging: {
      ...(targets.staging as Record<string, unknown>),
      capabilities: {
        ...((targets.staging as Record<string, unknown>).capabilities as Record<string, unknown>),
        billing: {
          enabled: 'false',
          owner: 'gateway',
          secrets: ['STRIPE_API_SK'],
        },
      },
    },
  };
}

function targetsWithUnknownOwner(): Record<string, unknown> {
  const targets = structuredClone(validTargets());
  return {
    ...targets,
    staging: {
      ...(targets.staging as Record<string, unknown>),
      capabilities: {
        ...((targets.staging as Record<string, unknown>).capabilities as Record<string, unknown>),
        billing: {
          enabled: true,
          owner: 'backend',
          secrets: ['STRIPE_API_SK'],
        },
      },
    },
  };
}

function targetsWithDuplicateSecretOwnership(): Record<string, unknown> {
  const targets = structuredClone(validTargets());
  return {
    ...targets,
    staging: {
      ...(targets.staging as Record<string, unknown>),
      capabilities: {
        ...((targets.staging as Record<string, unknown>).capabilities as Record<string, unknown>),
        billing: {
          enabled: true,
          owner: 'gateway',
          secrets: ['SHARED_SECRET'],
        },
        sponsoredExecution: {
          enabled: true,
          owner: 'gateway',
          secrets: ['SHARED_SECRET'],
        },
      },
    },
  };
}

function targetsWithMissingCapability(): Record<string, unknown> {
  const targets = structuredClone(validTargets());
  const staging = targets.staging as Record<string, unknown>;
  const capabilities = {
    ...(staging.capabilities as Record<string, unknown>),
  };
  delete capabilities.billing;
  return {
    ...targets,
    staging: { ...staging, capabilities },
  };
}

test('deployment target parsing rejects malformed capability records', async () => {
  const module = await deploymentTargetsModule;

  expect(() => module.parseDeploymentTargets(malformedTargets())).toThrow(/enabled/u);
});

test('deployment target parsing rejects unknown capability owners', async () => {
  const module = await deploymentTargetsModule;

  expect(() => module.parseDeploymentTargets(targetsWithUnknownOwner())).toThrow(
    /unknown component|owner/u,
  );
});

test('deployment target parsing rejects a secret claimed by multiple capabilities', async () => {
  const module = await deploymentTargetsModule;

  expect(() => module.parseDeploymentTargets(targetsWithDuplicateSecretOwnership())).toThrow(
    /secret.*ownership|duplicate/u,
  );
});

test('deployment target parsing rejects a partial capability set', async () => {
  const module = await deploymentTargetsModule;

  expect(() => module.parseDeploymentTargets(targetsWithMissingCapability())).toThrow(
    /capabilities must contain exactly/u,
  );
});

test('deployment target parsing rejects Gateway configuration drift', async () => {
  const module = await deploymentTargetsModule;
  const targets = structuredClone(validTargets());
  const staging = targets.staging as Record<string, unknown>;
  const gatewayDeploymentConfig = structuredClone(
    staging.gatewayDeploymentConfig as Record<string, unknown>,
  );
  const origins = gatewayDeploymentConfig.origins as Record<string, unknown>;
  origins.gateway = 'https://wrong-gateway.example';
  staging.gatewayDeploymentConfig = gatewayDeploymentConfig;

  expect(() => module.parseDeploymentTargets(targets)).toThrow(
    /gatewayDeploymentConfig does not match deployment target staging/u,
  );
});

test('required secrets are derived from enabled capabilities and their owners', async () => {
  const module = await deploymentTargetsModule;
  const targets = module.parseDeploymentTargets(validTargets());

  expect(module.componentSecretNames(targets.staging, 'gateway')).toEqual([
    'RELAY_SESSION_HMAC_SECRET',
    'ACCOUNT_ID_DERIVATION_SECRET',
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
    'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
    'STRIPE_API_SK',
    'SIGNING_SESSION_SEAL_KEY_VERSION',
    'SIGNING_SESSION_SHAMIR_P_B64U',
    'SIGNING_SESSION_SEAL_E_S_B64U',
    'SIGNING_SESSION_SEAL_D_S_B64U',
  ]);
  expect(module.componentSecretNames(targets.staging, 'gateway')).toContain('STRIPE_API_SK');
  expect(module.componentSecretNames(targets.production, 'gateway')).toContain('STRIPE_API_SK');
  expect(module.componentSecretNames(targets.staging, 'deriver-a')).toEqual([
    'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
    'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
    'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
    'DERIVER_A_PEER_SIGNING_KEY',
  ]);
});
