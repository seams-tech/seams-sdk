import { expect, test } from '@playwright/test';
import {
  d1StagingPackagePath,
  loadD1StagingScriptModule,
  validD1ConsoleStagingConfig,
  validD1GatewayStagingConfig,
  writeD1StagingTempFile,
} from './helpers/d1StagingScriptFixtures';

type ReadinessResult = {
  readonly ok: boolean;
  readonly errors: readonly string[];
};

type StagingProfile = 'console' | 'gateway';

type ReadinessModule = {
  readonly checkD1StagingReadiness: (input: {
    readonly configPath: string;
    readonly environmentName?: string;
    readonly profile?: StagingProfile;
  }) => ReadinessResult;
};

const readinessModule = loadD1StagingScriptModule<ReadinessModule>(
  'd1-staging-readiness-check.mjs',
);

async function checkConfig(source: string, profile: StagingProfile): Promise<ReadinessResult> {
  const filePath = writeD1StagingTempFile('seams-d1-staging-', 'wrangler.d1-staging.toml', source);
  const module = await readinessModule;
  return module.checkD1StagingReadiness({ configPath: filePath, profile });
}

function validEnvGatewayStagingConfig(): string {
  return `
name = "seams-sdk"
main = "src/router/cloudflare/devWorker.ts"
compatibility_date = "2026-04-17"

${envScopedGatewayStagingConfigBody()}`;
}

function envScopedGatewayStagingConfigBody(): string {
  return validD1GatewayStagingConfig()
    .replace(
      /^name = "seams-sdk-d1-gateway-staging"\nmain = "src\/router\/cloudflare\/d1RouterApiStagingWorker\.ts"\ncompatibility_date = "2026-04-17"\ncompatibility_flags = \["nodejs_compat"\]\n/,
      `[env.staging]\nname = "seams-sdk-d1-gateway-staging"\nmain = "src/router/cloudflare/d1RouterApiStagingWorker.ts"\n`,
    )
    .replaceAll('[[d1_databases]]', '[[env.staging.d1_databases]]')
    .replaceAll('[[durable_objects.bindings]]', '[[env.staging.durable_objects.bindings]]')
    .replaceAll('[[services]]', '[[env.staging.services]]')
    .replaceAll('[[migrations]]', '[[env.staging.migrations]]')
    .replaceAll('[[secrets_store_secrets]]', '[[env.staging.secrets_store_secrets]]')
    .replace('[vars]', '[env.staging.vars]')
    .replace('[triggers]', '[env.staging.triggers]')
    .replace('[secrets]', '[env.staging.secrets]');
}

function gatewayConfigWithD1Binding(binding: string, databaseName: string): string {
  return `${validD1GatewayStagingConfig()}

[[d1_databases]]
binding = "${binding}"
database_name = "${databaseName}"
database_id = "33333333-3333-4333-8333-333333333333"
migrations_dir = "migrations/d1-console"
`;
}

function expectErrorContaining(result: ReadinessResult, expected: string): void {
  expect(result.ok).toBe(false);
  for (const error of result.errors) {
    if (error.includes(expected)) return;
  }
  expect(result.errors.join('\n')).toContain(expected);
}

test('D1 staging readiness check accepts the console-only staging shape', async () => {
  const result = await checkConfig(validD1ConsoleStagingConfig(), 'console');
  expect(result).toMatchObject({ errors: [], ok: true });
});

test('D1 staging readiness check accepts the Gateway SIGNER_DB and Router A/B shape', async () => {
  const result = await checkConfig(validD1GatewayStagingConfig(), 'gateway');
  expect(result).toMatchObject({ errors: [], ok: true });
});

test('D1 staging readiness check rejects a retired Gateway runtime binding', async () => {
  const source = validD1GatewayStagingConfig().replace(
    '[[services]]',
    '[[durable_objects.bindings]]\nname = "ROUTER_API_RUNTIME"\nclass_name = "RouterApiRuntimeDurableObject"\n\n[[services]]',
  );

  expectErrorContaining(
    await checkConfig(source, 'gateway'),
    'retired Durable Object binding ROUTER_API_RUNTIME must be removed',
  );
});

test('D1 staging readiness check rejects retired direct role bindings', async () => {
  const source = validD1GatewayStagingConfig().replace(
    '[[services]]',
    '[[services]]\nbinding = "DERIVER_A"\nservice = "router-ab-deriver-a-staging"\n\n[[services]]',
  );

  expectErrorContaining(
    await checkConfig(source, 'gateway'),
    'retired Gateway Service Binding DERIVER_A must be removed',
  );
});

test('D1 staging readiness check supports env.staging Wrangler sections', async () => {
  const result = await checkConfig(validEnvGatewayStagingConfig(), 'gateway');
  expect(result).toMatchObject({ errors: [], ok: true });
});

test('D1 staging readiness check rejects unexpected D1 bindings', async () => {
  const result = await checkConfig(
    gatewayConfigWithD1Binding('EXTRA_DB', 'seams-extra-staging'),
    'gateway',
  );
  expectErrorContaining(result, 'unexpected D1 binding EXTRA_DB for Gateway profile');
});

test('D1 staging readiness check rejects duplicate D1 bindings', async () => {
  const result = await checkConfig(
    gatewayConfigWithD1Binding('SIGNER_DB', 'seams-signer-staging-nrt'),
    'gateway',
  );
  expectErrorContaining(result, 'duplicate D1 binding SIGNER_DB');
});

test('D1 staging readiness check rejects the checked-in console placeholder template', async () => {
  const module = await readinessModule;
  const result = module.checkD1StagingReadiness({
    configPath: d1StagingPackagePath('wrangler.d1-staging-console.toml.example'),
    profile: 'console',
  });

  expectErrorContaining(result, 'CONSOLE_DB.database_id still contains a placeholder');
});

test('D1 staging readiness check rejects the checked-in gateway placeholder template', async () => {
  const module = await readinessModule;
  const result = module.checkD1StagingReadiness({
    configPath: d1StagingPackagePath('wrangler.d1-staging-gateway.toml.example'),
    profile: 'gateway',
  });

  expectErrorContaining(result, 'SIGNER_DB.database_id still contains a placeholder');
  expectErrorContaining(result, 'RELAYER_PUBLIC_KEY still contains a placeholder');
});

test('D1 staging readiness check rejects signer bindings in console profile', async () => {
  const result = await checkConfig(validD1GatewayStagingConfig(), 'console');
  expectErrorContaining(result, 'console staging config must not reference SIGNER_DB');
});

test('D1 staging readiness check rejects the local development Worker config', async () => {
  const module = await readinessModule;
  const result = module.checkD1StagingReadiness({
    configPath: d1StagingPackagePath('wrangler.d1-local.toml'),
    profile: 'gateway',
  });

  expectErrorContaining(result, 'staging must not use the local D1 development Worker entrypoint');
  expectErrorContaining(result, 'SPONSORED_EVM_EXECUTORS_JSON must not be configured');
  expectErrorContaining(result, 'ACCOUNT_ID_DERIVATION_SECRET must not be configured');
  expectErrorContaining(result, 'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK must be declared');
});
