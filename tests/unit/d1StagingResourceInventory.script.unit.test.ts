import { expect, test } from '@playwright/test';
import {
  D1_STAGING_GENERATED_AT_ISO,
  d1StagingJsonCommandResult,
  d1StagingManifestPath,
  loadD1StagingScriptModule,
  readD1StagingJsonFile,
  type D1StagingCommandResult,
  type D1StagingCommandRunner,
  writeMisScopedConsoleD1StagingConfigFiles,
  writeValidD1StagingConfigFiles,
} from './helpers/d1StagingScriptFixtures';

type ResourceInventoryPlan = {
  readonly mode: string;
  readonly resources: {
    readonly consoleWorker: {
      readonly name: string;
      readonly d1Databases: readonly unknown[];
      readonly durableObjects: readonly unknown[];
    };
    readonly gatewayWorker: {
      readonly name: string;
      readonly d1Databases: readonly unknown[];
      readonly durableObjects: readonly unknown[];
      readonly secretsStoreSecrets: readonly unknown[];
    };
  };
  readonly commands: readonly {
    readonly id: string;
    readonly target: string;
    readonly command: string;
  }[];
};

type ResourceInventoryModule = {
  readonly buildD1StagingResourceInventoryPlan: (input: {
    readonly consoleConfigPath: string;
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => ResourceInventoryPlan;
  readonly runD1StagingResourceInventory: (input: {
    readonly consoleConfigPath: string;
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly commandRunner?: D1StagingCommandRunner;
  }) => {
    readonly manifestPath: string;
    readonly manifest: ResourceInventoryPlan & {
      readonly checks: readonly unknown[];
    };
  };
};

const resourceInventoryModule = loadD1StagingScriptModule<ResourceInventoryModule>(
  'd1-staging-resource-inventory.mjs',
);
const resourceInventoryInput = {
  ...writeValidD1StagingConfigFiles('seams-d1-staging-resources-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
};
const misScopedResourceInventoryInput = {
  ...writeMisScopedConsoleD1StagingConfigFiles('seams-d1-staging-resources-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
};

function resourceCommandRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, { command, ok: true });
}

function failingResourceCommandRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, { command, ok: false }, {
    status: 1,
    stderr: 'remote inventory failed',
  });
}

function emptyJsonResourceCommandRunner(command: string): D1StagingCommandResult {
  return {
    command,
    status: 0,
    stdout: '',
    stderr: '',
  };
}

test('D1 staging resource inventory records config-derived resource IDs', async () => {
  const module = await resourceInventoryModule;
  const plan = module.buildD1StagingResourceInventoryPlan(resourceInventoryInput);

  expect(plan.resources.consoleWorker.name).toBe('seams-sdk-d1-console-staging');
  expect(plan.resources.consoleWorker.d1Databases).toEqual([
    {
      binding: 'CONSOLE_DB',
      databaseName: 'seams-console-staging',
      databaseId: '11111111-1111-4111-8111-111111111111',
      migrationsDir: 'migrations/d1-console',
    },
  ]);
  expect(plan.resources.consoleWorker.durableObjects).toEqual([]);
  expect(plan.resources.gatewayWorker.d1Databases).toHaveLength(2);
  expect(plan.resources.gatewayWorker.durableObjects).toEqual([
    {
      name: 'THRESHOLD_STORE',
      className: 'ThresholdStoreDurableObject',
    },
    {
      name: 'ROUTER_API_RUNTIME',
      className: 'RouterApiRuntimeDurableObject',
    },
  ]);
  expect(plan.resources.gatewayWorker.secretsStoreSecrets).toEqual([
    {
      binding: 'SIGNING_ROOT_KEK_STAGING_R1',
      storeId: '33333333333333333333333333333333',
      secretName: 'signing-root-kek-staging-r1',
    },
  ]);
});

test('D1 staging resource inventory dry-run writes a manifest without remote commands', async () => {
  const module = await resourceInventoryModule;
  const manifestPath = d1StagingManifestPath('seams-d1-resources');
  const result = module.runD1StagingResourceInventory({
    ...resourceInventoryInput,
    manifestPath,
  });

  expect(result.manifest.checks).toEqual([]);
  expect(readD1StagingJsonFile(manifestPath).commands).toHaveLength(4);
});

test('D1 staging resource inventory remote mode records D1 and Worker JSON metadata', async () => {
  const module = await resourceInventoryModule;
  const manifestPath = d1StagingManifestPath('seams-d1-resources-remote');
  const result = module.runD1StagingResourceInventory({
    ...resourceInventoryInput,
    manifestPath,
    mode: 'remote',
    commandRunner: resourceCommandRunner,
  });

  expect(result.manifest.checks).toHaveLength(4);
  expect(result.manifest.checks[0]).toMatchObject({
    id: 'console_d1_info',
    target: 'console_d1',
  });
});

test('D1 staging resource inventory rejects failed remote metadata commands', async () => {
  const module = await resourceInventoryModule;
  expect(() =>
    module.runD1StagingResourceInventory({
      ...resourceInventoryInput,
      manifestPath: d1StagingManifestPath('seams-d1-resources-fail'),
      mode: 'remote',
      commandRunner: failingResourceCommandRunner,
    }),
  ).toThrow(/Command failed: pnpm --dir packages\/console-server-ts exec wrangler d1 info/);
});

test('D1 staging resource inventory rejects empty remote JSON metadata', async () => {
  const module = await resourceInventoryModule;
  expect(() =>
    module.runD1StagingResourceInventory({
      ...resourceInventoryInput,
      manifestPath: d1StagingManifestPath('seams-d1-resources-empty-json'),
      mode: 'remote',
      commandRunner: emptyJsonResourceCommandRunner,
    }),
  ).toThrow(/console_d1_info returned empty Wrangler JSON output/);
});

test('D1 staging resource inventory rejects configs that fail the readiness gate', async () => {
  const module = await resourceInventoryModule;
  expect(() =>
    module.buildD1StagingResourceInventoryPlan(misScopedResourceInventoryInput),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});
