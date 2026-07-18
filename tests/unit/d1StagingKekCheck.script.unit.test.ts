import { expect, test } from '@playwright/test';
import {
  D1_STAGING_GENERATED_AT_ISO,
  d1StagingCommandResult,
  d1StagingJsonCommandResult,
  d1StagingManifestPath,
  loadD1StagingScriptModule,
  readD1StagingJsonFile,
  type D1StagingCommandResult,
  type D1StagingCommandRunner,
  validD1GatewayStagingConfig,
  writeD1StagingTempFile,
} from './helpers/d1StagingScriptFixtures';

type KekCheckPlan = {
  readonly mode: string;
  readonly commands: readonly string[];
  readonly keks: readonly {
    readonly kekId: string;
    readonly binding: string;
    readonly secretName: string;
    readonly storeId: string;
  }[];
};

type KekCheckModule = {
  readonly buildD1StagingKekCheckPlan: (input: {
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => KekCheckPlan;
  readonly runD1StagingKekCheck: (input: {
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly commandRunner?: D1StagingCommandRunner;
  }) => {
    readonly manifestPath: string;
    readonly manifest: KekCheckPlan & {
      readonly checks: readonly unknown[];
    };
  };
};

const kekCheckModule = loadD1StagingScriptModule<KekCheckModule>('d1-staging-kek-check.mjs');
const kekGatewayConfigPath = writeD1StagingTempFile(
  'seams-d1-kek-check-', 'wrangler.d1-staging-gateway.toml', validD1GatewayStagingConfig(),
);
const kekCheckInput = {
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
  gatewayConfigPath: kekGatewayConfigPath,
};

function listedSecretRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, [{ name: 'signing-root-kek-staging-r1' }]);
}

function listedSecretTextRunner(command: string): D1StagingCommandResult {
  return d1StagingCommandResult(command, {
    stdout: [
      'Name                            Created',
      'signing-root-kek-staging-r1     2026-06-28T00:00:00Z',
    ].join('\n'),
  });
}

function missingSecretRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, [{ name: 'other-secret' }]);
}

function substringOnlySecretRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, [{ name: 'signing-root-kek-staging-r10' }]);
}

function nonzeroListedSecretRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, [{ name: 'signing-root-kek-staging-r1' }], {
    status: 1,
    stderr: 'remote list failed',
  });
}

test('D1 staging KEK check builds metadata-only Secrets Store commands', async () => {
  const module = await kekCheckModule;
  const plan = module.buildD1StagingKekCheckPlan(kekCheckInput);

  expect(plan.keks).toEqual([
    {
      kekId: 'signing-root-kek-staging-r1',
      binding: 'SIGNING_ROOT_KEK_STAGING_R1',
      secretName: 'signing-root-kek-staging-r1',
      storeId: '33333333333333333333333333333333',
    },
  ]);
  expect(plan.commands).toEqual([
    'pnpm --dir packages/console-server-ts exec wrangler secrets-store secret list 33333333333333333333333333333333 --remote --per-page 100',
  ]);
});

test('D1 staging KEK check writes a dry-run manifest without listing remote secrets', async () => {
  const module = await kekCheckModule;
  const manifestPath = d1StagingManifestPath('seams-d1-kek-check');
  const result = module.runD1StagingKekCheck({
    ...kekCheckInput,
    manifestPath,
  });

  expect(result.manifest.checks).toEqual([]);
  expect(readD1StagingJsonFile(manifestPath).keks).toHaveLength(1);
});

test('D1 staging KEK check remote mode records metadata presence without secret values', async () => {
  const module = await kekCheckModule;
  const manifestPath = d1StagingManifestPath('seams-d1-kek-check-remote');
  const result = module.runD1StagingKekCheck({
    ...kekCheckInput,
    manifestPath,
    mode: 'remote',
    commandRunner: listedSecretRunner,
  });

  expect(result.manifest.checks).toEqual([
    {
      storeId: '33333333333333333333333333333333',
      command:
        'pnpm --dir packages/console-server-ts exec wrangler secrets-store secret list 33333333333333333333333333333333 --remote --per-page 100',
      status: 0,
      presentSecretNames: ['signing-root-kek-staging-r1'],
    },
  ]);
});

test('D1 staging KEK check remote mode accepts exact names from Wrangler text output', async () => {
  const module = await kekCheckModule;
  const manifestPath = d1StagingManifestPath('seams-d1-kek-check-text');
  const result = module.runD1StagingKekCheck({
    ...kekCheckInput,
    manifestPath,
    mode: 'remote',
    commandRunner: listedSecretTextRunner,
  });

  expect(result.manifest.checks).toEqual([
    expect.objectContaining({
      presentSecretNames: ['signing-root-kek-staging-r1'],
      status: 0,
    }),
  ]);
});

test('D1 staging KEK check fails when the hosted KEK secret metadata is absent', async () => {
  const module = await kekCheckModule;
  expect(() =>
    module.runD1StagingKekCheck({
      ...kekCheckInput,
      manifestPath: d1StagingManifestPath('seams-d1-kek-check-fail'),
      mode: 'remote',
      commandRunner: missingSecretRunner,
    }),
  ).toThrow(/does not list required KEK secret signing-root-kek-staging-r1/);
});

test('D1 staging KEK check rejects substring-only secret metadata matches', async () => {
  const module = await kekCheckModule;
  expect(() =>
    module.runD1StagingKekCheck({
      ...kekCheckInput,
      manifestPath: d1StagingManifestPath('seams-d1-kek-check-substring'),
      mode: 'remote',
      commandRunner: substringOnlySecretRunner,
    }),
  ).toThrow(/does not list required KEK secret signing-root-kek-staging-r1/);
});

test('D1 staging KEK check rejects failed remote listing commands', async () => {
  const module = await kekCheckModule;
  expect(() =>
    module.runD1StagingKekCheck({
      ...kekCheckInput,
      manifestPath: d1StagingManifestPath('seams-d1-kek-check-nonzero'),
      mode: 'remote',
      commandRunner: nonzeroListedSecretRunner,
    }),
  ).toThrow(/Command failed: pnpm --dir packages\/console-server-ts exec wrangler secrets-store secret list/);
});
