import { expect, test } from '@playwright/test';
import {
  D1_STAGING_GENERATED_AT_ISO,
  d1StagingJsonCommandResult,
  loadD1StagingScriptModule,
  type D1StagingCommandRunner,
  writeValidD1StagingConfigFiles,
} from './helpers/d1StagingScriptFixtures';

type InventoryCounts = {
  readonly activeV1: number;
  readonly activeUsableV2: number;
  readonly activeV2WithoutCredential: number;
  readonly pendingV1AuthorizedOperations: number;
  readonly unconsumedHostedExchangeCodes: number;
  readonly v1OnlyQuotas: number;
  readonly activationCredentialRows: number;
  readonly provisioningCredentialRows: number;
};

type InventoryPlan = {
  readonly target: string;
  readonly databaseName: string;
  readonly query: string;
  readonly command: string;
};

type InventoryModule = {
  readonly buildSignerD1Phase1InventoryQuery: (nowMs?: number) => string;
  readonly buildD1StagingSignerPhase1InventoryPlan: (input: {
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly nowMs?: number;
  }) => InventoryPlan;
  readonly runD1StagingSignerPhase1Inventory: (input: {
    readonly gatewayConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly nowMs?: number;
    readonly commandRunner?: D1StagingCommandRunner;
  }) => InventoryPlan & { readonly counts: InventoryCounts | null };
};

const inventoryModule = loadD1StagingScriptModule<InventoryModule>(
  'd1-staging-signer-phase1-inventory.mjs',
);
const inventoryInput = {
  gatewayConfigPath: writeValidD1StagingConfigFiles('seams-d1-staging-signer-inventory-')
    .gatewayConfigPath,
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
  nowMs: 50,
};

test('signer Phase 1 inventory is a count-only query against the signer D1 target', async () => {
  const module = await inventoryModule;
  const query = module.buildSignerD1Phase1InventoryQuery(50);
  const plan = module.buildD1StagingSignerPhase1InventoryPlan(inventoryInput);

  expect(plan).toMatchObject({
    target: 'signer_d1',
    databaseName: 'seams-signer-staging-nrt',
  });
  expect(plan.command).toContain('d1 execute seams-signer-staging-nrt --remote --json');
  expect(plan.query).toBe(query);
  expect(query).toContain('COUNT(*)');
  expect(query).not.toContain('SELECT *');
  expect(query).toContain('json_tree(record_json)');
  expect(query).toContain("'walletSessionToken'");
  expect(query).toContain("'operationCredential'");
  expect(query).toContain("'clientRootProof'");
  expect(query).toContain("'passkeyBootstrapAuthorization'");
  expect(query).toContain('active_v1');
  expect(query).toContain('active_usable_v2');
  expect(query).toContain('active_v2_without_credential');
  expect(query).toContain('pending_v1_authorized_operations');
  expect(query).toContain('unconsumed_hosted_exchange_codes');
  expect(query).toContain('v1_only_quotas');
  expect(query).toContain('activation_credential_rows');
  expect(query).toContain('provisioning_credential_rows');
});

test('remote signer Phase 1 inventory emits sanitized counts and drops row bodies', async () => {
  const module = await inventoryModule;
  const secret = 'credential-bearing-row-secret';
  const runner: D1StagingCommandRunner = (command) =>
    d1StagingJsonCommandResult(command, [
      {
        results: [
          {
            active_v1: 1,
            active_usable_v2: 2,
            active_v2_without_credential: 3,
            pending_v1_authorized_operations: 4,
            unconsumed_hosted_exchange_codes: 5,
            v1_only_quotas: 6,
            activation_credential_rows: 7,
            provisioning_credential_rows: 8,
            record_json: JSON.stringify({ walletSessionToken: secret }),
          },
        ],
      },
    ]);

  const result = module.runD1StagingSignerPhase1Inventory({
    ...inventoryInput,
    mode: 'remote',
    commandRunner: runner,
  });

  expect(result.counts).toEqual({
    activeV1: 1,
    activeUsableV2: 2,
    activeV2WithoutCredential: 3,
    pendingV1AuthorizedOperations: 4,
    unconsumedHostedExchangeCodes: 5,
    v1OnlyQuotas: 6,
    activationCredentialRows: 7,
    provisioningCredentialRows: 8,
  });
  expect(JSON.stringify(result)).not.toContain(secret);
});

test('dry-run signer Phase 1 inventory does not execute the D1 command', async () => {
  const module = await inventoryModule;
  let calls = 0;
  const result = module.runD1StagingSignerPhase1Inventory({
    ...inventoryInput,
    commandRunner: () => {
      calls += 1;
      return d1StagingJsonCommandResult('unexpected', []);
    },
  });

  expect(result.counts).toBeNull();
  expect(calls).toBe(0);
});
