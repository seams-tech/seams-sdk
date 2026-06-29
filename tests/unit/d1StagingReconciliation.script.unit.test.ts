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

type ReconciliationPlan = {
  readonly mode: string;
  readonly tenant: {
    readonly namespace: string;
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  };
  readonly checks: readonly {
    readonly id: string;
    readonly target: string;
    readonly databaseName: string;
    readonly command: string;
  }[];
};

type ReconciliationModule = {
  readonly buildD1StagingReconciliationPlan: (input: {
    readonly consoleConfigPath: string;
    readonly routerApiConfigPath: string;
    readonly generatedAtIso?: string;
    readonly mode?: 'dry-run' | 'remote';
  }) => ReconciliationPlan;
  readonly runD1StagingReconciliation: (input: {
    readonly consoleConfigPath: string;
    readonly routerApiConfigPath: string;
    readonly generatedAtIso?: string;
    readonly manifestPath: string;
    readonly mode?: 'dry-run' | 'remote';
    readonly commandRunner?: D1StagingCommandRunner;
  }) => {
    readonly manifestPath: string;
    readonly manifest: ReconciliationPlan & {
      readonly executed: readonly {
        readonly id: string;
        readonly rowCount: number;
      }[];
    };
  };
};

const reconciliationModule = loadD1StagingScriptModule<ReconciliationModule>(
  'd1-staging-reconciliation.mjs',
);
const reconciliationInput = {
  ...writeValidD1StagingConfigFiles('seams-d1-staging-reconcile-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
};
const misScopedReconciliationInput = {
  ...writeMisScopedConsoleD1StagingConfigFiles('seams-d1-staging-reconcile-'),
  generatedAtIso: D1_STAGING_GENERATED_AT_ISO,
};

function emptyResultRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, [{ results: [] }]);
}

function mismatchResultRunner(command: string): D1StagingCommandResult {
  const rows = command.includes('billing_accounts')
    ? [{ namespace: 'seams-staging', org_id: 'org_staging', credit_balance_minor: 100, ledger_balance_minor: 0 }]
    : [];
  return d1StagingJsonCommandResult(command, [{ results: rows }]);
}

function failedEmptyResultRunner(command: string): D1StagingCommandResult {
  return d1StagingJsonCommandResult(command, [{ results: [] }], {
    status: 1,
    stderr: 'remote reconciliation failed',
  });
}

function emptyStdoutResultRunner(command: string): D1StagingCommandResult {
  return {
    command,
    status: 0,
    stdout: '',
    stderr: '',
  };
}

test('D1 staging reconciliation builds read-only console and signer checks', async () => {
  const module = await reconciliationModule;
  const plan = module.buildD1StagingReconciliationPlan(reconciliationInput);

  expect(plan.tenant).toEqual({
    namespace: 'seams-staging',
    orgId: 'org_staging',
    projectId: 'project_staging',
    envId: 'staging',
  });
  expect(plan.checks.map((check) => check.id)).toEqual([
    'billing_account_balance_mismatch',
    'prepaid_reservation_summary_mismatch',
    'sponsored_call_missing_billing_links',
    'sponsored_call_settlement_amount_mismatch',
    'signer_share_unknown_kek',
    'signer_share_invalid_rotation_state',
  ]);
  expect(plan.checks[0].command).toContain('d1 execute seams-console-staging --remote --json');
  expect(plan.checks[4].command).toContain('d1 execute seams-signer-staging --remote --json');
  expect(plan.checks[4].command).toContain('signing-root-kek-staging-r1');
});

test('D1 staging reconciliation dry-run writes a manifest without executing commands', async () => {
  const module = await reconciliationModule;
  const manifestPath = d1StagingManifestPath('seams-d1-reconcile');
  const result = module.runD1StagingReconciliation({
    ...reconciliationInput,
    manifestPath,
  });

  expect(result.manifest.executed).toEqual([]);
  expect(readD1StagingJsonFile(manifestPath).checks).toHaveLength(6);
});

test('D1 staging reconciliation remote mode records zero-row evidence', async () => {
  const module = await reconciliationModule;
  const manifestPath = d1StagingManifestPath('seams-d1-reconcile-remote');
  const result = module.runD1StagingReconciliation({
    ...reconciliationInput,
    manifestPath,
    mode: 'remote',
    commandRunner: emptyResultRunner,
  });

  expect(result.manifest.executed).toHaveLength(6);
  expect(result.manifest.executed.every((check) => check.rowCount === 0)).toBe(true);
});

test('D1 staging reconciliation fails when a check returns mismatch rows', async () => {
  const module = await reconciliationModule;
  expect(() =>
    module.runD1StagingReconciliation({
      ...reconciliationInput,
      manifestPath: d1StagingManifestPath('seams-d1-reconcile-fail'),
      mode: 'remote',
      commandRunner: mismatchResultRunner,
    }),
  ).toThrow(/billing_account_balance_mismatch: 1 mismatch row/);
});

test('D1 staging reconciliation rejects failed remote D1 query commands', async () => {
  const module = await reconciliationModule;
  expect(() =>
    module.runD1StagingReconciliation({
      ...reconciliationInput,
      manifestPath: d1StagingManifestPath('seams-d1-reconcile-command-fail'),
      mode: 'remote',
      commandRunner: failedEmptyResultRunner,
    }),
  ).toThrow(/Command failed: pnpm --dir packages\/sdk-server-ts exec wrangler d1 execute/);
});

test('D1 staging reconciliation rejects empty remote JSON output', async () => {
  const module = await reconciliationModule;
  expect(() =>
    module.runD1StagingReconciliation({
      ...reconciliationInput,
      manifestPath: d1StagingManifestPath('seams-d1-reconcile-empty-json'),
      mode: 'remote',
      commandRunner: emptyStdoutResultRunner,
    }),
  ).toThrow(/billing_account_balance_mismatch returned empty Wrangler JSON output/);
});

test('D1 staging reconciliation rejects configs that fail the readiness gate', async () => {
  const module = await reconciliationModule;
  expect(() =>
    module.buildD1StagingReconciliationPlan(misScopedReconciliationInput),
  ).toThrow(/console staging config must not reference SIGNER_DB/);
});
