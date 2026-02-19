import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type { ChainAccountRecord } from '../passkeyClientDB.types';
import type {
  DbMultichainSchemaParity,
  InvariantValidationSummary,
} from './invariants';
import {
  DB_CONFIG,
  DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY,
  DB_MULTICHAIN_MIGRATION_HEARTBEAT_INTERVAL_MS,
  DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
  DB_MULTICHAIN_MIGRATION_STATE_KEY,
} from './schema';

export interface DbMultichainMigrationLock {
  ownerTabId: string;
  acquiredAt: number;
  heartbeatAt: number;
}

export type DbMultichainMigrationStep =
  | 'smartAccountDefaultsBackfilled'
  | 'paritySummaryLogged'
  | 'invariantsValidatedAndQuarantined';

export type DbMultichainMigrationCheckpoints = Partial<Record<
  DbMultichainMigrationStep,
  {
    status: 'completed';
    completedAt: number;
    counts?: Record<string, number>;
  }
>>;

export interface DbMultichainMigrationCounts {
  smartAccountRowsScanned: number;
  smartAccountRowsBackfilled: number;
  invariantRowsChecked: number;
  invariantViolationsFound: number;
  invariantRowsQuarantined: number;
}

export interface DbMultichainMigrationState {
  status: 'running' | 'completed' | 'failed';
  schemaVersion: number;
  startedAt: number;
  finishedAt?: number;
  counts: DbMultichainMigrationCounts;
  checkpoints?: DbMultichainMigrationCheckpoints;
  error?: string;
}

export interface RunMigrationsIfNeededArgs {
  db: IDBPDatabase;
  getAppStateFromDb: (db: IDBPDatabase, key: string) => Promise<unknown | undefined>;
  setAppStateInDb: (db: IDBPDatabase, key: string, value: unknown) => Promise<void>;
  createMigrationOwnerId: () => string;
  tryAcquireMigrationLeaseInAppState: (
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ) => Promise<boolean>;
  refreshMigrationLeaseInAppState: (
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ) => Promise<void>;
  clearMigrationLeaseInAppState: (
    db: IDBPDatabase,
    ownerTabId: string,
  ) => Promise<void>;
  tryRunWithNavigatorMigrationLock: (
    runner: () => Promise<void>,
  ) => Promise<'executed' | 'unavailable' | 'unsupported'>;
  collectMigrationParity: (db: IDBPDatabase) => Promise<DbMultichainSchemaParity>;
  validateAndQuarantineInvariantViolations: (
    db: IDBPDatabase,
  ) => Promise<InvariantValidationSummary>;
}

function buildDefaultMigrationCounts(): DbMultichainMigrationCounts {
  return {
    smartAccountRowsScanned: 0,
    smartAccountRowsBackfilled: 0,
    invariantRowsChecked: 0,
    invariantViolationsFound: 0,
    invariantRowsQuarantined: 0,
  };
}

function normalizeAccountModel(value: unknown): string {
  return toTrimmedString(value || '').toLowerCase();
}

function normalizeAccountAddress(value: unknown): string {
  return toTrimmedString(value || '').toLowerCase();
}

function hasSmartAccountShape(row: ChainAccountRecord): boolean {
  const accountModel = normalizeAccountModel(row.accountModel);
  return (
    accountModel === 'erc4337'
    || accountModel === 'tempo-native'
    || toTrimmedString((row as any)?.factory || '').length > 0
    || toTrimmedString((row as any)?.entryPoint || '').length > 0
    || toTrimmedString((row as any)?.salt || '').length > 0
    || toTrimmedString((row as any)?.counterfactualAddress || '').length > 0
  );
}

export async function runMigrationsIfNeeded(args: RunMigrationsIfNeededArgs): Promise<void> {
  const { db } = args;

  const existingState = await args.getAppStateFromDb(
    db,
    DB_MULTICHAIN_MIGRATION_STATE_KEY,
  ).catch(() => undefined) as DbMultichainMigrationState | undefined;
  const existingVersion = Number(existingState?.schemaVersion || 1);
  if (
    existingState?.status === 'completed'
    && existingVersion >= DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION
  ) {
    return;
  }

  const checkpointsFromAppState = await args.getAppStateFromDb(
    db,
    DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY,
  ).catch(() => undefined) as DbMultichainMigrationCheckpoints | undefined;

  const ownerTabId = args.createMigrationOwnerId();
  const acquiredAt = Date.now();
  const startedAt =
    existingVersion >= DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION
    && typeof existingState?.startedAt === 'number'
      ? existingState.startedAt
      : acquiredAt;
  const counts: DbMultichainMigrationCounts = {
    ...buildDefaultMigrationCounts(),
    ...(existingState?.counts || {}),
  };
  const checkpoints: DbMultichainMigrationCheckpoints = {
    ...(checkpointsFromAppState || {}),
    ...(existingState?.checkpoints || {}),
  };
  let lastHeartbeatAt = 0;

  const refreshHeartbeat = async (force = false): Promise<void> => {
    const now = Date.now();
    if (!force && now - lastHeartbeatAt < DB_MULTICHAIN_MIGRATION_HEARTBEAT_INTERVAL_MS) {
      return;
    }
    await args.refreshMigrationLeaseInAppState(db, ownerTabId, acquiredAt);
    lastHeartbeatAt = now;
  };

  const persistRunningState = async (): Promise<void> => {
    await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, {
      status: 'running',
      schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
      startedAt,
      counts,
      checkpoints,
    } satisfies DbMultichainMigrationState);
    await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY, checkpoints);
    await refreshHeartbeat(true);
  };

  const markCheckpoint = async (
    step: DbMultichainMigrationStep,
    stepCounts?: Record<string, number>,
  ): Promise<void> => {
    checkpoints[step] = {
      status: 'completed',
      completedAt: Date.now(),
      ...(stepCounts ? { counts: stepCounts } : {}),
    };
    await persistRunningState();
    console.info('PasskeyClientDB: migration checkpoint completed', {
      step,
      counts: stepCounts || null,
    });
  };

  const runMigration = async (): Promise<void> => {
    const leaseAcquired = await args.tryAcquireMigrationLeaseInAppState(
      db,
      ownerTabId,
      acquiredAt,
    );
    if (!leaseAcquired) {
      console.info('PasskeyClientDB: skipping migration; another tab owns active app-state lock');
      return;
    }

    lastHeartbeatAt = Date.now();
    console.info('PasskeyClientDB: schema migration started', {
      schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
      ownerTabId,
    });

    try {
      await persistRunningState();

      if (!checkpoints.smartAccountDefaultsBackfilled) {
        let stepScanned = 0;
        let stepBackfilled = 0;
        if (db.objectStoreNames.contains(DB_CONFIG.chainAccountsStore)) {
          const chainTx = db.transaction(DB_CONFIG.chainAccountsStore, 'readwrite');
          let chainCursor = await chainTx.store.openCursor();
          while (chainCursor) {
            const current = chainCursor;
            await refreshHeartbeat();
            const row = current.value as ChainAccountRecord;
            if (hasSmartAccountShape(row)) {
              stepScanned += 1;
              counts.smartAccountRowsScanned += 1;
              const accountAddress = normalizeAccountAddress(row.accountAddress);
              const existingCounterfactual = normalizeAccountAddress(
                (row as any)?.counterfactualAddress,
              );
              const counterfactualAddress = existingCounterfactual || accountAddress;
              const hasDeployed = typeof (row as any)?.deployed === 'boolean';
              if (!hasDeployed || counterfactualAddress !== existingCounterfactual) {
                await current.update({
                  ...row,
                  counterfactualAddress,
                  deployed: hasDeployed ? (row as any).deployed : false,
                  updatedAt:
                    typeof (row as any)?.updatedAt === 'number'
                      ? (row as any).updatedAt
                      : Date.now(),
                } as ChainAccountRecord);
                stepBackfilled += 1;
                counts.smartAccountRowsBackfilled += 1;
              }
            }
            chainCursor = await current.continue();
          }
          await chainTx.done;
        }
        await markCheckpoint('smartAccountDefaultsBackfilled', {
          scanned: stepScanned,
          backfilled: stepBackfilled,
        });
      }

      if (!checkpoints.paritySummaryLogged) {
        const parity = await args.collectMigrationParity(db);
        await markCheckpoint('paritySummaryLogged', {
          mismatches: parity.mismatches.length,
        });
        console.info('PasskeyClientDB: migration parity summary', parity);
      }

      if (!checkpoints.invariantsValidatedAndQuarantined) {
        const invariantSummary = await args.validateAndQuarantineInvariantViolations(db);
        counts.invariantRowsChecked += invariantSummary.checked;
        counts.invariantViolationsFound += invariantSummary.violations;
        counts.invariantRowsQuarantined += invariantSummary.quarantined;
        await markCheckpoint('invariantsValidatedAndQuarantined', {
          checked: invariantSummary.checked,
          violations: invariantSummary.violations,
          quarantined: invariantSummary.quarantined,
        });
        console.info('PasskeyClientDB: migration invariants validation summary', invariantSummary);
      }

      const finishedAt = Date.now();
      const completedState: DbMultichainMigrationState = {
        status: 'completed',
        schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
        startedAt,
        finishedAt,
        counts,
        checkpoints,
      };
      await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, completedState);
      await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY, checkpoints);
      console.info('PasskeyClientDB: schema migration completed', {
        durationMs: finishedAt - startedAt,
        counts,
      });
    } catch (error: any) {
      const finishedAt = Date.now();
      const failedState: DbMultichainMigrationState = {
        status: 'failed',
        schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
        startedAt,
        finishedAt,
        counts,
        checkpoints,
        error: String(error?.message || error),
      };
      await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, failedState).catch(
        () => undefined,
      );
      console.error('PasskeyClientDB: schema migration failed', {
        durationMs: finishedAt - startedAt,
        error: failedState.error,
        counts,
      });
      throw error;
    } finally {
      await args.clearMigrationLeaseInAppState(db, ownerTabId).catch(() => undefined);
    }
  };

  const lockOutcome = await args.tryRunWithNavigatorMigrationLock(runMigration);
  if (lockOutcome === 'unsupported') {
    await runMigration();
    return;
  }
  if (lockOutcome === 'unavailable') {
    console.info('PasskeyClientDB: skipping migration; navigator lock held by another tab');
  }
}
