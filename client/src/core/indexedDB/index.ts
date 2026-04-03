export { PasskeyClientDBManager, DBConstraintError } from './passkeyClientDB/manager';
export { AccountKeyMaterialDBManager } from './accountKeyMaterialDB/manager';
export { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
export { passkeyClientDB, accountKeyMaterialDB } from './singletons';

export type {
  UserPreferences,
  ProfileAuthenticatorRecord,
  ProfileContinuitySnapshot,
  IndexedDBEvent,
  LastProfileState,
  ProfileId,
  ChainIdKey,
  AccountAddress,
  SignerId,
  AccountRef,
  MigrationQuarantineRecord,
  PasskeyCredentialRecord,
  ProfileRecord,
  ChainAccountRecord,
  AccountSignerRecord,
  AccountModelCapabilities,
  AccountSignerStatus,
  DBConstraintErrorCode,
  SignerOperationStatus,
  SignerMutationOptions,
  SignerOpOutboxRecord,
  ProfileRecoveryEmailRecord,
  UpsertProfileInput,
  UpsertChainAccountInput,
  UpsertAccountSignerInput,
  EnqueueSignerOperationInput,
} from './passkeyClientDB.types';

export type { UndeployedSmartAccountSignerSet } from '@shared/utils';

export type {
  KeyMaterialAlgorithm,
  KeyMaterialKind,
  KeyMaterialPayloadEnvelope,
  KeyMaterialPayloadEnvelopeAAD,
  KeyMaterialRecord,
} from './accountKeyMaterialDB.types';

import { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
import { passkeyClientDB, accountKeyMaterialDB } from './singletons';

export type IndexedDBMode = 'app' | 'wallet' | 'disabled';

const DB_CONFIG_BY_MODE: Record<
  IndexedDBMode,
  { clientDbName: string; accountKeyMaterialDbName: string; disabled: boolean }
> = {
  app: {
    clientDbName: 'PasskeyClientDB',
    accountKeyMaterialDbName: 'PasskeyAccountKeyMaterial',
    disabled: false,
  },
  wallet: {
    clientDbName: 'PasskeyClientDB',
    accountKeyMaterialDbName: 'PasskeyAccountKeyMaterial',
    disabled: false,
  },
  // When running the SDK on the app origin with a wallet iframe configured, we disable IndexedDB entirely
  // to ensure no SDK tables are created and nothing can accidentally persist there.
  disabled: {
    clientDbName: 'PasskeyClientDB',
    accountKeyMaterialDbName: 'PasskeyAccountKeyMaterial',
    disabled: true,
  },
};

let configured: {
  mode: IndexedDBMode;
  clientDbName: string;
  accountKeyMaterialDbName: string;
  disabled: boolean;
} | null = null;

/**
 * Configure IndexedDB database names for the current runtime.
 *
 * Call this once, early (before any IndexedDB access).
 * - Wallet iframe host should use `mode: 'wallet'`.
 * - App origin should use `mode: 'disabled'` when wallet-iframe mode is enabled.
 * - Non-iframe apps should use `mode: 'app'`.
 */
export function configureIndexedDB(args: { mode: IndexedDBMode }): {
  clientDbName: string;
  accountKeyMaterialDbName: string;
} {
  const mode = args?.mode;
  const next = DB_CONFIG_BY_MODE[mode];
  if (!next) {
    throw new Error(`[IndexedDBManager] Unknown IndexedDBMode: ${String(mode)}`);
  }

  if (configured) {
    const isSame =
      configured.clientDbName === next.clientDbName &&
      configured.accountKeyMaterialDbName === next.accountKeyMaterialDbName &&
      configured.disabled === next.disabled;
    if (!isSame) {
      console.warn(
        '[IndexedDBManager] configureIndexedDB called multiple times; ignoring subsequent configuration',
        {
          configured,
          requested: next,
        },
      );
    }
    return {
      clientDbName: configured.clientDbName,
      accountKeyMaterialDbName: configured.accountKeyMaterialDbName,
    };
  }

  configured = { mode, ...next };
  passkeyClientDB.setDbName(next.clientDbName);
  accountKeyMaterialDB.setDbName(next.accountKeyMaterialDbName);
  passkeyClientDB.setDisabled(next.disabled);
  accountKeyMaterialDB.setDisabled(next.disabled);
  return {
    clientDbName: configured.clientDbName,
    accountKeyMaterialDbName: configured.accountKeyMaterialDbName,
  };
}

export function getIndexedDBNames(): { clientDbName: string; accountKeyMaterialDbName: string } {
  return (
    configured || {
      clientDbName: passkeyClientDB.getDbName(),
      accountKeyMaterialDbName: accountKeyMaterialDB.getDbName(),
    }
  );
}

// Export singleton instance of unified manager
export const IndexedDBManager = new UnifiedIndexedDBManager({
  clientDB: passkeyClientDB,
  accountKeyMaterialDB: accountKeyMaterialDB,
});
