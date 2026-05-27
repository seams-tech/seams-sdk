export { PasskeyClientDBManager, DBConstraintError } from './passkeyClientDB/manager';
export { AccountKeyMaterialDBManager } from './accountKeyMaterialDB/manager';
export { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
export { createIndexedDBNonceLaneCoordinationStore } from './nonceLaneCoordinationStore';
export { passkeyClientDB, accountKeyMaterialDB, seamsWalletDB } from './singletons';
export {
  LEGACY_INDEXED_DB_NAMES,
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_DB_VERSION,
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_SCHEMA_MANIFEST,
  SEAMS_WALLET_STORES,
  assertCanonicalIndexedDBName,
  createSeamsTestWalletDbName,
} from './schemaNames';
export { upgradeSeamsWalletDBSchema } from './seamsWalletDB/schema';
export { SeamsWalletDBManager } from './seamsWalletDB/manager';

export type {
  ActivateAccountSignerInput,
  ActivateAccountSignerResult,
  AccountSignerActivationPlan,
  SignerActivationPolicy,
  SignerLifecycleErrorCode,
  SignerAuthMethod,
  SignerKind,
  SignerSource,
  StageAccountSignerInput,
  StageAccountSignerResult,
} from './accountSignerLifecycle';

export {
  SIGNER_MATERIAL_FINGERPRINT_METADATA_KEY,
  SignerLifecycleError,
  planAccountSignerActivation,
} from './accountSignerLifecycle';

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
  NonceLaneLeaseStoreRecord,
  NonceLaneLeaseStoreRecordState,
  NonceLaneLockStoreRecord,
  UpsertProfileInput,
  UpsertChainAccountInput,
  UpsertAccountSignerInput,
  EnqueueSignerOperationInput,
} from './passkeyClientDB.types';


export type {
  KeyMaterialAlgorithm,
  KeyMaterialKind,
  KeyMaterialPayloadEnvelope,
  KeyMaterialPayloadEnvelopeAAD,
  KeyMaterialRecord,
} from './accountKeyMaterialDB.types';

import { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
import { passkeyClientDB, accountKeyMaterialDB, seamsWalletDB } from './singletons';

export type IndexedDBMode = 'app' | 'wallet' | 'disabled';

const DB_CONFIG_BY_MODE: Record<
  IndexedDBMode,
  {
    clientDbName: string;
    accountKeyMaterialDbName: string;
    clientDisabled: boolean;
    accountKeyMaterialDisabled: boolean;
  }
> = {
  app: {
    clientDbName: 'PasskeyClientDB',
    accountKeyMaterialDbName: 'PasskeyAccountKeyMaterial',
    clientDisabled: false,
    accountKeyMaterialDisabled: false,
  },
  wallet: {
    clientDbName: 'PasskeyClientDB',
    accountKeyMaterialDbName: 'PasskeyAccountKeyMaterial',
    clientDisabled: false,
    accountKeyMaterialDisabled: false,
  },
  // Fully disables IndexedDB for runtimes that route all persistence elsewhere.
  disabled: {
    clientDbName: 'PasskeyClientDB',
    accountKeyMaterialDbName: 'PasskeyAccountKeyMaterial',
    clientDisabled: true,
    accountKeyMaterialDisabled: true,
  },
};

let configured: {
  mode: IndexedDBMode;
  clientDbName: string;
  accountKeyMaterialDbName: string;
  clientDisabled: boolean;
  accountKeyMaterialDisabled: boolean;
} | null = null;

/**
 * Configure IndexedDB database names for the current runtime.
 *
 * Call this once, early (before any IndexedDB access).
 * - Wallet iframe host should use `mode: 'wallet'`.
 * - App origin should use `mode: 'disabled'` when wallet-iframe mode is enabled.
 * - Non-iframe apps should use `mode: 'app'`.
 * - Headless/proxy runtimes that cannot touch IndexedDB should use `mode: 'disabled'`.
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
      configured.clientDisabled === next.clientDisabled &&
      configured.accountKeyMaterialDisabled === next.accountKeyMaterialDisabled;
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
  seamsWalletDB.setDbName('seams_wallet');
  passkeyClientDB.setDisabled(next.clientDisabled);
  accountKeyMaterialDB.setDisabled(next.accountKeyMaterialDisabled);
  seamsWalletDB.setDisabled(next.clientDisabled && next.accountKeyMaterialDisabled);
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

export function isIndexedDBPersistenceDisabled(): boolean {
  return Boolean(configured?.clientDisabled && configured?.accountKeyMaterialDisabled);
}

// Export singleton instance of unified manager
export const IndexedDBManager = new UnifiedIndexedDBManager({
  clientDB: passkeyClientDB,
  accountKeyMaterialDB: accountKeyMaterialDB,
});
