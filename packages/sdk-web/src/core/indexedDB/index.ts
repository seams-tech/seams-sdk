export { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
export { createIndexedDBNonceLaneCoordinationStore } from './nonceLaneCoordinationStore';
export { seamsWalletDB } from './singletons';
export {
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
export { SeamsWalletRepositories } from './seamsWalletDB/repositories';

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
  LocalWalletAuthMethodRecord,
} from './passkeyClientDB.types';


export type {
  KeyMaterialAlgorithm,
  KeyMaterialKind,
  KeyMaterialPayloadEnvelope,
  KeyMaterialPayloadEnvelopeAAD,
  KeyMaterialRecord,
} from './keyMaterial.types';

import { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
import { seamsWalletDB } from './singletons';
import { SEAMS_WALLET_DB_NAME } from './schemaNames';

export type IndexedDBMode = 'app' | 'wallet' | 'disabled';

const DB_CONFIG_BY_MODE: Record<
  IndexedDBMode,
  {
    walletDbName: typeof SEAMS_WALLET_DB_NAME;
    disabled: boolean;
  }
> = {
  app: {
    walletDbName: SEAMS_WALLET_DB_NAME,
    disabled: false,
  },
  wallet: {
    walletDbName: SEAMS_WALLET_DB_NAME,
    disabled: false,
  },
  // Fully disables IndexedDB for runtimes that route all persistence elsewhere.
  disabled: {
    walletDbName: SEAMS_WALLET_DB_NAME,
    disabled: true,
  },
};

let configured: {
  mode: IndexedDBMode;
  walletDbName: string;
  disabled: boolean;
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
  walletDbName: string;
} {
  const mode = args?.mode;
  const next = DB_CONFIG_BY_MODE[mode];
  if (!next) {
    throw new Error(`[IndexedDBManager] Unknown IndexedDBMode: ${String(mode)}`);
  }

  if (configured) {
    const isSame =
      configured.walletDbName === next.walletDbName && configured.disabled === next.disabled;
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
      walletDbName: configured.walletDbName,
    };
  }

  configured = { mode, ...next };
  seamsWalletDB.setDbName(next.walletDbName);
  seamsWalletDB.setDisabled(next.disabled);
  return {
    walletDbName: configured.walletDbName,
  };
}

export function getIndexedDBNames(): { walletDbName: string } {
  return (
    configured || {
      walletDbName: seamsWalletDB.getDbName(),
    }
  );
}

export function isIndexedDBPersistenceDisabled(): boolean {
  return Boolean(configured?.disabled);
}

// Export singleton instance of unified manager
export const IndexedDBManager = new UnifiedIndexedDBManager({
  seamsWalletDB,
});
