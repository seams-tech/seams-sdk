import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '../identity/exactSigningLaneIdentity';
import type { EcdsaThresholdKeyId } from '../keyMaterialBrands';
import type { Ed25519RestoreMaterialIdentity } from '../ed25519MaterialAuthority';
import type {
  RawSigningSessionSealedStoreRecord,
  RejectedSealedRecoveryRecord,
  SealedRecoveryRecord,
} from './recoveryRecord';

type RestoreSealedSessionListInput =
  | {
      walletId: string;
      authMethod: 'email_otp' | 'passkey';
      curve: 'ed25519';
    }
  | {
      walletId: string;
      authMethod: 'email_otp' | 'passkey';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

type RestorePersistedSessionForSigningBaseInput = {
  walletId: string;
  authMethod: 'email_otp' | 'passkey';
};

type RestorePersistedSessionForSigningTransactionInput =
  RestorePersistedSessionForSigningBaseInput & {
    signingGrantId: string;
    thresholdSessionId: string;
    reason: 'transaction' | 'export';
  };

export type RestorePersistedSessionForSigningInput =
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ed25519';
      chain: 'near';
      materialRestoreIdentity: {
        kind: 'ed25519_worker_material_restore';
        lane: ExactEd25519SigningLaneIdentity;
        // Resolved at the restore boundary against the live session record —
        // resolveEd25519RestoreMaterialIdentity is the only constructor. Raw lane
        // snapshots and durable-cache identities are planning data and deliberately
        // do not typecheck here; they must pass through the resolver, which prefers
        // the live record and only falls back to a hint when no authority exists.
        material: Ed25519RestoreMaterialIdentity;
        ecdsaThresholdKeyId?: never;
      };
    })
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      materialRestoreIdentity: {
        kind: 'ecdsa_role_local_restore';
        lane: ExactEcdsaSigningLaneIdentity;
        ecdsaThresholdKeyId: EcdsaThresholdKeyId;
        material?: never;
      };
    });

export type RestorePersistedSessionForSigningResult =
  | {
      kind: 'completed';
      attempted: number;
      restored: number;
      deferred: number;
      duplicateCount?: never;
      duplicateRecordSummaries?: never;
    }
  | {
      kind: 'duplicate_records';
      attempted: 0;
      restored: 0;
      deferred: 0;
      duplicateCount: number;
      duplicateRecordSummaries: readonly Record<string, unknown>[];
    };

export type RestorePersistedEd25519SessionForSigningInput = Extract<
  RestorePersistedSessionForSigningInput,
  { curve: 'ed25519' }
>;

export type RestorePersistedEcdsaSessionForSigningInput = Extract<
  RestorePersistedSessionForSigningInput,
  { curve: 'ecdsa' }
>;

export type RestorePersistedSessionPurpose = {
  walletId: string;
  authMethod: 'email_otp' | 'passkey';
  signingGrantId: string;
  thresholdSessionId: string;
  reason: 'transaction' | 'export' | 'session_status';
} & (
  | {
      curve: 'ed25519';
      chain: 'near';
    }
  | {
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    }
);

export type RestorePersistedEd25519SessionPurpose = Extract<
  RestorePersistedSessionPurpose,
  { curve: 'ed25519' }
>;

export type RestorePersistedEcdsaSessionPurpose = Extract<
  RestorePersistedSessionPurpose,
  { curve: 'ecdsa' }
>;

export type RestorePersistedSessionWorkItem = {
  record: SealedRecoveryRecord;
  purpose: RestorePersistedSessionPurpose;
};

type DiscoverPersistedSessionsForWalletBase = {
  walletId: string;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  authMethod?: 'email_otp' | 'passkey';
  maxRecords?: number;
};

export type DiscoverPersistedSessionsForWalletInput =
  | (DiscoverPersistedSessionsForWalletBase & {
      kind: 'discover_wallet_all_signing_sessions';
    })
  | (DiscoverPersistedSessionsForWalletBase & {
      kind: 'discover_wallet_ecdsa_signing_sessions';
    });

export type DiscoverPersistedSessionsForWalletResult = {
  listed: number;
  discovered: number;
  truncated: number;
};

export type RestoreSealedRecordResult = 'restored' | 'ready' | 'deferred';

export type SigningSessionRestoreCache = {
  hasSuccessfulRestore: (
    input: RestorePersistedSessionForSigningInput | RestorePersistedSessionPurpose,
    record: SealedRecoveryRecord,
  ) => boolean;
  rememberSuccessfulRestore: (
    input: RestorePersistedSessionForSigningInput | RestorePersistedSessionPurpose,
    record: SealedRecoveryRecord,
  ) => void;
  clear: () => void;
};

export type SigningSessionRestoreAttemptRegistry = {
  hasCompleted: (key: string) => boolean;
  rememberCompleted: (key: string) => void;
  getInFlight: (key: string) => Promise<void> | undefined;
  setInFlight: (key: string, task: Promise<void>) => void;
  clearInFlight: (key: string) => void;
  clear: () => void;
};

export type RestorePersistedSessionForSigningPorts = {
  listExactSealedSessionsForWallet: (
    args: RestoreSealedSessionListInput,
  ) => Promise<RawSigningSessionSealedStoreRecord[]>;
  restoreSealedRecordForWallet: (args: {
    walletId: string;
    record: SealedRecoveryRecord;
    purpose: RestorePersistedSessionPurpose;
  }) => Promise<RestoreSealedRecordResult>;
  onListError?: (args: {
    walletId: string;
    target: string;
    reason: RestorePersistedSessionForSigningInput['reason'];
    error: unknown;
  }) => void;
  onRejectedRecord?: (args: {
    walletId: string;
    rejection: RejectedSealedRecoveryRecord;
  }) => void;
  cache?: SigningSessionRestoreCache;
};

export type DiscoverPersistedSessionsForWalletPorts = {
  listExactSealedSessionsForWallet: (
    args: RestoreSealedSessionListInput,
  ) => Promise<RawSigningSessionSealedStoreRecord[]>;
  onListError?: (args: { walletId: string; error: unknown }) => void;
  onRejectedRecord?: (args: {
    walletId: string;
    rejection: RejectedSealedRecoveryRecord;
  }) => void;
};
