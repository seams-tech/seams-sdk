import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { EcdsaThresholdKeyId } from '../keyMaterialBrands';
import type {
  RawSigningSessionSealedStoreRecord,
  RejectedSealedRecoveryRecord,
  SealedRecoveryRecord,
} from './recoveryRecord';

type RestoreSealedSessionListInput = {
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
  RestorePersistedSessionForSigningTransactionInput & {
    curve: 'ecdsa';
    chainTarget: ThresholdEcdsaChainTarget;
    materialRestoreIdentity: {
      kind: 'ecdsa_role_local_restore';
      lane: ExactEcdsaSigningLaneIdentity;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    };
  };

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

export type RestorePersistedEcdsaSessionForSigningInput = RestorePersistedSessionForSigningInput;

export type RestorePersistedSessionPurpose = {
  walletId: string;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: string;
  thresholdSessionId: string;
  reason: 'transaction' | 'export' | 'session_status';
};

export type RestorePersistedEcdsaSessionPurpose = RestorePersistedSessionPurpose;

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

export type DiscoverPersistedSessionsForWalletInput = DiscoverPersistedSessionsForWalletBase & {
  kind: 'discover_wallet_ecdsa_signing_sessions';
};

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
  onRejectedRecord?: (args: { walletId: string; rejection: RejectedSealedRecoveryRecord }) => void;
  cache?: SigningSessionRestoreCache;
};

export type DiscoverPersistedSessionsForWalletPorts = {
  listExactSealedSessionsForWallet: (
    args: RestoreSealedSessionListInput,
  ) => Promise<RawSigningSessionSealedStoreRecord[]>;
  onListError?: (args: { walletId: string; error: unknown }) => void;
  onRejectedRecord?: (args: { walletId: string; rejection: RejectedSealedRecoveryRecord }) => void;
};
