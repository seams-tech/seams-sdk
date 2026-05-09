import type { SigningSessionSealedStoreRecord } from '../persistence/sealedSessionStore';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
    walletSigningSessionId: string;
    thresholdSessionId: string;
    reason: 'transaction' | 'export';
  };

export type RestorePersistedSessionForSigningInput =
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ed25519';
      chain: 'near';
    })
  | (RestorePersistedSessionForSigningTransactionInput & {
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    });

export type RestorePersistedSessionForSigningResult = {
  attempted: number;
  restored: number;
  deferred: number;
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
  walletSigningSessionId: string;
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
  record: SigningSessionSealedStoreRecord;
  purpose: RestorePersistedSessionPurpose;
};

export type RestorePersistedSessionsForAccountInput = {
  walletId: string;
  ecdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
  authMethod?: 'email_otp' | 'passkey';
  maxRecords?: number;
};

export type RestorePersistedSessionsForAccountResult = {
  listed: number;
  attempted: number;
  restored: number;
  deferred: number;
  skipped: number;
  truncated: number;
};

export type RestoreSealedRecordForAccountResult = 'restored' | 'ready' | 'deferred';

export type SigningSessionRestoreCache = {
  hasKnownMissing: (input: RestorePersistedSessionForSigningInput) => boolean;
  rememberKnownMissing: (input: RestorePersistedSessionForSigningInput) => void;
  hasSuccessfulRestore: (
    input: RestorePersistedSessionForSigningInput | RestorePersistedSessionPurpose,
    record: SigningSessionSealedStoreRecord,
  ) => boolean;
  rememberSuccessfulRestore: (
    input: RestorePersistedSessionForSigningInput | RestorePersistedSessionPurpose,
    record: SigningSessionSealedStoreRecord,
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
  listExactSealedSessionsForAccount: (
    args: RestoreSealedSessionListInput,
  ) => Promise<SigningSessionSealedStoreRecord[]>;
  restoreSealedRecordForAccount: (args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }) => Promise<RestoreSealedRecordForAccountResult>;
  onListError?: (args: {
    accountId: string;
    target: string;
    reason: RestorePersistedSessionForSigningInput['reason'];
    error: unknown;
  }) => void;
  cache?: SigningSessionRestoreCache;
};

export type RestorePersistedSessionsForAccountPorts = {
  listExactSealedSessionsForAccount: (
    args: RestoreSealedSessionListInput,
  ) => Promise<SigningSessionSealedStoreRecord[]>;
  restoreSealedRecordForAccount: (args: {
    accountId: string;
    record: SigningSessionSealedStoreRecord;
    purpose: RestorePersistedSessionPurpose;
  }) => Promise<RestoreSealedRecordForAccountResult>;
  onListError?: (args: { accountId: string; error: unknown }) => void;
  cache?: SigningSessionRestoreCache;
};
