import type { AccountId } from '../types/accountIds';
import type { ConfirmationConfig } from '../types/signer-worker';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SignerAuthMethod, SignerKind, SignerSource } from '@shared/utils';
import type { WalletAuthMethodRecord } from '@shared/utils/registrationIntent';

export interface PasskeyCredentialRecord {
  id: string;
  rawId: string;
}

export interface UserPreferences {
  useRelayer: boolean;
  useNetwork: 'testnet' | 'mainnet';
  confirmationConfig: ConfirmationConfig;
  // User preferences can be extended here as needed
}

export interface LastProfileState {
  profileId: string;
  activeSignerSlot: number;
  scope?: string | null;
}

export interface IndexedDBEvent {
  type: 'user-updated' | 'preferences-updated' | 'user-deleted';
  accountId: AccountId;
  data?: Record<string, unknown>;
}

export interface ProfileAuthenticatorRecord {
  profileId: string;
  signerSlot: number;
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[];
  name?: string;
  registered: string;
  syncedAt: string;
}

export type WalletPasskeyAuthenticatorLookup =
  | {
      kind: 'all_for_wallet';
      walletId: WalletId;
      credentialId?: never;
    }
  | {
      kind: 'by_credential';
      walletId: WalletId;
      credentialId: string;
    };

export type WalletSignerLookup =
  | {
      kind: 'active_by_family';
      walletId: WalletId;
      signerFamily: 'ed25519' | 'ecdsa';
      chainTarget?: never;
    }
  | {
      kind: 'active_ecdsa_by_chain_target';
      walletId: WalletId;
      signerFamily: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export interface SignerMutationOptions {
  routeThroughOutbox?: boolean;
  opId?: string;
  idempotencyKey?: string;
  outboxPayload?: Record<string, unknown>;
  outboxStatus?: SignerOperationStatus;
}

export type ProfileId = string;
export type ChainIdKey = string;
export type AccountAddress = string;
export type SignerId = string;

export interface AccountRef {
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
}

export type AccountModel = 'near-native' | 'threshold-ecdsa' | string;
export type AccountSignerType = 'passkey' | 'threshold' | 'session' | 'recovery' | string;
export type AccountSignerStatus = 'active' | 'pending' | 'revoked';
export type { SignerAuthMethod, SignerKind, SignerSource };
export interface AccountModelCapabilities {
  supportsMultiSigner: boolean;
  supportsAddRemoveSigner: boolean;
  supportsSessionSigner: boolean;
  supportsRecoverySigner: boolean;
}

export type DBConstraintErrorCode =
  | 'MISSING_PROFILE'
  | 'MISSING_CHAIN_ACCOUNT'
  | 'CHAIN_ACCOUNT_PROFILE_MISMATCH'
  | 'MULTI_SIGNER_NOT_SUPPORTED'
  | 'SIGNER_MUTATION_NOT_SUPPORTED'
  | 'SESSION_SIGNER_NOT_SUPPORTED'
  | 'RECOVERY_SIGNER_NOT_SUPPORTED'
  | 'MISSING_SIGNER_KIND'
  | 'DUPLICATE_ACTIVE_SIGNER_SLOT'
  | 'INVALID_SIGNER_STATUS_TRANSITION'
  | 'REVOKED_SIGNER_REQUIRES_REMOVED_AT'
  | 'INVALID_LAST_PROFILE_STATE'
  | 'INVALID_SIGNER_METADATA';

export type SignerOperationType =
  | 'add-signer'
  | 'revoke-signer'
  | 'activate-recovery-signer'
  | string;
export type SignerOperationStatus = 'queued' | 'submitted' | 'confirmed' | 'failed' | 'dead-letter';

export interface ProfileRecord {
  profileId: ProfileId;
  defaultSignerSlot: number;
  passkeyCredential?: PasskeyCredentialRecord;
  preferences?: UserPreferences;
  createdAt: number;
  updatedAt: number;
}

export interface ChainAccountRecord {
  profileId: ProfileId;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  accountModel: AccountModel;
  isPrimary?: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface AccountSignerRecord {
  profileId: ProfileId;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  signerId: SignerId;
  signerSlot: number;
  signerType: AccountSignerType;
  signerKind: SignerKind;
  signerAuthMethod: SignerAuthMethod;
  signerSource: SignerSource;
  status: AccountSignerStatus;
  addedAt: number;
  updatedAt: number;
  removedAt?: number;
  revocationReason?: string;
  metadata?: Record<string, unknown>;
}

export type LocalWalletAuthMethodRecord = WalletAuthMethodRecord & {
  localStatus: 'synced' | 'pending';
};

export interface ProfileContinuitySnapshot {
  profile: ProfileRecord;
  chainAccounts: ChainAccountRecord[];
  accountSigners: AccountSignerRecord[];
}

export interface SignerOpOutboxRecord {
  opId: string;
  idempotencyKey: string;
  opType: SignerOperationType;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  signerId: SignerId;
  payload?: Record<string, unknown>;
  status: SignerOperationStatus;
  attemptCount: number;
  nextAttemptAt: number;
  lastError?: string;
  txHash?: string;
  createdAt: number;
  updatedAt: number;
}

export type UpsertProfileInput = {
  profileId: ProfileId;
  defaultSignerSlot?: number;
  passkeyCredential?: PasskeyCredentialRecord;
  preferences?: UserPreferences;
};

export type UpsertChainAccountInput = {
  profileId: ProfileId;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  accountModel: AccountModel;
  isPrimary?: boolean;
};

export type UpsertAccountSignerInput = {
  profileId: ProfileId;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  signerId: SignerId;
  signerSlot: number;
  signerType: AccountSignerType;
  signerKind: SignerKind;
  signerAuthMethod: SignerAuthMethod;
  signerSource: SignerSource;
  status: AccountSignerStatus;
  removedAt?: number;
  revocationReason?: string;
  metadata?: Record<string, unknown>;
  mutation?: SignerMutationOptions;
};

export type EnqueueSignerOperationInput = {
  opId: string;
  idempotencyKey: string;
  opType: SignerOperationType;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  signerId: SignerId;
  payload?: Record<string, unknown>;
  status?: SignerOperationStatus;
  attemptCount?: number;
  nextAttemptAt?: number;
  lastError?: string;
  txHash?: string;
};

export interface ProfileRecoveryEmailRecord {
  profileId: ProfileId;
  hashHex: string;
  email: string;
  addedAt: number;
}

export type NonceLaneLeaseStoreRecordState = 'reserved' | 'signed' | 'broadcast_accepted';

interface NonceLaneLeaseStoreRecordBaseWithoutLifecycle {
  v: 1;
  leaseId: string;
  laneKey: string;
  networkKey: string;
  nonce: string;
  operationId: string;
  operationFingerprint: string;
  reservedAtMs: number;
  expiresAtMs: number;
  updatedAtMs: number;
  runtimeId?: string;
  fencingToken?: string;
  batchId?: string;
  txIndex?: number;
}

type NonceLaneLeaseStoreRecordLifecycle<TTransactionHash extends string> =
  | {
      state: 'reserved' | 'signed';
      txHash?: never;
    }
  | {
      state: 'broadcast_accepted';
      txHash: TTransactionHash;
    };

type NonceLaneLeaseStoreRecordBase<TTransactionHash extends string> =
  NonceLaneLeaseStoreRecordBaseWithoutLifecycle &
    NonceLaneLeaseStoreRecordLifecycle<TTransactionHash>;

export type NonceLaneLeaseStoreRecord =
  | (NonceLaneLeaseStoreRecordBase<`0x${string}`> & {
      family: 'evm';
      chainTarget: ThresholdEcdsaChainTarget;
      sender: `0x${string}` | string;
      nonceKey?: string;
      accountId: string;
    })
  | (NonceLaneLeaseStoreRecordBase<string> & {
      family: 'near';
      walletId: string;
      nearAccountId: string;
      publicKey: string;
    });

export interface NonceLaneLockStoreRecord {
  lockKey: string;
  ownerId: string;
  fencingToken: string;
  acquiredAtMs: number;
  expiresAtMs: number;
  updatedAtMs: number;
}
