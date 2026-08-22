import type { AccountId } from '../types/accountIds';
import type { NearProvisioningState } from '../types/seams';
import type { ConfirmationConfig } from '../types/signer-worker';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SignerAuthMethod, SignerKind, SignerSource } from '@shared/utils';
import type {
  WalletAuthMethodRecord,
  WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  MpcMaterialActivationRef,
  WalletAuthMethodId,
  WalletAuthorityId,
  WalletKeyId,
} from '@shared/utils/domainIds';
export type { LocalAuthorityInstallationReceiptV1 } from '@shared/device-linking/contracts';

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
  /* Refactor 94 Phase 6. Survives reloads so a wallet that registered
     ECDSA-ready does not come back looking NEAR-capable. */
  nearProvisioning?: NearProvisioningState;
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

export type LocalWalletAuthMethodRecord =
  | (Extract<WalletAuthMethodRecord, { kind: 'passkey' }> & {
      localStatus: 'synced' | 'pending';
      authority?: never;
    })
  | (Extract<WalletAuthMethodRecord, { kind: 'email_otp' }> & {
      localStatus: 'synced' | 'pending';
      authority: EmailOtpWalletAuthAuthority;
    });

export type LocalWalletAuthMethodRecordV2 = WalletAuthMethodRecordV2;

export type WalletAuthoritySignerMaterialRecordV1 = {
  readonly kind: 'wallet_authority_signer_material_v1';
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly activationId: MpcMaterialActivationRef['activationId'];
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly materialActivation: MpcMaterialActivationRef;
  readonly sealedMaterialB64u: string;
  readonly sealedMaterialDigestB64u: DigestB64u;
};

export type WalletAuthorityExportRootRecordV1 = {
  readonly kind: 'wallet_authority_export_root_v1';
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletKeyId: WalletKeyId;
  readonly sealedRootB64u: string;
  readonly sealedRootDigestB64u: DigestB64u;
};

export type WalletSelectionRecordV1 = {
  readonly kind: 'wallet_selection_v1';
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly lockGeneration: number;
  readonly lockState: 'locked' | 'unlocked';
  readonly updatedAtMs: number;
};

export type { WalletAuthMethodRecordV2 };

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
  nearProvisioning?: NearProvisioningState;
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
