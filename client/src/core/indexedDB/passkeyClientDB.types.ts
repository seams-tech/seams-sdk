import type { AccountId } from '../types/accountIds';
import type { ConfirmationConfig } from '../types/signer-worker';

export interface ClientUserData {
  // Primary key - now uses AccountId + deviceNumber for unique identification
  nearAccountId: AccountId;
  deviceNumber: number; // Device number for multi-device support (1-indexed)
  version?: number;

  // User metadata
  registeredAt?: number;
  lastLogin?: number;
  lastUpdated?: number;

  // WebAuthn/Passkey data (merged from WebAuthnManager)
  clientNearPublicKey: string;
  passkeyCredential: {
    id: string;
    rawId: string;
  };

  // User preferences
  preferences?: UserPreferences;
}

export type StoreUserDataInput = Omit<
  ClientUserData,
  'deviceNumber' | 'lastLogin' | 'registeredAt'
> & {
  deviceNumber?: number;
  version?: number;
};

export interface UserPreferences {
  useRelayer: boolean;
  useNetwork: 'testnet' | 'mainnet';
  confirmationConfig: ConfirmationConfig;
  // User preferences can be extended here as needed
}

// Authenticator cache
export interface ClientAuthenticatorData {
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[]; // AuthenticatorTransport[]
  name?: string;
  nearAccountId: AccountId; // FK reference using AccountId
  deviceNumber: number; // Device number for this authenticator (1-indexed)
  registered: string; // ISO date string
  syncedAt: string; // When this cache entry was last synced with contract
}

export interface LastProfileState {
  profileId: string;
  deviceNumber: number;
  scope?: string | null;
}

export interface IndexedDBEvent {
  type: 'user-updated' | 'preferences-updated' | 'user-deleted';
  accountId: AccountId;
  data?: Record<string, unknown>;
}

export interface RecoveryEmailRecord {
  nearAccountId: AccountId;
  hashHex: string;
  email: string;
  addedAt: number;
}

export interface ProfileAuthenticatorRecord {
  profileId: string;
  deviceNumber: number;
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[];
  name?: string;
  registered: string;
  syncedAt: string;
}

export interface MigrationQuarantineRecord {
  quarantineId?: number;
  sourceStore: string;
  sourcePrimaryKey: string;
  reason: string;
  record: unknown;
  detectedAt: number;
  schemaVersion: number;
}

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

export type AccountModel = 'near-native' | 'erc4337' | 'eoa' | 'tempo-native' | string;
export type AccountSignerType = 'passkey' | 'threshold' | 'session' | 'recovery' | string;
export type AccountSignerStatus = 'active' | 'pending' | 'revoked';
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
  | 'DUPLICATE_ACTIVE_SIGNER_SLOT'
  | 'EOA_ACTIVE_SIGNER_LIMIT'
  | 'INVALID_SIGNER_STATUS_TRANSITION'
  | 'REVOKED_SIGNER_REQUIRES_REMOVED_AT'
  | 'INVALID_LAST_PROFILE_STATE';

export type SignerOperationType =
  | 'add-signer'
  | 'revoke-signer'
  | 'activate-recovery-signer'
  | string;
export type SignerOperationStatus = 'queued' | 'submitted' | 'confirmed' | 'failed' | 'dead-letter';

export interface ProfileRecord {
  profileId: ProfileId;
  defaultDeviceNumber: number;
  passkeyCredential: ClientUserData['passkeyCredential'];
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
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
  deployed?: boolean;
  deploymentTxHash?: string;
  lastDeploymentCheckAt?: number;
}

export interface AccountSignerRecord {
  profileId: ProfileId;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  signerId: SignerId;
  signerSlot: number;
  signerType: AccountSignerType;
  status: AccountSignerStatus;
  addedAt: number;
  updatedAt: number;
  removedAt?: number;
  metadata?: Record<string, unknown>;
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
  defaultDeviceNumber?: number;
  passkeyCredential: ClientUserData['passkeyCredential'];
  preferences?: UserPreferences;
};

export type UpsertChainAccountInput = {
  profileId: ProfileId;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  accountModel: AccountModel;
  isPrimary?: boolean;
  factory?: string | null;
  entryPoint?: string | null;
  salt?: string | null;
  counterfactualAddress?: string | null;
  deployed?: boolean;
  deploymentTxHash?: string | null;
  lastDeploymentCheckAt?: number | null;
};

export type UpsertAccountSignerInput = {
  profileId: ProfileId;
  chainIdKey: ChainIdKey;
  accountAddress: AccountAddress;
  signerId: SignerId;
  signerSlot: number;
  signerType: AccountSignerType;
  status: AccountSignerStatus;
  removedAt?: number;
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
