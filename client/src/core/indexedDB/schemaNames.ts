export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;
export const SEAMS_WALLET_DB_VERSION = 1 as const;

export const SEAMS_WALLET_STORES = {
  appState: 'seams_app_state',
  walletSubjects: 'seams_wallet_subjects',
  walletAuthenticators: 'seams_wallet_authenticators',
  walletSigners: 'seams_wallet_signers',
  nearAccountProjections: 'seams_near_account_projections',
  signerOpsOutbox: 'seams_signer_ops_outbox',
  recoveryEmails: 'seams_recovery_emails',
  nonceLaneLeases: 'seams_nonce_lane_leases',
  nonceLaneLocks: 'seams_nonce_lane_locks',
  keyMaterial: 'seams_key_material',
  signingSessionSeals: 'seams_signing_session_seals',
  signingSessionRestoreLeases: 'seams_signing_session_restore_leases',
  emailOtpDeviceEnrollmentEscrows: 'seams_email_otp_device_enrollment_escrows',
} as const;

export const SEAMS_WALLET_INDEXES = {
  profileId: 'profile_id',
  credentialId: 'credential_id',
  credentialIdB64u: 'credential_id_b64u',
  profileIdCredentialId: 'profile_id_credential_id',
  profileIdSignerSlot: 'profile_id_signer_slot',
  updatedAt: 'updated_at',
  walletSubjectId: 'wallet_subject_id',
  walletSubjectIdRpId: 'wallet_subject_id_rp_id',
  walletSubjectIdKind: 'wallet_subject_id_kind',
  walletSubjectKindNearSignerSlot: 'wallet_subject_kind_near_signer_slot',
  walletSubjectKindChainTargetKeyHandle: 'wallet_subject_kind_chain_target_key_handle',
  walletSubjectKindChainTargetKeyFacts: 'wallet_subject_kind_chain_target_key_facts',
  walletSignerId: 'wallet_signer_id',
  nearAccountId: 'near_account_id',
  rpId: 'rp_id',
  rpIdCredentialId: 'rp_id_credential_id',
  chainIdKey: 'chain_id_key',
  chainIdKeyAccountAddress: 'chain_id_key_account_address',
  profileIdChainIdKey: 'profile_id_chain_id_key',
  chainIdKeyAccountAddressStatus: 'chain_id_key_account_address_status',
  chainTargetKey: 'chain_target_key',
  keyHandle: 'key_handle',
  thresholdOwnerAddress: 'threshold_owner_address',
  ecdsaThresholdKeyId: 'ecdsa_threshold_key_id',
  status: 'status',
  nextAttemptAt: 'next_attempt_at',
  statusNextAttemptAt: 'status_next_attempt_at',
  idempotencyKey: 'idempotency_key',
  laneKey: 'lane_key',
  accountId: 'account_id',
  state: 'state',
  expiresAtMs: 'expires_at_ms',
  laneState: 'lane_state',
  accountExpiresAt: 'account_expires_at',
  ownerId: 'owner_id',
  chainIdKeyKeyKind: 'chain_id_key_key_kind',
  publicKey: 'public_key',
  walletId: 'wallet_id',
  userId: 'user_id',
  authMethod: 'auth_method',
  curve: 'curve',
  signingRootId: 'signing_root_id',
  signingRootVersion: 'signing_root_version',
  walletSigningRootAuthMethod: 'wallet_signing_root_auth_method',
  ed25519ThresholdSessionId: 'ed25519_threshold_session_id',
  ecdsaThresholdSessionId: 'ecdsa_threshold_session_id',
  walletSigningSessionId: 'wallet_signing_session_id',
  thresholdSessionId: 'threshold_session_id',
  exactSigningLaneIdentityKey: 'exact_signing_lane_identity_key',
  budgetReservationKey: 'budget_reservation_key',
  authSubjectId: 'auth_subject_id',
  enrollmentId: 'enrollment_id',
  walletIdAuthSubjectId: 'wallet_id_auth_subject_id',
  walletIdAuthSubjectIdEnrollmentId: 'wallet_id_auth_subject_id_enrollment_id',
} as const;

export const LEGACY_INDEXED_DB_NAMES = [
  'PasskeyClientDB',
  'PasskeyAccountKeyMaterial',
  'seams_wallet_v1',
  'seams_email_otp_device_enrollment_escrows_v1',
] as const;

export type SeamsWalletStoreName =
  (typeof SEAMS_WALLET_STORES)[keyof typeof SEAMS_WALLET_STORES];

export type SeamsWalletIndexDefinition = {
  name: (typeof SEAMS_WALLET_INDEXES)[keyof typeof SEAMS_WALLET_INDEXES];
  keyPath: string | readonly string[];
  unique: boolean;
};

export type SeamsWalletStoreDefinition = {
  store: SeamsWalletStoreName;
  keyPath: string | readonly string[];
  indexes: readonly SeamsWalletIndexDefinition[];
};

export const SEAMS_WALLET_SCHEMA_MANIFEST = [
  {
    store: SEAMS_WALLET_STORES.appState,
    keyPath: 'key',
    indexes: [],
  },
  {
    store: SEAMS_WALLET_STORES.walletSubjects,
    keyPath: 'wallet_subject_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.rpId, keyPath: 'rp_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.status, keyPath: 'status', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.walletAuthenticators,
    keyPath: ['rp_id', 'credential_id_b64u'],
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletSubjectId, keyPath: 'wallet_subject_id', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.walletSubjectIdRpId,
        keyPath: ['wallet_subject_id', 'rp_id'],
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.walletSigners,
    keyPath: 'wallet_signer_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletSubjectId, keyPath: 'wallet_subject_id', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.walletSubjectIdKind,
        keyPath: ['wallet_subject_id', 'kind'],
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.walletSubjectKindNearSignerSlot,
        keyPath: ['wallet_subject_id', 'kind', 'near_signer_slot'],
        unique: true,
      },
      {
        name: SEAMS_WALLET_INDEXES.walletSubjectKindChainTargetKeyHandle,
        keyPath: ['wallet_subject_id', 'kind', 'chain_target_key', 'key_handle'],
        unique: true,
      },
      {
        name: SEAMS_WALLET_INDEXES.walletSubjectKindChainTargetKeyFacts,
        keyPath: ['wallet_subject_id', 'kind', 'chain_target_key', 'ecdsa_threshold_key_id'],
        unique: true,
      },
      { name: SEAMS_WALLET_INDEXES.chainTargetKey, keyPath: 'chain_target_key', unique: false },
      { name: SEAMS_WALLET_INDEXES.keyHandle, keyPath: 'key_handle', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.thresholdOwnerAddress,
        keyPath: 'threshold_owner_address',
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.status, keyPath: 'status', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.nearAccountProjections,
    keyPath: ['wallet_subject_id', 'near_account_id', 'signer_slot'],
    indexes: [
      { name: SEAMS_WALLET_INDEXES.nearAccountId, keyPath: 'near_account_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.profileId, keyPath: 'profile_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.publicKey, keyPath: 'public_key', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.signerOpsOutbox,
    keyPath: 'op_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.status, keyPath: 'status', unique: false },
      { name: SEAMS_WALLET_INDEXES.nextAttemptAt, keyPath: 'next_attempt_at', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.statusNextAttemptAt,
        keyPath: ['status', 'next_attempt_at'],
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.idempotencyKey, keyPath: 'idempotency_key', unique: true },
      { name: SEAMS_WALLET_INDEXES.walletSubjectId, keyPath: 'wallet_subject_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.chainTargetKey, keyPath: 'chain_target_key', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.recoveryEmails,
    keyPath: ['wallet_subject_id', 'hash_hex'],
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletSubjectId, keyPath: 'wallet_subject_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.nonceLaneLeases,
    keyPath: 'lease_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.laneKey, keyPath: 'lane_key', unique: false },
      { name: SEAMS_WALLET_INDEXES.accountId, keyPath: 'account_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.state, keyPath: 'state', unique: false },
      { name: SEAMS_WALLET_INDEXES.expiresAtMs, keyPath: 'expires_at_ms', unique: false },
      { name: SEAMS_WALLET_INDEXES.laneState, keyPath: ['lane_key', 'state'], unique: false },
      {
        name: SEAMS_WALLET_INDEXES.accountExpiresAt,
        keyPath: ['account_id', 'expires_at_ms'],
        unique: false,
      },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.nonceLaneLocks,
    keyPath: 'lock_key',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.expiresAtMs, keyPath: 'expires_at_ms', unique: false },
      { name: SEAMS_WALLET_INDEXES.ownerId, keyPath: 'owner_id', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.keyMaterial,
    keyPath: 'key_material_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletSubjectId, keyPath: 'wallet_subject_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.walletSignerId, keyPath: 'wallet_signer_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.chainTargetKey, keyPath: 'chain_target_key', unique: false },
      { name: SEAMS_WALLET_INDEXES.keyHandle, keyPath: 'key_handle', unique: false },
      { name: SEAMS_WALLET_INDEXES.publicKey, keyPath: 'public_key', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.signingSessionSeals,
    keyPath: 'store_key',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.walletSubjectId, keyPath: 'wallet_subject_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.authMethod, keyPath: 'auth_method', unique: false },
      { name: SEAMS_WALLET_INDEXES.curve, keyPath: 'curve', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.walletSigningSessionId,
        keyPath: 'wallet_signing_session_id',
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.ed25519ThresholdSessionId,
        keyPath: 'ed25519_threshold_session_id',
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.ecdsaThresholdSessionId,
        keyPath: 'ecdsa_threshold_session_id',
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.thresholdSessionId,
        keyPath: 'threshold_session_id',
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.keyHandle, keyPath: 'key_handle', unique: false },
      { name: SEAMS_WALLET_INDEXES.chainTargetKey, keyPath: 'chain_target_key', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.exactSigningLaneIdentityKey,
        keyPath: 'exact_signing_lane_identity_key',
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.expiresAtMs, keyPath: 'expires_at_ms', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.signingSessionRestoreLeases,
    keyPath: 'lease_key',
    indexes: [
      {
        name: SEAMS_WALLET_INDEXES.walletSigningSessionId,
        keyPath: 'wallet_signing_session_id',
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.thresholdSessionId,
        keyPath: 'threshold_session_id',
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.ownerId, keyPath: 'owner_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.expiresAtMs, keyPath: 'expires_at_ms', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.emailOtpDeviceEnrollmentEscrows,
    keyPath: ['wallet_id', 'auth_subject_id', 'enrollment_id'],
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.authSubjectId, keyPath: 'auth_subject_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.enrollmentId, keyPath: 'enrollment_id', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.walletIdAuthSubjectId,
        keyPath: ['wallet_id', 'auth_subject_id'],
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.walletIdAuthSubjectIdEnrollmentId,
        keyPath: ['wallet_id', 'auth_subject_id', 'enrollment_id'],
        unique: true,
      },
      { name: SEAMS_WALLET_INDEXES.signingRootId, keyPath: 'signing_root_id', unique: false },
    ],
  },
] as const satisfies readonly SeamsWalletStoreDefinition[];

const SAFE_INDEXED_DB_NAME_PATTERN = /^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/;

export function assertCanonicalIndexedDBName(name: string): void {
  if (!SAFE_INDEXED_DB_NAME_PATTERN.test(name)) {
    throw new Error(`IndexedDB name must be seams-prefixed snake_case: ${name}`);
  }
}

export function createSeamsTestWalletDbName(suffix: string): `seams_test_wallet_${string}` {
  const safeSuffix = String(suffix || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  if (!safeSuffix) {
    throw new Error('Test wallet IndexedDB name suffix is required');
  }
  return `seams_test_wallet_${safeSuffix}`;
}
