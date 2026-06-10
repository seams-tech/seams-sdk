export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;
export const SEAMS_WALLET_DB_VERSION = 6 as const;

export const SEAMS_WALLET_STORES = {
  appState: 'app_state',
  wallets: 'wallets',
  walletAuthMethods: 'wallet_auth_methods',
  walletSigners: 'wallet_signers',
  nearAccountProjections: 'near_accounts',
  signerOpsOutbox: 'signer_ops_outbox',
  recoveryEmails: 'recovery_emails',
  nonceLaneLeases: 'nonce_lane_leases',
  nonceLaneLocks: 'nonce_lane_locks',
  keyMaterial: 'key_material',
  signingSessionSeals: 'signing_session_seals',
  signingSessionRestoreLeases: 'signing_session_restore_leases',
  emailOtpDeviceEnrollmentEscrows: 'email_otp_escrows',
  emailOtpRecoveryCodeBackups: 'email_otp_pending_recovery_code_backups',
} as const;

export const SEAMS_WALLET_INDEXES = {
  profileId: 'profile_id',
  credentialId: 'credential_id',
  credentialIdB64u: 'credential_id_b64u',
  profileIdCredentialId: 'profile_id_credential_id',
  profileIdSignerSlot: 'profile_id_signer_slot',
  updatedAt: 'updated_at',
  walletId: 'wallet_id',
  walletIdRpId: 'wallet_id_rp_id',
  walletIdKind: 'wallet_id_kind',
  walletKindNearSignerSlot: 'wallet_kind_near_signer_slot',
  walletKindChainTargetKeyHandle: 'wallet_kind_chain_target_key_handle',
  walletKindChainTargetKeyFacts: 'wallet_kind_chain_target_key_facts',
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
  recoveryCodesIssuedAtMs: 'recovery_codes_issued_at_ms',
  laneState: 'lane_state',
  accountExpiresAt: 'account_expires_at',
  ownerId: 'owner_id',
  chainIdKeyKeyKind: 'chain_id_key_key_kind',
  publicKey: 'public_key',
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
  walletIdEnrollmentId: 'wallet_id_enrollment_id',
  walletIdAuthSubjectId: 'wallet_id_auth_subject_id',
  walletIdAuthSubjectIdEnrollmentId: 'wallet_id_auth_subject_id_enrollment_id',
  authIdentifierKey: 'auth_identifier_key',
  kindRpIdAuthIdentifier: 'kind_rp_id_auth_identifier',
  passkeyRpIdCredentialId: 'passkey_rp_id_credential_id',
} as const;

export const LEGACY_INDEXED_DB_NAMES = [
  'PasskeyClientDB',
  'PasskeyAccountKeyMaterial',
  'seams_wallet_v1',
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
    store: SEAMS_WALLET_STORES.wallets,
    keyPath: 'wallet_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.rpId, keyPath: 'rp_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.status, keyPath: 'status', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.walletAuthMethods,
    keyPath: 'wallet_auth_method_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.walletIdKind,
        keyPath: ['wallet_id', 'kind'],
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.authMethod, keyPath: 'auth_method', unique: false },
      { name: SEAMS_WALLET_INDEXES.rpId, keyPath: 'rp_id', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.authIdentifierKey,
        keyPath: 'auth_identifier_key',
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.kindRpIdAuthIdentifier,
        keyPath: ['kind', 'rp_id', 'auth_identifier_key'],
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.passkeyRpIdCredentialId,
        keyPath: ['kind', 'rp_id', 'credential_id_b64u'],
        unique: true,
      },
      { name: SEAMS_WALLET_INDEXES.status, keyPath: 'status', unique: false },
      { name: SEAMS_WALLET_INDEXES.updatedAt, keyPath: 'updated_at', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.walletSigners,
    keyPath: 'wallet_signer_id',
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.walletIdKind,
        keyPath: ['wallet_id', 'kind'],
        unique: false,
      },
      {
        name: SEAMS_WALLET_INDEXES.walletKindNearSignerSlot,
        keyPath: ['wallet_id', 'kind', 'near_signer_slot'],
        unique: true,
      },
      {
        name: SEAMS_WALLET_INDEXES.walletKindChainTargetKeyHandle,
        keyPath: ['wallet_id', 'kind', 'chain_target_key', 'key_handle'],
        unique: true,
      },
      {
        name: SEAMS_WALLET_INDEXES.walletKindChainTargetKeyFacts,
        keyPath: ['wallet_id', 'kind', 'chain_target_key', 'ecdsa_threshold_key_id'],
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
    keyPath: ['wallet_id', 'near_account_id', 'signer_slot'],
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
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.chainTargetKey, keyPath: 'chain_target_key', unique: false },
    ],
  },
  {
    store: SEAMS_WALLET_STORES.recoveryEmails,
    keyPath: ['wallet_id', 'hash_hex'],
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
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
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
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
  {
    store: SEAMS_WALLET_STORES.emailOtpRecoveryCodeBackups,
    keyPath: ['wallet_id', 'enrollment_id'],
    indexes: [
      { name: SEAMS_WALLET_INDEXES.walletId, keyPath: 'wallet_id', unique: false },
      { name: SEAMS_WALLET_INDEXES.enrollmentId, keyPath: 'enrollment_id', unique: false },
      {
        name: SEAMS_WALLET_INDEXES.walletIdEnrollmentId,
        keyPath: ['wallet_id', 'enrollment_id'],
        unique: true,
      },
      {
        name: SEAMS_WALLET_INDEXES.recoveryCodesIssuedAtMs,
        keyPath: 'recovery_codes_issued_at_ms',
        unique: false,
      },
      { name: SEAMS_WALLET_INDEXES.status, keyPath: 'status', unique: false },
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
