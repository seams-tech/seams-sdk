import { toTrimmedString } from '@shared/utils/validation';
import { buildNearProfileId } from '../../accountData/near/profileId';
import { toAccountId } from '../../types/accountIds';
import { alphabetizeStringify, sha256HexUtf8 } from '@shared/utils/digests';
import {
  parseMpcMaterialActivationRef,
  mpcMaterialActivationRefsEqual,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletKeyId,
  parseWalletRecoveryOperationId,
  type WalletRecoveryOperationId,
  parseWebAuthnRpId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
  type WalletKeyId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { sameDelegatedWalletAuthorityV1 } from '@shared/authorization/delegatedAuthority';
import { parseLocalAuthorityInstallationReceiptV1 } from '@shared/device-linking';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  parseWalletAuthMethodRecordV2,
  walletIdFromString,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  encodeWalletSignerActivationSetV1,
  isActiveRecoveredWalletAuthorityV1,
  parseWalletAuthorityV1,
  walletAuthorityDigestsMatchV1,
  type ActiveRecoveredWalletAuthorityV1,
  type PendingWalletAuthorityV1,
  type WalletAuthorityV1,
  type WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  parseWalletAuthAuthority,
  parseEmailOtpWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { KeyMaterialKind, KeyMaterialRecord } from '../keyMaterial.types';
import {
  buildEnvelopeAAD,
  normalizePayloadEnvelope,
  normalizeStoredPayloadRecord,
  sanitizePayload,
} from '../keyMaterialEnvelope';
import type {
  AccountRef,
  AccountSignerRecord,
  AccountSignerStatus,
  ChainAccountRecord,
  DBConstraintErrorCode,
  EnqueueSignerOperationInput,
  LastProfileState,
  LocalAuthorityInstallationReceiptV1,
  LocalWalletAuthMethodRecord,
  NonceLaneLeaseStoreRecord,
  NonceLaneLeaseStoreRecordState,
  NonceLaneLockStoreRecord,
  ProfileAuthenticatorRecord,
  ProfileContinuitySnapshot,
  ProfileRecord,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOperationType,
  SignerOpOutboxRecord,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
  WalletAuthorityExportRootRecordV1,
  WalletAuthoritySignerMaterialRecordV1,
  WalletSelectionRecordV1,
  WalletSignerLookup,
} from '../passkeyClientDB.types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseEcdsaThresholdKeyId } from '../../signingEngine/session/keyMaterialBrands';
import { parseWalletAuthorityLinkedSignerMaterialRecordV1 } from '../linkedAuthoritySignerMaterial';
import {
  planAccountSignerActivation,
  type ActivateAccountSignerInput,
  type ActivateAccountSignerResult,
  type StageAccountSignerInput,
  type StageAccountSignerResult,
} from '../accountSignerLifecycle';
import { parseLastProfileState } from '../lastProfileState';
import {
  normalizeIndexedDbAccountAddress,
  normalizeIndexedDbAccountModel,
  normalizeIndexedDbChainIdKey,
  normalizeLastUserScope,
  toIndexedDbChainTargetKey,
} from '../normalization';
import { SEAMS_WALLET_INDEXES, SEAMS_WALLET_STORES } from '../schemaNames';
import {
  assertPendingWalletRegistrationIdentity,
  buildPendingWalletRegistrationCommitV1,
  parsePendingWalletRegistrationCommitAppStateRow,
  pendingWalletRegistrationCommitAppStateKey,
  toPendingWalletRegistrationCommitAppStateRow,
  type PendingWalletRegistrationCommitV1,
} from '../pendingWalletRegistrationCommit';
import {
  buildPendingWalletRecoveryCommitV1,
  pendingWalletRecoveryCommitAppStateKey,
  pendingWalletRecoveryCommitAppStateRowsMatch,
  parsePendingWalletRecoveryCommitAppStateRow,
  toPendingWalletRecoveryCommitAppStateRow,
  type PendingWalletRecoveryCommitV1,
  type PendingWalletRecoveryCommitAppStateRow,
} from '../pendingWalletRecoveryCommit';
import type { SeamsWalletDBManager, SeamsWalletTransactionContext } from './manager';
import {
  parseStoredExactWalletSessionAuthorizationRowV6,
  readExactActiveWalletSessionForScopeInTransaction,
  replaceExactActiveWalletSessionAuthorizationInTransaction,
  toStoredExactWalletSessionAuthorizationRowV6,
  type ActiveWalletSessionV1,
} from './walletSessionAuthorizationStore';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking/contracts';

function assertNever(value: never): never {
  throw new Error(`Unhandled wallet auth method branch: ${String(value)}`);
}

function exportRootEnvelopeMatchesAuthMethod(
  authMethod: WalletAuthMethodRecordV2,
  envelope: PasskeyCustodyEnvelopeRecord,
): boolean {
  if (envelope.binding.kind !== 'ed25519_yao_client_root_v1') {
    return false;
  }
  switch (authMethod.kind) {
    case 'passkey':
      return (
        envelope.factor.kind === 'passkey' &&
        envelope.factor.rpId === authMethod.rpId &&
        envelope.factor.credentialIdB64u === authMethod.credentialIdB64u &&
        envelope.binding.targetFactor.kind === 'passkey_prf'
      );
    case 'email_otp':
      return (
        envelope.factor.kind === 'email_otp' && envelope.binding.targetFactor.kind === 'email_otp'
      );
    default:
      return assertNever(authMethod);
  }
}

type AppStateRow<T = unknown> = {
  key: string;
  value: T;
};

const LOCAL_AUTHORITY_PENDING_PROFILE_PROJECTION_APP_STATE_PREFIX_V1 =
  'local-authority/pending-profile-projection/v1/';

function localAuthorityPendingProfileProjectionAppStateKeyV1(authorityId: string): string {
  return `${LOCAL_AUTHORITY_PENDING_PROFILE_PROJECTION_APP_STATE_PREFIX_V1}${authorityId}`;
}

type WalletRow = {
  wallet_id: string;
  rp_id: string;
  status: 'active';
  created_at: number;
  updated_at: number;
  record: ProfileRecord;
};

type WalletAuthMethodBaseRow = {
  wallet_auth_method_id: string;
  wallet_id: string;
  kind: LocalWalletAuthMethodRecord['kind'];
  auth_method: LocalWalletAuthMethodRecord['kind'];
  rp_id: string;
  auth_identifier_key: string;
  status: LocalWalletAuthMethodRecord['status'];
  updated_at: number;
  record: LocalWalletAuthMethodRecord;
};

type WalletPasskeyAuthMethodRow = WalletAuthMethodBaseRow & {
  kind: 'passkey';
  auth_method: 'passkey';
  record: LocalWalletAuthMethodRecord & { kind: 'passkey' };
  credential_id_b64u: string;
  credential_public_key_b64u: string;
  signer_slot: number;
  authenticator: ProfileAuthenticatorRecord;
  email_hash_hex?: never;
  challenge_id?: never;
};

type WalletEmailOtpAuthMethodRow = WalletAuthMethodBaseRow & {
  kind: 'email_otp';
  auth_method: 'email_otp';
  record: LocalWalletAuthMethodRecord & { kind: 'email_otp' };
  email_hash_hex: string;
  challenge_id: string;
  credential_id_b64u?: never;
  credential_public_key_b64u?: never;
  signer_slot?: never;
  authenticator?: never;
};

type WalletAuthMethodRow = WalletPasskeyAuthMethodRow | WalletEmailOtpAuthMethodRow;

type ChainAccountProjectionRow = {
  wallet_id: string;
  near_account_id: string;
  signer_slot: number;
  profile_id: string;
  chain_id_key: string;
  account_address: string;
  account_model: string;
  is_primary: boolean;
  updated_at: number;
  record: ChainAccountRecord;
};

type WalletSignerRow = {
  wallet_signer_id: string;
  wallet_id: string;
  kind: string;
  chain_target_key: string;
  near_signer_slot?: number;
  near_ed25519_signing_key_id?: string;
  key_handle?: string;
  ecdsa_threshold_key_id?: string;
  threshold_owner_address?: string;
  status: AccountSignerStatus;
  updated_at: number;
  record: AccountSignerRecord;
};

type SignerOpsOutboxRow = {
  op_id: string;
  idempotency_key: string;
  status: SignerOperationStatus;
  next_attempt_at: number;
  wallet_id: string;
  chain_target_key: string;
  updated_at: number;
  record: SignerOpOutboxRecord;
};

type NonceLaneLeaseRow = {
  lease_id: string;
  lane_key: string;
  wallet_id: string;
  near_account_id?: string;
  state: NonceLaneLeaseStoreRecordState;
  expires_at_ms: number;
  record: NonceLaneLeaseStoreRecord;
};

type NonceLaneLockRow = {
  lock_key: string;
  owner_id: string;
  fencing_token: string;
  acquired_at_ms: number;
  expires_at_ms: number;
  updated_at_ms: number;
};

type KeyMaterialRow = {
  key_material_id: string;
  wallet_id: string;
  wallet_signer_id: string;
  chain_target_key: string;
  key_handle: string;
  public_key: string;
  updated_at: number;
  record: KeyMaterialRecord;
};

type WalletAuthorityRow = {
  authority_id: string;
  wallet_id: string;
  state: WalletAuthorityV1['state'];
  device_id: string;
  updated_at: number;
  record: WalletAuthorityV1;
};

type WalletAuthMethodV2Row = {
  wallet_auth_method_id: string;
  wallet_id: string;
  wallet_authority_id: string;
  kind: WalletAuthMethodRecordV2['kind'];
  status: WalletAuthMethodRecordV2['status'];
  updated_at: number;
  record: WalletAuthMethodRecordV2;
};

type WalletAuthoritySignerMaterialRow = {
  wallet_authority_id: string;
  wallet_auth_method_id: string;
  activation_id: string;
  key_family: WalletAuthoritySignerMaterialRecordV1['keyFamily'];
  ecdsa_threshold_key_id: string | undefined;
  sealed_material_b64u: string;
  sealed_material_digest_b64u: DigestB64u;
  record: WalletAuthoritySignerMaterialRecordV1;
};

type WalletAuthorityExportRootRow = {
  wallet_authority_id: string;
  wallet_auth_method_id: string;
  wallet_key_id: string;
  sealed_root_b64u: string;
  sealed_root_digest_b64u: DigestB64u;
  record: WalletAuthorityExportRootRecordV1;
};

type WalletAuthorityInstallationReceiptRow = {
  authority_id: string;
  wallet_id: string;
  wallet_auth_method_id: string;
  device_id: string;
  package_set_digest_b64u: DigestB64u;
  installed_at_ms: number;
  record: LocalAuthorityInstallationReceiptV1;
};

type WalletSelectionRow = {
  wallet_id: string;
  wallet_auth_method_id: string;
  lock_generation: number;
  lock_state: WalletSelectionRecordV1['lockState'];
  updated_at_ms: number;
  record: WalletSelectionRecordV1;
};

type LocalAuthorityPendingProfileProjectionV1 = {
  readonly kind: 'local_authority_pending_profile_projection_v1';
  readonly authorityId: string;
  readonly walletId: string;
  readonly authMethodId: string;
  readonly profile: WalletRow;
  readonly authenticator: WalletPasskeyAuthMethodRow | null;
  readonly localAuthMethod: WalletEmailOtpAuthMethodRow | null;
};

export type LocalAuthorityInstallationInputV1 = {
  readonly authority: PendingWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { status: 'pending_local_install' }>;
  readonly profile: UpsertProfileInput;
  readonly authenticator: ProfileAuthenticatorRecord | null;
  readonly localAuthMethod: Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> | null;
  readonly signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
  readonly exportRoot: WalletAuthorityExportRootRecordV1 | null;
  readonly receipt: LocalAuthorityInstallationReceiptV1;
  readonly expectedLockGeneration: number;
};

export type LocalAuthorityInstallationResultV1 =
  | {
      readonly kind: 'installed';
      readonly receipt: LocalAuthorityInstallationReceiptV1;
    }
  | {
      readonly kind: 'idempotent_replay';
      readonly receipt: LocalAuthorityInstallationReceiptV1;
    }
  | {
      readonly kind: 'stale_lock_generation';
      readonly expectedLockGeneration: number;
      readonly actualLockGeneration: number;
    }
  | {
      readonly kind: 'integrity_error';
      readonly reason: string;
    };

export type LocalAuthorityActivationFinalizationInputV1 = {
  readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly walletSession: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly expectedLockGeneration: number;
};

export type LocalAuthorityActivationPublicationInputV1 = {
  readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly expectedLockGeneration: number;
};

export type LocalAuthorityActivationPublicationResultV1 =
  | { readonly kind: 'published' }
  | {
      readonly kind: 'stale_lock_generation';
      readonly expectedLockGeneration: number;
      readonly actualLockGeneration: number;
    }
  | { readonly kind: 'wallet_locked'; readonly lockGeneration: number };

export type LocalAuthorityActivationFinalizationResultV1 =
  | { readonly kind: 'finalized' }
  | {
      readonly kind: 'stale_lock_generation';
      readonly expectedLockGeneration: number;
      readonly actualLockGeneration: number;
    }
  | {
      readonly kind: 'wallet_locked';
      readonly lockGeneration: number;
    };

export type WalletLockGenerationAdvanceInputV1 = {
  readonly walletId: WalletId;
  readonly lockedAtMs: number;
};

export type RecoveredWalletAuthorityProjectionInputV1 = {
  readonly authority: ActiveRecoveredWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly recoveredAtMs: number;
};

export type ResolveSelectedWalletAuthorityResultV1 =
  | {
      readonly kind: 'resolved';
      readonly selection: WalletSelectionRecordV1;
      readonly authMethod: WalletAuthMethodRecordV2;
      readonly authority: WalletAuthorityV1;
      readonly signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
      readonly exportRoot: WalletAuthorityExportRootRecordV1 | null;
    }
  | { readonly kind: 'missing_selection' }
  | {
      readonly kind: 'missing_auth_method';
      readonly walletAuthMethodId: WalletAuthMethodId;
    }
  | {
      readonly kind: 'missing_authority';
      readonly walletAuthorityId: WalletAuthorityId;
    }
  | {
      readonly kind: 'integrity_error';
      readonly reason: string;
    };

export type PersistFoundingWalletAuthorityInputV1 = {
  readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
};

type ValidatedFoundingWalletAuthorityInputV1 = PersistFoundingWalletAuthorityInputV1;

type ValidatedLocalAuthorityInstallationInput = {
  readonly authority: PendingWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { status: 'pending_local_install' }>;
  readonly profile: UpsertProfileInput;
  readonly authenticator: ProfileAuthenticatorRecord | null;
  readonly localAuthMethod: Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> | null;
  readonly signerMaterials: readonly WalletAuthoritySignerMaterialRecordV1[];
  readonly exportRoot: WalletAuthorityExportRootRecordV1 | null;
  readonly receipt: LocalAuthorityInstallationReceiptV1;
  readonly expectedLockGeneration: number;
};

function walletSelectionForInstalledAuthority(
  input: ValidatedLocalAuthorityInstallationInput,
  selection: WalletSelectionRow | null,
): WalletSelectionRecordV1 {
  return {
    kind: 'wallet_selection_v1',
    walletId: input.authority.walletId,
    walletAuthMethodId: input.authMethod.walletAuthMethodId,
    lockGeneration: selection?.record.lockGeneration ?? 0,
    lockState: selection?.record.lockState ?? 'unlocked',
    updatedAtMs: input.receipt.installedAtMs,
  };
}

export type StoreWalletRegistrationFinalizeBatchInput = {
  profiles: readonly UpsertProfileInput[];
  initialAuthMethod: LocalWalletAuthMethodRecord;
  authenticators: readonly ProfileAuthenticatorRecord[];
  signerActivations: readonly ActivateAccountSignerInput[];
  keyMaterials: readonly KeyMaterialRecord[];
  lastProfileState?: {
    profileId: string;
    activeSignerSlot: number;
    scope?: string | null;
  };
};

export type WalletRegistrationCommitPublicationRequestV1 = {
  readonly operation: PendingWalletRegistrationCommitV1['operation'];
  readonly registrationCeremonyId: string;
  readonly idempotencyKey: string;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
};

export type StoreWalletRegistrationPublicationInputV1 = Omit<
  StoreWalletRegistrationFinalizeBatchInput,
  'lastProfileState'
> & {
  readonly lastProfileState: {
    readonly profileId: string;
    readonly activeSignerSlot: number;
    readonly scope: string | null;
  };
};

export type WalletRegistrationSessionPublicationV1 =
  | {
      readonly kind: 'issued';
      readonly walletSession: ActiveWalletSessionV1;
      readonly operationCredential: WalletSessionOperationCredentialV1;
    }
  | {
      readonly kind: 'credential_free_projection';
      readonly walletSession: ActiveWalletSessionV1;
    };

export type PublishPendingWalletRegistrationCommitInputV1 = {
  readonly pending: PendingWalletRegistrationCommitV1;
  readonly authority: WalletAuthAuthority;
  readonly foundingAuthority: PersistFoundingWalletAuthorityInputV1;
  readonly request: WalletRegistrationCommitPublicationRequestV1;
  readonly registration: StoreWalletRegistrationPublicationInputV1;
  readonly walletSessionPublication: WalletRegistrationSessionPublicationV1;
};

export type PublishPendingWalletRecoveryCommitInputV1 = {
  readonly pending: Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'server_promoted' }>;
  readonly authority: ActiveRecoveredWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly registration: StoreWalletRegistrationPublicationInputV1;
};

function assertPendingWalletRegistrationRequestIdentity(
  pending: PendingWalletRegistrationCommitV1,
  request: WalletRegistrationCommitPublicationRequestV1,
): void {
  if (
    pending.operation !== request.operation ||
    pending.registrationCeremonyId !== request.registrationCeremonyId ||
    pending.idempotencyKey !== request.idempotencyKey ||
    pending.walletId !== request.walletId ||
    pending.walletAuthMethodId !== request.walletAuthMethodId
  ) {
    throw new Error('pending wallet registration commit does not match the request');
  }
}

function validateFoundingWalletAuthorityInput(
  input: PersistFoundingWalletAuthorityInputV1,
): ValidatedFoundingWalletAuthorityInputV1 {
  const authority = parseWalletAuthorityV1(input.authority);
  const authMethod = parseWalletAuthMethodRecordV2(input.authMethod);
  if (
    !authority.ok ||
    authority.value.state !== 'active' ||
    !authMethod ||
    authMethod.status !== 'active' ||
    authority.value.provenance.kind !== 'wallet_registration' ||
    authMethod.walletId !== authority.value.walletId ||
    authMethod.walletAuthorityId !== authority.value.authorityId
  ) {
    throw new Error('founding wallet authority records are invalid');
  }
  return { authority: authority.value, authMethod };
}

async function assertRegistrationFinalizeMatchesPending(input: {
  readonly request: WalletRegistrationCommitPublicationRequestV1;
  readonly pending: PendingWalletRegistrationCommitV1;
  readonly authority: WalletAuthAuthority;
  readonly foundingAuthority: ValidatedFoundingWalletAuthorityInputV1;
  readonly registration: StoreWalletRegistrationPublicationInputV1;
}): Promise<void> {
  const pending = input.pending;
  const foundingMethod = input.foundingAuthority.authMethod;
  const initialMethod = input.registration.initialAuthMethod;
  assertPendingWalletRegistrationRequestIdentity(pending, input.request);
  assertPendingWalletRegistrationIdentity(pending, {
    operation: input.request.operation,
    walletId: input.request.walletId,
    walletAuthMethodId: input.request.walletAuthMethodId,
    authority: input.authority,
  });
  if (
    foundingMethod.walletId !== pending.walletId ||
    foundingMethod.walletAuthMethodId !== pending.walletAuthMethodId ||
    initialMethod.walletId !== pending.walletId ||
    initialMethod.status !== 'active' ||
    initialMethod.localStatus !== 'synced' ||
    initialMethod.kind !== pending.auth.kind ||
    foundingMethod.kind !== pending.auth.kind ||
    !input.registration.profiles.some((profile) => profile.profileId === pending.walletId) ||
    input.registration.lastProfileState.profileId !== pending.walletId
  ) {
    throw new Error('registration finalize batch does not match the pending wallet');
  }
  const profileIds = new Set(input.registration.profiles.map((profile) => profile.profileId));
  for (const profile of input.registration.profiles) {
    if (
      profile.passkeyCredential &&
      (pending.auth.kind !== 'passkey' ||
        profile.passkeyCredential.rawId !== pending.auth.credentialIdB64u)
    ) {
      throw new Error('registration profile credential does not match the pending commit');
    }
  }
  for (const activation of input.registration.signerActivations) {
    if (!profileIds.has(activation.account.profileId)) {
      throw new Error('registration signer account is outside the publication profiles');
    }
  }
  for (const keyMaterial of input.registration.keyMaterials) {
    if (!profileIds.has(keyMaterial.profileId)) {
      throw new Error('registration key material is outside the publication profiles');
    }
  }
  switch (pending.auth.kind) {
    case 'passkey':
      if (
        !isPasskeyWalletAuthAuthority(input.authority) ||
        initialMethod.kind !== 'passkey' ||
        foundingMethod.kind !== 'passkey' ||
        initialMethod.rpId !== pending.auth.rpId ||
        initialMethod.credentialIdB64u !== pending.auth.credentialIdB64u ||
        foundingMethod.rpId !== pending.auth.rpId ||
        foundingMethod.credentialIdB64u !== pending.auth.credentialIdB64u ||
        initialMethod.credentialPublicKeyB64u !== foundingMethod.credentialPublicKeyB64u
      ) {
        throw new Error('registration passkey records do not match the pending commit');
      }
      for (const authenticator of input.registration.authenticators) {
        if (
          !profileIds.has(authenticator.profileId) ||
          authenticator.credentialId !== pending.auth.credentialIdB64u ||
          base64UrlEncode(authenticator.credentialPublicKey) !==
            initialMethod.credentialPublicKeyB64u
        ) {
          throw new Error('registration passkey authenticator does not match the pending commit');
        }
      }
      return;
    case 'email_otp':
      if (initialMethod.kind !== 'email_otp' || foundingMethod.kind !== 'email_otp') {
        throw new Error('registration Email OTP method records are invalid');
      }
      const emailAuthority = parseEmailOtpWalletAuthAuthority(initialMethod.authority);
      if (!emailAuthority || !isEmailOtpWalletAuthAuthority(input.authority)) {
        throw new Error('registration Email OTP authority records are invalid');
      }
      const expectedEmailHashHex = await sha256HexUtf8(pending.auth.email);
      if (
        initialMethod.registrationAuthorityId !== pending.auth.registrationAuthorityId ||
        foundingMethod.registrationAuthorityId !== pending.auth.registrationAuthorityId ||
        initialMethod.emailHashHex !== expectedEmailHashHex ||
        foundingMethod.emailHashHex !== expectedEmailHashHex ||
        input.authority.verifier.emailHashHex !== expectedEmailHashHex ||
        emailAuthority.factor.providerUserId !== pending.auth.providerSubject ||
        emailAuthority.factor.provider !== input.authority.factor.provider ||
        !walletAuthAuthoritiesMatch(emailAuthority, input.authority) ||
        input.registration.authenticators.length !== 0
      ) {
        throw new Error('registration Email OTP records do not match the pending commit');
      }
      return;
  }
}

function assertPendingWalletRecoveryPublicationMatchesProjection(
  input: PublishPendingWalletRecoveryCommitInputV1,
): void {
  const projection = input.pending.projection;
  if (
    alphabetizeStringify(input.authority) !== alphabetizeStringify(projection.authority) ||
    alphabetizeStringify(input.authMethod) !== alphabetizeStringify(projection.authMethod)
  ) {
    throw new Error('recovery publication records do not match the committed projection');
  }
  const initialMethod = input.registration.initialAuthMethod;
  const profiles = input.registration.profiles;
  if (
    initialMethod.status !== 'active' ||
    initialMethod.localStatus !== 'synced' ||
    initialMethod.walletId !== projection.walletId ||
    !profiles.some((profile) => profile.profileId === projection.walletId) ||
    input.registration.lastProfileState.profileId !== projection.walletId ||
    !Number.isSafeInteger(input.registration.lastProfileState.activeSignerSlot) ||
    input.registration.lastProfileState.activeSignerSlot < 1
  ) {
    throw new Error('recovery profile publication does not match the committed projection');
  }
  const profileIds = new Set(profiles.map((profile) => profile.profileId));
  for (const profile of profiles) {
    if (
      profile.passkeyCredential &&
      (projection.kind !== 'passkey' ||
        profile.passkeyCredential.rawId !== projection.target.credentialIdB64u)
    ) {
      throw new Error('recovery profile credential does not match the committed projection');
    }
  }
  for (const activation of input.registration.signerActivations) {
    if (!profileIds.has(activation.account.profileId)) {
      throw new Error('recovery signer account is outside the publication profiles');
    }
  }
  for (const keyMaterial of input.registration.keyMaterials) {
    if (!profileIds.has(keyMaterial.profileId)) {
      throw new Error('recovery key material is outside the publication profiles');
    }
  }
  if (projection.kind === 'passkey') {
    if (initialMethod.kind !== 'passkey') {
      throw new Error('recovery passkey publication method branch is invalid');
    }
    if (
      initialMethod.rpId !== projection.target.rpId ||
      initialMethod.credentialIdB64u !== projection.target.credentialIdB64u ||
      initialMethod.credentialPublicKeyB64u !== projection.authMethod.credentialPublicKeyB64u ||
      !input.registration.authenticators.some(
        (authenticator) =>
          authenticator.profileId === projection.walletId &&
          authenticator.credentialId === projection.target.credentialIdB64u &&
          base64UrlEncode(authenticator.credentialPublicKey) ===
            projection.authMethod.credentialPublicKeyB64u,
      )
    ) {
      throw new Error('recovery passkey publication does not match the committed projection');
    }
    return;
  }
  if (initialMethod.kind !== 'email_otp') {
    throw new Error('recovery Email OTP publication method branch is invalid');
  }
  if (
    initialMethod.emailHashHex !== projection.target.emailHashHex ||
    initialMethod.registrationAuthorityId !== projection.target.registrationAuthorityId ||
    input.registration.authenticators.length !== 0 ||
    profiles.some((profile) => profile.passkeyCredential !== undefined)
  ) {
    throw new Error('recovery Email OTP publication does not match the committed projection');
  }
  const localAuthority = parseEmailOtpWalletAuthAuthority(initialMethod.authority);
  if (
    !localAuthority ||
    localAuthority.walletId !== projection.walletId ||
    localAuthority.factor.provider !== 'google' ||
    localAuthority.factor.providerUserId !== projection.target.providerSubject ||
    localAuthority.verifier.emailHashHex !== projection.target.emailHashHex
  ) {
    throw new Error('recovery Email OTP factor does not match the committed projection');
  }
}

function shouldDeletePublishedPendingWalletRegistrationCommit(
  pending: PendingWalletRegistrationCommitV1,
): boolean {
  switch (pending.operation) {
    case 'near_provisioning':
      return true;
    case 'registration_activate':
      return (
        pending.localMaterial.keyFamilies.length === 1 &&
        pending.localMaterial.keyFamilies[0] === 'ecdsa_secp256k1'
      );
  }
}

function assertCredentialFreeRegistrationSessionProjectionMatchesExisting(input: {
  readonly incoming: ActiveWalletSessionV1;
  readonly existing: ActiveWalletSessionV1;
}): void {
  if (
    input.incoming.walletId !== input.existing.walletId ||
    input.incoming.authorityId !== input.existing.authorityId ||
    input.incoming.authMethodId !== input.existing.authMethodId ||
    input.incoming.authorizationId !== input.existing.authorizationId ||
    input.incoming.quotaId !== input.existing.quotaId ||
    input.incoming.issuedAtMs !== input.existing.issuedAtMs ||
    input.incoming.expiresAtMs !== input.existing.expiresAtMs
  ) {
    throw new Error('Credential-free registration projection changed immutable session identity');
  }
}

export type StoreWalletSignerFinalizeBatchInput = {
  profiles: readonly UpsertProfileInput[];
  signerActivations: readonly ActivateAccountSignerInput[];
  keyMaterials: readonly KeyMaterialRecord[];
  lastProfileState?: {
    profileId: string;
    activeSignerSlot: number;
    scope?: string | null;
  };
};

export type AtomicKeyMaterialRecoveryFinalizationInput = {
  journalKey: string;
  expectedJournal: unknown;
  replacement: KeyMaterialRecord;
  retire: {
    profileId: string;
    signerSlot: number;
    chainIdKey: string;
    keyKind: KeyMaterialKind;
  };
};

export type StoreWalletSignerFinalizeRollbackReceipt = {
  kind: 'wallet_signer_finalize_rollback_v1';
  profiles: readonly {
    committed: ProfileRecord;
    previous: ProfileRecord | null;
  }[];
  signers: readonly AccountSignerRecord[];
  keyMaterials: readonly KeyMaterialRecord[];
  lastProfileState: {
    key: string;
    committed: LastProfileState;
    previousPresent: boolean;
    previousValue: unknown;
  } | null;
};

export type StoreWalletSignerFinalizeBatchResult = StoreWalletRegistrationFinalizeBatchResult & {
  rollbackReceipt: StoreWalletSignerFinalizeRollbackReceipt;
};

export type StoreWalletRegistrationFinalizeBatchResult = {
  signerActivations: ActivateAccountSignerResult[];
};

const DEFAULT_NONCE_LANE_LOCK_TTL_MS = 5_000;
const DEFAULT_NONCE_LANE_LOCK_WAIT_TIMEOUT_MS = 3_000;
const DEFAULT_NONCE_LANE_LOCK_POLL_MS = 25;
const LAST_PROFILE_STATE_APP_STATE_KEY = 'lastProfileState';
const WALLET_REGISTRATION_FINALIZE_STORES = [
  SEAMS_WALLET_STORES.appState,
  SEAMS_WALLET_STORES.wallets,
  SEAMS_WALLET_STORES.walletAuthMethods,
  SEAMS_WALLET_STORES.walletSigners,
  SEAMS_WALLET_STORES.nearAccountProjections,
  SEAMS_WALLET_STORES.signerOpsOutbox,
  SEAMS_WALLET_STORES.keyMaterial,
] as const;
const WALLET_REGISTRATION_PUBLICATION_STORES = [
  SEAMS_WALLET_STORES.appState,
  SEAMS_WALLET_STORES.wallets,
  SEAMS_WALLET_STORES.walletAuthMethods,
  SEAMS_WALLET_STORES.walletAuthorities,
  SEAMS_WALLET_STORES.walletSelections,
  SEAMS_WALLET_STORES.walletSigners,
  SEAMS_WALLET_STORES.nearAccountProjections,
  SEAMS_WALLET_STORES.signerOpsOutbox,
  SEAMS_WALLET_STORES.keyMaterial,
  SEAMS_WALLET_STORES.walletSessionAuthorizations,
] as const;
const WALLET_RECOVERY_PUBLICATION_STORES = [
  SEAMS_WALLET_STORES.appState,
  SEAMS_WALLET_STORES.wallets,
  SEAMS_WALLET_STORES.walletAuthMethods,
  SEAMS_WALLET_STORES.walletAuthorities,
  SEAMS_WALLET_STORES.walletSelections,
  SEAMS_WALLET_STORES.walletSigners,
  SEAMS_WALLET_STORES.nearAccountProjections,
  SEAMS_WALLET_STORES.signerOpsOutbox,
  SEAMS_WALLET_STORES.keyMaterial,
] as const;

const DEFAULT_WALLET_RP_ID = 'local';

function requireWebAuthnRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}
const CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT = 0;

export class SeamsWalletDBConstraintError extends Error {
  readonly code: DBConstraintErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: DBConstraintErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'SeamsWalletDBConstraintError';
    this.code = code;
    this.details = details;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createRandomToken(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const suffix = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${prefix}-${suffix}`;
}

function nonceLeaseWalletId(record: NonceLaneLeaseStoreRecord): string {
  if (record.family === 'near') return record.walletId;
  return record.accountId;
}

function nonceLeaseNearAccountId(record: NonceLaneLeaseStoreRecord): string {
  return record.family === 'near' ? record.nearAccountId : '';
}

function nonceLeaseRow(record: NonceLaneLeaseStoreRecord): NonceLaneLeaseRow {
  const leaseId = toTrimmedString(record.leaseId || '');
  const laneKey = toTrimmedString(record.laneKey || '');
  const walletId = toTrimmedString(nonceLeaseWalletId(record) || '');
  const nearAccountId = toTrimmedString(nonceLeaseNearAccountId(record) || '');
  if (!leaseId || !laneKey || !walletId) {
    throw new Error('[SeamsWalletDB] nonce lease requires leaseId, laneKey, and wallet identity');
  }
  return {
    lease_id: leaseId,
    lane_key: laneKey,
    wallet_id: walletId,
    ...(nearAccountId ? { near_account_id: nearAccountId } : {}),
    state: record.state,
    expires_at_ms: Math.floor(Number(record.expiresAtMs)),
    record,
  };
}

function parseNonceLeaseRow(value: unknown): NonceLaneLeaseStoreRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<NonceLaneLeaseRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.lease_id !== record.leaseId) return null;
  if (row.lane_key !== record.laneKey) return null;
  if (row.wallet_id !== nonceLeaseWalletId(record)) return null;
  if ((row.near_account_id || '') !== nonceLeaseNearAccountId(record)) return null;
  if (row.state !== record.state) return null;
  if (row.expires_at_ms !== Math.floor(Number(record.expiresAtMs))) return null;
  return record;
}

function keyRangeUpperBound(value: number): IDBKeyRange {
  return IDBKeyRange.upperBound(value);
}

async function deleteRowsByIndex(args: {
  store: any;
  indexName: string;
  key: IDBValidKey | IDBKeyRange;
}): Promise<void> {
  let cursor = await args.store.index(args.indexName).openCursor(args.key);
  while (cursor) {
    await cursor.delete();
    cursor = await cursor.continue();
  }
}

function scopedLastProfileStateAppStateKey(scope?: string | null): string {
  const normalized = normalizeLastUserScope(scope);
  return normalized
    ? `${LAST_PROFILE_STATE_APP_STATE_KEY}::${normalized}`
    : LAST_PROFILE_STATE_APP_STATE_KEY;
}

function chainAccountProjectionId(args: { chainIdKey: string; accountAddress: string }): string {
  return `${args.chainIdKey}\0${args.accountAddress}`;
}

function walletSignerId(args: {
  chainIdKey: string;
  accountAddress: string;
  signerId: string;
}): string {
  return [args.chainIdKey, args.accountAddress, args.signerId].join('\0');
}

function signerChainTargetKey(args: { chainIdKey: string; accountAddress: string }): string {
  return [args.chainIdKey, args.accountAddress].join('\0');
}

function normalizeEcdsaChainTargetKey(value: unknown): string {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return '';
  const kind = toTrimmedString(obj.kind || '');
  const chainId = Number(obj.chainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return '';
  if (kind === 'evm') {
    if (toTrimmedString(obj.namespace || '') !== 'eip155') return '';
    return toIndexedDbChainTargetKey({
      kind: 'evm',
      namespace: 'eip155',
      chainId,
      networkSlug: toTrimmedString(obj.networkSlug || ''),
    });
  }
  if (kind === 'tempo') {
    return toIndexedDbChainTargetKey({
      kind: 'tempo',
      chainId,
      networkSlug: toTrimmedString(obj.networkSlug || ''),
    });
  }
  return '';
}

type WalletSignerScalarMirrors = {
  chainTargetKey: string;
  nearSignerSlot?: number;
  nearEd25519SigningKeyId?: string;
  keyHandle?: string;
  ecdsaThresholdKeyId?: string;
  thresholdOwnerAddress?: string;
};

function walletSignerScalarMirrors(record: AccountSignerRecord): WalletSignerScalarMirrors {
  if (record.signerKind === SIGNER_KINDS.thresholdEcdsa) {
    const metadata = record.metadata || {};
    const keyHandle = toTrimmedString(metadata.keyHandle || '');
    const ecdsaThresholdKeyId = toTrimmedString(metadata.ecdsaThresholdKeyId || '');
    const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(
      metadata.thresholdOwnerAddress || '',
    );
    const chainTargetKey = normalizeEcdsaChainTargetKey(metadata.chainTarget);
    if (!keyHandle || !ecdsaThresholdKeyId || !thresholdOwnerAddress || !chainTargetKey) {
      throw new Error(
        '[SeamsWalletDB] threshold ECDSA signer requires keyHandle, ecdsaThresholdKeyId, thresholdOwnerAddress, and chainTarget',
      );
    }
    return {
      chainTargetKey,
      keyHandle,
      ecdsaThresholdKeyId,
      thresholdOwnerAddress,
    };
  }

  const signerSlot = Number(record.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('[SeamsWalletDB] Ed25519 signer requires a positive signerSlot');
  }
  const nearEd25519SigningKeyId = toTrimmedString(record.metadata?.nearEd25519SigningKeyId || '');
  if (!nearEd25519SigningKeyId) {
    throw new Error('[SeamsWalletDB] Ed25519 signer requires nearEd25519SigningKeyId');
  }
  return {
    chainTargetKey: signerChainTargetKey({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
    }),
    nearSignerSlot: signerSlot,
    nearEd25519SigningKeyId,
  };
}

function shouldWriteNearAccountProjection(args: {
  accountModel: string;
  chainIdKey: string;
}): boolean {
  return args.accountModel === 'near-native' || args.chainIdKey.startsWith('near:');
}

function makeConstraintError(
  code: DBConstraintErrorCode,
  message: string,
  details?: Record<string, unknown>,
): SeamsWalletDBConstraintError {
  return new SeamsWalletDBConstraintError(code, message, details);
}

function profileRow(input: UpsertProfileInput, existing?: ProfileRecord): WalletRow {
  const profileId = toTrimmedString(input.profileId || '');
  if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
  const now = Date.now();
  const passkeyCredential = input.passkeyCredential?.rawId
    ? input.passkeyCredential
    : existing?.passkeyCredential;
  const record: ProfileRecord = {
    profileId,
    defaultSignerSlot: input.defaultSignerSlot ?? existing?.defaultSignerSlot ?? 1,
    ...(passkeyCredential ? { passkeyCredential } : {}),
    preferences: input.preferences ?? existing?.preferences,
    ...((input.nearProvisioning ?? existing?.nearProvisioning)
      ? { nearProvisioning: input.nearProvisioning ?? existing?.nearProvisioning }
      : {}),
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  return {
    wallet_id: profileId,
    rp_id: DEFAULT_WALLET_RP_ID,
    status: 'active',
    created_at: record.createdAt,
    updated_at: record.updatedAt,
    record,
  };
}

function profileRowFromRecord(record: ProfileRecord): WalletRow {
  return {
    wallet_id: record.profileId,
    rp_id: DEFAULT_WALLET_RP_ID,
    status: 'active',
    created_at: record.createdAt,
    updated_at: record.updatedAt,
    record,
  };
}

function rollbackRecordsEqual(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function parseProfileRow(value: unknown): ProfileRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<WalletRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.wallet_id !== record.profileId) return null;
  if (row.created_at !== record.createdAt) return null;
  if (row.updated_at !== record.updatedAt) return null;
  return record;
}

function parseLocalAuthorityPendingProfileProjectionV1(
  value: unknown,
): LocalAuthorityPendingProfileProjectionV1 | null {
  if (!isRecord(value) || value.kind !== 'local_authority_pending_profile_projection_v1') {
    return null;
  }
  const profile = parseProfileStorageRowV1(value.profile);
  const authenticator =
    value.authenticator === null
      ? null
      : parseWalletAuthMethodStorageRow(value.authenticator);
  const localAuthMethod =
    value.localAuthMethod === null
      ? null
      : parseWalletAuthMethodStorageRow(value.localAuthMethod);
  if (
    !profile ||
    (value.authenticator !== null &&
      (!authenticator || authenticator.kind !== 'passkey' || authenticator.status !== 'active')) ||
    (value.localAuthMethod !== null &&
      (!localAuthMethod || localAuthMethod.kind !== 'email_otp' || localAuthMethod.status !== 'active'))
  ) {
    return null;
  }
  const authorityId = value.authorityId;
  const walletId = value.walletId;
  const authMethodId = value.authMethodId;
  if (
    typeof authorityId !== 'string' ||
    typeof walletId !== 'string' ||
    typeof authMethodId !== 'string' ||
    !authorityId ||
    !walletId ||
    !authMethodId ||
    authorityId.trim() !== authorityId ||
    walletId.trim() !== walletId ||
    authMethodId.trim() !== authMethodId ||
    profile.wallet_id !== walletId ||
    (authenticator !== null && authenticator.wallet_id !== walletId) ||
    (localAuthMethod !== null && localAuthMethod.wallet_id !== walletId)
  ) {
    return null;
  }
  return {
    kind: 'local_authority_pending_profile_projection_v1',
    authorityId,
    walletId,
    authMethodId,
    profile,
    authenticator: authenticator?.kind === 'passkey' ? authenticator : null,
    localAuthMethod: localAuthMethod?.kind === 'email_otp' ? localAuthMethod : null,
  };
}

function parseProfileStorageRowV1(value: unknown): WalletRow | null {
  if (!isRecord(value) || value.status !== 'active' || typeof value.rp_id !== 'string') {
    return null;
  }
  const record = parseProfileRow(value);
  if (!record || value.wallet_id !== record.profileId) return null;
  return {
    wallet_id: record.profileId,
    rp_id: value.rp_id,
    status: 'active',
    created_at: record.createdAt,
    updated_at: record.updatedAt,
    record,
  };
}

function walletAuthMethodIdentifier(record: LocalWalletAuthMethodRecord): string {
  switch (record.kind) {
    case 'passkey':
      return toTrimmedString(record.credentialIdB64u || '');
    case 'email_otp':
      return toTrimmedString(record.emailHashHex || '');
    default: {
      const _exhaustive: never = record;
      throw new Error(`[SeamsWalletDB] Unsupported auth-method binding: ${String(_exhaustive)}`);
    }
  }
}

function walletAuthMethodId(record: LocalWalletAuthMethodRecord): string {
  if (record.kind === 'passkey') {
    return [
      toTrimmedString(record.walletId || ''),
      record.kind,
      toTrimmedString(record.rpId || ''),
      walletAuthMethodIdentifier(record),
    ].join('\0');
  }
  return [
    toTrimmedString(record.walletId || ''),
    record.kind,
    walletAuthMethodIdentifier(record),
  ].join('\0');
}

function walletAuthMethodFields(record: LocalWalletAuthMethodRecord): WalletAuthMethodBaseRow {
  if (record.version !== 'wallet_auth_method_v1') {
    throw new Error('[SeamsWalletDB] auth-method binding version is invalid');
  }
  const walletId = toTrimmedString(record.walletId || '');
  const rpId = record.kind === 'passkey' ? toTrimmedString(record.rpId || '') : '';
  const authIdentifierKey = walletAuthMethodIdentifier(record);
  const createdAtMs = Math.floor(Number(record.createdAtMs));
  const updatedAtMs = Math.floor(Number(record.updatedAtMs));
  if (!walletId || !authIdentifierKey || (record.kind === 'passkey' && !rpId)) {
    throw new Error('[SeamsWalletDB] auth-method binding requires walletId and branch identity');
  }
  if (record.status !== 'active' && record.status !== 'revoked') {
    throw new Error('[SeamsWalletDB] auth-method binding status is invalid');
  }
  if (record.localStatus !== 'synced' && record.localStatus !== 'pending') {
    throw new Error('[SeamsWalletDB] auth-method binding localStatus is invalid');
  }
  if (!Number.isSafeInteger(createdAtMs)) {
    throw new Error('[SeamsWalletDB] auth-method binding createdAtMs is invalid');
  }
  if (!Number.isSafeInteger(updatedAtMs)) {
    throw new Error('[SeamsWalletDB] auth-method binding updatedAtMs is invalid');
  }
  if (record.kind === 'passkey') {
    if (record.emailHashHex != null) {
      throw new Error('[SeamsWalletDB] passkey auth-method binding has Email OTP fields');
    }
    if (!toTrimmedString(record.credentialPublicKeyB64u || '')) {
      throw new Error('[SeamsWalletDB] passkey auth-method binding requires credential public key');
    }
    if (!Number.isSafeInteger(record.counter) || record.counter < 0) {
      throw new Error('[SeamsWalletDB] passkey auth-method binding counter is invalid');
    }
  }
  if (record.kind === 'email_otp') {
    if (
      record.credentialIdB64u != null ||
      record.credentialPublicKeyB64u != null ||
      record.counter != null ||
      record.rpId != null
    ) {
      throw new Error('[SeamsWalletDB] Email OTP auth-method binding has passkey fields');
    }
    if (!toTrimmedString(record.registrationAuthorityId || '')) {
      throw new Error(
        '[SeamsWalletDB] Email OTP auth-method binding requires registrationAuthorityId',
      );
    }
    if (!record.authority) {
      throw new Error('[SeamsWalletDB] Email OTP auth-method binding requires authority');
    }
    const authority = parseEmailOtpWalletAuthAuthority(record.authority);
    if (
      !authority ||
      authority.walletId !== record.walletId ||
      authority.verifier.emailHashHex !== record.emailHashHex ||
      !walletAuthAuthoritiesMatch(authority, record.authority)
    ) {
      throw new Error('[SeamsWalletDB] Email OTP auth-method authority binding is invalid');
    }
  }
  return {
    wallet_auth_method_id: walletAuthMethodId(record),
    wallet_id: walletId,
    kind: record.kind,
    auth_method: record.kind,
    rp_id: rpId,
    auth_identifier_key: authIdentifierKey,
    status: record.status,
    updated_at: updatedAtMs,
    record,
  };
}

function isoTimestampFromMs(ms: number): string {
  return new Date(ms).toISOString();
}

function timestampMsFromIso(value: string, fallbackMs: number): number {
  const parsed = Date.parse(value);
  return Number.isSafeInteger(parsed) ? parsed : fallbackMs;
}

function normalizeAuthenticatorRecord(
  record: ProfileAuthenticatorRecord,
): ProfileAuthenticatorRecord {
  const profileId = toTrimmedString(record.profileId || '');
  const credentialId = toTrimmedString(record.credentialId || '');
  const signerSlot = Number(record.signerSlot);
  if (!profileId || !credentialId) {
    throw new Error('[SeamsWalletDB] profileId and credentialId are required for authenticators');
  }
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('[SeamsWalletDB] authenticator signerSlot must be an integer >= 1');
  }
  const credentialPublicKey = record.credentialPublicKey;
  if (!(credentialPublicKey instanceof Uint8Array) || credentialPublicKey.byteLength === 0) {
    throw new Error(
      '[SeamsWalletDB] authenticator credentialPublicKey must be a non-empty Uint8Array',
    );
  }
  return {
    profileId,
    signerSlot,
    credentialId,
    credentialPublicKey,
    ...(Array.isArray(record.transports) ? { transports: record.transports } : {}),
    ...(record.name ? { name: String(record.name) } : {}),
    registered: toTrimmedString(record.registered || ''),
    syncedAt: toTrimmedString(record.syncedAt || ''),
  };
}

function passkeyAuthenticatorFromBinding(
  record: LocalWalletAuthMethodRecord & { kind: 'passkey' },
  signerSlot: number,
): ProfileAuthenticatorRecord {
  const normalizedSignerSlot = Number(signerSlot);
  if (!Number.isSafeInteger(normalizedSignerSlot) || normalizedSignerSlot < 1) {
    throw new Error('[SeamsWalletDB] passkey auth-method signerSlot must be an integer >= 1');
  }
  return normalizeAuthenticatorRecord({
    profileId: record.walletId,
    signerSlot: normalizedSignerSlot,
    credentialId: record.credentialIdB64u,
    credentialPublicKey: base64UrlDecode(record.credentialPublicKeyB64u),
    registered: isoTimestampFromMs(record.createdAtMs),
    syncedAt: isoTimestampFromMs(record.updatedAtMs),
  });
}

function passkeyBindingFromAuthenticator(
  authenticator: ProfileAuthenticatorRecord,
  existing?: LocalWalletAuthMethodRecord & { kind: 'passkey' },
): LocalWalletAuthMethodRecord & { kind: 'passkey' } {
  const normalized = normalizeAuthenticatorRecord(authenticator);
  const credentialPublicKeyB64u = base64UrlEncode(normalized.credentialPublicKey);
  if (existing) {
    if (existing.walletId !== normalized.profileId) {
      throw new Error(
        '[SeamsWalletDB] passkey auth-method walletId does not match authenticator profileId',
      );
    }
    if (existing.credentialIdB64u !== normalized.credentialId) {
      throw new Error(
        '[SeamsWalletDB] passkey auth-method credentialId does not match authenticator credentialId',
      );
    }
    if (existing.credentialPublicKeyB64u !== credentialPublicKeyB64u) {
      throw new Error(
        '[SeamsWalletDB] passkey auth-method public key does not match authenticator public key',
      );
    }
    return existing;
  }
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    localStatus: 'synced',
    walletId: walletIdFromString(normalized.profileId),
    rpId: requireWebAuthnRpId(DEFAULT_WALLET_RP_ID),
    credentialIdB64u: normalized.credentialId,
    credentialPublicKeyB64u,
    counter: 0,
    createdAtMs: timestampMsFromIso(normalized.registered, nowMs),
    updatedAtMs: timestampMsFromIso(normalized.syncedAt, nowMs),
  };
}

function passkeyAuthMethodRow(input: {
  binding: LocalWalletAuthMethodRecord & { kind: 'passkey' };
  authenticator: ProfileAuthenticatorRecord;
}): WalletPasskeyAuthMethodRow {
  const base = walletAuthMethodFields(input.binding);
  const authenticator = normalizeAuthenticatorRecord(input.authenticator);
  const credentialPublicKeyB64u = base64UrlEncode(authenticator.credentialPublicKey);
  if (base.kind !== 'passkey') {
    throw new Error('[SeamsWalletDB] passkey auth-method row requires a passkey binding');
  }
  if (authenticator.profileId !== base.wallet_id) {
    throw new Error('[SeamsWalletDB] passkey auth-method authenticator profileId mismatch');
  }
  if (authenticator.credentialId !== input.binding.credentialIdB64u) {
    throw new Error('[SeamsWalletDB] passkey auth-method authenticator credentialId mismatch');
  }
  if (credentialPublicKeyB64u !== input.binding.credentialPublicKeyB64u) {
    throw new Error('[SeamsWalletDB] passkey auth-method authenticator public key mismatch');
  }
  return {
    ...base,
    kind: 'passkey',
    auth_method: 'passkey',
    record: input.binding,
    credential_id_b64u: input.binding.credentialIdB64u,
    credential_public_key_b64u: input.binding.credentialPublicKeyB64u,
    signer_slot: authenticator.signerSlot,
    authenticator,
  };
}

function emailOtpAuthMethodRow(
  record: LocalWalletAuthMethodRecord & { kind: 'email_otp' },
): WalletEmailOtpAuthMethodRow {
  const base = walletAuthMethodFields(record);
  if (base.kind !== 'email_otp') {
    throw new Error('[SeamsWalletDB] Email OTP auth-method row requires an Email OTP binding');
  }
  return {
    ...base,
    kind: 'email_otp',
    auth_method: 'email_otp',
    record,
    email_hash_hex: record.emailHashHex,
    challenge_id: record.registrationAuthorityId,
  };
}

function walletAuthMethodRowFromBinding(
  record: LocalWalletAuthMethodRecord,
  signerSlot: number,
): WalletAuthMethodRow {
  switch (record.kind) {
    case 'passkey':
      return passkeyAuthMethodRow({
        binding: record,
        authenticator: passkeyAuthenticatorFromBinding(record, signerSlot),
      });
    case 'email_otp':
      return emailOtpAuthMethodRow(record);
    default: {
      const _exhaustive: never = record;
      throw new Error(`[SeamsWalletDB] Unsupported auth-method row: ${String(_exhaustive)}`);
    }
  }
}

function walletAuthMethodRowFromAuthenticator(
  record: ProfileAuthenticatorRecord,
  existing?: WalletPasskeyAuthMethodRow,
): WalletPasskeyAuthMethodRow {
  const authenticator = normalizeAuthenticatorRecord(record);
  return passkeyAuthMethodRow({
    binding: passkeyBindingFromAuthenticator(authenticator, existing?.record),
    authenticator,
  });
}

function buildLocalAuthorityPendingProfileProjectionV1(input: {
  readonly authorityId: string;
  readonly walletId: string;
  readonly authMethodId: string;
  readonly profile: WalletRow;
  readonly authenticator: WalletPasskeyAuthMethodRow | null;
  readonly localAuthMethod: WalletEmailOtpAuthMethodRow | null;
}): LocalAuthorityPendingProfileProjectionV1 {
  if (
    input.profile.wallet_id !== input.walletId ||
    (input.authenticator !== null && input.authenticator.wallet_id !== input.walletId) ||
    (input.localAuthMethod !== null && input.localAuthMethod.wallet_id !== input.walletId)
  ) {
    throw new Error('local authority profile projection identity does not match installation');
  }
  if (
    input.authenticator?.wallet_auth_method_id === input.authMethodId ||
    input.localAuthMethod?.wallet_auth_method_id === input.authMethodId
  ) {
    throw new Error('local authority profile projection collides with the V2 auth-method key');
  }
  return {
    kind: 'local_authority_pending_profile_projection_v1',
    authorityId: input.authorityId,
    walletId: input.walletId,
    authMethodId: input.authMethodId,
    profile: input.profile,
    authenticator: input.authenticator,
    localAuthMethod: input.localAuthMethod,
  };
}

function localAuthorityPendingProfileProjectionsMatchV1(
  left: LocalAuthorityPendingProfileProjectionV1,
  right: LocalAuthorityPendingProfileProjectionV1,
): boolean {
  return (
    left.authorityId === right.authorityId &&
    left.walletId === right.walletId &&
    left.authMethodId === right.authMethodId &&
    rollbackRecordsEqual(left.profile, right.profile) &&
    rollbackRecordsEqual(left.authenticator, right.authenticator) &&
    rollbackRecordsEqual(left.localAuthMethod, right.localAuthMethod)
  );
}

function localAuthorityPendingProfileProjectionMatchesInputV1(
  projection: LocalAuthorityPendingProfileProjectionV1,
  input: Pick<
    ValidatedLocalAuthorityInstallationInput,
    'authority' | 'authMethod' | 'profile' | 'authenticator' | 'localAuthMethod'
  >,
): boolean {
  return (
    projection.authorityId === input.authority.authorityId &&
    projection.walletId === input.authority.walletId &&
    projection.authMethodId === input.authMethod.walletAuthMethodId &&
    projection.profile.record.profileId === input.profile.profileId &&
    projection.profile.record.defaultSignerSlot === (input.profile.defaultSignerSlot ?? 1) &&
    (input.profile.passkeyCredential === undefined ||
      (projection.profile.record.passkeyCredential?.id === input.profile.passkeyCredential.id &&
        projection.profile.record.passkeyCredential.rawId === input.profile.passkeyCredential.rawId)) &&
    (input.profile.preferences === undefined ||
      rollbackRecordsEqual(projection.profile.record.preferences, input.profile.preferences)) &&
    (input.authenticator === null
      ? projection.authenticator === null
      : projection.authenticator !== null &&
        rollbackRecordsEqual(projection.authenticator.authenticator, input.authenticator)) &&
    (input.localAuthMethod === null
      ? projection.localAuthMethod === null
      : projection.localAuthMethod !== null &&
        rollbackRecordsEqual(projection.localAuthMethod.record, input.localAuthMethod))
  );
}

function parseWalletAuthMethodStorageRow(value: unknown): WalletAuthMethodRow | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<WalletAuthMethodRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  let normalized: WalletAuthMethodRow;
  try {
    if (record.kind === 'passkey') {
      if (!row.authenticator) return null;
      normalized = passkeyAuthMethodRow({
        binding: record,
        authenticator: row.authenticator,
      });
    } else if (record.kind === 'email_otp') {
      normalized = emailOtpAuthMethodRow(record);
    } else {
      return null;
    }
  } catch {
    return null;
  }
  if (row.wallet_auth_method_id !== normalized.wallet_auth_method_id) {
    return null;
  }
  if (row.wallet_id !== normalized.wallet_id) return null;
  if (row.kind !== normalized.kind) return null;
  if (row.auth_method !== normalized.auth_method) return null;
  if (normalized.kind === 'passkey' && row.rp_id !== normalized.rp_id) return null;
  if (row.auth_identifier_key !== normalized.auth_identifier_key) return null;
  if (row.status !== normalized.status) return null;
  if (row.updated_at !== normalized.updated_at) return null;
  if (normalized.kind === 'passkey') {
    if (row.credential_id_b64u !== normalized.credential_id_b64u) return null;
    if (row.credential_public_key_b64u !== normalized.credential_public_key_b64u) return null;
    if (row.signer_slot !== normalized.signer_slot) return null;
  } else {
    if (row.email_hash_hex !== normalized.email_hash_hex) return null;
    if (row.challenge_id !== normalized.challenge_id) return null;
  }
  return normalized;
}

function parseWalletAuthMethodRow(value: unknown): LocalWalletAuthMethodRecord | null {
  const row = parseWalletAuthMethodStorageRow(value);
  if (!row) return null;
  return row.record;
}

function parseAuthenticatorRow(value: unknown): ProfileAuthenticatorRecord | null {
  const row = parseWalletAuthMethodStorageRow(value);
  if (!row || row.kind !== 'passkey' || row.status !== 'active') return null;
  return row.authenticator;
}

type BoundaryParseResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: string };

type SignerMaterialExpectation = {
  readonly keyFamily: WalletAuthoritySignerMaterialRecordV1['keyFamily'];
  readonly materialActivation: MpcMaterialActivationRef;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actualKeys = Object.keys(record);
  if (actualKeys.length !== keys.length) return false;
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) return false;
  }
  return true;
}

function requireBoundaryParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
  return result.value;
}

function parseNonEmptyBoundaryString(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return raw;
}

function parseNonNegativeSafeInteger(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(raw);
}

function rawValueIsPresent(value: unknown): boolean {
  return value !== undefined;
}

function parseWalletAuthorityStorageRow(value: unknown): WalletAuthorityRow | null {
  if (!isRecord(value)) return null;
  const parsed = parseWalletAuthorityV1(value.record);
  if (!parsed.ok) return null;
  const record = parsed.value;
  if (
    value.authority_id !== record.authorityId ||
    value.wallet_id !== record.walletId ||
    value.state !== record.state ||
    value.device_id !== record.principal.deviceId ||
    value.updated_at !== record.updatedAtMs
  ) {
    return null;
  }
  return {
    authority_id: record.authorityId,
    wallet_id: record.walletId,
    state: record.state,
    device_id: record.principal.deviceId,
    updated_at: record.updatedAtMs,
    record,
  };
}

function walletAuthorityStorageRow(record: WalletAuthorityV1): WalletAuthorityRow {
  return {
    authority_id: record.authorityId,
    wallet_id: record.walletId,
    state: record.state,
    device_id: record.principal.deviceId,
    updated_at: record.updatedAtMs,
    record,
  };
}

function parseWalletAuthMethodV2StorageRow(value: unknown): WalletAuthMethodV2Row | null {
  if (!isRecord(value)) return null;
  const record = parseWalletAuthMethodRecordV2(value.record);
  if (!record) return null;
  if (
    value.wallet_auth_method_id !== record.walletAuthMethodId ||
    value.wallet_id !== record.walletId ||
    value.wallet_authority_id !== record.walletAuthorityId ||
    value.kind !== record.kind ||
    value.status !== record.status ||
    value.updated_at !== record.updatedAtMs
  ) {
    return null;
  }
  return {
    wallet_auth_method_id: record.walletAuthMethodId,
    wallet_id: record.walletId,
    wallet_authority_id: record.walletAuthorityId,
    kind: record.kind,
    status: record.status,
    updated_at: record.updatedAtMs,
    record,
  };
}

function walletAuthMethodV2StorageRow(record: WalletAuthMethodRecordV2): WalletAuthMethodV2Row {
  return {
    wallet_auth_method_id: record.walletAuthMethodId,
    wallet_id: record.walletId,
    wallet_authority_id: record.walletAuthorityId,
    kind: record.kind,
    status: record.status,
    updated_at: record.updatedAtMs,
    record,
  };
}

function parseWalletAuthoritySignerMaterialRecord(
  value: unknown,
): WalletAuthoritySignerMaterialRecordV1 {
  if (!isRecord(value)) throw new Error('signer material record must be an object');
  if (value.kind === 'wallet_authority_linked_signer_material_v1') {
    return parseWalletAuthorityLinkedSignerMaterialRecordV1(value);
  }
  if (value.kind !== 'wallet_authority_signer_material_v1') {
    throw new Error('signer material record kind is invalid');
  }
  if (value.keyFamily !== 'ed25519' && value.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('signer material keyFamily is invalid');
  }
  const commonKeys = [
    'kind',
    'authorityId',
    'walletAuthMethodId',
    'activationId',
    'keyFamily',
    'materialActivation',
    'sealedMaterialB64u',
    'sealedMaterialDigestB64u',
  ] as const;
  const expectedKeys =
    value.keyFamily === 'ecdsa_secp256k1' ? [...commonKeys, 'ecdsaThresholdKeyId'] : commonKeys;
  if (!hasExactKeys(value, expectedKeys)) {
    throw new Error('signer material record fields are invalid');
  }
  const authorityId = requireBoundaryParsed(
    parseWalletAuthorityId(value.authorityId),
    'authorityId',
  );
  const walletAuthMethodId = requireBoundaryParsed(
    parseWalletAuthMethodId(value.walletAuthMethodId),
    'walletAuthMethodId',
  );
  const materialActivation = requireBoundaryParsed(
    parseMpcMaterialActivationRef(value.materialActivation),
    'materialActivation',
  );
  const activationId = parseNonEmptyBoundaryString(value.activationId, 'activationId');
  const sealedMaterialB64u = parseNonEmptyBoundaryString(
    value.sealedMaterialB64u,
    'sealedMaterialB64u',
  );
  const sealedMaterialDigestB64u = parseDigestB64u(value.sealedMaterialDigestB64u);
  if (materialActivation.activationId !== activationId) {
    throw new Error('signer material activationId does not match materialActivation');
  }
  if (value.keyFamily === 'ed25519') {
    return {
      kind: 'wallet_authority_signer_material_v1',
      authorityId,
      walletAuthMethodId,
      activationId: materialActivation.activationId,
      keyFamily: 'ed25519',
      materialActivation,
      sealedMaterialB64u,
      sealedMaterialDigestB64u,
    };
  }
  return {
    kind: 'wallet_authority_signer_material_v1',
    authorityId,
    walletAuthMethodId,
    activationId: materialActivation.activationId,
    keyFamily: 'ecdsa_secp256k1',
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(value.ecdsaThresholdKeyId),
    materialActivation,
    sealedMaterialB64u,
    sealedMaterialDigestB64u,
  };
}

function parseWalletAuthoritySignerMaterialStorageRow(
  value: unknown,
): WalletAuthoritySignerMaterialRow | null {
  if (!isRecord(value)) return null;
  try {
    const record = parseWalletAuthoritySignerMaterialRecord(value.record);
    if (
      value.wallet_authority_id !== record.authorityId ||
      value.wallet_auth_method_id !== record.walletAuthMethodId ||
      value.activation_id !== record.activationId ||
      value.key_family !== record.keyFamily ||
      value.ecdsa_threshold_key_id !==
        (record.keyFamily === 'ecdsa_secp256k1' ? record.ecdsaThresholdKeyId : undefined) ||
      value.sealed_material_b64u !== record.sealedMaterialB64u ||
      value.sealed_material_digest_b64u !== record.sealedMaterialDigestB64u
    ) {
      return null;
    }
    return {
      wallet_authority_id: record.authorityId,
      wallet_auth_method_id: record.walletAuthMethodId,
      activation_id: record.activationId,
      key_family: record.keyFamily,
      ecdsa_threshold_key_id:
        record.keyFamily === 'ecdsa_secp256k1' ? record.ecdsaThresholdKeyId : undefined,
      sealed_material_b64u: record.sealedMaterialB64u,
      sealed_material_digest_b64u: record.sealedMaterialDigestB64u,
      record,
    };
  } catch {
    return null;
  }
}

function walletAuthoritySignerMaterialStorageRow(
  record: WalletAuthoritySignerMaterialRecordV1,
): WalletAuthoritySignerMaterialRow {
  return {
    wallet_authority_id: record.authorityId,
    wallet_auth_method_id: record.walletAuthMethodId,
    activation_id: record.activationId,
    key_family: record.keyFamily,
    ecdsa_threshold_key_id:
      record.keyFamily === 'ecdsa_secp256k1' ? record.ecdsaThresholdKeyId : undefined,
    sealed_material_b64u: record.sealedMaterialB64u,
    sealed_material_digest_b64u: record.sealedMaterialDigestB64u,
    record,
  };
}

function parseWalletAuthorityExportRootRecord(value: unknown): WalletAuthorityExportRootRecordV1 {
  if (!isRecord(value)) throw new Error('export root record must be an object');
  if (
    !hasExactKeys(value, ['kind', 'authorityId', 'walletAuthMethodId', 'walletKeyId', 'envelope'])
  ) {
    throw new Error('export root record fields are invalid');
  }
  if (value.kind !== 'wallet_authority_export_root_v1') {
    throw new Error('export root record kind is invalid');
  }
  const walletKeyId = requireBoundaryParsed(parseWalletKeyId(value.walletKeyId), 'walletKeyId');
  const envelope = parsePasskeyCustodyEnvelopeRecord(value.envelope);
  if (
    envelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
    envelope.binding.walletKeyId !== walletKeyId
  ) {
    throw new Error('export root envelope does not match walletKeyId');
  }
  return {
    kind: 'wallet_authority_export_root_v1',
    authorityId: requireBoundaryParsed(parseWalletAuthorityId(value.authorityId), 'authorityId'),
    walletAuthMethodId: requireBoundaryParsed(
      parseWalletAuthMethodId(value.walletAuthMethodId),
      'walletAuthMethodId',
    ),
    walletKeyId,
    envelope,
  };
}

function parseWalletAuthorityExportRootStorageRow(
  value: unknown,
): WalletAuthorityExportRootRow | null {
  if (!isRecord(value)) return null;
  try {
    const record = parseWalletAuthorityExportRootRecord(value.record);
    if (
      value.wallet_authority_id !== record.authorityId ||
      value.wallet_auth_method_id !== record.walletAuthMethodId ||
      value.wallet_key_id !== record.walletKeyId ||
      value.sealed_root_b64u !== record.envelope.sealedCustodySecretB64u ||
      value.sealed_root_digest_b64u !== record.envelope.ciphertextDigestB64u
    ) {
      return null;
    }
    return {
      wallet_authority_id: record.authorityId,
      wallet_auth_method_id: record.walletAuthMethodId,
      wallet_key_id: record.walletKeyId,
      sealed_root_b64u: record.envelope.sealedCustodySecretB64u,
      sealed_root_digest_b64u: record.envelope.ciphertextDigestB64u,
      record,
    };
  } catch {
    return null;
  }
}

function walletAuthorityExportRootStorageRow(
  record: WalletAuthorityExportRootRecordV1,
): WalletAuthorityExportRootRow {
  return {
    wallet_authority_id: record.authorityId,
    wallet_auth_method_id: record.walletAuthMethodId,
    wallet_key_id: record.walletKeyId,
    sealed_root_b64u: record.envelope.sealedCustodySecretB64u,
    sealed_root_digest_b64u: record.envelope.ciphertextDigestB64u,
    record,
  };
}

function parseLocalAuthorityInstallationReceiptStorageRow(
  value: unknown,
): WalletAuthorityInstallationReceiptRow | null {
  if (!isRecord(value)) return null;
  try {
    const record = parseLocalAuthorityInstallationReceiptV1(value.record);
    if (
      value.authority_id !== record.authorityId ||
      value.wallet_id !== record.walletId ||
      value.wallet_auth_method_id !== record.authMethodId ||
      value.device_id !== record.deviceId ||
      value.package_set_digest_b64u !== record.packageSetDigestB64u ||
      value.installed_at_ms !== record.installedAtMs
    ) {
      return null;
    }
    return {
      authority_id: record.authorityId,
      wallet_id: record.walletId,
      wallet_auth_method_id: record.authMethodId,
      device_id: record.deviceId,
      package_set_digest_b64u: record.packageSetDigestB64u,
      installed_at_ms: record.installedAtMs,
      record,
    };
  } catch {
    return null;
  }
}

function localAuthorityInstallationReceiptStorageRow(
  record: LocalAuthorityInstallationReceiptV1,
): WalletAuthorityInstallationReceiptRow {
  return {
    authority_id: record.authorityId,
    wallet_id: record.walletId,
    wallet_auth_method_id: record.authMethodId,
    device_id: record.deviceId,
    package_set_digest_b64u: record.packageSetDigestB64u,
    installed_at_ms: record.installedAtMs,
    record,
  };
}

function parseWalletSelectionRecord(value: unknown): WalletSelectionRecordV1 {
  if (!isRecord(value)) throw new Error('wallet selection record must be an object');
  if (
    !hasExactKeys(value, [
      'kind',
      'walletId',
      'walletAuthMethodId',
      'lockGeneration',
      'lockState',
      'updatedAtMs',
    ])
  ) {
    throw new Error('wallet selection record fields are invalid');
  }
  if (value.kind !== 'wallet_selection_v1')
    throw new Error('wallet selection record kind is invalid');
  if (value.lockState !== 'locked' && value.lockState !== 'unlocked') {
    throw new Error('wallet selection lockState is invalid');
  }
  return {
    kind: 'wallet_selection_v1',
    walletId: requireBoundaryParsed(parseWalletId(value.walletId), 'walletId'),
    walletAuthMethodId: requireBoundaryParsed(
      parseWalletAuthMethodId(value.walletAuthMethodId),
      'walletAuthMethodId',
    ),
    lockGeneration: parseNonNegativeSafeInteger(value.lockGeneration, 'lockGeneration'),
    lockState: value.lockState,
    updatedAtMs: parseNonNegativeSafeInteger(value.updatedAtMs, 'updatedAtMs'),
  };
}

function parseWalletSelectionStorageRow(value: unknown): WalletSelectionRow | null {
  if (!isRecord(value)) return null;
  try {
    const record = parseWalletSelectionRecord(value.record);
    if (
      value.wallet_id !== record.walletId ||
      value.wallet_auth_method_id !== record.walletAuthMethodId ||
      value.lock_generation !== record.lockGeneration ||
      value.lock_state !== record.lockState ||
      value.updated_at_ms !== record.updatedAtMs
    ) {
      return null;
    }
    return {
      wallet_id: record.walletId,
      wallet_auth_method_id: record.walletAuthMethodId,
      lock_generation: record.lockGeneration,
      lock_state: record.lockState,
      updated_at_ms: record.updatedAtMs,
      record,
    };
  } catch {
    return null;
  }
}

function walletSelectionStorageRow(record: WalletSelectionRecordV1): WalletSelectionRow {
  return {
    wallet_id: record.walletId,
    wallet_auth_method_id: record.walletAuthMethodId,
    lock_generation: record.lockGeneration,
    lock_state: record.lockState,
    updated_at_ms: record.updatedAtMs,
    record,
  };
}

function signerMaterialExpectations(
  value: WalletSignerActivationSetV1,
): readonly SignerMaterialExpectation[] {
  if (value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ed25519') {
    if (value.ed25519) {
      return [{ keyFamily: 'ed25519', materialActivation: value.ed25519.materialActivation }];
    }
  }
  if (value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ecdsa_secp256k1') {
    if (value.ecdsa) {
      return [{ keyFamily: 'ecdsa_secp256k1', materialActivation: value.ecdsa.materialActivation }];
    }
  }
  if (value.keyFamilies.length === 2) {
    if (value.ed25519 && value.ecdsa) {
      return [
        { keyFamily: 'ed25519', materialActivation: value.ed25519.materialActivation },
        { keyFamily: 'ecdsa_secp256k1', materialActivation: value.ecdsa.materialActivation },
      ];
    }
  }
  throw new Error('wallet signer activation families are invalid');
}

function ed25519WalletKeyId(value: WalletSignerActivationSetV1): WalletKeyId | null {
  if (value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ed25519') {
    return value.ed25519 ? value.ed25519.signer.walletKeyId : null;
  }
  if (value.keyFamilies.length === 2) {
    return value.ed25519 ? value.ed25519.signer.walletKeyId : null;
  }
  throw new Error('wallet signer activation families are invalid');
}

function hasEd25519SignerFamily(value: WalletSignerActivationSetV1): boolean {
  return value.keyFamilies.length === 2 || value.keyFamilies[0] === 'ed25519';
}

function canonicalBytesMatch(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function walletSignerActivationSetsMatch(
  left: WalletSignerActivationSetV1,
  right: WalletSignerActivationSetV1,
): boolean {
  return canonicalBytesMatch(
    encodeWalletSignerActivationSetV1(left),
    encodeWalletSignerActivationSetV1(right),
  );
}

function walletAuthorityPermissionsMatch(
  left: WalletAuthorityV1,
  right: WalletAuthorityV1,
): boolean {
  return sameDelegatedWalletAuthorityV1(
    { kind: 'delegated_wallet_authority_v1', permissions: left.permissions },
    { kind: 'delegated_wallet_authority_v1', permissions: right.permissions },
  );
}

function walletAuthorityProvenancesMatch(
  left: WalletAuthorityV1['provenance'],
  right: WalletAuthorityV1['provenance'],
): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === 'wallet_registration') return true;
  return (
    right.kind === 'device_link' &&
    left.enrollmentId === right.enrollmentId &&
    left.sourceAuthorityId === right.sourceAuthorityId &&
    left.linkSessionId === right.linkSessionId
  );
}

function walletAuthorityLifecycleFieldsMatch(
  left: WalletAuthorityV1,
  right: WalletAuthorityV1,
): boolean {
  if (left.state !== right.state) return false;
  switch (left.state) {
    case 'pending_local_install':
      return (
        right.state === 'pending_local_install' &&
        left.localInstallPackageSetDigestB64u === right.localInstallPackageSetDigestB64u
      );
    case 'active':
      return right.state === 'active' && left.activatedAtMs === right.activatedAtMs;
    case 'revoked':
      return (
        right.state === 'revoked' &&
        left.activatedAtMs === right.activatedAtMs &&
        left.revokedAtMs === right.revokedAtMs
      );
  }
}

function walletAuthorityRecordsMatch(left: WalletAuthorityV1, right: WalletAuthorityV1): boolean {
  return (
    left.kind === right.kind &&
    left.authorityId === right.authorityId &&
    left.walletId === right.walletId &&
    left.principal.kind === right.principal.kind &&
    left.principal.deviceId === right.principal.deviceId &&
    walletAuthorityProvenancesMatch(left.provenance, right.provenance) &&
    walletAuthorityPermissionsMatch(left, right) &&
    walletAuthorityLifecycleFieldsMatch(left, right) &&
    left.revocationEpoch === right.revocationEpoch &&
    left.createdAtMs === right.createdAtMs &&
    left.updatedAtMs === right.updatedAtMs &&
    left.signerActivationSetDigestB64u === right.signerActivationSetDigestB64u &&
    left.authorityDigestB64u === right.authorityDigestB64u &&
    walletSignerActivationSetsMatch(left.signerActivations, right.signerActivations)
  );
}

function walletAuthorityPendingMatchesActive(
  pending: Extract<WalletAuthorityV1, { readonly state: 'pending_local_install' }>,
  active: Extract<WalletAuthorityV1, { readonly state: 'active' }>,
): boolean {
  return (
    pending.kind === active.kind &&
    pending.authorityId === active.authorityId &&
    pending.walletId === active.walletId &&
    pending.principal.kind === active.principal.kind &&
    pending.principal.deviceId === active.principal.deviceId &&
    walletAuthorityProvenancesMatch(pending.provenance, active.provenance) &&
    walletAuthorityPermissionsMatch(pending, active) &&
    walletSignerActivationSetsMatch(pending.signerActivations, active.signerActivations) &&
    pending.signerActivationSetDigestB64u === active.signerActivationSetDigestB64u &&
    pending.revocationEpoch === active.revocationEpoch &&
    pending.createdAtMs === active.createdAtMs
  );
}

function walletAuthMethodRecordsMatch(
  left: WalletAuthMethodRecordV2,
  right: WalletAuthMethodRecordV2,
): boolean {
  if (
    left.version !== right.version ||
    left.walletAuthMethodId !== right.walletAuthMethodId ||
    left.walletId !== right.walletId ||
    left.walletAuthorityId !== right.walletAuthorityId ||
    left.createdAtMs !== right.createdAtMs ||
    left.updatedAtMs !== right.updatedAtMs ||
    left.kind !== right.kind ||
    left.status !== right.status
  ) {
    return false;
  }
  switch (left.kind) {
    case 'passkey':
      return (
        right.kind === 'passkey' &&
        left.rpId === right.rpId &&
        left.credentialIdB64u === right.credentialIdB64u &&
        left.credentialPublicKeyB64u === right.credentialPublicKeyB64u &&
        left.counter === right.counter &&
        (left.status === 'pending_local_install' || left.activatedAtMs === right.activatedAtMs) &&
        (left.status !== 'revoked' || left.revokedAtMs === right.revokedAtMs)
      );
    case 'email_otp':
      return (
        right.kind === 'email_otp' &&
        left.emailHashHex === right.emailHashHex &&
        left.registrationAuthorityId === right.registrationAuthorityId &&
        (left.status === 'pending_local_install' || left.activatedAtMs === right.activatedAtMs) &&
        (left.status !== 'revoked' || left.revokedAtMs === right.revokedAtMs)
      );
  }
}

function walletAuthMethodPendingMatchesActive(
  pending: Extract<WalletAuthMethodRecordV2, { readonly status: 'pending_local_install' }>,
  active: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
): boolean {
  if (
    pending.version !== active.version ||
    pending.walletAuthMethodId !== active.walletAuthMethodId ||
    pending.walletId !== active.walletId ||
    pending.walletAuthorityId !== active.walletAuthorityId ||
    pending.kind !== active.kind ||
    pending.createdAtMs !== active.createdAtMs
  ) {
    return false;
  }
  switch (pending.kind) {
    case 'passkey':
      return (
        active.kind === 'passkey' &&
        pending.rpId === active.rpId &&
        pending.credentialIdB64u === active.credentialIdB64u &&
        pending.credentialPublicKeyB64u === active.credentialPublicKeyB64u &&
        pending.counter === active.counter
      );
    case 'email_otp':
      return (
        active.kind === 'email_otp' &&
        pending.emailHashHex === active.emailHashHex &&
        pending.registrationAuthorityId === active.registrationAuthorityId
      );
  }
}

function walletAuthoritySignerMaterialRecordsMatch(
  left: WalletAuthoritySignerMaterialRecordV1,
  right: WalletAuthoritySignerMaterialRecordV1,
): boolean {
  if (
    left.kind === 'wallet_authority_linked_signer_material_v1' ||
    right.kind === 'wallet_authority_linked_signer_material_v1'
  ) {
    return left.kind === right.kind && alphabetizeStringify(left) === alphabetizeStringify(right);
  }
  return (
    left.kind === right.kind &&
    left.authorityId === right.authorityId &&
    left.walletAuthMethodId === right.walletAuthMethodId &&
    left.activationId === right.activationId &&
    left.keyFamily === right.keyFamily &&
    (left.keyFamily === 'ed25519' || left.ecdsaThresholdKeyId === right.ecdsaThresholdKeyId) &&
    mpcMaterialActivationRefsEqual(left.materialActivation, right.materialActivation) &&
    left.sealedMaterialB64u === right.sealedMaterialB64u &&
    left.sealedMaterialDigestB64u === right.sealedMaterialDigestB64u
  );
}

function walletAuthorityExportRootsMatch(
  left: WalletAuthorityExportRootRecordV1,
  right: WalletAuthorityExportRootRecordV1,
): boolean {
  return (
    left.kind === right.kind &&
    left.authorityId === right.authorityId &&
    left.walletAuthMethodId === right.walletAuthMethodId &&
    left.walletKeyId === right.walletKeyId &&
    alphabetizeStringify(left.envelope) === alphabetizeStringify(right.envelope)
  );
}

function localAuthorityInstallationReceiptsMatch(
  left: LocalAuthorityInstallationReceiptV1,
  right: LocalAuthorityInstallationReceiptV1,
): boolean {
  return (
    left.kind === right.kind &&
    left.authorityId === right.authorityId &&
    left.walletId === right.walletId &&
    left.authMethodId === right.authMethodId &&
    left.deviceId === right.deviceId &&
    left.packageSetDigestB64u === right.packageSetDigestB64u &&
    walletSignerActivationSetsMatch(left.installedActivationRefs, right.installedActivationRefs) &&
    left.installedRecordSetDigestB64u === right.installedRecordSetDigestB64u &&
    left.targetFactorVerificationDigestB64u === right.targetFactorVerificationDigestB64u &&
    left.installedAtMs === right.installedAtMs
  );
}

function walletSessionRecordsMatch(
  left: ActiveWalletSessionV1,
  right: ActiveWalletSessionV1,
): boolean {
  if (
    left.kind !== right.kind ||
    left.walletId !== right.walletId ||
    left.authorityId !== right.authorityId ||
    left.authMethodId !== right.authMethodId ||
    left.authorizationId !== right.authorizationId ||
    left.authorityDigestB64u !== right.authorityDigestB64u ||
    left.authorityRevocationEpoch !== right.authorityRevocationEpoch ||
    left.issuedAtMs !== right.issuedAtMs ||
    left.expiresAtMs !== right.expiresAtMs ||
    left.capabilitySubjects.length !== right.capabilitySubjects.length
  ) {
    return false;
  }
  for (let index = 0; index < left.capabilitySubjects.length; index += 1) {
    const leftSubject = left.capabilitySubjects[index];
    const rightSubject = right.capabilitySubjects[index];
    if (leftSubject.kind !== rightSubject.kind) return false;
    if (leftSubject.kind === 'link_devices' || leftSubject.kind === 'revoke_devices') {
      if (rightSubject.kind !== leftSubject.kind) return false;
      continue;
    }
    if (
      rightSubject.kind !== leftSubject.kind ||
      leftSubject.keyFamily !== rightSubject.keyFamily ||
      !mpcMaterialActivationRefsEqual(
        leftSubject.materialActivation,
        rightSubject.materialActivation,
      )
    ) {
      return false;
    }
  }
  return true;
}

function localAuthorityInstallationError(error: unknown): string {
  return error instanceof Error ? error.message : 'local authority installation input is invalid';
}

function parseLocalEmailOtpAuthMethodForInstallation(input: {
  readonly localAuthMethod: Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }>;
  readonly authority: PendingWalletAuthorityV1;
  readonly authMethod: Extract<
    WalletAuthMethodRecordV2,
    { kind: 'email_otp'; status: 'pending_local_install' }
  >;
}): Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> {
  const row = emailOtpAuthMethodRow(input.localAuthMethod);
  if (row.status !== 'active' || row.record.localStatus !== 'synced') {
    throw new Error('local Email OTP auth method must be active and synced');
  }
  if (
    row.record.walletId !== input.authority.walletId ||
    row.record.emailHashHex !== input.authMethod.emailHashHex ||
    row.record.registrationAuthorityId !== input.authMethod.registrationAuthorityId ||
    row.record.authority.walletId !== input.authority.walletId ||
    row.record.authority.bindingId !== input.authMethod.walletAuthMethodId
  ) {
    throw new Error('local Email OTP auth method does not match authMethod');
  }
  return row.record;
}

function parseLocalAuthorityInstallationInput(
  input: LocalAuthorityInstallationInputV1,
): BoundaryParseResult<ValidatedLocalAuthorityInstallationInput> {
  try {
    const parsedAuthority = parseWalletAuthorityV1(input.authority);
    const authority = requireBoundaryParsed(parsedAuthority, 'authority');
    if (authority.state !== 'pending_local_install') {
      throw new Error('authority must be pending_local_install');
    }
    const authMethod = parseWalletAuthMethodRecordV2(input.authMethod);
    if (!authMethod || authMethod.status !== 'pending_local_install') {
      throw new Error('authMethod must be a pending_local_install V2 record');
    }
    if (!isRecord(input.profile)) {
      throw new Error('profile must be an object');
    }
    const profileId = toTrimmedString(input.profile.profileId || '');
    if (!profileId || profileId !== String(authority.walletId)) {
      throw new Error('profile identity does not match authority');
    }
    const defaultSignerSlot =
      input.profile.defaultSignerSlot === undefined
        ? 1
        : parseNonNegativeSafeInteger(input.profile.defaultSignerSlot, 'profile.defaultSignerSlot');
    if (defaultSignerSlot < 1) {
      throw new Error('profile.defaultSignerSlot must be a positive safe integer');
    }
    const profile: UpsertProfileInput = {
      profileId,
      defaultSignerSlot,
      ...(input.profile.passkeyCredential
        ? { passkeyCredential: input.profile.passkeyCredential }
        : {}),
      ...(input.profile.preferences ? { preferences: input.profile.preferences } : {}),
      ...(input.profile.nearProvisioning
        ? { nearProvisioning: input.profile.nearProvisioning }
        : {}),
    };
    const authenticator =
      input.authenticator === null ? null : normalizeAuthenticatorRecord(input.authenticator);
    let localAuthMethod: Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> | null = null;
    if (authMethod.kind === 'passkey') {
      if (input.localAuthMethod !== null) {
        throw new Error('Passkey installation cannot include a local Email OTP auth method');
      }
      const passkeyCredential = profile.passkeyCredential;
      if (
        !passkeyCredential ||
        passkeyCredential.id !== authMethod.credentialIdB64u ||
        passkeyCredential.rawId !== authMethod.credentialIdB64u
      ) {
        throw new Error('profile passkey credential does not match authMethod');
      }
      if (
        !authenticator ||
        authenticator.profileId !== profileId ||
        authenticator.signerSlot !== defaultSignerSlot ||
        authenticator.credentialId !== authMethod.credentialIdB64u ||
        base64UrlEncode(authenticator.credentialPublicKey) !== authMethod.credentialPublicKeyB64u
      ) {
        throw new Error('profile authenticator does not match authMethod');
      }
    } else {
      if (authenticator !== null || profile.passkeyCredential !== undefined) {
        throw new Error('Email OTP installation cannot include passkey profile records');
      }
      if (input.localAuthMethod === null) {
        throw new Error('Email OTP installation requires a local auth method');
      }
      localAuthMethod = parseLocalEmailOtpAuthMethodForInstallation({
        localAuthMethod: input.localAuthMethod,
        authority,
        authMethod,
      });
    }
    if (!Array.isArray(input.signerMaterials)) {
      throw new Error('signerMaterials must be an array');
    }
    const signerMaterials: WalletAuthoritySignerMaterialRecordV1[] = [];
    for (const rawMaterial of input.signerMaterials) {
      signerMaterials.push(parseWalletAuthoritySignerMaterialRecord(rawMaterial));
    }
    const exportRoot =
      input.exportRoot === null ? null : parseWalletAuthorityExportRootRecord(input.exportRoot);
    const receipt = parseLocalAuthorityInstallationReceiptV1(input.receipt);
    const expectedLockGeneration = parseNonNegativeSafeInteger(
      input.expectedLockGeneration,
      'expectedLockGeneration',
    );
    if (
      authMethod.walletId !== authority.walletId ||
      authMethod.walletAuthorityId !== authority.authorityId ||
      receipt.walletId !== authority.walletId ||
      receipt.authorityId !== authority.authorityId ||
      receipt.authMethodId !== authMethod.walletAuthMethodId ||
      receipt.deviceId !== authority.principal.deviceId ||
      receipt.packageSetDigestB64u !== authority.localInstallPackageSetDigestB64u
    ) {
      throw new Error('authority, authMethod, and receipt identities do not match');
    }
    if (
      !walletSignerActivationSetsMatch(receipt.installedActivationRefs, authority.signerActivations)
    ) {
      throw new Error('receipt signer activations do not match authority');
    }
    const expectations = signerMaterialExpectations(authority.signerActivations);
    if (signerMaterials.length !== expectations.length) {
      throw new Error('signer material records do not match authority signer families');
    }
    for (let index = 0; index < expectations.length; index += 1) {
      const material = signerMaterials[index];
      const expected = expectations[index];
      if (
        material.authorityId !== authority.authorityId ||
        material.walletAuthMethodId !== authMethod.walletAuthMethodId ||
        material.keyFamily !== expected.keyFamily ||
        !mpcMaterialActivationRefsEqual(material.materialActivation, expected.materialActivation)
      ) {
        throw new Error('signer material record does not match authority activation');
      }
    }
    const requiredExportRoot =
      hasEd25519SignerFamily(authority.signerActivations) &&
      authority.permissions.includes('export_keys');
    if (requiredExportRoot !== (exportRoot !== null)) {
      throw new Error('Ed25519 export root presence does not match authority permissions');
    }
    if (exportRoot) {
      const expectedWalletKeyId = ed25519WalletKeyId(authority.signerActivations);
      if (
        expectedWalletKeyId === null ||
        exportRoot.authorityId !== authority.authorityId ||
        exportRoot.walletAuthMethodId !== authMethod.walletAuthMethodId ||
        exportRoot.walletKeyId !== expectedWalletKeyId ||
        exportRoot.envelope.walletId !== authority.walletId ||
        exportRoot.envelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
        exportRoot.envelope.binding.walletKeyId !== expectedWalletKeyId ||
        exportRoot.envelope.binding.registeredPublicKeyB64u !==
          authority.signerActivations.ed25519?.signer.registeredPublicKeyB64u ||
        authority.principal.kind !== 'owner_device' ||
        String(exportRoot.envelope.binding.deviceId) !== String(authority.principal.deviceId) ||
        exportRoot.envelope.lifecycle.state !== 'active' ||
        !exportRootEnvelopeMatchesAuthMethod(authMethod, exportRoot.envelope)
      ) {
        throw new Error('export root does not match the Ed25519 authority activation');
      }
    }
    return {
      ok: true,
      value: {
        authority,
        authMethod,
        profile,
        authenticator,
        localAuthMethod,
        signerMaterials,
        exportRoot,
        receipt,
        expectedLockGeneration,
      },
    };
  } catch (error) {
    return { ok: false, error: localAuthorityInstallationError(error) };
  }
}

function passkeyCredentialIndexKey(row: WalletPasskeyAuthMethodRow): string {
  return ['passkey', row.rp_id, row.credential_id_b64u].join('\0');
}

function walletAuthMethodRowsForRegistrationFinalize(
  input: StoreWalletRegistrationFinalizeBatchInput,
): WalletAuthMethodRow[] {
  const authenticators = input.authenticators.map((authenticator) =>
    normalizeAuthenticatorRecord(authenticator),
  );
  const rows = new Map<string, WalletAuthMethodRow>();
  const credentialRows = new Map<string, WalletPasskeyAuthMethodRow>();

  if (input.initialAuthMethod.kind === 'passkey') {
    const matchingAuthenticator = authenticators.find(
      (authenticator) =>
        authenticator.profileId === input.initialAuthMethod.walletId &&
        authenticator.credentialId === input.initialAuthMethod.credentialIdB64u,
    );
    if (!matchingAuthenticator) {
      throw new Error(
        '[SeamsWalletDB] passkey registration finalize requires matching authenticator material',
      );
    }
    const row = passkeyAuthMethodRow({
      binding: input.initialAuthMethod,
      authenticator: matchingAuthenticator,
    });
    rows.set(row.wallet_auth_method_id, row);
    credentialRows.set(passkeyCredentialIndexKey(row), row);
  } else {
    const row = emailOtpAuthMethodRow(input.initialAuthMethod);
    rows.set(row.wallet_auth_method_id, row);
  }

  for (const authenticator of authenticators) {
    if (
      input.initialAuthMethod.kind === 'passkey' &&
      authenticator.profileId === input.initialAuthMethod.walletId &&
      authenticator.credentialId === input.initialAuthMethod.credentialIdB64u
    ) {
      const row = passkeyAuthMethodRow({
        binding: input.initialAuthMethod,
        authenticator,
      });
      rows.set(row.wallet_auth_method_id, row);
      credentialRows.set(passkeyCredentialIndexKey(row), row);
      continue;
    }
    const row = walletAuthMethodRowFromAuthenticator(authenticator);
    const credentialKey = passkeyCredentialIndexKey(row);
    const existingCredentialRow = credentialRows.get(credentialKey);
    if (existingCredentialRow) {
      if (existingCredentialRow.credential_public_key_b64u !== row.credential_public_key_b64u) {
        throw new Error('[SeamsWalletDB] duplicate passkey credential has conflicting public key');
      }
      if (existingCredentialRow.wallet_auth_method_id === row.wallet_auth_method_id) {
        rows.set(row.wallet_auth_method_id, row);
        credentialRows.set(credentialKey, row);
      }
      continue;
    }
    rows.set(row.wallet_auth_method_id, row);
    credentialRows.set(credentialKey, row);
  }

  return [...rows.values()];
}

function chainAccountProjectionRow(
  input: UpsertChainAccountInput,
  existing?: ChainAccountRecord,
): ChainAccountProjectionRow {
  const profileId = toTrimmedString(input.profileId || '');
  const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
  const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
  const accountModel = normalizeIndexedDbAccountModel(input.accountModel);
  if (!profileId || !chainIdKey || !accountAddress) {
    throw new Error('[SeamsWalletDB] profileId, chainIdKey, and accountAddress are required');
  }
  if (!accountModel) {
    throw new Error('[SeamsWalletDB] accountModel is required');
  }
  const now = Date.now();
  const record: ChainAccountRecord = {
    profileId,
    chainIdKey,
    accountAddress,
    accountModel,
    isPrimary: input.isPrimary ?? existing?.isPrimary ?? false,
    createdAt: existing?.createdAt ?? now,
    updatedAt: now,
  };
  return {
    wallet_id: profileId,
    near_account_id: chainAccountProjectionId({ chainIdKey, accountAddress }),
    signer_slot: CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
    profile_id: profileId,
    chain_id_key: chainIdKey,
    account_address: accountAddress,
    account_model: accountModel,
    is_primary: !!record.isPrimary,
    updated_at: record.updatedAt,
    record,
  };
}

function parseChainAccountProjectionRow(value: unknown): ChainAccountRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<ChainAccountProjectionRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.wallet_id !== record.profileId) return null;
  if (row.profile_id !== record.profileId) return null;
  if (row.chain_id_key !== record.chainIdKey) return null;
  if (row.account_address !== record.accountAddress) return null;
  if (row.account_model !== record.accountModel) return null;
  if (row.is_primary !== !!record.isPrimary) return null;
  if (row.updated_at !== record.updatedAt) return null;
  if (
    row.near_account_id !==
    chainAccountProjectionId({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
    })
  ) {
    return null;
  }
  return record;
}

function accountSignerRow(record: AccountSignerRecord): WalletSignerRow {
  const profileId = toTrimmedString(record.profileId || '');
  const chainIdKey = normalizeIndexedDbChainIdKey(record.chainIdKey);
  const accountAddress = normalizeIndexedDbAccountAddress(record.accountAddress);
  const signerId = toTrimmedString(record.signerId || '');
  const signerKind = toTrimmedString(record.signerKind || '');
  if (!profileId || !chainIdKey || !accountAddress || !signerId || !signerKind) {
    throw new Error(
      '[SeamsWalletDB] signer requires profileId, chainIdKey, accountAddress, signerId, and signerKind',
    );
  }
  const mirrors = walletSignerScalarMirrors({
    ...record,
    profileId,
    chainIdKey,
    accountAddress,
    signerId,
  });
  const isActive = record.status === 'active';
  return {
    wallet_signer_id: walletSignerId({ chainIdKey, accountAddress, signerId }),
    wallet_id: profileId,
    kind: signerKind,
    chain_target_key: mirrors.chainTargetKey,
    ...(isActive && mirrors.nearSignerSlot != null
      ? { near_signer_slot: mirrors.nearSignerSlot }
      : {}),
    ...(isActive && mirrors.nearEd25519SigningKeyId
      ? { near_ed25519_signing_key_id: mirrors.nearEd25519SigningKeyId }
      : {}),
    ...(isActive && mirrors.keyHandle ? { key_handle: mirrors.keyHandle } : {}),
    ...(isActive && mirrors.ecdsaThresholdKeyId
      ? { ecdsa_threshold_key_id: mirrors.ecdsaThresholdKeyId }
      : {}),
    ...(isActive && mirrors.thresholdOwnerAddress
      ? { threshold_owner_address: mirrors.thresholdOwnerAddress }
      : {}),
    status: record.status,
    updated_at: record.updatedAt,
    record: {
      ...record,
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
    },
  };
}

function parseAccountSignerRow(value: unknown): AccountSignerRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<WalletSignerRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (
    row.wallet_signer_id !==
    walletSignerId({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
      signerId: record.signerId,
    })
  ) {
    return null;
  }
  if (row.wallet_id !== record.profileId) return null;
  if (row.kind !== record.signerKind) return null;
  let mirrors: WalletSignerScalarMirrors;
  try {
    mirrors = walletSignerScalarMirrors(record);
  } catch {
    return null;
  }
  const requiresActiveMirrors = record.status === 'active';
  if (record.signerKind === SIGNER_KINDS.thresholdEd25519) {
    if (row.chain_target_key !== undefined && row.chain_target_key !== mirrors.chainTargetKey) {
      return null;
    }
    if (requiresActiveMirrors && row.near_signer_slot !== mirrors.nearSignerSlot) {
      return null;
    }
    if (
      !requiresActiveMirrors &&
      row.near_signer_slot !== undefined &&
      row.near_signer_slot !== mirrors.nearSignerSlot
    ) {
      return null;
    }
    if (
      requiresActiveMirrors &&
      row.near_ed25519_signing_key_id !== mirrors.nearEd25519SigningKeyId
    ) {
      return null;
    }
    if (
      !requiresActiveMirrors &&
      row.near_ed25519_signing_key_id !== undefined &&
      row.near_ed25519_signing_key_id !== mirrors.nearEd25519SigningKeyId
    ) {
      return null;
    }
  } else if (requiresActiveMirrors && row.chain_target_key !== mirrors.chainTargetKey) {
    return null;
  } else if (
    !requiresActiveMirrors &&
    row.chain_target_key !== undefined &&
    row.chain_target_key !== mirrors.chainTargetKey
  ) {
    return null;
  }
  if (requiresActiveMirrors && row.key_handle !== mirrors.keyHandle) return null;
  if (
    !requiresActiveMirrors &&
    row.key_handle !== undefined &&
    row.key_handle !== mirrors.keyHandle
  ) {
    return null;
  }
  if (requiresActiveMirrors && row.ecdsa_threshold_key_id !== mirrors.ecdsaThresholdKeyId) {
    return null;
  }
  if (
    !requiresActiveMirrors &&
    row.ecdsa_threshold_key_id !== undefined &&
    row.ecdsa_threshold_key_id !== mirrors.ecdsaThresholdKeyId
  ) {
    return null;
  }
  if (requiresActiveMirrors && row.threshold_owner_address !== mirrors.thresholdOwnerAddress) {
    return null;
  }
  if (
    !requiresActiveMirrors &&
    row.threshold_owner_address !== undefined &&
    row.threshold_owner_address !== mirrors.thresholdOwnerAddress
  ) {
    return null;
  }
  if (row.status !== record.status) return null;
  if (row.updated_at !== record.updatedAt) return null;
  return record;
}

async function deleteConflictingThresholdEcdsaSignerRows(args: {
  store: any;
  nextRow: WalletSignerRow;
}): Promise<void> {
  const row = args.nextRow;
  if (row.kind !== SIGNER_KINDS.thresholdEcdsa || row.status === 'revoked') return;
  if (!row.key_handle || !row.ecdsa_threshold_key_id) return;

  const walletRows = (await args.store
    .index(SEAMS_WALLET_INDEXES.walletId)
    .getAll(row.wallet_id)) as Partial<WalletSignerRow>[] | undefined;
  const conflictingRowIds = new Set<string>();
  for (const existing of walletRows || []) {
    const existingRowId = toTrimmedString(existing?.wallet_signer_id || '');
    if (!existingRowId || existingRowId === row.wallet_signer_id) continue;
    if (existing?.kind !== row.kind || existing?.chain_target_key !== row.chain_target_key) {
      continue;
    }
    if (
      existing?.key_handle === row.key_handle ||
      existing?.ecdsa_threshold_key_id === row.ecdsa_threshold_key_id
    ) {
      conflictingRowIds.add(existingRowId);
    }
  }
  for (const rowId of conflictingRowIds) {
    await args.store.delete(rowId);
  }
}

function signerOutboxRow(record: SignerOpOutboxRecord): SignerOpsOutboxRow {
  const opId = toTrimmedString(record.opId || '');
  const idempotencyKey = toTrimmedString(record.idempotencyKey || '');
  const chainIdKey = normalizeIndexedDbChainIdKey(record.chainIdKey);
  const accountAddress = normalizeIndexedDbAccountAddress(record.accountAddress);
  const signerId = toTrimmedString(record.signerId || '');
  if (!opId || !idempotencyKey || !chainIdKey || !accountAddress || !signerId) {
    throw new Error(
      '[SeamsWalletDB] signer op requires opId, idempotencyKey, chainIdKey, accountAddress, and signerId',
    );
  }
  return {
    op_id: opId,
    idempotency_key: idempotencyKey,
    status: record.status,
    next_attempt_at: record.nextAttemptAt,
    wallet_id: toTrimmedString(String(record.payload?.profileId || '')),
    chain_target_key: signerChainTargetKey({ chainIdKey, accountAddress }),
    updated_at: record.updatedAt,
    record: {
      ...record,
      opId,
      idempotencyKey,
      chainIdKey,
      accountAddress,
      signerId,
    },
  };
}

function parseSignerOutboxRow(value: unknown): SignerOpOutboxRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<SignerOpsOutboxRow>;
  const record = row.record;
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  if (row.op_id !== record.opId) return null;
  if (row.idempotency_key !== record.idempotencyKey) return null;
  if (row.status !== record.status) return null;
  if (row.next_attempt_at !== record.nextAttemptAt) return null;
  if (
    row.chain_target_key !==
    signerChainTargetKey({ chainIdKey: record.chainIdKey, accountAddress: record.accountAddress })
  ) {
    return null;
  }
  return record;
}

function keyMaterialId(args: { walletSignerId: string; keyKind: string }): string {
  return [args.walletSignerId, args.keyKind].join('\0');
}

function walletSignerIdForKeyMaterial(record: KeyMaterialRecord): string {
  return walletSignerId({
    chainIdKey: record.chainIdKey,
    accountAddress: record.accountAddress,
    signerId: record.signerId,
  });
}

function keyMaterialRow(data: KeyMaterialRecord): KeyMaterialRow {
  const profileId = toTrimmedString(data.profileId || '');
  const signerId = toTrimmedString(data.signerId || '');
  const wrapKeySalt = toTrimmedString(data.wrapKeySalt || '');
  const chainIdKey = toTrimmedString(data.chainIdKey || '').toLowerCase();
  const accountAddress = normalizeIndexedDbAccountAddress(data.accountAddress);
  const keyKind = toTrimmedString(data.keyKind || '');
  const algorithm = toTrimmedString(data.algorithm || '');
  const publicKey = toTrimmedString(data.publicKey || '');
  if (!profileId) {
    throw new Error('[SeamsWalletDB] Missing profileId for key material record');
  }
  if (!Number.isSafeInteger(data.signerSlot) || data.signerSlot < 1) {
    throw new Error('[SeamsWalletDB] Invalid signerSlot for key material record');
  }
  if (!chainIdKey) {
    throw new Error('[SeamsWalletDB] Missing chainIdKey for key material record');
  }
  if (!accountAddress) {
    throw new Error('[SeamsWalletDB] Missing accountAddress for key material record');
  }
  if (!signerId) {
    throw new Error('[SeamsWalletDB] Missing signerId for key material record');
  }
  if (!keyKind) {
    throw new Error('[SeamsWalletDB] Missing keyKind for key material record');
  }
  if (!algorithm) {
    throw new Error('[SeamsWalletDB] Missing algorithm for key material record');
  }
  if (!publicKey) {
    throw new Error('[SeamsWalletDB] Missing publicKey for key material record');
  }
  if (typeof data.timestamp !== 'number') {
    throw new Error('[SeamsWalletDB] Missing timestamp for key material record');
  }
  if (!Number.isSafeInteger(data.schemaVersion) || data.schemaVersion < 1) {
    throw new Error('[SeamsWalletDB] Invalid schemaVersion for key material record');
  }

  const expectedAAD = buildEnvelopeAAD({
    profileId,
    signerSlot: data.signerSlot,
    chainIdKey,
    accountAddress,
    keyKind,
    schemaVersion: data.schemaVersion,
    signerId,
  });
  const payloadEnvelope = normalizePayloadEnvelope(
    data.payloadEnvelope,
    expectedAAD,
    `${profileId}/${data.signerSlot}/${chainIdKey}/${keyKind}`,
  );
  const payload = sanitizePayload(data.payload);
  const record: KeyMaterialRecord = {
    profileId,
    signerSlot: data.signerSlot,
    chainIdKey,
    accountAddress,
    keyKind,
    algorithm,
    publicKey,
    signerId,
    ...(wrapKeySalt ? { wrapKeySalt } : {}),
    ...(payload ? { payload } : {}),
    ...(payloadEnvelope ? { payloadEnvelope } : {}),
    timestamp: data.timestamp,
    schemaVersion: data.schemaVersion,
  };
  const walletSignerId = walletSignerIdForKeyMaterial(record);
  const chainTargetKey = signerChainTargetKey({ chainIdKey, accountAddress });
  return {
    key_material_id: keyMaterialId({ walletSignerId, keyKind }),
    wallet_id: profileId,
    wallet_signer_id: walletSignerId,
    chain_target_key: chainTargetKey,
    key_handle: signerId,
    public_key: publicKey,
    updated_at: data.timestamp,
    record,
  };
}

function signerKeyMaterialPairKey(args: {
  profileId: string;
  chainIdKey: string;
  accountAddress: string;
  signerId: string;
  signerSlot: number;
}): string {
  return [
    toTrimmedString(args.profileId || ''),
    normalizeIndexedDbChainIdKey(args.chainIdKey),
    normalizeIndexedDbAccountAddress(args.accountAddress),
    toTrimmedString(args.signerId || ''),
    String(Number(args.signerSlot)),
  ].join('\0');
}

function assertSignerKeyMaterialPairs(args: {
  signers: readonly AccountSignerRecord[];
  keyMaterials: readonly KeyMaterialRecord[];
}): void {
  const signerKeys = new Set(
    args.signers.map((signer) =>
      signerKeyMaterialPairKey({
        profileId: signer.profileId,
        chainIdKey: signer.chainIdKey,
        accountAddress: signer.accountAddress,
        signerId: signer.signerId,
        signerSlot: signer.signerSlot,
      }),
    ),
  );
  const keyMaterialKeys = new Set(
    args.keyMaterials
      .filter((keyMaterial) => keyMaterial.keyKind === 'threshold_share_v1')
      .map((keyMaterial) =>
        signerKeyMaterialPairKey({
          profileId: keyMaterial.profileId,
          chainIdKey: keyMaterial.chainIdKey,
          accountAddress: keyMaterial.accountAddress,
          signerId: keyMaterial.signerId,
          signerSlot: keyMaterial.signerSlot,
        }),
      ),
  );
  const missingSigner = args.signers.find(
    (signer) =>
      signer.status === 'active' &&
      !keyMaterialKeys.has(
        signerKeyMaterialPairKey({
          profileId: signer.profileId,
          chainIdKey: signer.chainIdKey,
          accountAddress: signer.accountAddress,
          signerId: signer.signerId,
          signerSlot: signer.signerSlot,
        }),
      ),
  );
  if (missingSigner) {
    throw new Error(
      `[SeamsWalletDB] active signer ${missingSigner.signerId} requires matching threshold key material`,
    );
  }
  const orphanedKeyMaterial = args.keyMaterials.find(
    (keyMaterial) =>
      keyMaterial.keyKind === 'threshold_share_v1' &&
      !signerKeys.has(
        signerKeyMaterialPairKey({
          profileId: keyMaterial.profileId,
          chainIdKey: keyMaterial.chainIdKey,
          accountAddress: keyMaterial.accountAddress,
          signerId: keyMaterial.signerId,
          signerSlot: keyMaterial.signerSlot,
        }),
      ),
  );
  if (orphanedKeyMaterial) {
    throw new Error(
      `[SeamsWalletDB] threshold key material for signer ${orphanedKeyMaterial.signerId} has no matching signer activation`,
    );
  }
}

function parseKeyMaterialRow(value: unknown): KeyMaterialRecord | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Partial<KeyMaterialRow>;
  const record = normalizeStoredPayloadRecord(row.record as KeyMaterialRecord);
  if (!record) return null;
  if (
    row.key_material_id !==
    keyMaterialId({
      walletSignerId: walletSignerIdForKeyMaterial(record),
      keyKind: record.keyKind,
    })
  ) {
    return null;
  }
  if (row.wallet_id !== record.profileId) return null;
  if (row.wallet_signer_id !== walletSignerIdForKeyMaterial(record)) return null;
  if (
    row.chain_target_key !==
    signerChainTargetKey({
      chainIdKey: record.chainIdKey,
      accountAddress: record.accountAddress,
    })
  ) {
    return null;
  }
  if (row.key_handle !== toTrimmedString(record.signerId || '')) return null;
  if (row.public_key !== record.publicKey) return null;
  return record;
}

function signerKeyMaterialPairKeyForSigner(signer: AccountSignerRecord): string {
  return signerKeyMaterialPairKey({
    profileId: signer.profileId,
    chainIdKey: signer.chainIdKey,
    accountAddress: signer.accountAddress,
    signerId: signer.signerId,
    signerSlot: signer.signerSlot,
  });
}

function signerKeyMaterialPairKeyForMaterial(keyMaterial: KeyMaterialRecord): string {
  return signerKeyMaterialPairKey({
    profileId: keyMaterial.profileId,
    chainIdKey: keyMaterial.chainIdKey,
    accountAddress: keyMaterial.accountAddress,
    signerId: keyMaterial.signerId,
    signerSlot: keyMaterial.signerSlot,
  });
}

function collectSignerKeyMaterialProfileIds(args: {
  signers: readonly AccountSignerRecord[];
  keyMaterials: readonly KeyMaterialRecord[];
}): string[] {
  const profileIds = new Set<string>();
  for (const signer of args.signers) {
    const profileId = toTrimmedString(signer.profileId || '');
    if (profileId) profileIds.add(profileId);
  }
  for (const keyMaterial of args.keyMaterials) {
    const profileId = toTrimmedString(keyMaterial.profileId || '');
    if (profileId) profileIds.add(profileId);
  }
  return [...profileIds];
}

async function readActiveSignersForProfilesInTransaction(
  ctx: SeamsWalletTransactionContext,
  profileIds: readonly string[],
): Promise<AccountSignerRecord[]> {
  const store = ctx.store(SEAMS_WALLET_STORES.walletSigners);
  const signers: AccountSignerRecord[] = [];
  for (const profileId of profileIds) {
    const rows = (await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(profileId)) as unknown[];
    for (const row of rows) {
      const parsed = parseAccountSignerRow(row);
      if (parsed?.status === 'active') signers.push(parsed);
    }
  }
  return signers;
}

async function readThresholdKeyMaterialsForProfilesInTransaction(
  ctx: SeamsWalletTransactionContext,
  profileIds: readonly string[],
): Promise<KeyMaterialRecord[]> {
  const store = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
  const keyMaterials: KeyMaterialRecord[] = [];
  for (const profileId of profileIds) {
    const rows = (await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(profileId)) as unknown[];
    for (const row of rows) {
      const parsed = parseKeyMaterialRow(row);
      if (parsed?.keyKind === 'threshold_share_v1') keyMaterials.push(parsed);
    }
  }
  return keyMaterials;
}

function mergeKeyMaterialsById(args: {
  existing: readonly KeyMaterialRecord[];
  incoming: readonly KeyMaterialRecord[];
}): KeyMaterialRecord[] {
  const merged = new Map<string, KeyMaterialRecord>();
  for (const keyMaterial of args.existing) {
    merged.set(
      keyMaterialId({
        walletSignerId: walletSignerIdForKeyMaterial(keyMaterial),
        keyKind: keyMaterial.keyKind,
      }),
      keyMaterial,
    );
  }
  for (const keyMaterial of args.incoming) {
    merged.set(
      keyMaterialId({
        walletSignerId: walletSignerIdForKeyMaterial(keyMaterial),
        keyKind: keyMaterial.keyKind,
      }),
      keyMaterial,
    );
  }
  return [...merged.values()];
}

async function assertSignerKeyMaterialPairsInTransaction(args: {
  ctx: SeamsWalletTransactionContext;
  signers: readonly AccountSignerRecord[];
  keyMaterials: readonly KeyMaterialRecord[];
}): Promise<void> {
  const profileIds = collectSignerKeyMaterialProfileIds({
    signers: args.signers,
    keyMaterials: args.keyMaterials,
  });
  if (profileIds.length === 0) return;
  const activeSigners = await readActiveSignersForProfilesInTransaction(args.ctx, profileIds);
  const activeSignerKeys = new Set(activeSigners.map(signerKeyMaterialPairKeyForSigner));
  const existingKeyMaterials = (
    await readThresholdKeyMaterialsForProfilesInTransaction(args.ctx, profileIds)
  ).filter((keyMaterial) => activeSignerKeys.has(signerKeyMaterialPairKeyForMaterial(keyMaterial)));
  assertSignerKeyMaterialPairs({
    signers: activeSigners,
    keyMaterials: mergeKeyMaterialsById({
      existing: existingKeyMaterials,
      incoming: args.keyMaterials,
    }),
  });
}

function isUsableKeyMaterialForRead(record: KeyMaterialRecord): boolean {
  if (record.keyKind !== 'threshold_share_v1' || record.algorithm !== 'ed25519') return true;
  const payload = record.payload || {};
  return (
    !!toTrimmedString(payload.relayerKeyId || '') && !!toTrimmedString(payload.keyVersion || '')
  );
}

function selectKeyMaterialForRead(args: {
  matches: readonly KeyMaterialRecord[];
  activeSigners: readonly AccountSignerRecord[];
}): KeyMaterialRecord | null {
  const activeSignerKeys = new Set(args.activeSigners.map(signerKeyMaterialPairKeyForSigner));
  const activeMatches = args.matches.filter((record) =>
    activeSignerKeys.has(signerKeyMaterialPairKeyForMaterial(record)),
  );
  const usableActive = activeMatches.find(isUsableKeyMaterialForRead);
  if (usableActive) return usableActive;
  const usable = args.matches.find(isUsableKeyMaterialForRead);
  if (usable) return usable;
  return [...args.matches].sort((a, b) => b.timestamp - a.timestamp)[0] || null;
}

export class SeamsWalletRepositories {
  constructor(private readonly manager: SeamsWalletDBManager) {}

  async installLocalAuthority(
    input: LocalAuthorityInstallationInputV1,
  ): Promise<LocalAuthorityInstallationResultV1> {
    const parsed = parseLocalAuthorityInstallationInput(input);
    if (!parsed.ok) return { kind: 'integrity_error', reason: parsed.error };
    if (!(await walletAuthorityDigestsMatchV1(parsed.value.authority))) {
      return {
        kind: 'integrity_error',
        reason: 'authority digest does not match canonical encoding',
      };
    }
    return this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.walletAuthorities,
        SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
        SEAMS_WALLET_STORES.walletAuthorityExportRoots,
        SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts,
        SEAMS_WALLET_STORES.walletSelections,
      ],
      'readwrite',
      this.installLocalAuthorityInTransaction.bind(this, parsed.value),
    );
  }

  async finalizeLocalAuthorityActivation(
    input: LocalAuthorityActivationFinalizationInputV1,
  ): Promise<LocalAuthorityActivationFinalizationResultV1> {
    const authorityResult = parseWalletAuthorityV1(input.authority);
    if (!authorityResult.ok || authorityResult.value.state !== 'active') {
      throw new Error('active WalletAuthorityV1 is invalid');
    }
    const authMethod = parseWalletAuthMethodRecordV2(input.authMethod);
    if (!authMethod || authMethod.status !== 'active') {
      throw new Error('active WalletAuthMethodRecordV2 is invalid');
    }
    const walletSessionWithCredential = parseStoredExactWalletSessionAuthorizationRowV6(
      toStoredExactWalletSessionAuthorizationRowV6(input.walletSession, input.operationCredential),
    );
    const walletSession = walletSessionWithCredential?.record ?? null;
    if (!walletSession) {
      throw new Error('active Wallet Session is invalid');
    }
    const expectedLockGeneration = parseNonNegativeSafeInteger(
      input.expectedLockGeneration,
      'expectedLockGeneration',
    );
    if (
      authMethod.walletId !== authorityResult.value.walletId ||
      authMethod.walletAuthorityId !== authorityResult.value.authorityId ||
      walletSession.walletId !== authorityResult.value.walletId ||
      walletSession.authorityId !== authorityResult.value.authorityId ||
      walletSession.authMethodId !== authMethod.walletAuthMethodId ||
      walletSession.authorityDigestB64u !== authorityResult.value.authorityDigestB64u ||
      walletSession.authorityRevocationEpoch !== authorityResult.value.revocationEpoch
    ) {
      throw new Error('active authority, auth method, and Wallet Session identities differ');
    }
    return await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletAuthorities,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts,
        SEAMS_WALLET_STORES.walletSelections,
        SEAMS_WALLET_STORES.walletSessionAuthorizations,
      ],
      'readwrite',
      this.finalizeLocalAuthorityActivationInTransaction.bind(this, {
        authority: authorityResult.value,
        authMethod,
        walletSession,
        operationCredential: input.operationCredential,
        expectedLockGeneration,
      }),
    );
  }

  async publishLocalAuthorityActivation(
    input: LocalAuthorityActivationPublicationInputV1,
  ): Promise<LocalAuthorityActivationPublicationResultV1> {
    const authorityResult = parseWalletAuthorityV1(input.authority);
    if (!authorityResult.ok || authorityResult.value.state !== 'active') {
      throw new Error('active WalletAuthorityV1 is invalid');
    }
    const authMethod = parseWalletAuthMethodRecordV2(input.authMethod);
    if (!authMethod || authMethod.status !== 'active') {
      throw new Error('active WalletAuthMethodRecordV2 is invalid');
    }
    const expectedLockGeneration = parseNonNegativeSafeInteger(
      input.expectedLockGeneration,
      'expectedLockGeneration',
    );
    if (
      authMethod.walletId !== authorityResult.value.walletId ||
      authMethod.walletAuthorityId !== authorityResult.value.authorityId
    ) {
      throw new Error('active authority and auth method identities differ');
    }
    if (!(await walletAuthorityDigestsMatchV1(authorityResult.value))) {
      throw new Error('active WalletAuthorityV1 digest is invalid');
    }
    return await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletAuthorities,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts,
        SEAMS_WALLET_STORES.walletSelections,
      ],
      'readwrite',
      this.publishLocalAuthorityActivationInTransaction.bind(this, {
        authority: authorityResult.value,
        authMethod,
        expectedLockGeneration,
      }),
    );
  }

  async advanceWalletLockGeneration(input: WalletLockGenerationAdvanceInputV1): Promise<number> {
    const walletId = requireBoundaryParsed(parseWalletId(input.walletId), 'walletId');
    const lockedAtMs = parseNonNegativeSafeInteger(input.lockedAtMs, 'lockedAtMs');
    return this.manager.runTransaction(
      [SEAMS_WALLET_STORES.walletSelections],
      'readwrite',
      this.advanceWalletLockGenerationInTransaction.bind(this, { walletId, lockedAtMs }),
    );
  }

  async markWalletSelectionUnlocked(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly unlockedAtMs: number;
  }): Promise<void> {
    const walletId = requireBoundaryParsed(parseWalletId(input.walletId), 'walletId');
    const walletAuthMethodId = requireBoundaryParsed(
      parseWalletAuthMethodId(input.walletAuthMethodId),
      'walletAuthMethodId',
    );
    const unlockedAtMs = parseNonNegativeSafeInteger(input.unlockedAtMs, 'unlockedAtMs');
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.walletSelections, SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      this.markWalletSelectionUnlockedInTransaction.bind(this, {
        walletId,
        walletAuthMethodId,
        unlockedAtMs,
      }),
    );
  }

  async persistRecoveredWalletAuthority(
    input: RecoveredWalletAuthorityProjectionInputV1,
  ): Promise<void> {
    const authority = requireBoundaryParsed(parseWalletAuthorityV1(input.authority), 'authority');
    const authMethod = parseWalletAuthMethodRecordV2(input.authMethod);
    const recoveredAtMs = parseNonNegativeSafeInteger(input.recoveredAtMs, 'recoveredAtMs');
    if (
      authority.state !== 'active' ||
      !isActiveRecoveredWalletAuthorityV1(authority) ||
      !authMethod ||
      authMethod.status !== 'active' ||
      authMethod.walletId !== authority.walletId ||
      authMethod.walletAuthorityId !== authority.authorityId
    ) {
      throw new Error('recovered Wallet Authority projection is invalid');
    }
    if (!(await walletAuthorityDigestsMatchV1(authority))) {
      throw new Error('recovered Wallet Authority digest is invalid');
    }
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.walletAuthorities,
        SEAMS_WALLET_STORES.walletSelections,
        SEAMS_WALLET_STORES.walletAuthMethods,
      ],
      'readwrite',
      this.persistRecoveredWalletAuthorityInTransaction.bind(this, {
        authority,
        authMethod,
        recoveredAtMs,
      }),
    );
  }

  async getLocalAuthorityInstallationReceipt(
    authorityId: string,
  ): Promise<LocalAuthorityInstallationReceiptV1 | null> {
    const parsedAuthorityId = parseWalletAuthorityId(authorityId);
    if (!parsedAuthorityId.ok) return null;
    const db = await this.manager.getDB();
    return (
      parseLocalAuthorityInstallationReceiptStorageRow(
        await db.get(
          SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts,
          parsedAuthorityId.value,
        ),
      )?.record || null
    );
  }

  private async finalizeLocalAuthorityActivationInTransaction(
    input: LocalAuthorityActivationFinalizationInputV1,
    ctx: SeamsWalletTransactionContext,
  ): Promise<LocalAuthorityActivationFinalizationResultV1> {
    const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);
    const authorityStore = ctx.store(SEAMS_WALLET_STORES.walletAuthorities);
    const authMethodStore = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
    const receiptStore = ctx.store(SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts);
    const selectionStore = ctx.store(SEAMS_WALLET_STORES.walletSelections);
    const sessionStore = ctx.store(SEAMS_WALLET_STORES.walletSessionAuthorizations);
    const authorityRaw = await authorityStore.get(input.authority.authorityId);
    const authMethodRaw = await authMethodStore.get(input.authMethod.walletAuthMethodId);
    const receiptRaw = await receiptStore.get(input.authority.authorityId);
    const sessionRaw = await sessionStore.get(input.operationCredential.walletSessionId);
    const profileProjectionRaw = await appStateStore.get(
      localAuthorityPendingProfileProjectionAppStateKeyV1(input.authority.authorityId),
    );
    const profileProjection =
      profileProjectionRaw === undefined
        ? null
        : parseLocalAuthorityPendingProfileProjectionV1(profileProjectionRaw.value);
    if (profileProjectionRaw !== undefined && !profileProjection) {
      throw new Error('local authority profile projection is missing or corrupt');
    }
    const existingAuthority =
      authorityRaw === undefined ? null : parseWalletAuthorityStorageRow(authorityRaw);
    const existingAuthMethod =
      authMethodRaw === undefined ? null : parseWalletAuthMethodV2StorageRow(authMethodRaw);
    const receipt =
      receiptRaw === undefined
        ? null
        : parseLocalAuthorityInstallationReceiptStorageRow(receiptRaw);
    const existingSessionWithCredential =
      sessionRaw === undefined ? null : parseStoredExactWalletSessionAuthorizationRowV6(sessionRaw);
    const existingSession = existingSessionWithCredential?.record ?? null;
    if (!receipt) throw new Error('local authority installation receipt is missing or corrupt');
    if (
      receipt.record.authorityId !== input.authority.authorityId ||
      receipt.record.walletId !== input.authority.walletId ||
      receipt.record.authMethodId !== input.authMethod.walletAuthMethodId ||
      !walletSignerActivationSetsMatch(
        receipt.record.installedActivationRefs,
        input.authority.signerActivations,
      )
    ) {
      throw new Error('local authority installation receipt does not match active authority');
    }
    if (!existingAuthority || !existingAuthMethod) {
      throw new Error('pending local authority records are missing');
    }
    if (existingAuthority.record.state === 'active') {
      if (
        !walletAuthorityRecordsMatch(existingAuthority.record, input.authority) ||
        existingAuthMethod.record.status !== 'active' ||
        !walletAuthMethodRecordsMatch(existingAuthMethod.record, input.authMethod)
      ) {
        throw new Error('active local authority replay conflicts with supplied records');
      }
      if (profileProjection) {
        await this.publishPendingLocalAuthorityProfileProjectionInTransaction(
          input.authority,
          input.authMethod,
          profileProjection,
          ctx,
        );
      }
      if (!existingSession) {
        const selectionRaw = await selectionStore.get(input.authority.walletId);
        if (selectionRaw === undefined) throw new Error('wallet selection is missing');
        const selection = parseWalletSelectionStorageRow(selectionRaw);
        if (!selection || selection.wallet_id !== input.authority.walletId) {
          throw new Error('wallet selection is corrupt');
        }
        if (selection.lock_generation !== input.expectedLockGeneration) {
          return {
            kind: 'stale_lock_generation',
            expectedLockGeneration: input.expectedLockGeneration,
            actualLockGeneration: selection.lock_generation,
          };
        }
        if (selection.record.lockState === 'locked') {
          return { kind: 'wallet_locked', lockGeneration: selection.lock_generation };
        }
        await sessionStore.put(
          toStoredExactWalletSessionAuthorizationRowV6(
            input.walletSession,
            input.operationCredential,
          ),
        );
        await selectionStore.put(
          walletSelectionStorageRow({
            kind: 'wallet_selection_v1',
            walletId: selection.record.walletId,
            walletAuthMethodId: input.authMethod.walletAuthMethodId,
            lockGeneration: selection.record.lockGeneration,
            lockState: 'unlocked',
            updatedAtMs: input.walletSession.issuedAtMs,
          }),
        );
        return { kind: 'finalized' };
      }
      if (
        existingSession.kind !== 'active_wallet_session_v1' ||
        !walletSessionRecordsMatch(existingSession, input.walletSession) ||
        existingSessionWithCredential?.operationCredential.token !== input.operationCredential.token
      ) {
        throw new Error('active local authority replay conflicts with supplied Wallet Session');
      }
      await sessionStore.put(
        toStoredExactWalletSessionAuthorizationRowV6(
          input.walletSession,
          input.operationCredential,
        ),
      );
      return { kind: 'finalized' };
    }
    if (
      existingAuthority.record.state !== 'pending_local_install' ||
      existingAuthMethod.record.status !== 'pending_local_install' ||
      !walletAuthorityPendingMatchesActive(existingAuthority.record, input.authority) ||
      !walletAuthMethodPendingMatchesActive(existingAuthMethod.record, input.authMethod)
    ) {
      throw new Error('local authority records are not the expected pending installation');
    }
    if (existingSession && existingSession.kind !== 'active_wallet_session_v1') {
      throw new Error('Wallet Session authorization is not active');
    }
    if (
      existingSession?.kind === 'active_wallet_session_v1' &&
      (!walletSessionRecordsMatch(existingSession, input.walletSession) ||
        existingSessionWithCredential?.operationCredential.token !==
          input.operationCredential.token)
    ) {
      throw new Error('Wallet Session authorization conflicts with finalization');
    }
    const selectionRaw = await selectionStore.get(input.authority.walletId);
    if (selectionRaw === undefined) throw new Error('wallet selection is missing');
    const selection = parseWalletSelectionStorageRow(selectionRaw);
    if (!selection || selection.wallet_id !== input.authority.walletId) {
      throw new Error('wallet selection is corrupt');
    }
    if (selection.lock_generation !== input.expectedLockGeneration) {
      return {
        kind: 'stale_lock_generation',
        expectedLockGeneration: input.expectedLockGeneration,
        actualLockGeneration: selection.lock_generation,
      };
    }
    if (selection.record.lockState === 'locked') {
      return { kind: 'wallet_locked', lockGeneration: selection.lock_generation };
    }
    if (!profileProjection) {
      throw new Error('local authority profile projection is missing or corrupt');
    }
    await this.publishPendingLocalAuthorityProfileProjectionInTransaction(
      input.authority,
      input.authMethod,
      profileProjection,
      ctx,
    );
    await authorityStore.put(walletAuthorityStorageRow(input.authority));
    await authMethodStore.put(walletAuthMethodV2StorageRow(input.authMethod));
    await sessionStore.put(
      toStoredExactWalletSessionAuthorizationRowV6(input.walletSession, input.operationCredential),
    );
    await selectionStore.put(
      walletSelectionStorageRow({
        kind: 'wallet_selection_v1',
        walletId: selection.record.walletId,
        walletAuthMethodId: input.authMethod.walletAuthMethodId,
        lockGeneration: selection.record.lockGeneration,
        lockState: 'unlocked',
        updatedAtMs: input.walletSession.issuedAtMs,
      }),
    );
    return { kind: 'finalized' };
  }

  private async publishPendingLocalAuthorityProfileProjectionInTransaction(
    authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>,
    authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
    projection: LocalAuthorityPendingProfileProjectionV1,
    ctx: SeamsWalletTransactionContext,
  ): Promise<void> {
    if (
      projection.authorityId !== authority.authorityId ||
      projection.walletId !== authority.walletId ||
      projection.authMethodId !== authMethod.walletAuthMethodId
    ) {
      throw new Error('local authority profile projection identity does not match activation');
    }
    const expectedV2Row = walletAuthMethodV2StorageRow(authMethod);
    if (
      projection.authenticator?.wallet_auth_method_id === expectedV2Row.wallet_auth_method_id ||
      projection.localAuthMethod?.wallet_auth_method_id === expectedV2Row.wallet_auth_method_id
    ) {
      throw new Error('local authority profile projection collides with the V2 auth-method key');
    }
    const profileStore = ctx.store(SEAMS_WALLET_STORES.wallets);
    const authMethodStore = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
    const existingProfileRaw = await profileStore.get(projection.profile.wallet_id);
    const existingProfile =
      existingProfileRaw === undefined ? null : parseProfileStorageRowV1(existingProfileRaw);
    if (existingProfileRaw !== undefined && !existingProfile) {
      throw new Error('stored wallet profile is corrupt during authority publication');
    }
    if (existingProfile && !rollbackRecordsEqual(existingProfile, projection.profile.record)) {
      throw new Error('stored wallet profile changed during authority publication');
    }
    await profileStore.put(projection.profile);
    for (const row of [projection.authenticator, projection.localAuthMethod]) {
      if (!row) continue;
      const existingRaw = await authMethodStore.get(row.wallet_auth_method_id);
      if (existingRaw !== undefined) {
        const existing = parseWalletAuthMethodStorageRow(existingRaw);
        if (!existing || !rollbackRecordsEqual(existing, row)) {
          throw new Error('stored local auth method changed during authority publication');
        }
      }
      await authMethodStore.put(row);
    }
    await authMethodStore.put(expectedV2Row);
    await ctx
      .store(SEAMS_WALLET_STORES.appState)
      .delete(localAuthorityPendingProfileProjectionAppStateKeyV1(authority.authorityId));
  }

  private async publishLocalAuthorityActivationInTransaction(
    input: LocalAuthorityActivationPublicationInputV1,
    ctx: SeamsWalletTransactionContext,
  ): Promise<LocalAuthorityActivationPublicationResultV1> {
    const profileProjectionRaw = await ctx
      .store(SEAMS_WALLET_STORES.appState)
      .get(localAuthorityPendingProfileProjectionAppStateKeyV1(input.authority.authorityId));
    const profileProjection =
      profileProjectionRaw === undefined
        ? null
        : parseLocalAuthorityPendingProfileProjectionV1(profileProjectionRaw.value);
    if (profileProjectionRaw !== undefined && !profileProjection) {
      throw new Error('local authority profile projection is missing or corrupt');
    }
    const authorityRaw = await ctx
      .store(SEAMS_WALLET_STORES.walletAuthorities)
      .get(input.authority.authorityId);
    const authMethodRaw = await ctx
      .store(SEAMS_WALLET_STORES.walletAuthMethods)
      .get(input.authMethod.walletAuthMethodId);
    const receiptRaw = await ctx
      .store(SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts)
      .get(input.authority.authorityId);
    const authority = authorityRaw === undefined ? null : parseWalletAuthorityStorageRow(authorityRaw);
    const authMethod =
      authMethodRaw === undefined ? null : parseWalletAuthMethodV2StorageRow(authMethodRaw);
    const receipt =
      receiptRaw === undefined ? null : parseLocalAuthorityInstallationReceiptStorageRow(receiptRaw);
    if (!authority || !authMethod || !receipt) {
      throw new Error('local authority publication prerequisites are missing');
    }
    if (
      receipt.record.authorityId !== input.authority.authorityId ||
      receipt.record.walletId !== input.authority.walletId ||
      receipt.record.authMethodId !== input.authMethod.walletAuthMethodId ||
      !walletSignerActivationSetsMatch(
        receipt.record.installedActivationRefs,
        input.authority.signerActivations,
      )
    ) {
      throw new Error('local authority installation receipt does not match publication');
    }
    if (authority.record.state === 'active') {
      if (
        !walletAuthorityRecordsMatch(authority.record, input.authority) ||
        authMethod.record.status !== 'active' ||
        !walletAuthMethodRecordsMatch(authMethod.record, input.authMethod)
      ) {
        throw new Error('active local authority publication conflicts with stored records');
      }
      if (profileProjection) {
        await this.publishPendingLocalAuthorityProfileProjectionInTransaction(
          input.authority,
          input.authMethod,
          profileProjection,
          ctx,
        );
      }
      return { kind: 'published' };
    }
    if (
      authority.record.state !== 'pending_local_install' ||
      authMethod.record.status !== 'pending_local_install' ||
      !walletAuthorityPendingMatchesActive(authority.record, input.authority) ||
      !walletAuthMethodPendingMatchesActive(authMethod.record, input.authMethod)
    ) {
      throw new Error('local authority records are not the expected pending installation');
    }
    const selectionRaw = await ctx.store(SEAMS_WALLET_STORES.walletSelections).get(input.authority.walletId);
    if (selectionRaw === undefined) throw new Error('wallet selection is missing');
    const selection = parseWalletSelectionStorageRow(selectionRaw);
    if (!selection || selection.wallet_id !== input.authority.walletId) {
      throw new Error('wallet selection is corrupt');
    }
    if (selection.lock_generation !== input.expectedLockGeneration) {
      return {
        kind: 'stale_lock_generation',
        expectedLockGeneration: input.expectedLockGeneration,
        actualLockGeneration: selection.lock_generation,
      };
    }
    if (selection.record.lockState === 'locked') {
      return { kind: 'wallet_locked', lockGeneration: selection.lock_generation };
    }
    if (!profileProjection) {
      throw new Error('local authority profile projection is missing or corrupt');
    }
    await this.publishPendingLocalAuthorityProfileProjectionInTransaction(
      input.authority,
      input.authMethod,
      profileProjection,
      ctx,
    );
    await ctx.store(SEAMS_WALLET_STORES.walletAuthorities).put(walletAuthorityStorageRow(input.authority));
    return { kind: 'published' };
  }

  private async advanceWalletLockGenerationInTransaction(
    input: WalletLockGenerationAdvanceInputV1,
    ctx: SeamsWalletTransactionContext,
  ): Promise<number> {
    const selectionStore = ctx.store(SEAMS_WALLET_STORES.walletSelections);
    const selectionRaw = await selectionStore.get(input.walletId);
    if (selectionRaw === undefined) throw new Error('wallet selection is missing');
    const selection = parseWalletSelectionStorageRow(selectionRaw);
    if (!selection || selection.wallet_id !== input.walletId) {
      throw new Error('wallet selection is corrupt');
    }
    if (selection.record.lockGeneration >= Number.MAX_SAFE_INTEGER) {
      throw new Error('wallet lock generation cannot advance');
    }
    const lockGeneration = selection.record.lockGeneration + 1;
    await selectionStore.put(
      walletSelectionStorageRow({
        kind: 'wallet_selection_v1',
        walletId: selection.record.walletId,
        walletAuthMethodId: selection.record.walletAuthMethodId,
        lockGeneration,
        lockState: 'locked',
        updatedAtMs: input.lockedAtMs,
      }),
    );
    return lockGeneration;
  }

  private async assertSelectionMoveBetweenAuthorityMembers(
    input: {
      readonly walletId: WalletId;
      readonly fromWalletAuthMethodId: WalletAuthMethodId;
      readonly toWalletAuthMethodId: WalletAuthMethodId;
    },
    ctx: SeamsWalletTransactionContext,
  ): Promise<void> {
    const authMethodStore = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
    const fromRaw = await authMethodStore.get(input.fromWalletAuthMethodId);
    const toRaw = await authMethodStore.get(input.toWalletAuthMethodId);
    const from = fromRaw === undefined ? null : parseWalletAuthMethodV2StorageRow(fromRaw);
    const to = toRaw === undefined ? null : parseWalletAuthMethodV2StorageRow(toRaw);
    if (
      !from ||
      !to ||
      to.record.status !== 'active' ||
      to.record.walletId !== input.walletId ||
      from.record.walletId !== input.walletId ||
      from.record.walletAuthorityId !== to.record.walletAuthorityId
    ) {
      throw new Error('wallet selection is missing or corrupt');
    }
  }

  private async markWalletSelectionUnlockedInTransaction(
    input: {
      readonly walletId: WalletId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly unlockedAtMs: number;
    },
    ctx: SeamsWalletTransactionContext,
  ): Promise<void> {
    const selectionStore = ctx.store(SEAMS_WALLET_STORES.walletSelections);
    const selectionRaw = await selectionStore.get(input.walletId);
    const selection =
      selectionRaw === undefined ? null : parseWalletSelectionStorageRow(selectionRaw);
    if (!selection || selection.wallet_id !== input.walletId) {
      throw new Error('wallet selection is missing or corrupt');
    }
    if (selection.record.walletAuthMethodId !== input.walletAuthMethodId) {
      // R109C: unlocking with a sibling method on the same wallet authority
      // moves the selection to it. Invariant 9 makes lock and unlock the route
      // by which a newly added method becomes the one in use, so a selection
      // still naming the source method is the expected state here rather than
      // corruption. A method on another authority is refused as before.
      await this.assertSelectionMoveBetweenAuthorityMembers(
        {
          walletId: input.walletId,
          fromWalletAuthMethodId: selection.record.walletAuthMethodId,
          toWalletAuthMethodId: input.walletAuthMethodId,
        },
        ctx,
      );
    }
    await selectionStore.put(
      walletSelectionStorageRow({
        kind: 'wallet_selection_v1',
        walletId: selection.record.walletId,
        walletAuthMethodId: input.walletAuthMethodId,
        lockGeneration: selection.record.lockGeneration,
        lockState: 'unlocked',
        updatedAtMs: input.unlockedAtMs,
      }),
    );
  }

  private async persistRecoveredWalletAuthorityInTransaction(
    input: RecoveredWalletAuthorityProjectionInputV1,
    ctx: SeamsWalletTransactionContext,
  ): Promise<void> {
    const authorityStore = ctx.store(SEAMS_WALLET_STORES.walletAuthorities);
    const existingAuthorityRaw = await authorityStore.get(input.authority.authorityId);
    const existingAuthority =
      existingAuthorityRaw === undefined
        ? null
        : parseWalletAuthorityStorageRow(existingAuthorityRaw)?.record;
    if (existingAuthorityRaw !== undefined && !existingAuthority) {
      throw new Error('local Wallet Authority is corrupt');
    }
    if (existingAuthority && !walletAuthorityRecordsMatch(existingAuthority, input.authority)) {
      throw new Error('recovered Wallet Authority conflicts with local authority');
    }
    await authorityStore.put(walletAuthorityStorageRow(input.authority));
    await ctx
      .store(SEAMS_WALLET_STORES.walletAuthMethods)
      .put(walletAuthMethodV2StorageRow(input.authMethod));
    const selectionStore = ctx.store(SEAMS_WALLET_STORES.walletSelections);
    const selectionRaw = await selectionStore.get(input.authority.walletId);
    const selection =
      selectionRaw === undefined ? null : parseWalletSelectionStorageRow(selectionRaw);
    if (selectionRaw !== undefined && !selection) {
      throw new Error('recovered wallet selection is corrupt');
    }
    await selectionStore.put(
      walletSelectionStorageRow({
        kind: 'wallet_selection_v1',
        walletId: input.authority.walletId,
        walletAuthMethodId: input.authMethod.walletAuthMethodId,
        lockGeneration: selection?.record.lockGeneration ?? 0,
        lockState: 'locked',
        updatedAtMs: input.recoveredAtMs,
      }),
    );
  }

  private async installLocalAuthorityInTransaction(
    input: ValidatedLocalAuthorityInstallationInput,
    ctx: SeamsWalletTransactionContext,
  ): Promise<LocalAuthorityInstallationResultV1> {
    const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);
    const profileStore = ctx.store(SEAMS_WALLET_STORES.wallets);
    const profileRaw = await profileStore.get(input.profile.profileId);
    const existingProfile = profileRaw === undefined ? null : parseProfileRow(profileRaw);
    if (profileRaw !== undefined && !existingProfile) {
      return { kind: 'integrity_error', reason: 'wallet profile row is invalid' };
    }
    const authenticatorStore = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
    const authenticatorLookupRow = input.authenticator
      ? walletAuthMethodRowFromAuthenticator(input.authenticator)
      : null;
    const localAuthMethodRow = input.localAuthMethod
      ? walletAuthMethodRowFromBinding(input.localAuthMethod, input.profile.defaultSignerSlot ?? 1)
      : null;
    const authenticatorRaw = authenticatorLookupRow
      ? await authenticatorStore.get(authenticatorLookupRow.wallet_auth_method_id)
      : undefined;
    const existingAuthenticatorRow =
      authenticatorRaw === undefined ? null : parseWalletAuthMethodStorageRow(authenticatorRaw);
    const authenticatorRow = input.authenticator
      ? walletAuthMethodRowFromAuthenticator(
          input.authenticator,
          existingAuthenticatorRow?.kind === 'passkey' ? existingAuthenticatorRow : undefined,
        )
      : null;
    const localAuthMethodRaw = localAuthMethodRow
      ? await authenticatorStore.get(localAuthMethodRow.wallet_auth_method_id)
      : undefined;
    const existingLocalAuthMethodRow =
      localAuthMethodRaw === undefined ? null : parseWalletAuthMethodStorageRow(localAuthMethodRaw);
    const selectionStore = ctx.store(SEAMS_WALLET_STORES.walletSelections);
    const selectionRaw = await selectionStore.get(input.authority.walletId);
    const selection =
      selectionRaw === undefined ? null : parseWalletSelectionStorageRow(selectionRaw);
    if (
      selectionRaw !== undefined &&
      (!selection || selection.wallet_id !== input.authority.walletId)
    ) {
      return { kind: 'integrity_error', reason: 'wallet selection row is invalid' };
    }
    if (selection && selection.lock_generation !== input.expectedLockGeneration) {
      return {
        kind: 'stale_lock_generation',
        expectedLockGeneration: input.expectedLockGeneration,
        actualLockGeneration: selection.lock_generation,
      };
    }
    if (!selection && input.expectedLockGeneration !== 0) {
      return {
        kind: 'integrity_error',
        reason: 'initial wallet selection requires lock generation zero',
      };
    }

    const authorityStore = ctx.store(SEAMS_WALLET_STORES.walletAuthorities);
    const authMethodStore = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
    const signerMaterialStore = ctx.store(SEAMS_WALLET_STORES.walletAuthoritySignerMaterials);
    const exportRootStore = ctx.store(SEAMS_WALLET_STORES.walletAuthorityExportRoots);
    const receiptStore = ctx.store(SEAMS_WALLET_STORES.walletAuthorityInstallationReceipts);
    const profileProjectionKey = localAuthorityPendingProfileProjectionAppStateKeyV1(
      input.authority.authorityId,
    );
    const profileProjectionRaw = await appStateStore.get(profileProjectionKey);
    const profileProjection =
      profileProjectionRaw === undefined
        ? null
        : parseLocalAuthorityPendingProfileProjectionV1(profileProjectionRaw.value);
    if (profileProjectionRaw !== undefined && !profileProjection) {
      return {
        kind: 'integrity_error',
        reason: 'local authority profile projection is missing or corrupt',
      };
    }
    const profileProjectionRecord =
      profileProjection ??
      buildLocalAuthorityPendingProfileProjectionV1({
        authorityId: input.authority.authorityId,
        walletId: input.authority.walletId,
        authMethodId: input.authMethod.walletAuthMethodId,
        profile: profileRow(input.profile, existingProfile || undefined),
        authenticator: authenticatorRow,
        localAuthMethod: localAuthMethodRow?.kind === 'email_otp' ? localAuthMethodRow : null,
      });
    const authorityRaw = await authorityStore.get(input.authority.authorityId);
    const authMethodRaw = await authMethodStore.get(input.authMethod.walletAuthMethodId);
    const signerMaterialRaws: unknown[] = [];
    for (const material of input.signerMaterials) {
      signerMaterialRaws.push(
        await signerMaterialStore.get([
          material.authorityId,
          material.walletAuthMethodId,
          material.activationId,
        ]),
      );
    }
    const exportRootRaw = input.exportRoot
      ? await exportRootStore.get([
          input.exportRoot.authorityId,
          input.exportRoot.walletAuthMethodId,
          input.exportRoot.walletKeyId,
        ])
      : undefined;
    const receiptRaw = await receiptStore.get(input.receipt.authorityId);
    const existingAuthority =
      authorityRaw === undefined ? null : parseWalletAuthorityStorageRow(authorityRaw);
    const existingAuthMethod =
      authMethodRaw === undefined ? null : parseWalletAuthMethodV2StorageRow(authMethodRaw);
    const existingSignerMaterials: (WalletAuthoritySignerMaterialRecordV1 | null)[] = [];
    for (let index = 0; index < signerMaterialRaws.length; index += 1) {
      const raw = signerMaterialRaws[index];
      existingSignerMaterials.push(
        raw === undefined
          ? null
          : parseWalletAuthoritySignerMaterialStorageRow(raw)?.record || null,
      );
    }
    const existingExportRoot =
      exportRootRaw === undefined
        ? null
        : parseWalletAuthorityExportRootStorageRow(exportRootRaw)?.record || null;
    const existingReceipt =
      receiptRaw === undefined
        ? null
        : parseLocalAuthorityInstallationReceiptStorageRow(receiptRaw)?.record || null;
    if (
      profileProjection &&
      !localAuthorityPendingProfileProjectionMatchesInputV1(profileProjection, input)
    ) {
      return {
        kind: 'integrity_error',
        reason: 'local authority profile projection conflicts with replay',
      };
    }
    const installationStateExists =
      authorityRaw !== undefined ||
      authMethodRaw !== undefined ||
      signerMaterialRaws.some(rawValueIsPresent) ||
      exportRootRaw !== undefined ||
      receiptRaw !== undefined ||
      profileProjectionRaw !== undefined;
    const allInstallationRecords =
      authorityRaw !== undefined &&
      authMethodRaw !== undefined &&
      signerMaterialRaws.every(rawValueIsPresent) &&
      (input.exportRoot === null ? exportRootRaw === undefined : exportRootRaw !== undefined) &&
      receiptRaw !== undefined;
    if (installationStateExists) {
      if (
        !selection ||
        !allInstallationRecords ||
        !existingAuthority ||
        !existingAuthMethod ||
        !existingReceipt ||
        !profileProjection ||
        !localAuthorityPendingProfileProjectionsMatchV1(profileProjection, profileProjectionRecord)
      ) {
        return {
          kind: 'integrity_error',
          reason: 'local authority replay is incomplete or malformed',
        };
      }
      if (
        !walletAuthorityRecordsMatch(existingAuthority.record, input.authority) ||
        !walletAuthMethodRecordsMatch(existingAuthMethod.record, input.authMethod) ||
        !localAuthorityInstallationReceiptsMatch(existingReceipt, input.receipt)
      ) {
        return {
          kind: 'integrity_error',
          reason: 'local authority replay conflicts with stored records',
        };
      }
      if (
        (existingProfile &&
          !rollbackRecordsEqual(existingProfile, profileProjection.profile.record)) ||
        (profileProjection.authenticator &&
          existingAuthenticatorRow !== null &&
          !rollbackRecordsEqual(existingAuthenticatorRow, profileProjection.authenticator)) ||
        (profileProjection.localAuthMethod &&
          existingLocalAuthMethodRow !== null &&
          !rollbackRecordsEqual(existingLocalAuthMethodRow, profileProjection.localAuthMethod))
      ) {
        return {
          kind: 'integrity_error',
          reason: 'stored local profile projection conflicts with replay',
        };
      }
      for (let index = 0; index < input.signerMaterials.length; index += 1) {
        const existingMaterial = existingSignerMaterials[index];
        if (
          !existingMaterial ||
          !walletAuthoritySignerMaterialRecordsMatch(existingMaterial, input.signerMaterials[index])
        ) {
          return {
            kind: 'integrity_error',
            reason: 'stored signer material conflicts with replay',
          };
        }
      }
      if (input.exportRoot) {
        if (
          !existingExportRoot ||
          !walletAuthorityExportRootsMatch(existingExportRoot, input.exportRoot)
        ) {
          return { kind: 'integrity_error', reason: 'stored export root conflicts with replay' };
        }
      }
      await selectionStore.put(
        walletSelectionStorageRow(walletSelectionForInstalledAuthority(input, selection)),
      );
      return { kind: 'idempotent_replay', receipt: existingReceipt };
    }

    await appStateStore.put({ key: profileProjectionKey, value: profileProjectionRecord });
    await authorityStore.put(walletAuthorityStorageRow(input.authority));
    await authMethodStore.put(walletAuthMethodV2StorageRow(input.authMethod));
    for (const material of input.signerMaterials) {
      await signerMaterialStore.put(walletAuthoritySignerMaterialStorageRow(material));
    }
    if (input.exportRoot) {
      await exportRootStore.put(walletAuthorityExportRootStorageRow(input.exportRoot));
    }
    await receiptStore.put(localAuthorityInstallationReceiptStorageRow(input.receipt));
    await selectionStore.put(
      walletSelectionStorageRow(walletSelectionForInstalledAuthority(input, selection)),
    );
    return { kind: 'installed', receipt: input.receipt };
  }

  async getWalletAuthority(walletAuthorityId: string): Promise<WalletAuthorityV1 | null> {
    const parsedId = parseWalletAuthorityId(walletAuthorityId);
    if (!parsedId.ok) return null;
    const db = await this.manager.getDB();
    const row = parseWalletAuthorityStorageRow(
      await db.get(SEAMS_WALLET_STORES.walletAuthorities, parsedId.value),
    );
    if (!row || !(await walletAuthorityDigestsMatchV1(row.record))) return null;
    return row.record;
  }

  async persistFoundingWalletAuthority(
    input: PersistFoundingWalletAuthorityInputV1,
  ): Promise<void> {
    const validated = validateFoundingWalletAuthorityInput(input);
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.walletAuthorities,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletSelections,
      ],
      'readwrite',
      this.persistFoundingWalletAuthorityInTransaction.bind(this, validated),
    );
  }

  private async persistFoundingWalletAuthorityInTransaction(
    input: ValidatedFoundingWalletAuthorityInputV1,
    ctx: SeamsWalletTransactionContext,
  ): Promise<void> {
    await ctx
      .store(SEAMS_WALLET_STORES.walletAuthorities)
      .put(walletAuthorityStorageRow(input.authority));
    await ctx
      .store(SEAMS_WALLET_STORES.walletAuthMethods)
      .put(walletAuthMethodV2StorageRow(input.authMethod));
    await ctx.store(SEAMS_WALLET_STORES.walletSelections).put(
      walletSelectionStorageRow({
        kind: 'wallet_selection_v1',
        walletId: input.authority.walletId,
        walletAuthMethodId: input.authMethod.walletAuthMethodId,
        lockGeneration: 0,
        lockState: 'unlocked',
        updatedAtMs: input.authMethod.activatedAtMs,
      }),
    );
  }

  async getWalletAuthMethodV2(
    walletAuthMethodId: string,
  ): Promise<WalletAuthMethodRecordV2 | null> {
    const parsedId = parseWalletAuthMethodId(walletAuthMethodId);
    if (!parsedId.ok) return null;
    const db = await this.manager.getDB();
    return (
      parseWalletAuthMethodV2StorageRow(
        await db.get(SEAMS_WALLET_STORES.walletAuthMethods, parsedId.value),
      )?.record || null
    );
  }

  async listWalletSelections(): Promise<WalletSelectionRecordV1[]> {
    const db = await this.manager.getDB();
    const rows = (await db
      .transaction(SEAMS_WALLET_STORES.walletSelections, 'readonly')
      .store.getAll()) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseWalletSelectionStorageRow(row);
      return parsed ? [parsed.record] : [];
    });
  }

  async listWalletSelectionWalletIds(): Promise<WalletId[]> {
    const db = await this.manager.getDB();
    const keys = await db
      .transaction(SEAMS_WALLET_STORES.walletSelections, 'readonly')
      .store.getAllKeys();
    return keys.flatMap((key) => {
      const parsed = parseWalletId(key);
      return parsed.ok ? [parsed.value] : [];
    });
  }

  async listWalletAuthMethodsV2ForWallet(walletId: string): Promise<WalletAuthMethodRecordV2[]> {
    const normalizedWalletId = toTrimmedString(walletId || '');
    if (!normalizedWalletId) return [];
    const db = await this.manager.getDB();
    const rows = (await db
      .transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly')
      .store.index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(normalizedWalletId)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseWalletAuthMethodV2StorageRow(row);
      return parsed ? [parsed.record] : [];
    });
  }

  async resolveSelectedWalletAuthority(
    walletId: string,
  ): Promise<ResolveSelectedWalletAuthorityResultV1> {
    return await this.resolveWalletAuthorityForSelection(walletId, null);
  }

  /**
   * R109C: resolve the authority as a named method rather than as the selected
   * one.
   *
   * Unlocking a sibling is how an added method comes into use - invariant 9
   * makes lock and unlock the route - and the unlock moves the selection to it.
   * Resolving through the selection first would make that impossible: the
   * method cannot become selected until it unlocks, and it cannot unlock until
   * it is selected. Naming the method breaks the circle; the move itself is
   * still guarded, and still only between members of one authority.
   */
  async resolveWalletAuthorityForMethod(
    walletId: string,
    walletAuthMethodId: string,
  ): Promise<ResolveSelectedWalletAuthorityResultV1> {
    const parsed = parseWalletAuthMethodId(walletAuthMethodId);
    if (!parsed.ok) {
      return { kind: 'integrity_error', reason: 'walletAuthMethodId is invalid' };
    }
    return await this.resolveWalletAuthorityForSelection(walletId, parsed.value);
  }

  private async resolveWalletAuthorityForSelection(
    walletId: string,
    walletAuthMethodId: WalletAuthMethodId | null,
  ): Promise<ResolveSelectedWalletAuthorityResultV1> {
    const parsedWalletId = parseWalletId(walletId);
    if (!parsedWalletId.ok) return { kind: 'integrity_error', reason: 'walletId is invalid' };
    return this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.walletSelections,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.walletAuthorities,
        SEAMS_WALLET_STORES.walletAuthoritySignerMaterials,
        SEAMS_WALLET_STORES.walletAuthorityExportRoots,
      ],
      'readonly',
      (ctx) =>
        this.resolveSelectedWalletAuthorityInTransaction(
          parsedWalletId.value,
          ctx,
          walletAuthMethodId,
        ),
    );
  }

  private async resolveSelectedWalletAuthorityInTransaction(
    walletId: WalletId,
    ctx: SeamsWalletTransactionContext,
    requestedWalletAuthMethodId: WalletAuthMethodId | null = null,
  ): Promise<ResolveSelectedWalletAuthorityResultV1> {
    const selectionRaw = await ctx.store(SEAMS_WALLET_STORES.walletSelections).get(walletId);
    if (selectionRaw === undefined) return { kind: 'missing_selection' };
    const selection = parseWalletSelectionStorageRow(selectionRaw);
    if (!selection || selection.wallet_id !== walletId) {
      return { kind: 'integrity_error', reason: 'wallet selection row is invalid' };
    }
    const resolvedAuthMethodId = requestedWalletAuthMethodId ?? selection.record.walletAuthMethodId;
    const authMethodRaw = await ctx
      .store(SEAMS_WALLET_STORES.walletAuthMethods)
      .get(String(resolvedAuthMethodId));
    if (authMethodRaw === undefined) {
      return {
        kind: 'missing_auth_method',
        walletAuthMethodId: resolvedAuthMethodId,
      };
    }
    const authMethod = parseWalletAuthMethodV2StorageRow(authMethodRaw);
    if (!authMethod || authMethod.wallet_id !== walletId) {
      return { kind: 'integrity_error', reason: 'selected V2 auth method row is invalid' };
    }
    const authorityRaw = await ctx
      .store(SEAMS_WALLET_STORES.walletAuthorities)
      .get(authMethod.wallet_authority_id);
    if (authorityRaw === undefined) {
      return {
        kind: 'missing_authority',
        walletAuthorityId: authMethod.record.walletAuthorityId,
      };
    }
    const authority = parseWalletAuthorityStorageRow(authorityRaw);
    if (!authority || authority.wallet_id !== walletId) {
      return { kind: 'integrity_error', reason: 'selected wallet authority row is invalid' };
    }
    if (authority.authority_id !== authMethod.wallet_authority_id) {
      return {
        kind: 'integrity_error',
        reason: 'auth method authority reference does not resolve exactly',
      };
    }
    if (
      authority.record.provenance.kind === 'wallet_registration' ||
      authority.record.provenance.kind === 'wallet_recovery'
    ) {
      if (!(await walletAuthorityDigestsMatchV1(authority.record))) {
        return { kind: 'integrity_error', reason: 'selected wallet authority digest is invalid' };
      }
      return {
        kind: 'resolved',
        selection: selection.record,
        authMethod: authMethod.record,
        authority: authority.record,
        signerMaterials: [],
        exportRoot: null,
      };
    }
    const signerMaterialStore = ctx.store(SEAMS_WALLET_STORES.walletAuthoritySignerMaterials);
    const signerMaterials: WalletAuthoritySignerMaterialRecordV1[] = [];
    let expectations: readonly SignerMaterialExpectation[];
    try {
      expectations = signerMaterialExpectations(authority.record.signerActivations);
    } catch {
      return {
        kind: 'integrity_error',
        reason: 'selected authority signer activations are invalid',
      };
    }
    for (const expected of expectations) {
      const rawMaterial = await signerMaterialStore.get([
        authority.record.authorityId,
        authMethod.record.walletAuthMethodId,
        expected.materialActivation.activationId,
      ]);
      if (rawMaterial === undefined) {
        return {
          kind: 'integrity_error',
          reason: 'selected signer material row is missing',
        };
      }
      const materialRow = parseWalletAuthoritySignerMaterialStorageRow(rawMaterial);
      if (
        !materialRow ||
        materialRow.wallet_authority_id !== authority.record.authorityId ||
        materialRow.wallet_auth_method_id !== authMethod.record.walletAuthMethodId ||
        materialRow.activation_id !== expected.materialActivation.activationId ||
        materialRow.key_family !== expected.keyFamily ||
        !mpcMaterialActivationRefsEqual(
          materialRow.record.materialActivation,
          expected.materialActivation,
        )
      ) {
        return {
          kind: 'integrity_error',
          reason: 'selected signer material row is invalid',
        };
      }
      signerMaterials.push(materialRow.record);
    }
    const exportRootRaws = (await ctx
      .store(SEAMS_WALLET_STORES.walletAuthorityExportRoots)
      .index(SEAMS_WALLET_INDEXES.walletAuthorityAuthMethodId)
      .getAll([authority.record.authorityId, authMethod.record.walletAuthMethodId])) as unknown[];
    const requiresExportRoot =
      hasEd25519SignerFamily(authority.record.signerActivations) &&
      authority.record.permissions.includes('export_keys');
    if (exportRootRaws.length !== (requiresExportRoot ? 1 : 0)) {
      return {
        kind: 'integrity_error',
        reason: 'selected authority export-root cardinality is invalid',
      };
    }
    let exportRoot: WalletAuthorityExportRootRecordV1 | null = null;
    if (requiresExportRoot) {
      const row = parseWalletAuthorityExportRootStorageRow(exportRootRaws[0]);
      const expectedWalletKeyId = ed25519WalletKeyId(authority.record.signerActivations);
      if (
        !row ||
        expectedWalletKeyId === null ||
        row.wallet_authority_id !== authority.record.authorityId ||
        row.wallet_auth_method_id !== authMethod.record.walletAuthMethodId ||
        row.record.walletKeyId !== expectedWalletKeyId ||
        row.record.envelope.walletId !== walletId ||
        row.record.envelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
        row.record.envelope.binding.walletKeyId !== expectedWalletKeyId ||
        row.record.envelope.binding.registeredPublicKeyB64u !==
          authority.record.signerActivations.ed25519?.signer.registeredPublicKeyB64u ||
        authority.record.principal.kind !== 'owner_device' ||
        String(row.record.envelope.binding.deviceId) !==
          String(authority.record.principal.deviceId) ||
        row.record.envelope.lifecycle.state !== 'active' ||
        !exportRootEnvelopeMatchesAuthMethod(authMethod.record, row.record.envelope)
      ) {
        return { kind: 'integrity_error', reason: 'selected authority export root is invalid' };
      }
      exportRoot = row.record;
    }
    if (!(await walletAuthorityDigestsMatchV1(authority.record))) {
      return { kind: 'integrity_error', reason: 'selected wallet authority digest is invalid' };
    }
    return {
      kind: 'resolved',
      selection: selection.record,
      authMethod: authMethod.record,
      authority: authority.record,
      signerMaterials,
      exportRoot,
    };
  }

  async getAppState<T = unknown>(key: string): Promise<T | undefined> {
    const normalizedKey = toTrimmedString(key || '');
    if (!normalizedKey) return undefined;
    const db = await this.manager.getDB();
    const row = (await db.get(SEAMS_WALLET_STORES.appState, normalizedKey)) as
      | AppStateRow<T>
      | undefined;
    return row?.value;
  }

  async listAppStateEntriesByPrefix(prefix: string): Promise<ReadonlyArray<AppStateRow>> {
    const normalizedPrefix = toTrimmedString(prefix || '');
    if (!normalizedPrefix) return [];
    const db = await this.manager.getDB();
    const rawRows = (await db.getAll(SEAMS_WALLET_STORES.appState)) as unknown[];
    return rawRows.flatMap((raw) => {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [];
      const row = raw as Partial<AppStateRow>;
      return typeof row.key === 'string' && row.key.startsWith(normalizedPrefix)
        ? [{ key: row.key, value: row.value }]
        : [];
    });
  }

  async setAppState<T = unknown>(key: string, value: T): Promise<void> {
    const normalizedKey = toTrimmedString(key || '');
    if (!normalizedKey) return;
    await this.manager.runTransaction([SEAMS_WALLET_STORES.appState], 'readwrite', async (ctx) => {
      await ctx.store(SEAMS_WALLET_STORES.appState).put({ key: normalizedKey, value });
    });
  }

  /* Keep pending commits in the existing private app-state store: opening a
     new schema version currently rebuilds every object store. The namespaced
     rows never participate in profile discovery. */
  async putPendingWalletRegistrationCommit(
    record: PendingWalletRegistrationCommitV1,
  ): Promise<void> {
    const row = toPendingWalletRegistrationCommitAppStateRow(record);
    await this.manager.runTransaction([SEAMS_WALLET_STORES.appState], 'readwrite', async (ctx) => {
      await ctx.store(SEAMS_WALLET_STORES.appState).put(row);
    });
  }

  async getPendingWalletRegistrationCommit(input: {
    registrationCeremonyId: string;
    operation: PendingWalletRegistrationCommitV1['operation'];
  }): Promise<PendingWalletRegistrationCommitV1 | null> {
    const registrationCeremonyId = toTrimmedString(input.registrationCeremonyId || '');
    if (!registrationCeremonyId) return null;
    const db = await this.manager.getDB();
    const raw = await db.get(
      SEAMS_WALLET_STORES.appState,
      pendingWalletRegistrationCommitAppStateKey({
        registrationCeremonyId,
        operation: input.operation,
      }),
    );
    return parsePendingWalletRegistrationCommitAppStateRow(raw)?.record || null;
  }

  async listPendingWalletRegistrationCommits(): Promise<PendingWalletRegistrationCommitV1[]> {
    const db = await this.manager.getDB();
    const rawRows = (await db.getAll(SEAMS_WALLET_STORES.appState)) as unknown[];
    return rawRows.flatMap((raw) => {
      const parsed = parsePendingWalletRegistrationCommitAppStateRow(raw);
      return parsed ? [parsed.record] : [];
    });
  }

  async deletePendingWalletRegistrationCommit(input: {
    registrationCeremonyId: string;
    operation: PendingWalletRegistrationCommitV1['operation'];
  }): Promise<void> {
    const registrationCeremonyId = toTrimmedString(input.registrationCeremonyId || '');
    if (!registrationCeremonyId) return;
    await this.manager.runTransaction([SEAMS_WALLET_STORES.appState], 'readwrite', async (ctx) => {
      await ctx.store(SEAMS_WALLET_STORES.appState).delete(
        pendingWalletRegistrationCommitAppStateKey({
          registrationCeremonyId,
          operation: input.operation,
        }),
      );
    });
  }

  async putPendingWalletRecoveryCommit(record: PendingWalletRecoveryCommitV1): Promise<void> {
    const row = await toPendingWalletRecoveryCommitAppStateRow(record);
    await this.manager.runTransaction([SEAMS_WALLET_STORES.appState], 'readwrite', async (ctx) => {
      await ctx.store(SEAMS_WALLET_STORES.appState).put(row);
    });
  }

  async getPendingWalletRecoveryCommit(
    recoveryOperationId: WalletRecoveryOperationId,
  ): Promise<PendingWalletRecoveryCommitV1 | null> {
    const parsedRecoveryOperationId = requireBoundaryParsed(
      parseWalletRecoveryOperationId(recoveryOperationId),
      'recoveryOperationId',
    );
    const db = await this.manager.getDB();
    const parsed = await parsePendingWalletRecoveryCommitAppStateRow(
      await db.get(
        SEAMS_WALLET_STORES.appState,
        pendingWalletRecoveryCommitAppStateKey(parsedRecoveryOperationId),
      ),
    );
    return parsed?.record ?? null;
  }

  async listPendingWalletRecoveryCommits(): Promise<PendingWalletRecoveryCommitV1[]> {
    const db = await this.manager.getDB();
    const parsedRows = await Promise.all(
      ((await db.getAll(SEAMS_WALLET_STORES.appState)) as unknown[]).map(
        parsePendingWalletRecoveryCommitAppStateRow,
      ),
    );
    return parsedRows.flatMap((parsed) => (parsed ? [parsed.record] : []));
  }

  async deletePendingWalletRecoveryCommit(
    recoveryOperationId: WalletRecoveryOperationId,
  ): Promise<void> {
    const parsedRecoveryOperationId = requireBoundaryParsed(
      parseWalletRecoveryOperationId(recoveryOperationId),
      'recoveryOperationId',
    );
    await this.manager.runTransaction([SEAMS_WALLET_STORES.appState], 'readwrite', async (ctx) => {
      await ctx
        .store(SEAMS_WALLET_STORES.appState)
        .delete(pendingWalletRecoveryCommitAppStateKey(parsedRecoveryOperationId));
    });
  }

  async compareAndSwapAppState(input: {
    key: string;
    expected: unknown | null;
    replacement: unknown;
  }): Promise<boolean> {
    const normalizedKey = toTrimmedString(input.key || '');
    if (!normalizedKey) throw new Error('[SeamsWalletDB] app-state CAS key is required');
    return this.manager.runTransaction([SEAMS_WALLET_STORES.appState], 'readwrite', async (ctx) => {
      const store = ctx.store(SEAMS_WALLET_STORES.appState);
      const current = (await store.get(normalizedKey)) as AppStateRow<unknown> | undefined;
      const matches =
        input.expected === null
          ? current === undefined
          : current !== undefined &&
            alphabetizeStringify(current.value) === alphabetizeStringify(input.expected);
      if (!matches) {
        return false;
      }
      await store.put({ key: normalizedKey, value: input.replacement });
      return true;
    });
  }

  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return null;
    const db = await this.manager.getDB();
    return parseProfileRow(await db.get(SEAMS_WALLET_STORES.wallets, normalizedProfileId));
  }

  async getWalletPreferences(walletId: string): Promise<Partial<UserPreferences>> {
    const walletProfile = await this.getProfile(walletId);
    return walletProfile?.preferences || {};
  }

  async listProfiles(args?: { limit?: number }): Promise<ProfileRecord[]> {
    const db = await this.manager.getDB();
    const limit =
      Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0
        ? Number(args?.limit)
        : undefined;
    const rows = (
      limit
        ? await db.getAll(SEAMS_WALLET_STORES.wallets, undefined, limit)
        : await db.getAll(SEAMS_WALLET_STORES.wallets)
    ) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseProfileRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    const profileId = toTrimmedString(input.profileId || '');
    if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
    let written: ProfileRecord | null = null;
    await this.manager.runTransaction([SEAMS_WALLET_STORES.wallets], 'readwrite', async (ctx) => {
      const store = ctx.store(SEAMS_WALLET_STORES.wallets);
      const existing = parseProfileRow(await store.get(profileId)) || undefined;
      const next = profileRow(input, existing);
      written = next.record;
      await store.put(next);
    });
    if (!written) throw new Error('[SeamsWalletDB] profile write did not complete');
    return written;
  }

  async upsertWalletAuthMethod(
    record: LocalWalletAuthMethodRecord,
  ): Promise<LocalWalletAuthMethodRecord> {
    const fields = walletAuthMethodFields(record);
    let written: LocalWalletAuthMethodRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets, SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(fields.wallet_id),
        );
        if (!profile) {
          throw makeConstraintError(
            'MISSING_PROFILE',
            `Cannot upsert auth-method binding for unknown wallet: ${fields.wallet_id}`,
            { profileId: fields.wallet_id, authIdentifierKey: fields.auth_identifier_key },
          );
        }
        const store = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
        const existing = parseWalletAuthMethodStorageRow(
          await store.get(fields.wallet_auth_method_id),
        );
        const row =
          record.kind === 'passkey' && existing?.kind === 'passkey'
            ? passkeyAuthMethodRow({ binding: record, authenticator: existing.authenticator })
            : walletAuthMethodRowFromBinding(record, profile.defaultSignerSlot);
        await store.put(row);
        written = row.record;
      },
    );
    if (!written) throw new Error('[SeamsWalletDB] auth-method write did not complete');
    return written;
  }

  async upsertWalletAuthMethodV2(record: WalletAuthMethodRecordV2): Promise<void> {
    const parsed = parseWalletAuthMethodRecordV2(record);
    if (!parsed) throw new Error('[SeamsWalletDB] auth-method V2 record is invalid');
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets, SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(parsed.walletId),
        );
        if (!profile) {
          throw makeConstraintError(
            'MISSING_PROFILE',
            `Cannot upsert auth-method V2 binding for unknown wallet: ${String(parsed.walletId)}`,
            { profileId: String(parsed.walletId) },
          );
        }
        await ctx
          .store(SEAMS_WALLET_STORES.walletAuthMethods)
          .put(walletAuthMethodV2StorageRow(parsed));
      },
    );
  }

  async getWalletAuthMethod(args: {
    kind: LocalWalletAuthMethodRecord['kind'];
    rpId: string;
    authIdentifierKey: string;
  }): Promise<LocalWalletAuthMethodRecord | null> {
    const kind = args.kind;
    const rpId = toTrimmedString(args.rpId || '');
    const authIdentifierKey = toTrimmedString(args.authIdentifierKey || '');
    if (!rpId || !authIdentifierKey) return null;
    const db = await this.manager.getDB();
    const rows = (await db
      .transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly')
      .store.index(SEAMS_WALLET_INDEXES.kindRpIdAuthIdentifier)
      .getAll([kind, rpId, authIdentifierKey])) as unknown[];
    const parsed = rows.flatMap((row) => {
      const record = parseWalletAuthMethodRow(row);
      return record ? [record] : [];
    });
    return parsed.length === 1 ? parsed[0] : null;
  }

  async listWalletAuthMethodsForWallet(walletId: string): Promise<LocalWalletAuthMethodRecord[]> {
    const normalizedWalletId = toTrimmedString(walletId || '');
    if (!normalizedWalletId) return [];
    const db = await this.manager.getDB();
    const rows = (await db
      .transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly')
      .store.index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(normalizedWalletId)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseWalletAuthMethodRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    const profileId = toTrimmedString(input.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
    if (!profileId || !chainIdKey || !accountAddress) {
      throw new Error('[SeamsWalletDB] profileId, chainIdKey, and accountAddress are required');
    }
    let written: ChainAccountRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets, SEAMS_WALLET_STORES.nearAccountProjections],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(profileId),
        );
        if (!profile) {
          throw new Error(
            `[SeamsWalletDB] Cannot upsert chain account for unknown profile: ${profileId}`,
          );
        }
        const store = ctx.store(SEAMS_WALLET_STORES.nearAccountProjections);
        const projectionId = chainAccountProjectionId({ chainIdKey, accountAddress });
        const existing =
          parseChainAccountProjectionRow(
            await store.get([profileId, projectionId, CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT]),
          ) || undefined;
        const next = chainAccountProjectionRow(input, existing);
        written = next.record;

        if (next.record.isPrimary) {
          const rows = (await store.index(SEAMS_WALLET_INDEXES.profileId).getAll(profileId)) as
            | unknown[]
            | undefined;
          for (const row of rows || []) {
            const parsed = parseChainAccountProjectionRow(row);
            if (!parsed || parsed.chainIdKey !== chainIdKey || !parsed.isPrimary) continue;
            if (parsed.accountAddress === accountAddress) continue;
            await store.put(
              chainAccountProjectionRow(
                {
                  profileId: parsed.profileId,
                  chainIdKey: parsed.chainIdKey,
                  accountAddress: parsed.accountAddress,
                  accountModel: parsed.accountModel,
                  isPrimary: false,
                },
                parsed,
              ),
            );
          }
        }

        await store.put(next);
      },
    );
    if (!written) throw new Error('[SeamsWalletDB] chain-account write did not complete');
    return written;
  }

  async listChainAccountsByProfile(profileId: string): Promise<ChainAccountRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.nearAccountProjections, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.profileId)
      .getAll(normalizedProfileId)) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseChainAccountProjectionRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async listChainAccountsByProfileAndChain(
    profileId: string,
    chainIdKey: string,
  ): Promise<ChainAccountRecord[]> {
    const normalizedChainIdKey = normalizeIndexedDbChainIdKey(chainIdKey);
    if (!normalizedChainIdKey) return [];
    const rows = await this.listChainAccountsByProfile(profileId);
    return rows.filter((row) => row.chainIdKey === normalizedChainIdKey);
  }

  async getChainAccount(input: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
  }): Promise<ChainAccountRecord | null> {
    const profileId = toTrimmedString(input.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
    if (!profileId || !chainIdKey || !accountAddress) return null;
    const db = await this.manager.getDB();
    return parseChainAccountProjectionRow(
      await db.get(SEAMS_WALLET_STORES.nearAccountProjections, [
        profileId,
        chainAccountProjectionId({ chainIdKey, accountAddress }),
        CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
      ]),
    );
  }

  async resolveProfileAccountContext(
    accountRef: AccountRef,
  ): Promise<{ profileId: string; accountRef: AccountRef } | null> {
    const chainIdKey = normalizeIndexedDbChainIdKey(accountRef.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(accountRef.accountAddress);
    if (!chainIdKey || !accountAddress) return null;
    const db = await this.manager.getDB();
    const rows = (await db.getAll(SEAMS_WALLET_STORES.nearAccountProjections)) as unknown[];
    const match = rows
      .flatMap((row) => {
        const parsed = parseChainAccountProjectionRow(row);
        return parsed ? [parsed] : [];
      })
      .find((row) => row.chainIdKey === chainIdKey && row.accountAddress === accountAddress);
    if (!match?.profileId) return null;
    return {
      profileId: match.profileId,
      accountRef: { chainIdKey, accountAddress },
    };
  }

  async listChainAccountsByChain(chainIdKey: string): Promise<ChainAccountRecord[]> {
    const normalizedChainIdKey = normalizeIndexedDbChainIdKey(chainIdKey);
    if (!normalizedChainIdKey) return [];
    const db = await this.manager.getDB();
    const rows = (await db.getAll(SEAMS_WALLET_STORES.nearAccountProjections)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseChainAccountProjectionRow(row);
      return parsed && parsed.chainIdKey === normalizedChainIdKey ? [parsed] : [];
    });
  }

  private buildAccountSignerRecord(args: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    signerSlot: number;
    signerType: string;
    signerKind: AccountSignerRecord['signerKind'];
    signerAuthMethod: AccountSignerRecord['signerAuthMethod'];
    signerSource: AccountSignerRecord['signerSource'];
    status: AccountSignerStatus;
    existing?: AccountSignerRecord;
    now: number;
    removedAt?: number;
    revocationReason?: string;
    metadata?: Record<string, unknown>;
  }): AccountSignerRecord {
    const removedAt =
      args.status === 'revoked'
        ? (args.removedAt ?? args.existing?.removedAt ?? args.now)
        : undefined;
    return {
      profileId: args.profileId,
      chainIdKey: args.chainIdKey,
      accountAddress: args.accountAddress,
      signerId: args.signerId,
      signerSlot: args.signerSlot,
      signerType: args.signerType,
      signerKind: args.signerKind,
      signerAuthMethod: args.signerAuthMethod,
      signerSource: args.signerSource,
      status: args.status,
      addedAt: args.existing?.addedAt ?? args.now,
      updatedAt: args.now,
      ...(removedAt != null ? { removedAt } : {}),
      ...(args.revocationReason
        ? { revocationReason: toTrimmedString(args.revocationReason) }
        : args.existing?.revocationReason
          ? { revocationReason: args.existing.revocationReason }
          : {}),
      ...(args.metadata != null
        ? { metadata: args.metadata }
        : args.existing?.metadata != null
          ? { metadata: args.existing.metadata }
          : {}),
    };
  }

  private assertSignerWriteInvariants(args: {
    next: AccountSignerRecord;
    accountModel: string;
    existingStatus?: AccountSignerStatus;
    activeSigners: AccountSignerRecord[];
  }): void {
    const { next } = args;
    if (next.status !== 'revoked') {
      if (!next.signerKind || !next.signerAuthMethod || !next.signerSource) {
        throw makeConstraintError(
          'MISSING_SIGNER_KIND',
          'Active and pending account signers require signerKind, signerAuthMethod, and signerSource',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
            status: next.status,
          },
        );
      }
    }
    if (next.status === 'revoked' && next.removedAt == null) {
      throw makeConstraintError(
        'REVOKED_SIGNER_REQUIRES_REMOVED_AT',
        `Revoked signer ${next.signerId} must include removedAt`,
        {
          chainIdKey: next.chainIdKey,
          accountAddress: next.accountAddress,
          signerId: next.signerId,
        },
      );
    }
    if (next.status === 'active') {
      const conflictingSlot = args.activeSigners.find(
        (row) => row.signerId !== next.signerId && row.signerSlot === next.signerSlot,
      );
      if (conflictingSlot) {
        throw makeConstraintError(
          'DUPLICATE_ACTIVE_SIGNER_SLOT',
          `Active signer slot ${next.signerSlot} is already used for ${next.chainIdKey}/${next.accountAddress}`,
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
            signerSlot: next.signerSlot,
            conflictingSignerId: conflictingSlot.signerId,
          },
        );
      }
    }
    if (args.existingStatus && args.existingStatus !== next.status) {
      const allowed: Record<AccountSignerStatus, ReadonlySet<AccountSignerStatus>> = {
        pending: new Set<AccountSignerStatus>(['pending', 'active', 'revoked']),
        active: new Set<AccountSignerStatus>(['active', 'revoked']),
        revoked: new Set<AccountSignerStatus>(['revoked']),
      };
      if (!allowed[args.existingStatus]?.has(next.status)) {
        throw makeConstraintError(
          'INVALID_SIGNER_STATUS_TRANSITION',
          `Invalid signer status transition ${args.existingStatus} -> ${next.status}`,
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
            previousStatus: args.existingStatus,
            nextStatus: next.status,
          },
        );
      }
    }
    if (next.status === 'active' && String(next.signerKind || '') === 'threshold-ecdsa') {
      const metadata = next.metadata || {};
      if (!toTrimmedString(metadata.keyHandle)) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.keyHandle',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      if (!toTrimmedString(metadata.ecdsaThresholdKeyId)) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.ecdsaThresholdKeyId',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(
        metadata.thresholdOwnerAddress,
      );
      if (!thresholdOwnerAddress || thresholdOwnerAddress !== next.accountAddress) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.thresholdOwnerAddress matching accountAddress',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      const chainTargetKey = normalizeEcdsaChainTargetKey(metadata.chainTarget);
      if (!chainTargetKey) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer requires metadata.chainTarget',
          {
            chainIdKey: next.chainIdKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
      if (chainTargetKey !== next.chainIdKey) {
        throw makeConstraintError(
          'INVALID_SIGNER_METADATA',
          'Active threshold ECDSA signer metadata.chainTarget must match chainIdKey',
          {
            chainIdKey: next.chainIdKey,
            chainTargetKey,
            accountAddress: next.accountAddress,
            signerId: next.signerId,
          },
        );
      }
    }
  }

  private async enqueueSignerOperationInTransaction(
    store: any,
    input: EnqueueSignerOperationInput,
  ): Promise<SignerOpOutboxRecord> {
    const opId = toTrimmedString(input.opId || '');
    const idempotencyKey = toTrimmedString(input.idempotencyKey || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.accountAddress);
    const signerId = toTrimmedString(input.signerId || '');
    if (!opId || !idempotencyKey || !chainIdKey || !accountAddress || !signerId) {
      throw new Error(
        '[SeamsWalletDB] opId, idempotencyKey, chainIdKey, accountAddress, and signerId are required',
      );
    }

    const existing = parseSignerOutboxRow(await store.get(opId));
    if (!existing) {
      const byIdempotency = parseSignerOutboxRow(
        await store.index(SEAMS_WALLET_INDEXES.idempotencyKey).get(idempotencyKey),
      );
      if (byIdempotency) return byIdempotency;
    }

    const now = Date.now();
    const next: SignerOpOutboxRecord = {
      opId,
      idempotencyKey,
      opType: input.opType,
      chainIdKey,
      accountAddress,
      signerId,
      payload: input.payload ?? existing?.payload,
      status: input.status ?? existing?.status ?? 'queued',
      attemptCount: input.attemptCount ?? existing?.attemptCount ?? 0,
      nextAttemptAt: input.nextAttemptAt ?? existing?.nextAttemptAt ?? now,
      lastError: input.lastError ?? existing?.lastError,
      txHash: input.txHash ?? existing?.txHash,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await store.put(signerOutboxRow(next));
    return next;
  }

  private async activateAccountSignerInTransaction(
    ctx: SeamsWalletTransactionContext,
    input: ActivateAccountSignerInput,
  ): Promise<ActivateAccountSignerResult> {
    const profileId = toTrimmedString(input.account.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.account.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.account.accountAddress);
    const accountModel = normalizeIndexedDbAccountModel(input.account.accountModel);
    const signerId = toTrimmedString(input.signer.signerId || '');
    const signerKind = toTrimmedString(
      input.signer.signerKind || '',
    ) as AccountSignerRecord['signerKind'];
    const signerAuthMethod = toTrimmedString(
      input.signer.signerAuthMethod || '',
    ) as AccountSignerRecord['signerAuthMethod'];
    const signerSource = toTrimmedString(
      input.signer.signerSource || '',
    ) as AccountSignerRecord['signerSource'];
    if (
      !profileId ||
      !chainIdKey ||
      !accountAddress ||
      !accountModel ||
      !signerId ||
      !signerKind ||
      !signerAuthMethod ||
      !signerSource
    ) {
      throw new Error(
        '[SeamsWalletDB] profileId, chainIdKey, accountAddress, accountModel, signerId, signerKind, signerAuthMethod, and signerSource are required',
      );
    }

    const signerStore = ctx.store(SEAMS_WALLET_STORES.walletSigners);
    const profile = parseProfileRow(await ctx.store(SEAMS_WALLET_STORES.wallets).get(profileId));
    if (!profile) {
      throw makeConstraintError(
        'MISSING_PROFILE',
        `Cannot upsert signer without profile row: ${profileId}`,
        { profileId, chainIdKey, accountAddress, signerId },
      );
    }
    if (shouldWriteNearAccountProjection({ accountModel, chainIdKey })) {
      const chainAccountStore = ctx.store(SEAMS_WALLET_STORES.nearAccountProjections);
      const existingChainAccount = parseChainAccountProjectionRow(
        await chainAccountStore.get([
          profileId,
          chainAccountProjectionId({ chainIdKey, accountAddress }),
          CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
        ]),
      );
      const chainAccount = chainAccountProjectionRow(
        {
          profileId,
          chainIdKey,
          accountAddress,
          accountModel,
          isPrimary:
            input.selectAsActive === true ? true : (existingChainAccount?.isPrimary ?? true),
        },
        existingChainAccount || undefined,
      );
      await chainAccountStore.put(chainAccount);
    }

    const activeRows = (await signerStore
      .index(SEAMS_WALLET_INDEXES.status)
      .getAll('active')) as unknown[];
    const allActiveSigners = activeRows.flatMap((row) => {
      const parsed = parseAccountSignerRow(row);
      return parsed ? [parsed] : [];
    });
    const activeSigners = allActiveSigners.flatMap((parsed) => {
      return parsed.chainIdKey === chainIdKey && parsed.accountAddress === accountAddress
        ? [parsed]
        : [];
    });
    const plan = planAccountSignerActivation({
      activeSigners,
      signer: { signerId, signerKind, signerAuthMethod, signerSource },
      activationPolicy: input.activationPolicy,
      ...(input.preferredSlot != null ? { preferredSlot: input.preferredSlot } : {}),
    });
    const now = Date.now();
    await this.revokeSignersForReplacement({
      signerStore,
      allActiveSigners,
      accountActiveSigners: activeSigners,
      profileId,
      chainIdKey,
      accountModel,
      signerId,
      activationPolicy: input.activationPolicy,
      now,
    });
    const activeSignersForInvariant = this.activeSignersAfterReplacement({
      allActiveSigners,
      accountActiveSigners: activeSigners,
      profileId,
      chainIdKey,
      signerId,
      activationPolicy: input.activationPolicy,
    });
    const existingSigner = parseAccountSignerRow(
      await signerStore.get(walletSignerId({ chainIdKey, accountAddress, signerId })),
    );
    if (existingSigner && existingSigner.profileId !== profileId) {
      throw makeConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
        { expectedProfileId: profileId, existingProfileId: existingSigner.profileId },
      );
    }
    const signer = this.buildAccountSignerRecord({
      profileId,
      chainIdKey,
      accountAddress,
      signerId,
      signerSlot: plan.signerSlot,
      signerType: input.signer.signerType,
      signerKind,
      signerAuthMethod,
      signerSource,
      status: 'active',
      existing: existingSigner || undefined,
      now,
      ...(input.signer.metadata ? { metadata: input.signer.metadata } : {}),
    });
    this.assertSignerWriteInvariants({
      next: signer,
      accountModel,
      existingStatus: existingSigner?.status,
      activeSigners: activeSignersForInvariant,
    });
    const signerRow = accountSignerRow(signer);
    await deleteConflictingThresholdEcdsaSignerRows({ store: signerStore, nextRow: signerRow });
    await signerStore.put(signerRow);
    if (input.selectAsActive ?? true) {
      await ctx.store(SEAMS_WALLET_STORES.appState).put({
        key: scopedLastProfileStateAppStateKey(),
        value: { profileId, activeSignerSlot: plan.signerSlot },
      });
    }
    if (input.mutation?.routeThroughOutbox ?? false) {
      const opId = toTrimmedString(input.mutation?.opId || '') || createRandomToken('add-signer');
      const idempotencyKey =
        toTrimmedString(input.mutation?.idempotencyKey || '') ||
        `add-signer:${signer.chainIdKey}:${signer.accountAddress}:${signer.signerId}:${signer.signerSlot}`;
      await this.enqueueSignerOperationInTransaction(
        ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
        {
          opId,
          idempotencyKey,
          opType: 'add-signer',
          chainIdKey: signer.chainIdKey,
          accountAddress: signer.accountAddress,
          signerId: signer.signerId,
          payload: this.signerOutboxPayload(signer, input.mutation),
          status: input.mutation?.outboxStatus || 'queued',
        },
      );
    }
    return { signer, signerSlot: plan.signerSlot };
  }

  private activeSignersAfterReplacement(args: {
    allActiveSigners: AccountSignerRecord[];
    accountActiveSigners: AccountSignerRecord[];
    profileId: string;
    chainIdKey: string;
    signerId: string;
    activationPolicy: ActivateAccountSignerInput['activationPolicy'];
  }): AccountSignerRecord[] {
    const replacedSignerIds = new Set<string>();
    for (const signer of this.signersRetiredByActivationPolicy(args)) {
      replacedSignerIds.add(signer.signerId);
    }
    if (replacedSignerIds.size === 0) return args.accountActiveSigners;
    const retained: AccountSignerRecord[] = [];
    for (const signer of args.accountActiveSigners) {
      if (!replacedSignerIds.has(signer.signerId)) retained.push(signer);
    }
    return retained;
  }

  private signersRetiredByActivationPolicy(args: {
    allActiveSigners: AccountSignerRecord[];
    accountActiveSigners: AccountSignerRecord[];
    profileId: string;
    chainIdKey: string;
    signerId: string;
    activationPolicy: ActivateAccountSignerInput['activationPolicy'];
  }): AccountSignerRecord[] {
    const retired: AccountSignerRecord[] = [];
    switch (args.activationPolicy.mode) {
      case 'replace_slot':
        for (const signer of args.accountActiveSigners) {
          if (
            signer.signerSlot === args.activationPolicy.signerSlot &&
            signer.signerId !== args.signerId
          ) {
            retired.push(signer);
          }
        }
        return retired;
      case 'replace_profile_chain_kind':
        for (const signer of args.allActiveSigners) {
          if (
            signer.profileId === args.profileId &&
            signer.chainIdKey === args.chainIdKey &&
            signer.signerKind === args.activationPolicy.replacedSignerKind &&
            signer.signerId !== args.signerId
          ) {
            retired.push(signer);
          }
        }
        return retired;
      default:
        return retired;
    }
  }

  private async revokeSignersForReplacement(args: {
    signerStore: any;
    allActiveSigners: AccountSignerRecord[];
    accountActiveSigners: AccountSignerRecord[];
    profileId: string;
    chainIdKey: string;
    accountModel: string;
    signerId: string;
    activationPolicy: ActivateAccountSignerInput['activationPolicy'];
    now: number;
  }): Promise<void> {
    const retired = this.signersRetiredByActivationPolicy(args);
    if (retired.length === 0) return;
    const revocationReason = toTrimmedString(
      args.activationPolicy.mode === 'replace_slot' ||
        args.activationPolicy.mode === 'replace_profile_chain_kind'
        ? args.activationPolicy.revocationReason
        : '',
    );
    for (const signer of retired) {
      const revoked = this.buildAccountSignerRecord({
        ...signer,
        status: 'revoked',
        existing: signer,
        now: args.now,
        removedAt: args.now,
        revocationReason,
      });
      this.assertSignerWriteInvariants({
        next: revoked,
        accountModel: args.accountModel,
        existingStatus: signer.status,
        activeSigners: args.accountActiveSigners,
      });
      await args.signerStore.put(accountSignerRow(revoked));
    }
  }

  async activateAccountSigner(
    input: ActivateAccountSignerInput,
  ): Promise<ActivateAccountSignerResult> {
    let result: ActivateAccountSignerResult | null = null;
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.signerOpsOutbox,
      ],
      'readwrite',
      async (ctx) => {
        result = await this.activateAccountSignerInTransaction(ctx, input);
      },
    );
    if (!result) throw new Error('[SeamsWalletDB] signer activation did not complete');
    return result;
  }

  async stageAccountSigner(input: StageAccountSignerInput): Promise<StageAccountSignerResult> {
    return this.writePreparedAccountSigner({
      account: input.account,
      signer: input.signer,
      status: 'pending',
      signerSlot: input.signer.signerSlot,
      mutation: input.mutation,
    });
  }

  private async writePreparedAccountSigner(input: {
    account: StageAccountSignerInput['account'];
    signer: StageAccountSignerInput['signer'];
    status: AccountSignerStatus;
    signerSlot: number;
    mutation?: SignerMutationOptions;
  }): Promise<StageAccountSignerResult> {
    const profileId = toTrimmedString(input.account.profileId || '');
    const chainIdKey = normalizeIndexedDbChainIdKey(input.account.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(input.account.accountAddress);
    const accountModel = normalizeIndexedDbAccountModel(input.account.accountModel);
    const signerId = toTrimmedString(input.signer.signerId || '');
    const signerSlot = Number(input.signerSlot);
    const signerKind = toTrimmedString(
      input.signer.signerKind || '',
    ) as AccountSignerRecord['signerKind'];
    const signerAuthMethod = toTrimmedString(
      input.signer.signerAuthMethod || '',
    ) as AccountSignerRecord['signerAuthMethod'];
    const signerSource = toTrimmedString(
      input.signer.signerSource || '',
    ) as AccountSignerRecord['signerSource'];
    if (
      !profileId ||
      !chainIdKey ||
      !accountAddress ||
      !accountModel ||
      !signerId ||
      !signerKind ||
      !signerAuthMethod ||
      !signerSource
    ) {
      throw new Error(
        '[SeamsWalletDB] profileId, chainIdKey, accountAddress, accountModel, signerId, signerKind, signerAuthMethod, and signerSource are required',
      );
    }
    if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
      throw new Error('[SeamsWalletDB] signerSlot must be an integer >= 1');
    }

    let result: StageAccountSignerResult | null = null;
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.signerOpsOutbox,
      ],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(profileId),
        );
        if (!profile) {
          throw makeConstraintError(
            'MISSING_PROFILE',
            `Cannot upsert signer without profile row: ${profileId}`,
            { profileId, chainIdKey, accountAddress, signerId },
          );
        }
        const chainAccountStore = ctx.store(SEAMS_WALLET_STORES.nearAccountProjections);
        const existingChainAccount = parseChainAccountProjectionRow(
          await chainAccountStore.get([
            profileId,
            chainAccountProjectionId({ chainIdKey, accountAddress }),
            CHAIN_ACCOUNT_PROJECTION_SIGNER_SLOT,
          ]),
        );
        const chainAccount = chainAccountProjectionRow(
          {
            profileId,
            chainIdKey,
            accountAddress,
            accountModel,
            isPrimary: existingChainAccount?.isPrimary,
          },
          existingChainAccount || undefined,
        );
        await chainAccountStore.put(chainAccount);
        const signerStore = ctx.store(SEAMS_WALLET_STORES.walletSigners);
        const existingSigner = parseAccountSignerRow(
          await signerStore.get(walletSignerId({ chainIdKey, accountAddress, signerId })),
        );
        if (existingSigner && existingSigner.profileId !== profileId) {
          throw makeConstraintError(
            'CHAIN_ACCOUNT_PROFILE_MISMATCH',
            `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
            { expectedProfileId: profileId, existingProfileId: existingSigner.profileId },
          );
        }
        const activeRows = (await signerStore
          .index(SEAMS_WALLET_INDEXES.status)
          .getAll('active')) as unknown[];
        const activeSigners = activeRows.flatMap((row) => {
          const parsed = parseAccountSignerRow(row);
          return parsed &&
            parsed.chainIdKey === chainIdKey &&
            parsed.accountAddress === accountAddress
            ? [parsed]
            : [];
        });
        const now = Date.now();
        const signer = this.buildAccountSignerRecord({
          profileId,
          chainIdKey,
          accountAddress,
          signerId,
          signerSlot,
          signerType: input.signer.signerType,
          signerKind,
          signerAuthMethod,
          signerSource,
          status: input.status,
          existing: existingSigner || undefined,
          now,
          ...(input.signer.metadata ? { metadata: input.signer.metadata } : {}),
        });
        this.assertSignerWriteInvariants({
          next: signer,
          accountModel,
          existingStatus: existingSigner?.status,
          activeSigners,
        });
        const signerRow = accountSignerRow(signer);
        await deleteConflictingThresholdEcdsaSignerRows({ store: signerStore, nextRow: signerRow });
        await signerStore.put(signerRow);
        if (input.mutation?.routeThroughOutbox ?? false) {
          const opId =
            toTrimmedString(input.mutation?.opId || '') || createRandomToken('add-signer');
          const idempotencyKey =
            toTrimmedString(input.mutation?.idempotencyKey || '') ||
            `add-signer:${signer.chainIdKey}:${signer.accountAddress}:${signer.signerId}:${signer.signerSlot}`;
          await this.enqueueSignerOperationInTransaction(
            ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
            {
              opId,
              idempotencyKey,
              opType: 'add-signer',
              chainIdKey: signer.chainIdKey,
              accountAddress: signer.accountAddress,
              signerId: signer.signerId,
              payload: this.signerOutboxPayload(signer, input.mutation),
              status: input.mutation?.outboxStatus || 'queued',
            },
          );
        }
        result = { signer, signerSlot };
      },
    );
    if (!result) throw new Error('[SeamsWalletDB] signer write did not complete');
    return result;
  }

  private signerOutboxPayload(
    signer: AccountSignerRecord,
    mutation?: SignerMutationOptions,
  ): Record<string, unknown> {
    return {
      profileId: signer.profileId,
      signerSlot: signer.signerSlot,
      signerType: signer.signerType,
      signerKind: signer.signerKind,
      signerAuthMethod: signer.signerAuthMethod,
      signerSource: signer.signerSource,
      ...(signer.metadata ? { signerMetadata: signer.metadata } : {}),
      ...(mutation?.outboxPayload ? mutation.outboxPayload : {}),
    };
  }

  async listAccountSigners(args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    const chainIdKey = normalizeIndexedDbChainIdKey(args.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(args.accountAddress);
    if (!chainIdKey || !accountAddress) return [];
    const db = await this.manager.getDB();
    const rows = args.status
      ? ((await db
          .transaction(SEAMS_WALLET_STORES.walletSigners, 'readonly')
          .store.index(SEAMS_WALLET_INDEXES.status)
          .getAll(args.status)) as unknown[])
      : ((await db.getAll(SEAMS_WALLET_STORES.walletSigners)) as unknown[]);
    return rows.flatMap((row) => {
      const parsed = parseAccountSignerRow(row);
      return parsed && parsed.chainIdKey === chainIdKey && parsed.accountAddress === accountAddress
        ? [parsed]
        : [];
    });
  }

  async listAccountSignersByProfile(args: {
    profileId: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    const profileId = toTrimmedString(args.profileId || '');
    if (!profileId) return [];
    const db = await this.manager.getDB();
    const rows = (await db
      .transaction(SEAMS_WALLET_STORES.walletSigners, 'readonly')
      .store.index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(profileId)) as unknown[];
    return rows.flatMap((row) => {
      const parsed = parseAccountSignerRow(row);
      return parsed && (!args.status || parsed.status === args.status) ? [parsed] : [];
    });
  }

  /**
   * The wallet's active signers, resolved from its identity — not from a guess
   * that the wallet id is a profile key.
   *
   * Two local profile identities exist: the canonical wallet profile, keyed by
   * the wallet id and carrying NEAR provisioning, and the NEAR account profile
   * (`buildNearProfileId`), which owns the signer rows. Reading signer rows
   * with the wallet id as the profile key answered "none" for every registered
   * wallet, which surfaced far away as an unresolvable session identity and as
   * ECDSA material reporting `device_link_required` on a device that was never
   * linked.
   *
   * The pivot goes through branded constructors on purpose: only a NEAR
   * account id proven by the wallet's own provisioning record can become the
   * profile key. Rows written directly under the wallet id are still read —
   * that is the canonical wallet profile's own signer set.
   */
  async listActiveWalletSigners(args: {
    walletId: string;
    signerFamily: WalletSignerLookup['signerFamily'];
  }): Promise<AccountSignerRecord[]> {
    const walletId = toTrimmedString(args.walletId || '');
    if (!walletId) return [];
    const signerKind =
      args.signerFamily === 'ecdsa' ? SIGNER_KINDS.thresholdEcdsa : SIGNER_KINDS.thresholdEd25519;
    const profileIds = [walletId];
    const walletProfile = await this.getProfile(walletId);
    const provisioning = walletProfile?.nearProvisioning;
    if (provisioning?.status === 'near_ready' && provisioning.nearAccountId) {
      profileIds.push(String(buildNearProfileId(toAccountId(provisioning.nearAccountId))));
    }
    const collected: AccountSignerRecord[] = [];
    const seen = new Set<string>();
    for (const profileId of profileIds) {
      const signers = await this.listAccountSignersByProfile({ profileId, status: 'active' });
      for (const signer of signers) {
        if (signer.signerKind !== signerKind) continue;
        // A signer row names its wallet in metadata; a row claiming another
        // wallet must not leak in through a shared NEAR profile.
        const metadataWalletId = toTrimmedString(String(signer.metadata?.walletId ?? ''));
        if (metadataWalletId && metadataWalletId !== walletId) continue;
        const key = `${signer.chainIdKey}/${signer.accountAddress}/${signer.signerId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        collected.push(signer);
      }
    }
    return collected;
  }

  async getActiveWalletSignerForChainTarget(args: {
    walletId: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<AccountSignerRecord | null> {
    const walletId = toTrimmedString(args.walletId || '');
    if (!walletId) return null;
    const chainTargetKey = toIndexedDbChainTargetKey(args.chainTarget);
    const matches = (
      await this.listActiveWalletSigners({
        walletId,
        signerFamily: 'ecdsa',
      })
    ).filter((signer) => signer.chainIdKey === chainTargetKey);
    if (matches.length > 1) {
      throw new Error(
        `[SeamsWalletDB] ambiguous active ECDSA wallet signer for ${walletId}/${chainTargetKey}`,
      );
    }
    return matches[0] || null;
  }

  async getAccountSigner(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null> {
    const chainIdKey = normalizeIndexedDbChainIdKey(args.chainIdKey);
    const accountAddress = normalizeIndexedDbAccountAddress(args.accountAddress);
    const signerId = toTrimmedString(args.signerId || '');
    if (!chainIdKey || !accountAddress || !signerId) return null;
    const db = await this.manager.getDB();
    return parseAccountSignerRow(
      await db.get(
        SEAMS_WALLET_STORES.walletSigners,
        walletSignerId({ chainIdKey, accountAddress, signerId }),
      ),
    );
  }

  async setAccountSignerStatus(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    revocationReason?: string;
    mutation?: SignerMutationOptions;
  }): Promise<AccountSignerRecord | null> {
    const existing = await this.getAccountSigner(args);
    if (!existing) return null;
    const chainAccount = await this.getChainAccount({
      profileId: existing.profileId,
      chainIdKey: existing.chainIdKey,
      accountAddress: existing.accountAddress,
    });
    if (!chainAccount) {
      throw makeConstraintError(
        'MISSING_CHAIN_ACCOUNT',
        `Cannot update signer status without chain account row: ${existing.profileId}/${existing.chainIdKey}/${existing.accountAddress}`,
        {
          profileId: existing.profileId,
          chainIdKey: existing.chainIdKey,
          accountAddress: existing.accountAddress,
          signerId: existing.signerId,
        },
      );
    }
    let updated: AccountSignerRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.walletSigners, SEAMS_WALLET_STORES.signerOpsOutbox],
      'readwrite',
      async (ctx) => {
        const signerStore = ctx.store(SEAMS_WALLET_STORES.walletSigners);
        const activeRows = (await signerStore
          .index(SEAMS_WALLET_INDEXES.status)
          .getAll('active')) as unknown[];
        const activeSigners = activeRows.flatMap((row) => {
          const parsed = parseAccountSignerRow(row);
          return parsed &&
            parsed.chainIdKey === existing.chainIdKey &&
            parsed.accountAddress === existing.accountAddress
            ? [parsed]
            : [];
        });
        const next = this.buildAccountSignerRecord({
          ...existing,
          status: args.status,
          existing,
          now: Date.now(),
          ...(args.removedAt != null ? { removedAt: args.removedAt } : {}),
          ...(args.revocationReason ? { revocationReason: args.revocationReason } : {}),
        });
        this.assertSignerWriteInvariants({
          next,
          accountModel: chainAccount.accountModel,
          existingStatus: existing.status,
          activeSigners,
        });
        await signerStore.put(accountSignerRow(next));
        if (args.mutation?.routeThroughOutbox ?? true) {
          const opType: SignerOperationType =
            args.status === 'revoked' ? 'revoke-signer' : 'add-signer';
          const opId = toTrimmedString(args.mutation?.opId || '') || createRandomToken(opType);
          const idempotencyKey =
            toTrimmedString(args.mutation?.idempotencyKey || '') ||
            `signer-status:${args.status}:${next.chainIdKey}:${next.accountAddress}:${next.signerId}`;
          await this.enqueueSignerOperationInTransaction(
            ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
            {
              opId,
              idempotencyKey,
              opType,
              chainIdKey: next.chainIdKey,
              accountAddress: next.accountAddress,
              signerId: next.signerId,
              payload: {
                profileId: next.profileId,
                signerSlot: next.signerSlot,
                status: next.status,
                ...(next.removedAt != null ? { removedAt: next.removedAt } : {}),
                ...(next.revocationReason ? { revocationReason: next.revocationReason } : {}),
                ...(args.mutation?.outboxPayload ? args.mutation.outboxPayload : {}),
              },
              status: args.mutation?.outboxStatus || 'queued',
            },
          );
        }
        updated = next;
      },
    );
    return updated;
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    let record: SignerOpOutboxRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.signerOpsOutbox],
      'readwrite',
      async (ctx) => {
        record = await this.enqueueSignerOperationInTransaction(
          ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
          input,
        );
      },
    );
    if (!record) throw new Error('[SeamsWalletDB] signer op enqueue did not complete');
    return record;
  }

  async listSignerOperations(args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<SignerOpOutboxRecord[]> {
    const statuses =
      args?.statuses && args.statuses.length > 0
        ? args.statuses
        : (['queued', 'submitted', 'failed'] as SignerOperationStatus[]);
    const dueBeforeRaw = typeof args?.dueBefore === 'number' ? args.dueBefore : Date.now();
    const dueBefore = Number.isFinite(dueBeforeRaw) ? dueBeforeRaw : Number.MAX_SAFE_INTEGER;
    const limit =
      Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0 ? Number(args?.limit) : 100;
    const db = await this.manager.getDB();
    const collected: SignerOpOutboxRecord[] = [];
    for (const status of statuses) {
      const tx = db.transaction(SEAMS_WALLET_STORES.signerOpsOutbox, 'readonly');
      const rows = (await tx.store
        .index(SEAMS_WALLET_INDEXES.statusNextAttemptAt)
        .getAll(IDBKeyRange.bound([status, Number.MIN_SAFE_INTEGER], [status, dueBefore]))) as
        | unknown[]
        | undefined;
      await tx.done;
      collected.push(
        ...(rows || []).flatMap((row) => {
          const parsed = parseSignerOutboxRow(row);
          return parsed ? [parsed] : [];
        }),
      );
    }
    collected.sort((a, b) => {
      const timeDelta = (a.nextAttemptAt || 0) - (b.nextAttemptAt || 0);
      if (timeDelta !== 0) return timeDelta;
      return String(a.opId || '').localeCompare(String(b.opId || ''));
    });
    return collected.slice(0, limit);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<SignerOpOutboxRecord | null> {
    const opId = toTrimmedString(args.opId || '');
    if (!opId) return null;
    let updated: SignerOpOutboxRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.signerOpsOutbox],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox);
        const existing = parseSignerOutboxRow(await store.get(opId));
        if (!existing) return;
        const attemptDelta = Number.isFinite(args.attemptDelta) ? Number(args.attemptDelta) : 0;
        const attemptCount = Math.max(0, (existing.attemptCount || 0) + attemptDelta);
        const next: SignerOpOutboxRecord = {
          ...existing,
          status: args.status,
          attemptCount,
          nextAttemptAt:
            typeof args.nextAttemptAt === 'number' ? args.nextAttemptAt : existing.nextAttemptAt,
          ...(args.lastError === null
            ? { lastError: undefined }
            : typeof args.lastError === 'string'
              ? { lastError: args.lastError }
              : { lastError: existing.lastError }),
          ...(args.txHash === null
            ? { txHash: undefined }
            : typeof args.txHash === 'string'
              ? { txHash: args.txHash }
              : { txHash: existing.txHash }),
          updatedAt: Date.now(),
        };
        await store.put(signerOutboxRow(next));
        updated = next;
      },
    );
    return updated;
  }

  async getProfileContinuitySnapshot(profileId: string): Promise<ProfileContinuitySnapshot | null> {
    const profile = await this.getProfile(profileId);
    if (!profile) return null;
    return {
      profile,
      chainAccounts: await this.listChainAccountsByProfile(profile.profileId),
      accountSigners: await this.listAccountSignersByProfile({ profileId: profile.profileId }),
    };
  }

  async listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.walletIdKind)
      .getAll([normalizedProfileId, 'passkey'])) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseAuthenticatorRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async listWalletPasskeyAuthenticators(walletId: string): Promise<ProfileAuthenticatorRecord[]> {
    // Same pivot as listActiveWalletSigners: authenticators registered through
    // NEAR-account flows live under the NEAR profile, and the canonical wallet
    // profile's provisioning record is the proof linking the two identities.
    const own = await this.listProfileAuthenticators(walletId);
    const walletProfile = await this.getProfile(walletId);
    const provisioning = walletProfile?.nearProvisioning;
    if (provisioning?.status !== 'near_ready' || !provisioning.nearAccountId) return own;
    const nearProfileId = String(buildNearProfileId(toAccountId(provisioning.nearAccountId)));
    if (nearProfileId === walletId) return own;
    const nearRows = await this.listProfileAuthenticators(nearProfileId);
    const seen = new Set(own.map((record) => record.credentialId));
    return [...own, ...nearRows.filter((record) => !seen.has(record.credentialId))];
  }

  async getWalletPasskeyAuthenticator(args: {
    walletId: string;
    credentialId: string;
  }): Promise<ProfileAuthenticatorRecord | null> {
    // Same wallet/NEAR-profile pivot as listWalletPasskeyAuthenticators: an
    // authenticator registered through a NEAR-account flow lives under the
    // NEAR profile, and a direct wallet-profile lookup misses it.
    const credentialId = toTrimmedString(args.credentialId || '');
    if (!credentialId) return null;
    const records = await this.listWalletPasskeyAuthenticators(args.walletId);
    return records.find((record) => record.credentialId === credentialId) ?? null;
  }

  async upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void> {
    const normalized = normalizeAuthenticatorRecord(record);
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.wallets, SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      async (ctx) => {
        const profile = parseProfileRow(
          await ctx.store(SEAMS_WALLET_STORES.wallets).get(normalized.profileId),
        );
        if (!profile) {
          throw makeConstraintError(
            'MISSING_PROFILE',
            `Cannot upsert authenticator for unknown profile: ${normalized.profileId}`,
            { profileId: normalized.profileId, credentialId: normalized.credentialId },
          );
        }
        const store = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
        const existing = parseWalletAuthMethodStorageRow(
          await store
            .index(SEAMS_WALLET_INDEXES.passkeyRpIdCredentialId)
            .get(['passkey', DEFAULT_WALLET_RP_ID, normalized.credentialId]),
        );
        const row = walletAuthMethodRowFromAuthenticator(
          normalized,
          existing?.kind === 'passkey' ? existing : undefined,
        );
        await store.put(row);
      },
    );
  }

  async getProfileAuthenticatorByCredentialId(
    profileId: string,
    credentialId: string,
  ): Promise<ProfileAuthenticatorRecord | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedCredentialId = toTrimmedString(credentialId || '');
    if (!normalizedProfileId || !normalizedCredentialId) return null;
    const db = await this.manager.getDB();
    const row = parseAuthenticatorRow(
      await db
        .transaction(SEAMS_WALLET_STORES.walletAuthMethods, 'readonly')
        .store.index(SEAMS_WALLET_INDEXES.passkeyRpIdCredentialId)
        .get(['passkey', DEFAULT_WALLET_RP_ID, normalizedCredentialId]),
    );
    return row?.profileId === normalizedProfileId ? row : null;
  }

  async persistWalletRegistrationFinalize(
    input: StoreWalletRegistrationFinalizeBatchInput,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    return this.manager.runTransaction(
      WALLET_REGISTRATION_FINALIZE_STORES,
      'readwrite',
      this.persistWalletRegistrationFinalizeInTransaction.bind(this, input),
    );
  }

  async publishPendingWalletRegistrationCommit(
    input: PublishPendingWalletRegistrationCommitInputV1,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    const pending = buildPendingWalletRegistrationCommitV1(input.pending);
    const authority = parseWalletAuthAuthority(input.authority);
    if (!authority) {
      throw new Error('registration wallet auth authority is invalid');
    }
    const foundingAuthority = validateFoundingWalletAuthorityInput(input.foundingAuthority);
    await assertRegistrationFinalizeMatchesPending({
      request: input.request,
      pending,
      authority,
      foundingAuthority,
      registration: input.registration,
    });
    const walletSession = input.walletSessionPublication.walletSession;
    if (
      walletSession.walletId !== pending.walletId ||
      walletSession.authorityId !== foundingAuthority.authority.authorityId ||
      walletSession.authMethodId !== pending.walletAuthMethodId ||
      walletSession.authorityDigestB64u !== foundingAuthority.authority.authorityDigestB64u ||
      walletSession.authorityRevocationEpoch !== foundingAuthority.authority.revocationEpoch
    ) {
      throw new Error('registration Wallet Session identity does not match the pending wallet');
    }
    return this.manager.runTransaction(
      WALLET_REGISTRATION_PUBLICATION_STORES,
      'readwrite',
      this.publishPendingWalletRegistrationCommitInTransaction.bind(this, {
        request: input.request,
        pending,
        authority,
        foundingAuthority,
        registration: input.registration,
        walletSessionPublication: input.walletSessionPublication,
      }),
    );
  }

  async publishPendingWalletRecoveryCommit(
    input: PublishPendingWalletRecoveryCommitInputV1,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    const pending = await buildPendingWalletRecoveryCommitV1(input.pending);
    if (pending.stage !== 'server_promoted') {
      throw new Error('pending wallet recovery commit is not server-promoted');
    }
    const authorityResult = parseWalletAuthorityV1(input.authority);
    const authority = requireBoundaryParsed(authorityResult, 'authority');
    if (authority.state !== 'active' || !isActiveRecoveredWalletAuthorityV1(authority)) {
      throw new Error('recovered Wallet Authority projection is invalid');
    }
    const authMethod = parseWalletAuthMethodRecordV2(input.authMethod);
    if (!authMethod || authMethod.status !== 'active') {
      throw new Error('recovered Wallet Auth Method projection is invalid');
    }
    if (!(await walletAuthorityDigestsMatchV1(authority))) {
      throw new Error('recovered Wallet Authority digest is invalid');
    }
    const normalizedInput: PublishPendingWalletRecoveryCommitInputV1 = {
      pending,
      authority,
      authMethod,
      registration: input.registration,
    };
    assertPendingWalletRecoveryPublicationMatchesProjection(normalizedInput);
    const pendingRow = await toPendingWalletRecoveryCommitAppStateRow(pending);
    return this.manager.runTransaction(
      WALLET_RECOVERY_PUBLICATION_STORES,
      'readwrite',
      this.publishPendingWalletRecoveryCommitInTransaction.bind(this, {
        ...normalizedInput,
        pendingRow,
      }),
    );
  }

  private async publishPendingWalletRegistrationCommitInTransaction(
    input: {
      readonly request: WalletRegistrationCommitPublicationRequestV1;
      readonly pending: PendingWalletRegistrationCommitV1;
      readonly authority: WalletAuthAuthority;
      readonly foundingAuthority: ValidatedFoundingWalletAuthorityInputV1;
      readonly registration: StoreWalletRegistrationPublicationInputV1;
      readonly walletSessionPublication: WalletRegistrationSessionPublicationV1;
    },
    ctx: SeamsWalletTransactionContext,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    const pendingKey = pendingWalletRegistrationCommitAppStateKey({
      registrationCeremonyId: input.request.registrationCeremonyId,
      operation: input.request.operation,
    });
    const storedPendingRow = parsePendingWalletRegistrationCommitAppStateRow(
      await ctx.store(SEAMS_WALLET_STORES.appState).get(pendingKey),
    );
    const storedPending = storedPendingRow?.record;
    if (storedPending) {
      assertPendingWalletRegistrationRequestIdentity(storedPending, input.request);
    }
    if (
      !storedPendingRow ||
      !storedPending ||
      storedPendingRow?.registration_ceremony_id !== input.request.registrationCeremonyId ||
      storedPendingRow.operation !== input.request.operation ||
      storedPendingRow.wallet_id !== input.request.walletId ||
      storedPendingRow.wallet_auth_method_id !== input.request.walletAuthMethodId ||
      storedPendingRow.updated_at_ms !== input.pending.updatedAtMs ||
      alphabetizeStringify(storedPending) !== alphabetizeStringify(input.pending)
    ) {
      throw new Error('stored pending wallet registration commit does not match the expected row');
    }
    let credentialFreeSessionReconciled = false;
    if (input.walletSessionPublication.kind === 'issued') {
      await replaceExactActiveWalletSessionAuthorizationInTransaction({
        ctx,
        active: input.walletSessionPublication.walletSession,
        operationCredential: input.walletSessionPublication.operationCredential,
      });
    } else {
      const existingSession = await readExactActiveWalletSessionForScopeInTransaction({
        ctx,
        walletId: input.pending.walletId,
        authorityId: input.foundingAuthority.authority.authorityId,
        authMethodId: input.pending.walletAuthMethodId,
      });
      if (existingSession.kind !== 'found') {
        throw new Error(
          'Credential-free registration projection has no exact local Wallet Session',
        );
      }
      assertCredentialFreeRegistrationSessionProjectionMatchesExisting({
        incoming: input.walletSessionPublication.walletSession,
        existing: existingSession.record,
      });
      await replaceExactActiveWalletSessionAuthorizationInTransaction({
        ctx,
        active: input.walletSessionPublication.walletSession,
        operationCredential: existingSession.operationCredential,
      });
      credentialFreeSessionReconciled = true;
    }
    const result = await this.persistWalletRegistrationFinalizeInTransaction(
      input.registration,
      ctx,
    );
    await this.persistFoundingWalletAuthorityInTransaction(input.foundingAuthority, ctx);
    const shouldDeletePending =
      input.walletSessionPublication.kind === 'issued'
        ? shouldDeletePublishedPendingWalletRegistrationCommit(input.pending)
        : credentialFreeSessionReconciled;
    if (shouldDeletePending) {
      await ctx.store(SEAMS_WALLET_STORES.appState).delete(pendingKey);
    }
    return result;
  }

  private async publishPendingWalletRecoveryCommitInTransaction(
    input: PublishPendingWalletRecoveryCommitInputV1 & {
      readonly pendingRow: PendingWalletRecoveryCommitAppStateRow;
    },
    ctx: SeamsWalletTransactionContext,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    const storedPending = await ctx.store(SEAMS_WALLET_STORES.appState).get(input.pendingRow.key);
    if (!pendingWalletRecoveryCommitAppStateRowsMatch(storedPending, input.pendingRow)) {
      throw new Error('stored pending wallet recovery commit does not match the expected row');
    }
    const result = await this.persistWalletRegistrationFinalizeInTransaction(
      input.registration,
      ctx,
    );
    await this.persistRecoveredWalletAuthorityInTransaction(
      {
        authority: input.authority,
        authMethod: input.authMethod,
        recoveredAtMs: input.pending.updatedAtMs,
      },
      ctx,
    );
    await ctx.store(SEAMS_WALLET_STORES.appState).delete(input.pendingRow.key);
    return result;
  }

  private async persistWalletRegistrationFinalizeInTransaction(
    input: StoreWalletRegistrationFinalizeBatchInput,
    ctx: SeamsWalletTransactionContext,
  ): Promise<StoreWalletRegistrationFinalizeBatchResult> {
    const authMethodRows = walletAuthMethodRowsForRegistrationFinalize(input);
    const keyMaterialRows = input.keyMaterials.map((keyMaterial) => keyMaterialRow(keyMaterial));
    const signerActivations: ActivateAccountSignerResult[] = [];
    const profileStore = ctx.store(SEAMS_WALLET_STORES.wallets);
    for (const profile of input.profiles) {
      const profileId = toTrimmedString(profile.profileId || '');
      if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
      const existing = parseProfileRow(await profileStore.get(profileId)) || undefined;
      await profileStore.put(profileRow(profile, existing));
    }
    const authMethodStore = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
    for (const row of authMethodRows) {
      const profile = parseProfileRow(await profileStore.get(row.wallet_id));
      if (!profile) {
        throw makeConstraintError(
          'MISSING_PROFILE',
          `Cannot upsert auth method for unknown wallet: ${row.wallet_id}`,
          {
            profileId: row.wallet_id,
            authIdentifierKey: row.auth_identifier_key,
          },
        );
      }
      await authMethodStore.put(row);
    }
    for (const activation of input.signerActivations) {
      signerActivations.push(await this.activateAccountSignerInTransaction(ctx, activation));
    }
    await assertSignerKeyMaterialPairsInTransaction({
      ctx,
      signers: signerActivations.map((activation) => activation.signer),
      keyMaterials: input.keyMaterials,
    });
    const keyMaterialStore = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
    for (const row of keyMaterialRows) {
      await keyMaterialStore.put(row);
    }
    if (input.lastProfileState) {
      await ctx.store(SEAMS_WALLET_STORES.appState).put({
        key: scopedLastProfileStateAppStateKey(input.lastProfileState.scope),
        value: {
          profileId: input.lastProfileState.profileId,
          activeSignerSlot: input.lastProfileState.activeSignerSlot,
          ...(input.lastProfileState.scope
            ? { scope: normalizeLastUserScope(input.lastProfileState.scope) }
            : {}),
        },
      });
    }
    return { signerActivations };
  }

  async persistWalletSignerFinalize(
    input: StoreWalletSignerFinalizeBatchInput,
  ): Promise<StoreWalletSignerFinalizeBatchResult> {
    const keyMaterialRows = input.keyMaterials.map((keyMaterial) => keyMaterialRow(keyMaterial));
    const signerActivations: ActivateAccountSignerResult[] = [];
    const profiles: Array<{
      committed: ProfileRecord;
      previous: ProfileRecord | null;
    }> = [];
    let lastProfileState: StoreWalletSignerFinalizeRollbackReceipt['lastProfileState'] = null;
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.signerOpsOutbox,
        SEAMS_WALLET_STORES.keyMaterial,
      ],
      'readwrite',
      async (ctx) => {
        const profileStore = ctx.store(SEAMS_WALLET_STORES.wallets);
        if (input.lastProfileState) {
          const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);
          const key = scopedLastProfileStateAppStateKey(input.lastProfileState.scope);
          const previousRow = (await appStateStore.get(key)) as AppStateRow | undefined;
          const committed: LastProfileState = {
            profileId: input.lastProfileState.profileId,
            activeSignerSlot: input.lastProfileState.activeSignerSlot,
            ...(input.lastProfileState.scope
              ? { scope: normalizeLastUserScope(input.lastProfileState.scope) }
              : {}),
          };
          lastProfileState = {
            key,
            committed,
            previousPresent: previousRow !== undefined,
            previousValue: previousRow?.value,
          };
        }
        for (const profile of input.profiles) {
          const profileId = toTrimmedString(profile.profileId || '');
          if (!profileId) throw new Error('[SeamsWalletDB] profileId is required');
          const existing = parseProfileRow(await profileStore.get(profileId));
          const committedRow = profileRow(profile, existing || undefined);
          await profileStore.put(committedRow);
          profiles.push({
            committed: committedRow.record,
            previous: existing,
          });
        }

        for (const activation of input.signerActivations) {
          signerActivations.push(await this.activateAccountSignerInTransaction(ctx, activation));
        }
        await assertSignerKeyMaterialPairsInTransaction({
          ctx,
          signers: signerActivations.map((activation) => activation.signer),
          keyMaterials: input.keyMaterials,
        });

        const keyMaterialStore = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
        for (const row of keyMaterialRows) {
          await keyMaterialStore.put(row);
        }

        if (input.lastProfileState) {
          const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);
          if (!lastProfileState) {
            throw new Error('[SeamsWalletDB] last profile rollback state was not captured');
          }
          await appStateStore.put({
            key: lastProfileState.key,
            value: lastProfileState.committed,
          });
        }
      },
    );
    return {
      signerActivations,
      rollbackReceipt: {
        kind: 'wallet_signer_finalize_rollback_v1',
        profiles,
        signers: signerActivations.map((activation) => activation.signer),
        keyMaterials: keyMaterialRows.map((row) => row.record),
        lastProfileState,
      },
    };
  }

  async rollbackWalletSignerFinalize(
    receipt: StoreWalletSignerFinalizeRollbackReceipt,
  ): Promise<void> {
    if (receipt.kind !== 'wallet_signer_finalize_rollback_v1') {
      throw new Error('[SeamsWalletDB] invalid wallet signer rollback receipt');
    }
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.keyMaterial,
      ],
      'readwrite',
      async (ctx) => {
        const profileStore = ctx.store(SEAMS_WALLET_STORES.wallets);
        const signerStore = ctx.store(SEAMS_WALLET_STORES.walletSigners);
        const keyMaterialStore = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
        const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);

        for (const profile of receipt.profiles) {
          const current = parseProfileRow(await profileStore.get(profile.committed.profileId));
          if (!rollbackRecordsEqual(current, profile.committed)) {
            throw new Error('[SeamsWalletDB] wallet signer rollback profile changed');
          }
        }
        for (const signer of receipt.signers) {
          const id = walletSignerId({
            chainIdKey: signer.chainIdKey,
            accountAddress: signer.accountAddress,
            signerId: signer.signerId,
          });
          const current = parseAccountSignerRow(await signerStore.get(id));
          if (!rollbackRecordsEqual(current, signer)) {
            throw new Error('[SeamsWalletDB] wallet signer rollback signer changed');
          }
        }
        for (const keyMaterial of receipt.keyMaterials) {
          const id = keyMaterialId({
            walletSignerId: walletSignerIdForKeyMaterial(keyMaterial),
            keyKind: keyMaterial.keyKind,
          });
          const current = parseKeyMaterialRow(await keyMaterialStore.get(id));
          if (!rollbackRecordsEqual(current, keyMaterial)) {
            throw new Error('[SeamsWalletDB] wallet signer rollback key material changed');
          }
        }
        if (receipt.lastProfileState) {
          const current = parseLastProfileState(
            ((await appStateStore.get(receipt.lastProfileState.key)) as AppStateRow | undefined)
              ?.value,
          );
          if (!rollbackRecordsEqual(current, receipt.lastProfileState.committed)) {
            throw new Error('[SeamsWalletDB] wallet signer rollback selection changed');
          }
        }

        for (const signer of receipt.signers) {
          await signerStore.delete(
            walletSignerId({
              chainIdKey: signer.chainIdKey,
              accountAddress: signer.accountAddress,
              signerId: signer.signerId,
            }),
          );
        }
        for (const keyMaterial of receipt.keyMaterials) {
          await keyMaterialStore.delete(
            keyMaterialId({
              walletSignerId: walletSignerIdForKeyMaterial(keyMaterial),
              keyKind: keyMaterial.keyKind,
            }),
          );
        }
        for (const profile of receipt.profiles) {
          if (profile.previous) {
            await profileStore.put(profileRowFromRecord(profile.previous));
          } else {
            await profileStore.delete(profile.committed.profileId);
          }
        }
        if (receipt.lastProfileState) {
          if (receipt.lastProfileState.previousPresent) {
            await appStateStore.put({
              key: receipt.lastProfileState.key,
              value: receipt.lastProfileState.previousValue,
            });
          } else {
            await appStateStore.delete(receipt.lastProfileState.key);
          }
        }
      },
    );
  }

  async clearProfileAuthenticators(profileId: string): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.walletAuthMethods],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.walletAuthMethods);
        let cursor = await store
          .index(SEAMS_WALLET_INDEXES.walletIdKind)
          .openCursor(IDBKeyRange.only([normalizedProfileId, 'passkey']));
        while (cursor) {
          await cursor.delete();
          cursor = await cursor.continue();
        }
      },
    );
  }

  async selectProfileAuthenticatorsForPrompt(args: {
    profileId: string;
    authenticators: ProfileAuthenticatorRecord[];
    selectedCredentialRawId?: string;
    accountLabel?: string;
  }): Promise<{
    authenticatorsForPrompt: ProfileAuthenticatorRecord[];
    wrongPasskeyError?: string;
  }> {
    const profileId = toTrimmedString(args.profileId || '');
    const authenticators = Array.isArray(args.authenticators) ? args.authenticators : [];
    if (!profileId || authenticators.length <= 1) {
      return { authenticatorsForPrompt: authenticators };
    }

    const lastProfileState = await this.getLastProfileState().catch(() => null);
    if (!lastProfileState) {
      return { authenticatorsForPrompt: authenticators };
    }

    const expectedSignerSlot = Number(lastProfileState.activeSignerSlot);
    const bySignerSlot = authenticators.filter((authenticator) => {
      return authenticator.signerSlot === expectedSignerSlot;
    });
    const expectedCredentialId = toTrimmedString(
      bySignerSlot[0]?.credentialId || authenticators[0]?.credentialId || '',
    );
    const byCredentialId = expectedCredentialId
      ? authenticators.filter(
          (authenticator) => authenticator.credentialId === expectedCredentialId,
        )
      : [];
    const authenticatorsForPrompt =
      byCredentialId.length > 0
        ? byCredentialId
        : bySignerSlot.length > 0
          ? bySignerSlot
          : authenticators;

    const selectedCredentialRawId = toTrimmedString(args.selectedCredentialRawId || '');
    const accountLabel = toTrimmedString(args.accountLabel || profileId);
    const wrongPasskeyError =
      selectedCredentialRawId &&
      expectedCredentialId &&
      selectedCredentialRawId !== expectedCredentialId
        ? `You have multiple passkeys for account ${accountLabel}, ` +
          'but used a different passkey than the most recently logged-in one. ' +
          'Please use the passkey for the most recently active signer.'
        : undefined;

    return { authenticatorsForPrompt, wrongPasskeyError };
  }

  async updatePreferences(args: {
    profileId: string;
    preferences: Partial<UserPreferences>;
  }): Promise<UserPreferences | null> {
    const profileId = toTrimmedString(args.profileId || '');
    if (!profileId) return null;
    let updatedPreferences: UserPreferences | null = null;
    await this.manager.runTransaction([SEAMS_WALLET_STORES.wallets], 'readwrite', async (ctx) => {
      const store = ctx.store(SEAMS_WALLET_STORES.wallets);
      const profile = parseProfileRow(await store.get(profileId));
      if (!profile) return;
      updatedPreferences = {
        ...(profile.preferences || {}),
        ...args.preferences,
      } as UserPreferences;
      const next = profileRow(
        {
          profileId: profile.profileId,
          defaultSignerSlot: profile.defaultSignerSlot,
          preferences: updatedPreferences,
          ...(profile.passkeyCredential ? { passkeyCredential: profile.passkeyCredential } : {}),
        },
        profile,
      );
      await store.put(next);
    });
    return updatedPreferences;
  }

  async updateWalletPreferences(args: {
    walletId: string;
    preferences: Partial<UserPreferences>;
  }): Promise<UserPreferences | null> {
    const walletId = toTrimmedString(args.walletId || '');
    if (!walletId) return null;
    return await this.updatePreferences({
      profileId: walletId,
      preferences: args.preferences,
    });
  }

  async deleteProfileData(profileId: string, scope?: string | null): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    if (!normalizedProfileId) return;
    await this.manager.runTransaction(
      [
        SEAMS_WALLET_STORES.appState,
        SEAMS_WALLET_STORES.wallets,
        SEAMS_WALLET_STORES.walletAuthMethods,
        SEAMS_WALLET_STORES.walletSigners,
        SEAMS_WALLET_STORES.nearAccountProjections,
        SEAMS_WALLET_STORES.signerOpsOutbox,
        SEAMS_WALLET_STORES.keyMaterial,
      ],
      'readwrite',
      async (ctx) => {
        const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);
        const unscopedLastProfile = parseLastProfileState(
          (await appStateStore.get(scopedLastProfileStateAppStateKey()))?.value,
        );
        if (unscopedLastProfile?.profileId === normalizedProfileId) {
          await appStateStore.put({ key: scopedLastProfileStateAppStateKey(), value: null });
        }
        const scopedKey = scopedLastProfileStateAppStateKey(scope);
        if (scopedKey !== scopedLastProfileStateAppStateKey()) {
          const scopedLastProfile = parseLastProfileState(
            (await appStateStore.get(scopedKey))?.value,
          );
          if (scopedLastProfile?.profileId === normalizedProfileId) {
            await appStateStore.put({ key: scopedKey, value: null });
          }
        }

        await ctx.store(SEAMS_WALLET_STORES.wallets).delete(normalizedProfileId);
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.walletAuthMethods),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.walletSigners),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.nearAccountProjections),
          indexName: SEAMS_WALLET_INDEXES.profileId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.signerOpsOutbox),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
        await deleteRowsByIndex({
          store: ctx.store(SEAMS_WALLET_STORES.keyMaterial),
          indexName: SEAMS_WALLET_INDEXES.walletId,
          key: IDBKeyRange.only(normalizedProfileId),
        });
      },
    );
  }

  async getLastProfileState(scope?: string | null): Promise<LastProfileState | null> {
    const key = scopedLastProfileStateAppStateKey(scope);
    const scopedRaw = await this.getAppState<unknown>(key).catch(() => undefined);
    return parseLastProfileState(scopedRaw);
  }

  async setLastProfileState(state: LastProfileState | null, scope?: string | null): Promise<void> {
    const key = scopedLastProfileStateAppStateKey(scope);
    const normalizedState = state ? parseLastProfileState(state) : null;
    if (state && !normalizedState) {
      throw new Error('[SeamsWalletDB] invalid last profile state');
    }
    await this.setAppState(key, normalizedState);
  }

  async setLastProfileStateForProfile(
    profileId: string,
    activeSignerSlot: number,
    scope?: string | null,
  ): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedActiveSignerSlot = Number(activeSignerSlot);
    if (!normalizedProfileId) {
      throw new Error('[SeamsWalletDB] profileId is required');
    }
    if (!Number.isSafeInteger(normalizedActiveSignerSlot) || normalizedActiveSignerSlot < 1) {
      throw new Error('[SeamsWalletDB] activeSignerSlot must be an integer >= 1');
    }
    const normalizedScope = normalizeLastUserScope(scope);
    await this.setLastProfileState(
      {
        profileId: normalizedProfileId,
        activeSignerSlot: normalizedActiveSignerSlot,
        ...(normalizedScope ? { scope: normalizedScope } : {}),
      },
      normalizedScope,
    );
  }

  async clearLastProfileSelection(scope?: string | null): Promise<void> {
    await this.setLastProfileState(null, scope);
  }

  async storeKeyMaterial(data: KeyMaterialRecord): Promise<void> {
    const row = keyMaterialRow(data);
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.keyMaterial],
      'readwrite',
      async (ctx) => {
        await ctx.store(SEAMS_WALLET_STORES.keyMaterial).put(row);
      },
    );
  }

  async getKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<KeyMaterialRecord | null> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainIdKey || !normalizedKeyKind) return null;
    let selected: KeyMaterialRecord | null = null;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.keyMaterial, SEAMS_WALLET_STORES.walletSigners],
      'readonly',
      async (ctx) => {
        const keyMaterialRows = (await ctx
          .store(SEAMS_WALLET_STORES.keyMaterial)
          .index(SEAMS_WALLET_INDEXES.walletId)
          .getAll(normalizedProfileId)) as unknown[];
        const matches = keyMaterialRows.flatMap((row) => {
          const parsed = parseKeyMaterialRow(row);
          return parsed &&
            parsed.signerSlot === signerSlot &&
            parsed.chainIdKey === normalizedChainIdKey &&
            parsed.keyKind === normalizedKeyKind
            ? [parsed]
            : [];
        });
        if (matches.length === 0) {
          selected = null;
          return;
        }
        const signerRows = (await ctx
          .store(SEAMS_WALLET_STORES.walletSigners)
          .index(SEAMS_WALLET_INDEXES.walletId)
          .getAll(normalizedProfileId)) as unknown[];
        const activeSigners = signerRows.flatMap((row) => {
          const parsed = parseAccountSignerRow(row);
          return parsed?.status === 'active' &&
            parsed.signerSlot === signerSlot &&
            parsed.chainIdKey === normalizedChainIdKey
            ? [parsed]
            : [];
        });
        selected = selectKeyMaterialForRead({ matches, activeSigners });
      },
    );
    return selected;
  }

  async listKeyMaterialByProfile(
    profileId: string,
    chainIdKey?: string,
  ): Promise<KeyMaterialRecord[]> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    if (!normalizedProfileId) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.keyMaterial, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.walletId)
      .getAll(normalizedProfileId)) as unknown[];
    await tx.done;
    const records = rows.flatMap((row) => {
      const parsed = parseKeyMaterialRow(row);
      return parsed ? [parsed] : [];
    });
    if (!normalizedChainIdKey) return records;
    return records.filter((record) => record.chainIdKey === normalizedChainIdKey);
  }

  async listKeyMaterialByProfileAndSignerSlot(
    profileId: string,
    signerSlot: number,
    chainIdKey?: string,
  ): Promise<KeyMaterialRecord[]> {
    if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) return [];
    const records = await this.listKeyMaterialByProfile(profileId, chainIdKey);
    return records.filter((record) => record.signerSlot === signerSlot);
  }

  async deleteKeyMaterial(
    profileId: string,
    signerSlot: number,
    chainIdKey: string,
    keyKind: KeyMaterialKind,
  ): Promise<void> {
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainIdKey = toTrimmedString(chainIdKey || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainIdKey || !normalizedKeyKind) return;
    if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.keyMaterial],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
        const rows = (await store
          .index(SEAMS_WALLET_INDEXES.walletId)
          .getAll(normalizedProfileId)) as unknown[];
        for (const row of rows) {
          const parsed = parseKeyMaterialRow(row);
          if (
            parsed &&
            parsed.signerSlot === signerSlot &&
            parsed.chainIdKey === normalizedChainIdKey &&
            parsed.keyKind === normalizedKeyKind
          ) {
            await store.delete(
              keyMaterialId({
                walletSignerId: walletSignerIdForKeyMaterial(parsed),
                keyKind: parsed.keyKind,
              }),
            );
          }
        }
      },
    );
  }

  async finalizeKeyMaterialRecovery(
    input: AtomicKeyMaterialRecoveryFinalizationInput,
  ): Promise<void> {
    const journalKey = toTrimmedString(input.journalKey || '');
    if (!journalKey) throw new Error('[SeamsWalletDB] recovery journal key is required');
    const replacementRow = keyMaterialRow(input.replacement);
    const retireProfileId = toTrimmedString(input.retire.profileId || '');
    const retireChainIdKey = toTrimmedString(input.retire.chainIdKey || '').toLowerCase();
    const retireKeyKind = toTrimmedString(input.retire.keyKind || '');
    if (
      !retireProfileId ||
      !retireChainIdKey ||
      !retireKeyKind ||
      !Number.isSafeInteger(input.retire.signerSlot) ||
      input.retire.signerSlot < 1
    ) {
      throw new Error('[SeamsWalletDB] recovery source coordinates are invalid');
    }
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.appState, SEAMS_WALLET_STORES.keyMaterial],
      'readwrite',
      async (ctx) => {
        const appStateStore = ctx.store(SEAMS_WALLET_STORES.appState);
        const journal = (await appStateStore.get(journalKey)) as AppStateRow<unknown> | undefined;
        if (
          !journal ||
          alphabetizeStringify(journal.value) !== alphabetizeStringify(input.expectedJournal)
        ) {
          throw new Error('[SeamsWalletDB] recovery journal changed before finalization');
        }
        const keyMaterialStore = ctx.store(SEAMS_WALLET_STORES.keyMaterial);
        await keyMaterialStore.put(replacementRow);
        const rows = (await keyMaterialStore
          .index(SEAMS_WALLET_INDEXES.walletId)
          .getAll(retireProfileId)) as unknown[];
        for (const row of rows) {
          const parsed = parseKeyMaterialRow(row);
          if (
            parsed &&
            parsed.signerSlot === input.retire.signerSlot &&
            parsed.chainIdKey === retireChainIdKey &&
            parsed.keyKind === retireKeyKind
          ) {
            await keyMaterialStore.delete(
              keyMaterialId({
                walletSignerId: walletSignerIdForKeyMaterial(parsed),
                keyKind: parsed.keyKind,
              }),
            );
          }
        }
        await appStateStore.delete(journalKey);
      },
    );
  }

  async readNonceLaneLeaseRecords(laneKey: string): Promise<NonceLaneLeaseStoreRecord[]> {
    const normalizedLaneKey = toTrimmedString(laneKey || '');
    if (!normalizedLaneKey) return [];
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.nonceLaneLeases, 'readonly');
    const rows = (await tx.store
      .index(SEAMS_WALLET_INDEXES.laneKey)
      .getAll(normalizedLaneKey)) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseNonceLeaseRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async listNonceLaneLeaseRecords(args?: {
    walletId?: string;
  }): Promise<NonceLaneLeaseStoreRecord[]> {
    const walletId = toTrimmedString(args?.walletId || '');
    const db = await this.manager.getDB();
    const tx = db.transaction(SEAMS_WALLET_STORES.nonceLaneLeases, 'readonly');
    const rows = (
      walletId
        ? await tx.store.index(SEAMS_WALLET_INDEXES.walletId).getAll(walletId)
        : await tx.store.getAll()
    ) as unknown[];
    await tx.done;
    return rows.flatMap((row) => {
      const parsed = parseNonceLeaseRow(row);
      return parsed ? [parsed] : [];
    });
  }

  async upsertNonceLaneLeaseRecord(record: NonceLaneLeaseStoreRecord): Promise<void> {
    const row = nonceLeaseRow(record);
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        await ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases).put(row);
      },
    );
  }

  async removeNonceLaneLeaseRecord(input: { leaseId: string }): Promise<void> {
    const leaseId = toTrimmedString(input.leaseId || '');
    if (!leaseId) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        await ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases).delete(leaseId);
      },
    );
  }

  async clearNonceLaneLeaseRecordsForWallet(walletId: string): Promise<void> {
    const normalizedWalletId = toTrimmedString(walletId || '');
    if (!normalizedWalletId) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases);
        const rows = (await store
          .index(SEAMS_WALLET_INDEXES.walletId)
          .getAll(normalizedWalletId)) as unknown[];
        for (const row of rows) {
          const parsed = parseNonceLeaseRow(row);
          if (parsed && parsed.state !== 'broadcast_accepted') {
            await store.delete(parsed.leaseId);
          }
        }
      },
    );
  }

  async clearAllNonceLaneLeaseRecords(): Promise<void> {
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        await ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases).clear();
      },
    );
  }

  async pruneExpiredNonceLaneLeaseRecords(nowMs: number): Promise<void> {
    const normalizedNow = Math.floor(Number(nowMs));
    if (!Number.isSafeInteger(normalizedNow)) return;
    await this.manager.runTransaction(
      [SEAMS_WALLET_STORES.nonceLaneLeases],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLeases);
        const rows = (await store
          .index(SEAMS_WALLET_INDEXES.expiresAtMs)
          .getAll(keyRangeUpperBound(normalizedNow))) as unknown[];
        for (const row of rows) {
          const parsed = parseNonceLeaseRow(row);
          if (parsed && parsed.state !== 'broadcast_accepted') {
            await store.delete(parsed.leaseId);
          }
        }
      },
    );
  }

  async withNonceLaneCoordinationLock<T>(
    input: {
      lockKey: string;
      ownerId: string;
      ttlMs?: number;
      waitTimeoutMs?: number;
    },
    task: () => Promise<T>,
  ): Promise<T> {
    const lockKey = toTrimmedString(input.lockKey || '');
    const ownerId = toTrimmedString(input.ownerId || '');
    if (!lockKey || !ownerId) {
      throw new Error('[SeamsWalletDB] nonce lane lock requires lockKey and ownerId');
    }
    const ttlMs = Math.max(1, Math.floor(Number(input.ttlMs) || DEFAULT_NONCE_LANE_LOCK_TTL_MS));
    const waitTimeoutMs = Math.max(
      1,
      Math.floor(Number(input.waitTimeoutMs) || DEFAULT_NONCE_LANE_LOCK_WAIT_TIMEOUT_MS),
    );
    const fencingToken = createRandomToken('nonce-lane-lock');
    const deadlineMs = Date.now() + waitTimeoutMs;

    const tryAcquire = async (): Promise<boolean> => {
      let acquired = false;
      await this.manager.runTransaction(
        [SEAMS_WALLET_STORES.nonceLaneLocks],
        'readwrite',
        async (ctx) => {
          const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLocks);
          const nowMs = Date.now();
          const existing = (await store.get(lockKey)) as NonceLaneLockRow | undefined;
          if (existing && Number(existing.expires_at_ms) > nowMs) return;
          const next: NonceLaneLockRow = {
            lock_key: lockKey,
            owner_id: ownerId,
            fencing_token: fencingToken,
            acquired_at_ms: nowMs,
            expires_at_ms: nowMs + ttlMs,
            updated_at_ms: nowMs,
          };
          await store.put(next);
          acquired = true;
        },
      );
      return acquired;
    };

    while (!(await tryAcquire())) {
      if (Date.now() >= deadlineMs) {
        const error = new Error('[SeamsWalletDB] durable nonce lane lock timed out') as Error & {
          code?: string;
        };
        error.code = 'durable_lock_timeout';
        throw error;
      }
      await sleep(DEFAULT_NONCE_LANE_LOCK_POLL_MS);
    }

    try {
      return await task();
    } finally {
      await this.manager
        .runTransaction([SEAMS_WALLET_STORES.nonceLaneLocks], 'readwrite', async (ctx) => {
          const store = ctx.store(SEAMS_WALLET_STORES.nonceLaneLocks);
          const existing = (await store.get(lockKey)) as NonceLaneLockRow | undefined;
          if (existing?.fencing_token === fencingToken) {
            await store.delete(lockKey);
          }
        })
        .catch(() => undefined);
    }
  }
}
