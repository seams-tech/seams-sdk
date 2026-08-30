import {
  parseEmailOtpChallengeId,
  parseEmailOtpProviderUserId,
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseVerifiedEmailAddress,
  hasWhitespaceOrControlCharacters,
  parseMpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletId,
  type EmailOtpChallengeId,
  type EmailOtpProviderUserId,
  type VerifiedEmailAddress,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  parseCorrelationId,
  parseDigestB64u,
  type CorrelationId,
  type DigestB64u,
} from '@shared/utils/canonicalPrimitives';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  type EstablishedCustodyRecordsPayload,
  type RecoveryReplacementEnvelopePayload,
  type WalletCustodyCeremonyCommitPayload,
  type WalletCustodyCeremonyRecoveryWrapPayload,
  type WalletCustodyEvmFamilyPublicFacts,
  type WalletCustodyRecoveryCodeLocatorPayload,
} from '@shared/passkey-custody';
import type { WalletEmailOtpEnrollmentMaterialV1 } from '@shared/utils/registrationIntent';
import type { RouterAbEd25519YaoBytes32V1 } from '@shared/utils/routerAbEd25519Yao';
import {
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';

export type PendingWalletRegistrationEcdsaReplayV1 = {
  readonly activationJournalId: CorrelationId;
  readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly activationRequestDigestB64u: DigestB64u;
};

/**
 * The local registration journal entry written before a terminal request.
 *
 * This record deliberately contains request identities and sealed local
 * material only. A Wallet Session token, operation credential, and terminal
 * response are not part of the record and cannot be reconstructed from it.
 */
export type PendingWalletRegistrationCommitAuthV1 =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      readonly transports: readonly string[];
    }
  | {
      readonly kind: 'email_otp';
      readonly email: VerifiedEmailAddress;
      readonly registrationAuthorityId: EmailOtpChallengeId;
      readonly providerSubject: EmailOtpProviderUserId;
      /** Sealed server factor material needed to retry Route 4 after reload. */
      readonly enrollment: WalletEmailOtpEnrollmentMaterialV1;
    };

export type PendingWalletRegistrationActivationReferenceV1 = {
  readonly kind: 'router_ab_ed25519_yao_activation_reference_v1';
  readonly lifecycle_id: string;
  readonly session_id: RouterAbEd25519YaoBytes32V1;
};

type PendingWalletRegistrationEd25519LocalMaterialV1 = {
  readonly activationReference: PendingWalletRegistrationActivationReferenceV1;
  readonly localMaterial: {
    readonly b64u: string;
    readonly nonceB64u: string;
    readonly applicationBindingDigestB64u: string;
  };
  readonly metadata: PendingWalletRegistrationEd25519MetadataV1;
};

export type PendingWalletRegistrationEd25519MetadataV1 = {
  readonly materialActivation: MpcMaterialActivationRef;
  readonly registeredPublicKeyB64u: string;
  readonly signingWorkerVerifyingShareB64u: string;
  readonly stateEpoch: string;
  readonly signingWorkerId: string;
  readonly participantIds: readonly [number, number];
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
};

export type PendingWalletRegistrationLocalMaterialV1 =
  | {
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly custodyCommit: WalletCustodyCeremonyCommitPayload;
      readonly ecdsa: PendingWalletRegistrationEcdsaReplayV1;
      readonly ed25519?: never;
      readonly activationReference?: never;
    }
  | {
      readonly keyFamilies: readonly ['ed25519'];
      readonly custodyCommit: WalletCustodyCeremonyCommitPayload;
      readonly ed25519: PendingWalletRegistrationEd25519LocalMaterialV1;
      readonly ecdsa?: never;
      readonly activationReference?: never;
    }
  | {
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly custodyCommit: WalletCustodyCeremonyCommitPayload;
      readonly ed25519: PendingWalletRegistrationEd25519LocalMaterialV1;
      readonly ecdsa: PendingWalletRegistrationEcdsaReplayV1;
      readonly activationReference?: never;
    };

export type PendingWalletRegistrationSignerPlanKind =
  | 'near_ed25519'
  | 'evm_family_ecdsa'
  | 'near_ed25519_and_evm_family_ecdsa';

type PendingWalletRegistrationCommitCommonV1 = {
  readonly kind: 'pending_wallet_registration_commit_v1';
  readonly registrationCeremonyId: string;
  readonly idempotencyKey: string;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly signedSetup: string;
  readonly auth: PendingWalletRegistrationCommitAuthV1;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type PendingWalletRegistrationEd25519LocalMaterialBranchV1 = Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ed25519'] }
>;

export type PendingWalletRegistrationCommitV1 =
  | (PendingWalletRegistrationCommitCommonV1 & {
      readonly operation: 'registration_activate';
      readonly signerPlanKind: 'near_ed25519';
      readonly localMaterial: PendingWalletRegistrationEd25519LocalMaterialBranchV1;
    })
  | (PendingWalletRegistrationCommitCommonV1 & {
      readonly operation: 'registration_activate';
      readonly signerPlanKind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa';
      readonly localMaterial: Extract<
        PendingWalletRegistrationLocalMaterialV1,
        { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
      >;
    })
  | (PendingWalletRegistrationCommitCommonV1 & {
      readonly operation: 'registration_activate';
      readonly signerPlanKind: 'near_ed25519_and_evm_family_ecdsa';
      readonly localMaterial: Extract<
        PendingWalletRegistrationLocalMaterialV1,
        { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
      >;
    })
  | (PendingWalletRegistrationCommitCommonV1 & {
      readonly operation: 'near_provisioning';
      readonly signerPlanKind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa';
      readonly localMaterial: PendingWalletRegistrationEd25519LocalMaterialBranchV1;
    });

export type PendingWalletRegistrationCommitStorageRow = {
  readonly registration_ceremony_id: string;
  readonly operation: PendingWalletRegistrationCommitV1['operation'];
  readonly wallet_id: WalletId;
  readonly wallet_auth_method_id: WalletAuthMethodId;
  readonly updated_at_ms: number;
  readonly record: PendingWalletRegistrationCommitV1;
};

const PENDING_WALLET_REGISTRATION_COMMIT_APP_STATE_PREFIX =
  'pending_wallet_registration_commit_v1:';

export function pendingWalletRegistrationCommitAppStateKey(input: {
  readonly registrationCeremonyId: string;
  readonly operation: PendingWalletRegistrationCommitV1['operation'];
}): string {
  return `${PENDING_WALLET_REGISTRATION_COMMIT_APP_STATE_PREFIX}${input.registrationCeremonyId}:${input.operation}`;
}

export function toPendingWalletRegistrationCommitAppStateRow(
  record: PendingWalletRegistrationCommitV1,
): { readonly key: string; readonly value: PendingWalletRegistrationCommitStorageRow } {
  const storageRow = toPendingWalletRegistrationCommitStorageRow(record);
  return {
    key: pendingWalletRegistrationCommitAppStateKey({
      registrationCeremonyId: storageRow.registration_ceremony_id,
      operation: storageRow.operation,
    }),
    value: storageRow,
  };
}

export function parsePendingWalletRegistrationCommitAppStateRow(
  raw: unknown,
): PendingWalletRegistrationCommitStorageRow | null {
  if (!isRecord(raw) || !hasExactKeys(raw, ['key', 'value'])) return null;
  if (
    typeof raw.key !== 'string' ||
    !raw.key.startsWith(PENDING_WALLET_REGISTRATION_COMMIT_APP_STATE_PREFIX)
  ) {
    return null;
  }
  const parsed = parsePendingWalletRegistrationCommitStorageRow(raw.value);
  if (!parsed) return null;
  return pendingWalletRegistrationCommitAppStateKey({
    registrationCeremonyId: parsed.registration_ceremony_id,
    operation: parsed.operation,
  }) === raw.key
    ? parsed
    : null;
}

export function buildPendingWalletRegistrationCommitV1(
  input: PendingWalletRegistrationCommitV1,
): PendingWalletRegistrationCommitV1 {
  const parsed = parsePendingWalletRegistrationCommitV1(input);
  if (!parsed) throw new Error('pending wallet registration commit is invalid');
  return parsed;
}

export function toPendingWalletRegistrationCommitStorageRow(
  record: PendingWalletRegistrationCommitV1,
): PendingWalletRegistrationCommitStorageRow {
  const parsed = buildPendingWalletRegistrationCommitV1(record);
  return {
    registration_ceremony_id: parsed.registrationCeremonyId,
    operation: parsed.operation,
    wallet_id: parsed.walletId,
    wallet_auth_method_id: parsed.walletAuthMethodId,
    updated_at_ms: parsed.updatedAtMs,
    record: parsed,
  };
}

export function parsePendingWalletRegistrationCommitStorageRow(
  raw: unknown,
): PendingWalletRegistrationCommitStorageRow | null {
  if (!isRecord(raw)) return null;
  if (
    !hasExactKeys(raw, [
      'registration_ceremony_id',
      'operation',
      'wallet_id',
      'wallet_auth_method_id',
      'updated_at_ms',
      'record',
    ])
  ) {
    return null;
  }
  const record = parsePendingWalletRegistrationCommitV1(raw.record);
  if (!record) return null;
  if (
    raw.registration_ceremony_id !== record.registrationCeremonyId ||
    raw.operation !== record.operation ||
    raw.wallet_id !== record.walletId ||
    raw.wallet_auth_method_id !== record.walletAuthMethodId ||
    raw.updated_at_ms !== record.updatedAtMs
  ) {
    return null;
  }
  return {
    registration_ceremony_id: record.registrationCeremonyId,
    operation: record.operation,
    wallet_id: record.walletId,
    wallet_auth_method_id: record.walletAuthMethodId,
    updated_at_ms: record.updatedAtMs,
    record,
  };
}

/** Parse raw IndexedDB data into the one supported pending-registration state. */
export function parsePendingWalletRegistrationCommitV1(
  raw: unknown,
): PendingWalletRegistrationCommitV1 | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  if (
    !hasExactKeys(raw, [
      'kind',
      'operation',
      'signerPlanKind',
      'registrationCeremonyId',
      'idempotencyKey',
      'walletId',
      'walletAuthMethodId',
      'signedSetup',
      'auth',
      'localMaterial',
      'createdAtMs',
      'updatedAtMs',
    ]) ||
    raw.kind !== 'pending_wallet_registration_commit_v1'
  ) {
    return null;
  }
  const operation = parsePendingOperation(raw.operation);
  const signerPlanKind = parsePendingSignerPlanKind(raw.signerPlanKind);
  const registrationCeremonyId = parseCanonicalString(raw.registrationCeremonyId);
  const idempotencyKey = parseCanonicalString(raw.idempotencyKey);
  const signedSetup = parseCanonicalString(raw.signedSetup);
  const walletId = parseWalletId(raw.walletId);
  const walletAuthMethodId = parseWalletAuthMethodId(raw.walletAuthMethodId);
  const auth = parsePendingAuth(raw.auth);
  const localMaterial = parsePendingLocalMaterial(raw.localMaterial);
  const createdAtMs = parsePositiveSafeInteger(raw.createdAtMs);
  const updatedAtMs = parsePositiveSafeInteger(raw.updatedAtMs);
  if (
    (operation !== 'registration_activate' && operation !== 'near_provisioning') ||
    signerPlanKind === null ||
    registrationCeremonyId === null ||
    idempotencyKey === null ||
    signedSetup === null ||
    !walletId.ok ||
    !walletAuthMethodId.ok ||
    !auth ||
    !localMaterial ||
    localMaterial.custodyCommit.walletId !== walletId.value ||
    createdAtMs === null ||
    updatedAtMs === null ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  const common = {
    kind: 'pending_wallet_registration_commit_v1' as const,
    registrationCeremonyId,
    idempotencyKey,
    walletId: walletId.value,
    walletAuthMethodId: walletAuthMethodId.value,
    signedSetup,
    auth,
    createdAtMs,
    updatedAtMs,
  };
  if (operation === 'registration_activate') {
    if (signerPlanKind === 'near_ed25519') {
      return isEd25519LocalMaterial(localMaterial)
        ? { ...common, operation, signerPlanKind, localMaterial }
        : null;
    }
    if (signerPlanKind === 'evm_family_ecdsa') {
      return isEcdsaOnlyLocalMaterial(localMaterial)
        ? { ...common, operation, signerPlanKind, localMaterial }
        : null;
    }
    if (isEcdsaOnlyLocalMaterial(localMaterial)) {
      return { ...common, operation, signerPlanKind, localMaterial };
    }
    if (isMixedLocalMaterial(localMaterial)) {
      return { ...common, operation, signerPlanKind, localMaterial };
    }
    return null;
  }
  if (operation === 'near_provisioning') {
    if (
      signerPlanKind !== 'near_ed25519' &&
      signerPlanKind !== 'near_ed25519_and_evm_family_ecdsa'
    ) {
      return null;
    }
    if (!isEd25519LocalMaterial(localMaterial)) return null;
    return { ...common, operation, signerPlanKind, localMaterial };
  }
  return null;
}

/**
 * A terminal projection may be used only with the exact pending operation and
 * founding method. This is intentionally independent of bearer issuance.
 */
export function assertPendingWalletRegistrationIdentity(
  pending: PendingWalletRegistrationCommitV1,
  projection: {
    readonly operation: PendingWalletRegistrationCommitV1['operation'];
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly authority: WalletAuthAuthority;
  },
): void {
  if (
    pending.operation !== projection.operation ||
    pending.walletId !== projection.walletId ||
    pending.walletAuthMethodId !== projection.walletAuthMethodId ||
    projection.authority.walletId !== pending.walletId ||
    projection.authority.bindingId !== pending.walletAuthMethodId
  ) {
    throw new Error('pending wallet registration commit identity does not match projection');
  }
  if (pending.auth.kind === 'passkey') {
    if (
      !isPasskeyWalletAuthAuthority(projection.authority) ||
      projection.authority.factor.credentialIdB64u !== pending.auth.credentialIdB64u ||
      projection.authority.verifier.rpId !== pending.auth.rpId
    ) {
      throw new Error('pending passkey registration authority does not match projection');
    }
    return;
  }
  if (!isEmailOtpWalletAuthAuthority(projection.authority)) {
    throw new Error('pending Email OTP registration authority does not match projection');
  }
  if (
    projection.authority.factor.providerUserId !== pending.auth.providerSubject ||
    projection.authority.verifier.emailHashHex.length === 0
  ) {
    throw new Error('pending Email OTP registration factor does not match projection');
  }
}

function parsePendingOperation(
  value: unknown,
): PendingWalletRegistrationCommitV1['operation'] | null {
  return value === 'registration_activate' || value === 'near_provisioning' ? value : null;
}

function parsePendingSignerPlanKind(
  value: unknown,
): PendingWalletRegistrationSignerPlanKind | null {
  return value === 'near_ed25519' ||
    value === 'evm_family_ecdsa' ||
    value === 'near_ed25519_and_evm_family_ecdsa'
    ? value
    : null;
}

function parsePendingAuth(raw: unknown): PendingWalletRegistrationCommitAuthV1 | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw) || typeof raw.kind !== 'string')
    return null;
  if (raw.kind === 'passkey') {
    if (!hasExactKeys(raw, ['kind', 'rpId', 'credentialIdB64u', 'transports'])) return null;
    const rpId = parseWebAuthnRpId(raw.rpId);
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(raw.credentialIdB64u);
    const transports = parseCanonicalStringArray(raw.transports);
    return rpId.ok && credentialIdB64u.ok && transports
      ? {
          kind: 'passkey',
          rpId: rpId.value,
          credentialIdB64u: credentialIdB64u.value,
          transports,
        }
      : null;
  }
  if (raw.kind !== 'email_otp') return null;
  if (
    !hasExactKeys(raw, [
      'kind',
      'email',
      'registrationAuthorityId',
      'providerSubject',
      'enrollment',
    ])
  ) {
    return null;
  }
  const email = parseVerifiedEmailAddress(raw.email);
  const registrationAuthorityId = parseEmailOtpChallengeId(raw.registrationAuthorityId);
  const providerSubject = parseEmailOtpProviderUserId(raw.providerSubject);
  const enrollment = parseEmailOtpEnrollmentMaterial(raw.enrollment);
  if (!email.ok || !registrationAuthorityId.ok || !providerSubject.ok || !enrollment) {
    return null;
  }
  return {
    kind: 'email_otp',
    email: email.value,
    registrationAuthorityId: registrationAuthorityId.value,
    providerSubject: providerSubject.value,
    enrollment,
  };
}

function parseCanonicalStringArray(raw: unknown): readonly string[] | null {
  if (!Array.isArray(raw)) return null;
  const values: string[] = [];
  const seen = new Set<string>();
  for (const value of raw) {
    const parsed = parseCanonicalString(value);
    if (parsed === null || seen.has(parsed)) return null;
    seen.add(parsed);
    values.push(parsed);
  }
  return values;
}

function parseEmailOtpEnrollmentMaterial(raw: unknown): WalletEmailOtpEnrollmentMaterialV1 | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  const keys = [
    'enrollmentSealKeyVersion',
    'serverSealedFactorCiphertextB64u',
    'clientUnlockPublicKeyB64u',
    'unlockKeyVersion',
  ] as const;
  if (!hasExactKeys(raw, keys)) return null;
  const enrollmentSealKeyVersion = parseCanonicalString(raw.enrollmentSealKeyVersion);
  const serverSealedFactorCiphertextB64u = parseCanonicalString(
    raw.serverSealedFactorCiphertextB64u,
  );
  const clientUnlockPublicKeyB64u = parseCanonicalString(raw.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = parseCanonicalString(raw.unlockKeyVersion);
  if (
    !enrollmentSealKeyVersion ||
    !serverSealedFactorCiphertextB64u ||
    !clientUnlockPublicKeyB64u ||
    !unlockKeyVersion
  ) {
    return null;
  }
  return {
    enrollmentSealKeyVersion,
    serverSealedFactorCiphertextB64u,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
  };
}

function parsePendingLocalMaterial(raw: unknown): PendingWalletRegistrationLocalMaterialV1 | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw) || !Array.isArray(raw.keyFamilies)) {
    return null;
  }
  if (raw.keyFamilies.length === 1 && raw.keyFamilies[0] === 'ecdsa_secp256k1') {
    if (!hasExactKeys(raw, ['keyFamilies', 'custodyCommit', 'ecdsa'])) return null;
    const custodyCommit = parseCustodyCommit(raw.custodyCommit);
    const ecdsa = parseEcdsaLocalMaterial(raw.ecdsa);
    return custodyCommit && custodyCommit.keySet === 'evm_family_ecdsa_v1' && ecdsa
      ? { keyFamilies: ['ecdsa_secp256k1'], custodyCommit, ecdsa }
      : null;
  }
  if (
    raw.keyFamilies.length === 1 &&
    raw.keyFamilies[0] === 'ed25519' &&
    hasExactKeys(raw, ['keyFamilies', 'custodyCommit', 'ed25519'])
  ) {
    const custodyCommit = parseCustodyCommit(raw.custodyCommit);
    const ed25519 = parseEd25519LocalMaterial(raw.ed25519);
    return custodyCommit && custodyCommit.keySet === 'near_ed25519_v1' && ed25519
      ? { keyFamilies: ['ed25519'], custodyCommit, ed25519 }
      : null;
  }
  if (
    raw.keyFamilies.length === 2 &&
    raw.keyFamilies[0] === 'ed25519' &&
    raw.keyFamilies[1] === 'ecdsa_secp256k1' &&
    hasExactKeys(raw, ['keyFamilies', 'custodyCommit', 'ed25519', 'ecdsa'])
  ) {
    const custodyCommit = parseCustodyCommit(raw.custodyCommit);
    const ed25519 = parseEd25519LocalMaterial(raw.ed25519);
    const ecdsa = parseEcdsaLocalMaterial(raw.ecdsa);
    return custodyCommit && custodyCommit.keySet === 'evm_family_ecdsa_v1' && ed25519 && ecdsa
      ? { keyFamilies: ['ed25519', 'ecdsa_secp256k1'], custodyCommit, ed25519, ecdsa }
      : null;
  }
  return null;
}

function isEd25519LocalMaterial(
  localMaterial: PendingWalletRegistrationLocalMaterialV1,
): localMaterial is Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> {
  return localMaterial.keyFamilies.length === 1 && localMaterial.keyFamilies[0] === 'ed25519';
}

function isEcdsaOnlyLocalMaterial(
  localMaterial: PendingWalletRegistrationLocalMaterialV1,
): localMaterial is Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
> {
  return localMaterial.keyFamilies.length === 1 && localMaterial.keyFamilies[0] === 'ecdsa_secp256k1';
}

function isMixedLocalMaterial(
  localMaterial: PendingWalletRegistrationLocalMaterialV1,
): localMaterial is Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
> {
  return (
    localMaterial.keyFamilies.length === 2 &&
    localMaterial.keyFamilies[0] === 'ed25519' &&
    localMaterial.keyFamilies[1] === 'ecdsa_secp256k1'
  );
}

function parseEd25519LocalMaterial(
  raw: unknown,
): PendingWalletRegistrationEd25519LocalMaterialV1 | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  if (!hasExactKeys(raw, ['activationReference', 'localMaterial', 'metadata'])) return null;
  const activationReference = parseActivationReference(raw.activationReference);
  if (!isRecord(raw.localMaterial) || hasForbiddenCredentialField(raw.localMaterial)) return null;
  if (!hasExactKeys(raw.localMaterial, ['b64u', 'nonceB64u', 'applicationBindingDigestB64u'])) {
    return null;
  }
  const b64u = parseCanonicalString(raw.localMaterial.b64u);
  const nonceB64u = parseCanonicalString(raw.localMaterial.nonceB64u);
  const applicationBindingDigestB64u = parseCanonicalString(
    raw.localMaterial.applicationBindingDigestB64u,
  );
  const metadata = parseEd25519Metadata(raw.metadata);
  return activationReference && b64u && nonceB64u && applicationBindingDigestB64u && metadata
    ? {
        activationReference,
        localMaterial: { b64u, nonceB64u, applicationBindingDigestB64u },
        metadata,
      }
    : null;
}

function parseEd25519Metadata(raw: unknown): PendingWalletRegistrationEd25519MetadataV1 | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  if (
    !hasExactKeys(raw, [
      'materialActivation',
      'registeredPublicKeyB64u',
      'signingWorkerVerifyingShareB64u',
      'stateEpoch',
      'signingWorkerId',
      'participantIds',
      'nearEd25519SigningKeyId',
      'signerSlot',
    ])
  ) {
    return null;
  }
  const materialActivation = parseMpcMaterialActivationRef(raw.materialActivation);
  const registeredPublicKeyB64u = parseCanonicalString(raw.registeredPublicKeyB64u);
  const signingWorkerVerifyingShareB64u = parseCanonicalString(raw.signingWorkerVerifyingShareB64u);
  const stateEpoch = parseCanonicalStateEpoch(raw.stateEpoch);
  const signingWorkerId = parseCanonicalString(raw.signingWorkerId);
  const nearEd25519SigningKeyId = parseCanonicalString(raw.nearEd25519SigningKeyId);
  if (
    !materialActivation.ok ||
    !registeredPublicKeyB64u ||
    !signingWorkerVerifyingShareB64u ||
    !stateEpoch ||
    !signingWorkerId ||
    !nearEd25519SigningKeyId ||
    !Array.isArray(raw.participantIds) ||
    raw.participantIds.length !== 2 ||
    raw.participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || Number(participantId) < 1,
    ) ||
    !Number.isSafeInteger(raw.signerSlot) ||
    Number(raw.signerSlot) < 1
  ) {
    return null;
  }
  return {
    materialActivation: materialActivation.value,
    registeredPublicKeyB64u,
    signingWorkerVerifyingShareB64u,
    stateEpoch,
    signingWorkerId,
    participantIds: [Number(raw.participantIds[0]), Number(raw.participantIds[1])],
    nearEd25519SigningKeyId,
    signerSlot: Number(raw.signerSlot),
  };
}

function parseEcdsaLocalMaterial(raw: unknown): {
  readonly activationJournalId: CorrelationId;
  readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
  readonly activationRequestDigestB64u: DigestB64u;
} | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  if (
    !hasExactKeys(raw, ['activationJournalId', 'clientActivation', 'activationRequestDigestB64u'])
  ) {
    return null;
  }
  const activationJournalId = parseCorrelationIdSafely(raw.activationJournalId);
  const activationRequestDigestB64u = parseDigestB64uSafely(raw.activationRequestDigestB64u);
  if (!activationJournalId || !activationRequestDigestB64u) return null;
  try {
    return {
      activationJournalId,
      clientActivation: parseRouterAbEcdsaVerifiedClientActivationFactsV1(raw.clientActivation),
      activationRequestDigestB64u,
    };
  } catch {
    return null;
  }
}

function parseEcdsaPublicFacts(raw: unknown): WalletCustodyEvmFamilyPublicFacts | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  const keys = [
    'contextBinding32B64u',
    'derivationClientSharePublicKey33B64u',
    'clientVerifyingShare33B64u',
    'relayerPublicKey33B64u',
    'groupPublicKey33B64u',
    'ethereumAddress',
    'clientShareRetryCounter',
    'relayerShareRetryCounter',
  ] as const;
  if (!hasExactKeys(raw, keys)) return null;
  const strings = keys.slice(0, 6).map((key) => parseCanonicalString(raw[key]));
  if (strings.some((value) => value === null)) return null;
  if (
    !Number.isSafeInteger(raw.clientShareRetryCounter) ||
    Number(raw.clientShareRetryCounter) < 0 ||
    !Number.isSafeInteger(raw.relayerShareRetryCounter) ||
    Number(raw.relayerShareRetryCounter) < 0
  ) {
    return null;
  }
  return {
    contextBinding32B64u: strings[0]!,
    derivationClientSharePublicKey33B64u: strings[1]!,
    clientVerifyingShare33B64u: strings[2]!,
    relayerPublicKey33B64u: strings[3]!,
    groupPublicKey33B64u: strings[4]!,
    ethereumAddress: strings[5]!,
    clientShareRetryCounter: Number(raw.clientShareRetryCounter),
    relayerShareRetryCounter: Number(raw.relayerShareRetryCounter),
  };
}

function parseActivationReference(
  raw: unknown,
): PendingWalletRegistrationActivationReferenceV1 | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  if (!hasExactKeys(raw, ['kind', 'lifecycle_id', 'session_id'])) return null;
  if (raw.kind !== 'router_ab_ed25519_yao_activation_reference_v1') return null;
  const lifecycleId = parseCanonicalString(raw.lifecycle_id);
  if (!lifecycleId || !Array.isArray(raw.session_id) || raw.session_id.length !== 32) return null;
  const sessionId: number[] = [];
  for (const value of raw.session_id) {
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    sessionId.push(value);
  }
  return { kind: raw.kind, lifecycle_id: lifecycleId, session_id: sessionId };
}

function parseCustodyCommit(raw: unknown): WalletCustodyCeremonyCommitPayload | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  const allowed = [
    'walletId',
    'keySet',
    'keyManifestDigestB64u',
    'establishedCustody',
    'recoveryBackupAcknowledged',
    'recoveryReplacementEnvelope',
    'registeredPublicKeyB64u',
    'clientRootPublicKey33B64u',
    'ecdsaPublicFacts',
  ] as const;
  if (
    !hasRequiredKeys(raw, ['walletId', 'keySet', 'keyManifestDigestB64u']) ||
    !hasOnlyKeys(raw, allowed)
  ) {
    return null;
  }
  const walletId = parseCanonicalString(raw.walletId);
  const keySet = parseCanonicalString(raw.keySet);
  const keyManifestDigestB64u = parseCanonicalString(raw.keyManifestDigestB64u);
  if (
    !walletId ||
    !keySet ||
    !keyManifestDigestB64u ||
    (keySet !== 'near_ed25519_v1' && keySet !== 'evm_family_ecdsa_v1')
  ) {
    return null;
  }
  if (raw.recoveryBackupAcknowledged !== undefined && raw.recoveryBackupAcknowledged !== true) {
    return null;
  }
  const establishedCustody =
    raw.establishedCustody === undefined
      ? undefined
      : parseEstablishedCustody(raw.establishedCustody);
  if (raw.establishedCustody !== undefined && !establishedCustody) return null;
  const recoveryReplacementEnvelope =
    raw.recoveryReplacementEnvelope === undefined
      ? undefined
      : parseRecoveryReplacementEnvelope(raw.recoveryReplacementEnvelope);
  if (raw.recoveryReplacementEnvelope !== undefined && !recoveryReplacementEnvelope) return null;
  const registeredPublicKeyB64u =
    raw.registeredPublicKeyB64u === undefined
      ? undefined
      : parseCanonicalString(raw.registeredPublicKeyB64u);
  if (raw.registeredPublicKeyB64u !== undefined && !registeredPublicKeyB64u) return null;
  const clientRootPublicKey33B64u =
    raw.clientRootPublicKey33B64u === undefined
      ? undefined
      : parseCanonicalString(raw.clientRootPublicKey33B64u);
  if (raw.clientRootPublicKey33B64u !== undefined && !clientRootPublicKey33B64u) return null;
  const ecdsaPublicFacts =
    raw.ecdsaPublicFacts === undefined ? undefined : parseEcdsaPublicFacts(raw.ecdsaPublicFacts);
  if (raw.ecdsaPublicFacts !== undefined && !ecdsaPublicFacts) return null;
  return {
    walletId,
    keySet,
    keyManifestDigestB64u,
    ...(establishedCustody ? { establishedCustody } : {}),
    ...(raw.recoveryBackupAcknowledged === true
      ? { recoveryBackupAcknowledged: true as const }
      : {}),
    ...(recoveryReplacementEnvelope ? { recoveryReplacementEnvelope } : {}),
    ...(registeredPublicKeyB64u ? { registeredPublicKeyB64u } : {}),
    ...(clientRootPublicKey33B64u ? { clientRootPublicKey33B64u } : {}),
    ...(ecdsaPublicFacts ? { ecdsaPublicFacts } : {}),
  };
}

function parseEstablishedCustody(raw: unknown): EstablishedCustodyRecordsPayload | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  const keys = [
    'envelopeId',
    'envelopeBindingJson',
    'envelopeNonceB64u',
    'sealedCustodySecretB64u',
    'envelopeAadHashB64u',
    'envelopeCiphertextDigestB64u',
    'recoveryManifestKekWraps',
    'recoveryCodeLocators',
    'recoveryEntryNonceB64u',
    'recoveryEntryCiphertextB64u',
    'recoveryEntryAadHashB64u',
  ] as const;
  const requiredKeys = keys.filter((key) => key !== 'recoveryCodeLocators');
  if (!hasRequiredKeys(raw, requiredKeys) || !hasOnlyKeys(raw, keys)) return null;
  const strings = [
    parseCanonicalString(raw.envelopeId),
    parseCanonicalString(raw.envelopeBindingJson),
    parseCanonicalString(raw.envelopeNonceB64u),
    parseCanonicalString(raw.sealedCustodySecretB64u),
    parseCanonicalString(raw.envelopeAadHashB64u),
    parseCanonicalString(raw.envelopeCiphertextDigestB64u),
    parseCanonicalString(raw.recoveryEntryNonceB64u),
    parseCanonicalString(raw.recoveryEntryCiphertextB64u),
    parseCanonicalString(raw.recoveryEntryAadHashB64u),
  ];
  if (strings.some((value) => value === null)) return null;
  if (!Array.isArray(raw.recoveryManifestKekWraps)) return null;
  const parsedRecoveryManifestKekWraps = raw.recoveryManifestKekWraps.map(parseRecoveryWrap);
  if (parsedRecoveryManifestKekWraps.some((value) => value === null)) return null;
  const recoveryManifestKekWraps = parsedRecoveryManifestKekWraps.filter(isPresent);
  let recoveryCodeLocators: WalletCustodyRecoveryCodeLocatorPayload[] | undefined;
  if (raw.recoveryCodeLocators !== undefined) {
    if (!Array.isArray(raw.recoveryCodeLocators)) return null;
    const parsedRecoveryCodeLocators = raw.recoveryCodeLocators.map(parseRecoveryCodeLocator);
    if (parsedRecoveryCodeLocators.some((value) => value === null)) return null;
    recoveryCodeLocators = parsedRecoveryCodeLocators.filter(isPresent);
  }
  return {
    envelopeId: strings[0]!,
    envelopeBindingJson: strings[1]!,
    envelopeNonceB64u: strings[2]!,
    sealedCustodySecretB64u: strings[3]!,
    envelopeAadHashB64u: strings[4]!,
    envelopeCiphertextDigestB64u: strings[5]!,
    recoveryManifestKekWraps,
    ...(recoveryCodeLocators ? { recoveryCodeLocators } : {}),
    recoveryEntryNonceB64u: strings[6]!,
    recoveryEntryCiphertextB64u: strings[7]!,
    recoveryEntryAadHashB64u: strings[8]!,
  };
}

function parseRecoveryWrap(raw: unknown): WalletCustodyCeremonyRecoveryWrapPayload | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  if (!hasExactKeys(raw, ['recoveryKeyId', 'nonceB64u', 'ciphertextB64u', 'aadHashB64u']))
    return null;
  const recoveryKeyId = parseCanonicalString(raw.recoveryKeyId);
  const nonceB64u = parseCanonicalString(raw.nonceB64u);
  const ciphertextB64u = parseCanonicalString(raw.ciphertextB64u);
  const aadHashB64u = parseCanonicalString(raw.aadHashB64u);
  return recoveryKeyId && nonceB64u && ciphertextB64u && aadHashB64u
    ? { recoveryKeyId, nonceB64u, ciphertextB64u, aadHashB64u }
    : null;
}

function parseRecoveryCodeLocator(raw: unknown): WalletCustodyRecoveryCodeLocatorPayload | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  if (!hasExactKeys(raw, ['locatorB64u', 'recoveryKeyId'])) return null;
  const locatorB64u = parseCanonicalString(raw.locatorB64u);
  const recoveryKeyId = parseCanonicalString(raw.recoveryKeyId);
  return locatorB64u && recoveryKeyId ? { locatorB64u, recoveryKeyId } : null;
}

function parseRecoveryReplacementEnvelope(raw: unknown): RecoveryReplacementEnvelopePayload | null {
  if (!isRecord(raw) || hasForbiddenCredentialField(raw)) return null;
  const keys = [
    'envelopeId',
    'envelopeBindingJson',
    'envelopeNonceB64u',
    'sealedCustodySecretB64u',
    'envelopeAadHashB64u',
    'envelopeCiphertextDigestB64u',
  ] as const;
  if (!hasExactKeys(raw, keys)) return null;
  const values = keys.map((key) => parseCanonicalString(raw[key]));
  if (values.some((value) => value === null)) return null;
  return {
    envelopeId: values[0]!,
    envelopeBindingJson: values[1]!,
    envelopeNonceB64u: values[2]!,
    sealedCustodySecretB64u: values[3]!,
    envelopeAadHashB64u: values[4]!,
    envelopeCiphertextDigestB64u: values[5]!,
  };
}

function isPresent<T>(value: T | null): value is T {
  return value !== null;
}

function parseCanonicalString(value: unknown): string | null {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.trim() === value &&
    !hasWhitespaceOrControlCharacters(value)
    ? value
    : null;
}

function parseCanonicalStateEpoch(value: unknown): string | null {
  const parsed = parseCanonicalString(value);
  return parsed && /^[1-9][0-9]*$/u.test(parsed) ? parsed : null;
}

function parsePositiveSafeInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : null;
}

function parseCorrelationIdSafely(value: unknown): CorrelationId | null {
  try {
    return parseCorrelationId(value);
  } catch {
    return null;
  }
}

function parseDigestB64uSafely(value: unknown): DigestB64u | null {
  try {
    return parseDigestB64u(value);
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === expected.length && expected.every((key) => actual.includes(key));
}

function hasRequiredKeys(record: Record<string, unknown>, required: readonly string[]): boolean {
  return required.every((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowed.includes(key));
}

function hasForbiddenCredentialField(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasForbiddenCredentialField);
  if (!isRecord(value)) return false;
  for (const [key, nested] of Object.entries(value)) {
    if (
      key === 'walletSessionToken' ||
      key === 'wallet_session_token' ||
      key === 'operationCredential' ||
      key === 'primaryOperationCredential' ||
      key === 'childOperationCredential' ||
      key === 'walletSessionOperationCredential' ||
      key === 'hostedWalletSessionOperationCredential' ||
      key === 'operation_credential' ||
      key === 'primary_operation_credential' ||
      key === 'child_operation_credential' ||
      key === 'primaryCredential' ||
      key === 'childCredential' ||
      key === 'registrationEstablishedSession' ||
      key === 'response'
    ) {
      return true;
    }
    if (hasForbiddenCredentialField(nested)) return true;
  }
  return false;
}
