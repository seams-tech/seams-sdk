import type { WalletRecoveryReplacementCredential } from '@/core/signingEngine/walletCustody/walletRecoveryCredential';
import {
  parsePasskeyCustodyEnvelopeRecord,
  parseEd25519PublicKeyB64u,
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseKeyCreationSignerSlot,
  parseSecp256k1CompressedPublicKeyB64u,
  requireRecord,
  rejectUnknownFields,
  type PasskeyCustodyEnvelopeRecord,
  type WalletCustodyEvmFamilyPublicFacts,
} from '@shared/passkey-custody';
import type {
  RecoveredWalletCustodyEcdsaKeySetV1,
  RecoveredWalletCustodyManifestV1,
  RecoveredWalletCustodyNearKeySetV1,
  WalletRecoveryReplacementFactorInput,
} from '@/core/signingEngine/walletCustody/walletRecoveryManifest';
import {
  parseWalletRecoveryPreparationKeyManifest,
  type WalletRecoveryPreparationKeyManifest,
  type WalletRecoveryPreparationKeyManifestEntry,
} from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
  type WalletCustodySealedEd25519MaterialV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import {
  parseEmailOtpProviderUserId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseThresholdEd25519SessionId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import { sha256HexUtf8 } from '@shared/utils/digests';
import { normalizeThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  parseRouterAbMpcMaterialActivationRef,
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { parseWalletRecoveryEcdsaPossessionProofV1 } from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import type { PendingWalletRecoveryCommitV1 } from '@/core/indexedDB/pendingWalletRecoveryCommit';
import type { WalletRecoveryEmailOtpEnrollmentMaterial } from '@/core/rpcClients/relayer/walletRecoveryGoogleEmailOtp';

export const WALLET_RECOVERY_DURABLE_PAYLOAD_VERSION = 1 as const;

export type WalletRecoveryEmailOtpEnrollment =
  | {
      readonly kind: 'existing';
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
    }
  | {
      readonly kind: 'create';
      readonly enrollmentId: string;
      readonly providerSubject: string;
      readonly verifiedEmail: string;
      readonly material: WalletRecoveryEmailOtpEnrollmentMaterial;
    };

type WalletRecoveryDurableOperationCommon = {
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly prepared: {
    readonly recoveryOperationId: string;
    readonly reservationId: RecoveryCodeReservationId;
    readonly targetDeviceId: DeviceId;
    readonly targetAuthorityId: WalletAuthorityId;
    readonly targetWalletAuthMethodId: WalletAuthMethodId;
  };
  readonly recovered: RecoveredWalletCustodyManifestV1;
};

export type WalletRecoveryDurableOperationInput =
  | (WalletRecoveryDurableOperationCommon & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
      readonly prepared: WalletRecoveryDurableOperationCommon['prepared'] & {
        readonly registration: {
          readonly replacementId: string;
          readonly challengeId: string;
        };
      };
      readonly replacement: {
        readonly kind: 'passkey';
        readonly registration: WalletRecoveryReplacementCredential['registration'];
        readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      };
    })
  | (WalletRecoveryDurableOperationCommon & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
      readonly prepared: WalletRecoveryDurableOperationCommon['prepared'] & {
        readonly registration?: never;
      };
      readonly replacement: {
        readonly kind: 'email_otp';
        readonly factor: WalletRecoveryReplacementFactorInput;
        readonly enrollment: WalletRecoveryEmailOtpEnrollment;
        readonly providerSubject: string;
        readonly verifiedEmail: string;
        readonly registrationAuthorityId: string;
      };
    });

type WalletRecoveryRedactedRegistrationV1 = {
  readonly kind: 'wallet_recovery_redacted_registration_v1';
  readonly id: string;
  readonly rawId: string;
  readonly type: string;
  readonly authenticatorAttachment: string | null;
  readonly response: {
    readonly clientDataJSON: string;
    readonly attestationObject: string;
    readonly transports: readonly string[];
  };
};

type WalletRecoveryDurableNearKeySetV1 = {
  readonly kind: 'near_ed25519';
  readonly keySetId: string;
  readonly binding: WalletCustodyEd25519MaterialBindingV1;
  readonly thresholdSessionId: string;
  readonly runtimePolicyScope: NonNullable<ReturnType<typeof normalizeThresholdRuntimePolicyScope>>;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly sealed: WalletCustodySealedEd25519MaterialV1;
};

type WalletRecoveryPreparationEcdsaEntry = Extract<
  WalletRecoveryPreparationKeyManifestEntry,
  { readonly kind: 'evm_family_ecdsa' }
>;

type WalletRecoveryDurableEcdsaKeySetV1 = {
  readonly kind: 'evm_family_ecdsa';
  readonly entry: WalletRecoveryPreparationEcdsaEntry;
  readonly possessionProof: ReturnType<typeof parseWalletRecoveryEcdsaPossessionProofV1>;
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

type WalletRecoveryDurableNearKeySetRecordV1 = {
  readonly kind: 'near_ed25519';
  readonly keySetId: string;
  readonly applicationBindingDigestB64u: string;
  readonly registeredPublicKeyB64u: string;
  readonly participantIds: readonly [number, number];
  readonly stateEpoch: string;
  readonly signingWorkerVerifyingShareB64u: string;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly sealed: {
    readonly ciphertextB64u: string;
    readonly nonceB64u: string;
  };
};

type WalletRecoveryDurableEcdsaKeySetRecordV1 = {
  readonly kind: 'evm_family_ecdsa';
  readonly keySetId: string;
  readonly possessionProof: ReturnType<typeof parseWalletRecoveryEcdsaPossessionProofV1>;
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

type WalletRecoveryDurablePayloadCommonV1 = {
  readonly kind: 'wallet_recovery_durable_payload_v1';
  readonly version: 1;
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly keyManifest: WalletRecoveryPreparationKeyManifest;
  readonly nearKeySets: readonly WalletRecoveryDurableNearKeySetV1[];
  readonly ecdsaKeySets: readonly WalletRecoveryDurableEcdsaKeySetV1[];
};

export type WalletRecoveryDurablePayloadV1 =
  | (WalletRecoveryDurablePayloadCommonV1 & {
      readonly target: { readonly kind: 'passkey'; readonly rpId: WebAuthnRpId };
      readonly replacementId: string;
      readonly challengeId: string;
      readonly registration: WalletRecoveryRedactedRegistrationV1;
    })
  | (WalletRecoveryDurablePayloadCommonV1 & {
      readonly target: { readonly kind: 'google_email_otp' };
      readonly providerSubject: string;
      readonly verifiedEmail: string;
      readonly emailHashHex: string;
      readonly registrationAuthorityId: string;
      readonly replacementId: string;
      readonly enrollment: WalletRecoveryEmailOtpEnrollment;
    });

export type WalletRecoveryDurablePasskeyPayload = Extract<
  WalletRecoveryDurablePayloadV1,
  { readonly target: { readonly kind: 'passkey' } }
>;

export type WalletRecoveryDurableEmailOtpPayload = Extract<
  WalletRecoveryDurablePayloadV1,
  { readonly target: { readonly kind: 'google_email_otp' } }
>;

export function isDurablePasskeyPayload(
  payload: WalletRecoveryDurablePayloadV1,
): payload is WalletRecoveryDurablePasskeyPayload {
  return payload.target.kind === 'passkey';
}

export function durableEmailEnrollmentReference(payload: WalletRecoveryDurableEmailOtpPayload): {
  readonly kind: 'email_otp_enrollment_reference_v1';
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
} {
  return {
    kind: 'email_otp_enrollment_reference_v1',
    enrollmentId: payload.enrollment.enrollmentId,
    enrollmentSealKeyVersion:
      payload.enrollment.kind === 'existing'
        ? payload.enrollment.enrollmentSealKeyVersion
        : payload.enrollment.material.enrollmentSealKeyVersion,
  };
}

const NEAR_KEY_SET_FIELDS = [
  'kind',
  'keySetId',
  'applicationBindingDigestB64u',
  'registeredPublicKeyB64u',
  'participantIds',
  'stateEpoch',
  'signingWorkerVerifyingShareB64u',
  'materialActivation',
  'sealed',
] as const;
const ECDSA_KEY_SET_FIELDS = [
  'kind',
  'keySetId',
  'possessionProof',
  'readyStateBlobB64u',
  'publicFacts',
] as const;
const PUBLIC_FACTS_FIELDS = [
  'contextBinding32B64u',
  'derivationClientSharePublicKey33B64u',
  'clientVerifyingShare33B64u',
  'relayerPublicKey33B64u',
  'groupPublicKey33B64u',
  'ethereumAddress',
  'clientShareRetryCounter',
  'relayerShareRetryCounter',
] as const;

const PAYLOAD_COMMON_FIELDS = [
  'kind',
  'version',
  'recoveryOperationId',
  'walletId',
  'reservationId',
  'targetDeviceId',
  'targetAuthorityId',
  'targetWalletAuthMethodId',
  'replacementEnvelope',
  'keyManifest',
  'nearKeySets',
  'ecdsaKeySets',
  'target',
] as const;

function durableExactFields(
  value: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  rejectUnknownFields(value, fields, label);
  if (Object.keys(value).length !== fields.length) {
    throw new Error(label + ' fields are invalid');
  }
}

function durableString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(label + ' must be a non-empty canonical string');
  }
  return value;
}

function durableBase64Url(value: unknown, label: string, byteLength?: number): string {
  const normalized = durableString(value, label);
  const bytes = base64UrlDecode(normalized);
  if (byteLength !== undefined && bytes.byteLength !== byteLength) {
    throw new Error(label + ' must decode to ' + byteLength + ' bytes');
  }
  return normalized;
}

function durableCompressedPublicKey(value: unknown, label: string): string {
  return parseSecp256k1CompressedPublicKeyB64u(value, label);
}

function durableSafeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(label + ' must be a non-negative safe integer');
  }
  return value;
}

function durableParticipantPair(value: unknown, label: string): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2 || value.some(isInvalidParticipant)) {
    throw new Error(label + ' must contain two positive participant IDs');
  }
  return [value[0], value[1]];
}

function isInvalidParticipant(value: unknown): boolean {
  return typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1;
}

function nearManifestEntryForKeySet(
  manifest: WalletRecoveryPreparationKeyManifest,
  raw: unknown,
): Extract<WalletRecoveryPreparationKeyManifestEntry, { readonly kind: 'near_ed25519' }> {
  const keySetId = durableString(
    requireRecord(raw, 'recovery durable NEAR key set').keySetId,
    'recovery durable NEAR keySetId',
  );
  const entry = manifest.entries.find((candidate) => candidate.keySetId === keySetId);
  if (!entry || entry.kind !== 'near_ed25519') {
    throw new Error('recovery durable NEAR key-set manifest entry is invalid');
  }
  return entry;
}

function ecdsaManifestEntryForKeySet(
  manifest: WalletRecoveryPreparationKeyManifest,
  raw: unknown,
): WalletRecoveryPreparationEcdsaEntry {
  const keySetId = durableString(
    requireRecord(raw, 'recovery durable ECDSA key set').keySetId,
    'recovery durable ECDSA keySetId',
  );
  const entry = manifest.entries.find((candidate) => candidate.keySetId === keySetId);
  if (!entry || entry.kind !== 'evm_family_ecdsa') {
    throw new Error('recovery durable ECDSA key-set manifest entry is invalid');
  }
  return entry;
}

function durableRuntimePolicyScope(
  value: unknown,
): NonNullable<ReturnType<typeof normalizeThresholdRuntimePolicyScope>> {
  const scope = normalizeThresholdRuntimePolicyScope(value);
  if (!scope) throw new Error('recovery runtime policy scope is invalid');
  return scope;
}

function parseWalletRecoveryDurableNearKeySet(
  raw: unknown,
  manifestEntry: Extract<
    WalletRecoveryPreparationKeyManifestEntry,
    { readonly kind: 'near_ed25519' }
  >,
): WalletRecoveryDurableNearKeySetV1 {
  const record = requireRecord(raw, 'recovery durable NEAR key set');
  durableExactFields(record, NEAR_KEY_SET_FIELDS, 'recovery durable NEAR key set');
  if (record.kind !== 'near_ed25519' || record.keySetId !== manifestEntry.keySetId) {
    throw new Error('recovery durable NEAR key-set identity is invalid');
  }
  const basis = manifestEntry.recoveryBasis;
  const thresholdSessionId = basis.scope.threshold_session_id;
  if (!parseThresholdEd25519SessionId(thresholdSessionId).ok) {
    throw new Error('recovery durable NEAR thresholdSessionId is invalid');
  }
  const binding: WalletCustodyEd25519MaterialBindingV1 = {
    kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    applicationBindingDigestB64u: parseDigestField(
      record.applicationBindingDigestB64u,
      'recovery durable NEAR application binding digest',
    ),
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
      record.registeredPublicKeyB64u,
      'recovery durable NEAR registered public key',
    ),
    participantIds: durableParticipantPair(
      record.participantIds,
      'recovery durable NEAR participantIds',
    ),
    stateEpoch: durableString(record.stateEpoch, 'recovery durable NEAR stateEpoch'),
    walletId: basis.applicationBinding.wallet_id,
    nearAccountId: manifestEntry.nearAccountId,
    nearEd25519SigningKeyId: basis.applicationBinding.near_ed25519_signing_key_id,
    signerSlot: parseKeyCreationSignerSlot(
      basis.applicationBinding.key_creation_signer_slot,
      'recovery durable NEAR signerSlot',
    ),
    signingWorkerId: basis.scope.signing_worker_id,
    signingWorkerVerifyingShareB64u: parseEd25519PublicKeyB64u(
      record.signingWorkerVerifyingShareB64u,
      'recovery durable NEAR signing-worker verifying share',
    ),
  };
  const sealedRecord = requireRecord(record.sealed, 'recovery durable NEAR sealed material');
  durableExactFields(
    sealedRecord,
    ['ciphertextB64u', 'nonceB64u'],
    'recovery durable NEAR sealed material',
  );
  return {
    kind: 'near_ed25519',
    keySetId: manifestEntry.keySetId,
    binding,
    thresholdSessionId,
    runtimePolicyScope: durableRuntimePolicyScope(basis.runtimePolicyScope),
    materialActivation: parseRouterAbMpcMaterialActivationRef(record.materialActivation),
    sealed: {
      ciphertextB64u: parseEnvelopeCiphertextB64u(
        sealedRecord.ciphertextB64u,
        'recovery durable NEAR ciphertext',
      ),
      nonceB64u: parseEnvelopeNonceB64u(sealedRecord.nonceB64u, 'recovery durable NEAR nonce'),
    },
  };
}

function parseWalletRecoveryDurableEcdsaPublicFacts(
  raw: unknown,
): WalletCustodyEvmFamilyPublicFacts {
  const record = requireRecord(raw, 'recovery durable ECDSA public facts');
  durableExactFields(record, PUBLIC_FACTS_FIELDS, 'recovery durable ECDSA public facts');
  const ethereumAddress = durableString(
    record.ethereumAddress,
    'recovery durable ECDSA ethereumAddress',
  ).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(ethereumAddress)) {
    throw new Error('recovery durable ECDSA ethereumAddress is invalid');
  }
  return {
    contextBinding32B64u: parseDigestField(
      record.contextBinding32B64u,
      'recovery durable ECDSA context binding',
    ),
    derivationClientSharePublicKey33B64u: durableCompressedPublicKey(
      record.derivationClientSharePublicKey33B64u,
      'recovery durable ECDSA client share',
    ),
    clientVerifyingShare33B64u: durableCompressedPublicKey(
      record.clientVerifyingShare33B64u,
      'recovery durable ECDSA client verifying share',
    ),
    relayerPublicKey33B64u: durableCompressedPublicKey(
      record.relayerPublicKey33B64u,
      'recovery durable ECDSA relayer public key',
    ),
    groupPublicKey33B64u: durableCompressedPublicKey(
      record.groupPublicKey33B64u,
      'recovery durable ECDSA group public key',
    ),
    ethereumAddress,
    clientShareRetryCounter: durableSafeInteger(
      record.clientShareRetryCounter,
      'recovery durable ECDSA client-share retry counter',
    ),
    relayerShareRetryCounter: durableSafeInteger(
      record.relayerShareRetryCounter,
      'recovery durable ECDSA relayer-share retry counter',
    ),
  };
}

function parseWalletRecoveryDurableEcdsaKeySet(
  raw: unknown,
  manifestEntry: WalletRecoveryPreparationEcdsaEntry,
): WalletRecoveryDurableEcdsaKeySetV1 {
  const record = requireRecord(raw, 'recovery durable ECDSA key set');
  durableExactFields(record, ECDSA_KEY_SET_FIELDS, 'recovery durable ECDSA key set');
  if (record.kind !== 'evm_family_ecdsa' || record.keySetId !== manifestEntry.keySetId) {
    throw new Error('recovery durable ECDSA key-set identity is invalid');
  }
  return {
    kind: 'evm_family_ecdsa',
    entry: manifestEntry,
    possessionProof: parseWalletRecoveryEcdsaPossessionProofV1(record.possessionProof),
    readyStateBlobB64u: durableBase64Url(
      record.readyStateBlobB64u,
      'recovery durable ECDSA ready-state blob',
    ),
    publicFacts: parseWalletRecoveryDurableEcdsaPublicFacts(record.publicFacts),
  };
}

function parseWalletRecoveryDurableRegistration(
  raw: unknown,
): WalletRecoveryRedactedRegistrationV1 {
  const record = requireRecord(raw, 'recovery durable registration');
  durableExactFields(
    record,
    ['kind', 'id', 'rawId', 'type', 'authenticatorAttachment', 'response'],
    'recovery durable registration',
  );
  if (record.kind !== 'wallet_recovery_redacted_registration_v1') {
    throw new Error('recovery durable registration kind is invalid');
  }
  if (
    record.authenticatorAttachment !== null &&
    typeof record.authenticatorAttachment !== 'string'
  ) {
    throw new Error('recovery durable registration authenticatorAttachment is invalid');
  }
  const responseRecord = requireRecord(record.response, 'recovery durable registration response');
  durableExactFields(
    responseRecord,
    ['clientDataJSON', 'attestationObject', 'transports'],
    'recovery durable registration response',
  );
  if (!Array.isArray(responseRecord.transports)) {
    throw new Error('recovery durable registration transports are invalid');
  }
  return {
    kind: 'wallet_recovery_redacted_registration_v1',
    id: durableString(record.id, 'recovery durable registration id'),
    rawId: durableBase64Url(record.rawId, 'recovery durable registration rawId'),
    type: durableString(record.type, 'recovery durable registration type'),
    authenticatorAttachment: record.authenticatorAttachment,
    response: {
      clientDataJSON: durableBase64Url(
        responseRecord.clientDataJSON,
        'recovery durable registration clientDataJSON',
      ),
      attestationObject: durableBase64Url(
        responseRecord.attestationObject,
        'recovery durable registration attestationObject',
      ),
      transports: responseRecord.transports.map((transport, index) =>
        durableString(transport, 'recovery durable registration transports[' + index + ']'),
      ),
    },
  };
}

function parseWalletRecoveryDurableEnrollment(raw: unknown): WalletRecoveryEmailOtpEnrollment {
  const record = requireRecord(raw, 'recovery durable Email OTP enrollment');
  if (record.kind === 'existing') {
    durableExactFields(
      record,
      ['kind', 'enrollmentId', 'enrollmentSealKeyVersion'],
      'recovery durable existing Email OTP enrollment',
    );
    return {
      kind: 'existing',
      enrollmentId: durableString(record.enrollmentId, 'recovery enrollmentId'),
      enrollmentSealKeyVersion: durableString(
        record.enrollmentSealKeyVersion,
        'recovery enrollment seal-key version',
      ),
    };
  }
  if (record.kind !== 'create') {
    throw new Error('recovery durable Email OTP enrollment kind is invalid');
  }
  durableExactFields(
    record,
    ['kind', 'enrollmentId', 'providerSubject', 'verifiedEmail', 'material'],
    'recovery durable create Email OTP enrollment',
  );
  const material = requireRecord(record.material, 'recovery durable enrollment material');
  durableExactFields(
    material,
    [
      'enrollmentSealKeyVersion',
      'clientUnlockPublicKeyB64u',
      'unlockKeyVersion',
      'serverSealedFactorCiphertextB64u',
    ],
    'recovery durable enrollment material',
  );
  return {
    kind: 'create',
    enrollmentId: durableString(record.enrollmentId, 'recovery enrollmentId'),
    providerSubject: durableString(record.providerSubject, 'recovery enrollment providerSubject'),
    verifiedEmail: durableString(record.verifiedEmail, 'recovery enrollment verifiedEmail'),
    material: {
      enrollmentSealKeyVersion: durableString(
        material.enrollmentSealKeyVersion,
        'recovery enrollment material seal-key version',
      ),
      clientUnlockPublicKeyB64u: durableBase64Url(
        material.clientUnlockPublicKeyB64u,
        'recovery enrollment client unlock public key',
      ),
      unlockKeyVersion: durableString(
        material.unlockKeyVersion,
        'recovery enrollment unlock-key version',
      ),
      serverSealedFactorCiphertextB64u: durableBase64Url(
        material.serverSealedFactorCiphertextB64u,
        'recovery enrollment sealed factor ciphertext',
      ),
    },
  };
}

export function parseWalletRecoveryDurablePayload(raw: unknown): WalletRecoveryDurablePayloadV1 {
  const record = requireRecord(raw, 'wallet recovery durable payload');
  if (
    record.kind !== 'wallet_recovery_durable_payload_v1' ||
    record.version !== WALLET_RECOVERY_DURABLE_PAYLOAD_VERSION
  ) {
    throw new Error('wallet recovery durable payload version is invalid');
  }
  durableExactFields(
    record,
    [
      ...PAYLOAD_COMMON_FIELDS,
      ...(requireRecord(record.target, 'wallet recovery durable target').kind === 'passkey'
        ? ['replacementId', 'challengeId', 'registration']
        : [
            'providerSubject',
            'verifiedEmail',
            'emailHashHex',
            'registrationAuthorityId',
            'replacementId',
            'enrollment',
          ]),
    ],
    'wallet recovery durable payload',
  );

  const recoveryOperationId = parseWalletRecoveryOperationId(record.recoveryOperationId);
  const walletId = parseWalletId(record.walletId);
  let reservationId: RecoveryCodeReservationId;
  try {
    reservationId = parseRecoveryCodeReservationId(record.reservationId);
  } catch (error: unknown) {
    throw new Error('wallet recovery durable reservationId is invalid', { cause: error });
  }
  const targetDeviceId = parseDeviceId(record.targetDeviceId);
  const targetAuthorityId = parseWalletAuthorityId(record.targetAuthorityId);
  const targetWalletAuthMethodId = parseWalletAuthMethodId(record.targetWalletAuthMethodId);
  if (
    !recoveryOperationId.ok ||
    !walletId.ok ||
    !targetDeviceId.ok ||
    !targetAuthorityId.ok ||
    !targetWalletAuthMethodId.ok
  ) {
    throw new Error('wallet recovery durable payload identity is invalid');
  }
  if (!Array.isArray(record.nearKeySets) || !Array.isArray(record.ecdsaKeySets)) {
    throw new Error('wallet recovery durable key-set arrays are invalid');
  }
  const keyManifest = parseWalletRecoveryPreparationKeyManifest(
    record.keyManifest,
    String(walletId.value),
  );
  const nearKeySets = record.nearKeySets.map((keySet) =>
    parseWalletRecoveryDurableNearKeySet(keySet, nearManifestEntryForKeySet(keyManifest, keySet)),
  );
  const ecdsaKeySets = record.ecdsaKeySets.map((keySet) =>
    parseWalletRecoveryDurableEcdsaKeySet(keySet, ecdsaManifestEntryForKeySet(keyManifest, keySet)),
  );
  const keySetIds = [
    ...nearKeySets.map((keySet) => keySet.keySetId),
    ...ecdsaKeySets.map((keySet) => keySet.entry.keySetId),
  ];
  if (new Set(keySetIds).size !== keySetIds.length) {
    throw new Error('wallet recovery durable key-set ids are duplicated');
  }
  if (
    keyManifest.entries.length !== keySetIds.length ||
    keyManifest.entries.some((entry) => !keySetIds.includes(entry.keySetId))
  ) {
    throw new Error('wallet recovery durable key-set manifest coverage is invalid');
  }
  const common: WalletRecoveryDurablePayloadCommonV1 = {
    kind: 'wallet_recovery_durable_payload_v1',
    version: WALLET_RECOVERY_DURABLE_PAYLOAD_VERSION,
    recoveryOperationId: recoveryOperationId.value,
    walletId: walletId.value,
    reservationId,
    targetDeviceId: targetDeviceId.value,
    targetAuthorityId: targetAuthorityId.value,
    targetWalletAuthMethodId: targetWalletAuthMethodId.value,
    replacementEnvelope: parsePasskeyCustodyEnvelopeRecord(
      record.replacementEnvelope,
      'wallet recovery durable replacementEnvelope',
    ),
    keyManifest,
    nearKeySets,
    ecdsaKeySets,
  };
  if (String(common.replacementEnvelope.walletId) !== String(walletId.value)) {
    throw new Error('wallet recovery durable replacement envelope wallet changed');
  }
  if (
    common.replacementEnvelope.ownership.kind !== 'method_bound' ||
    common.replacementEnvelope.ownership.walletAuthMethodId !== targetWalletAuthMethodId.value
  ) {
    throw new Error('wallet recovery durable replacement envelope method changed');
  }
  for (const keySet of nearKeySets) {
    if (keySet.binding.walletId !== String(walletId.value)) {
      throw new Error('wallet recovery durable NEAR binding wallet changed');
    }
  }
  const target = requireRecord(record.target, 'wallet recovery durable target');
  if (target.kind === 'passkey') {
    durableExactFields(target, ['kind', 'rpId'], 'wallet recovery durable passkey target');
    const rpId = parseWebAuthnRpId(target.rpId);
    if (!rpId.ok) throw new Error('wallet recovery durable passkey RP ID is invalid');
    const registration = parseWalletRecoveryDurableRegistration(record.registration);
    if (registration.rawId !== common.replacementEnvelope.factor.credentialIdB64u) {
      throw new Error('wallet recovery durable passkey registration identity changed');
    }
    if (common.replacementEnvelope.factor.kind !== 'passkey') {
      throw new Error('wallet recovery durable passkey envelope factor is invalid');
    }
    if (
      common.replacementEnvelope.factor.rpId !== rpId.value ||
      common.replacementEnvelope.factor.credentialIdB64u !== registration.rawId
    ) {
      throw new Error('wallet recovery durable passkey envelope identity changed');
    }
    const replacementId = durableString(
      record.replacementId,
      'wallet recovery durable replacementId',
    );
    if (String(common.replacementEnvelope.envelopeId) !== replacementId) {
      throw new Error('wallet recovery durable passkey envelope id changed');
    }
    return {
      ...common,
      target: { kind: 'passkey', rpId: rpId.value },
      replacementId,
      challengeId: durableString(record.challengeId, 'wallet recovery durable challengeId'),
      registration,
    };
  }
  if (target.kind !== 'google_email_otp') {
    throw new Error('wallet recovery durable target kind is invalid');
  }
  durableExactFields(target, ['kind'], 'wallet recovery durable Email OTP target');
  const providerSubject = durableString(record.providerSubject, 'wallet recovery providerSubject');
  if (!parseEmailOtpProviderUserId(providerSubject).ok) {
    throw new Error('wallet recovery durable providerSubject is invalid');
  }
  const verifiedEmail = durableString(
    record.verifiedEmail,
    'wallet recovery durable verifiedEmail',
  );
  const emailHashHex = durableString(record.emailHashHex, 'wallet recovery durable emailHashHex');
  if (!/^[0-9a-f]{64}$/.test(emailHashHex)) {
    throw new Error('wallet recovery durable emailHashHex is invalid');
  }
  const registrationAuthorityId = durableString(
    record.registrationAuthorityId,
    'wallet recovery durable registrationAuthorityId',
  );
  const enrollment = parseWalletRecoveryDurableEnrollment(record.enrollment);
  if (common.replacementEnvelope.factor.kind !== 'email_otp') {
    throw new Error('wallet recovery durable Email OTP envelope factor is invalid');
  }
  const enrollmentReference =
    enrollment.kind === 'existing'
      ? {
          enrollmentId: enrollment.enrollmentId,
          enrollmentSealKeyVersion: enrollment.enrollmentSealKeyVersion,
        }
      : {
          enrollmentId: enrollment.enrollmentId,
          enrollmentSealKeyVersion: enrollment.material.enrollmentSealKeyVersion,
        };
  if (
    common.replacementEnvelope.factor.enrollmentId !== enrollmentReference.enrollmentId ||
    common.replacementEnvelope.factor.enrollmentSealKeyVersion !==
      enrollmentReference.enrollmentSealKeyVersion
  ) {
    throw new Error('wallet recovery durable Email OTP envelope identity changed');
  }
  if (
    enrollment.kind === 'create' &&
    (enrollment.providerSubject !== providerSubject || enrollment.verifiedEmail !== verifiedEmail)
  ) {
    throw new Error('wallet recovery durable Email OTP enrollment identity changed');
  }
  const replacementId = durableString(
    record.replacementId,
    'wallet recovery durable replacementId',
  );
  if (String(common.replacementEnvelope.envelopeId) !== replacementId) {
    throw new Error('wallet recovery durable Email OTP envelope id changed');
  }
  return {
    ...common,
    target: { kind: 'google_email_otp' },
    providerSubject,
    verifiedEmail,
    emailHashHex,
    registrationAuthorityId,
    replacementId,
    enrollment,
  };
}

/**
 * Projects a parsed payload back onto the serialized wire shape the parser
 * accepts. Parsing enriches the key sets with manifest-derived facts (the
 * NEAR material binding, threshold session, and runtime scope; the ECDSA
 * manifest entry), so serializing the parsed record directly produces fields
 * the exact-field parser rejects on the next decrypt. The projection is
 * validated by the parser before it is returned, so an encrypt-time failure
 * surfaces immediately instead of stranding an undecodable journal record.
 */
export function walletRecoveryDurablePayloadWireForm(
  payload: WalletRecoveryDurablePayloadV1,
): Record<string, unknown> {
  const nearKeySets = payload.nearKeySets.map((keySet) => ({
    kind: keySet.kind,
    keySetId: keySet.keySetId,
    applicationBindingDigestB64u: keySet.binding.applicationBindingDigestB64u,
    registeredPublicKeyB64u: keySet.binding.registeredPublicKeyB64u,
    participantIds: keySet.binding.participantIds,
    stateEpoch: keySet.binding.stateEpoch,
    signingWorkerVerifyingShareB64u: keySet.binding.signingWorkerVerifyingShareB64u,
    materialActivation: keySet.materialActivation,
    sealed: keySet.sealed,
  }));
  const ecdsaKeySets = payload.ecdsaKeySets.map((keySet) => ({
    kind: keySet.kind,
    keySetId: keySet.entry.keySetId,
    possessionProof: keySet.possessionProof,
    readyStateBlobB64u: keySet.readyStateBlobB64u,
    publicFacts: keySet.publicFacts,
  }));
  const common = {
    kind: payload.kind,
    version: payload.version,
    recoveryOperationId: String(payload.recoveryOperationId),
    walletId: String(payload.walletId),
    reservationId: String(payload.reservationId),
    targetDeviceId: String(payload.targetDeviceId),
    targetAuthorityId: String(payload.targetAuthorityId),
    targetWalletAuthMethodId: String(payload.targetWalletAuthMethodId),
    replacementEnvelope: payload.replacementEnvelope,
    keyManifest: payload.keyManifest,
    nearKeySets,
    ecdsaKeySets,
  };
  const wire = isDurablePasskeyPayload(payload)
    ? {
        ...common,
        target: payload.target,
        replacementId: payload.replacementId,
        challengeId: payload.challengeId,
        registration: payload.registration,
      }
    : {
        ...common,
        target: payload.target,
        providerSubject: payload.providerSubject,
        verifiedEmail: payload.verifiedEmail,
        emailHashHex: payload.emailHashHex,
        registrationAuthorityId: payload.registrationAuthorityId,
        replacementId: payload.replacementId,
        enrollment: payload.enrollment,
      };
  parseWalletRecoveryDurablePayload(wire);
  return wire;
}

export async function validateWalletRecoveryDurablePayloadBindings(
  payload: WalletRecoveryDurablePayloadV1,
): Promise<void> {
  if (isDurablePasskeyPayload(payload)) return;
  const expectedEmailHashHex = await sha256HexUtf8(payload.verifiedEmail);
  if (payload.emailHashHex !== expectedEmailHashHex) {
    throw new Error('wallet recovery durable email hash does not match verified email');
  }
  if (
    payload.enrollment.kind === 'create' &&
    (payload.enrollment.providerSubject !== payload.providerSubject ||
      payload.enrollment.verifiedEmail !== payload.verifiedEmail)
  ) {
    throw new Error('wallet recovery durable enrollment does not match Email OTP identity');
  }
}

export function durablePayloadIdentityTarget(
  payload: WalletRecoveryDurablePasskeyPayload,
): Extract<PendingWalletRecoveryCommitV1['target'], { readonly kind: 'passkey' }>;
export function durablePayloadIdentityTarget(
  payload: WalletRecoveryDurableEmailOtpPayload,
): Extract<PendingWalletRecoveryCommitV1['target'], { readonly kind: 'google_email_otp' }>;
export function durablePayloadIdentityTarget(
  payload: WalletRecoveryDurablePayloadV1,
): PendingWalletRecoveryCommitV1['target'];
export function durablePayloadIdentityTarget(
  payload: WalletRecoveryDurablePayloadV1,
): PendingWalletRecoveryCommitV1['target'] {
  if (isDurablePasskeyPayload(payload)) {
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(payload.registration.rawId);
    if (!credentialIdB64u.ok) {
      throw new Error('wallet recovery durable passkey credential id is invalid');
    }
    return {
      kind: 'passkey',
      rpId: payload.target.rpId,
      credentialIdB64u: credentialIdB64u.value,
    };
  }
  const providerSubject = parseEmailOtpProviderUserId(payload.providerSubject);
  if (!providerSubject.ok) throw new Error('wallet recovery durable providerSubject is invalid');
  return {
    kind: 'google_email_otp',
    providerSubject: providerSubject.value,
    emailHashHex: payload.emailHashHex,
    registrationAuthorityId: payload.registrationAuthorityId,
    enrollment: durableEmailEnrollmentReference(payload),
  };
}

function durableNearKeySetFromRecovered(
  recovered: RecoveredWalletCustodyNearKeySetV1,
): WalletRecoveryDurableNearKeySetRecordV1 {
  return {
    kind: 'near_ed25519',
    keySetId: recovered.entry.keySetId,
    applicationBindingDigestB64u: recovered.localMaterial.applicationBindingDigestB64u,
    registeredPublicKeyB64u: base64UrlEncode(recovered.metadata.registeredPublicKey),
    participantIds: recovered.metadata.participantIds,
    stateEpoch: String(recovered.metadata.stateEpoch),
    signingWorkerVerifyingShareB64u: base64UrlEncode(
      recovered.metadata.signingWorkerVerifyingShare,
    ),
    materialActivation: routerAbMpcMaterialActivationRefToWire(
      recovered.metadata.materialActivation,
    ),
    sealed: {
      ciphertextB64u: recovered.localMaterial.b64u,
      nonceB64u: recovered.localMaterial.nonceB64u,
    },
  };
}

function durableEcdsaKeySetFromRecovered(
  recovered: RecoveredWalletCustodyEcdsaKeySetV1,
): WalletRecoveryDurableEcdsaKeySetRecordV1 {
  return {
    kind: 'evm_family_ecdsa',
    keySetId: recovered.entry.keySetId,
    possessionProof: parseWalletRecoveryEcdsaPossessionProofV1(
      recovered.activation.possessionProof,
    ),
    readyStateBlobB64u: recovered.readyStateBlobB64u,
    publicFacts: recovered.publicFacts,
  };
}

function redactedRecoveryRegistration(
  registration: WalletRecoveryReplacementCredential['registration'],
): WalletRecoveryRedactedRegistrationV1 {
  return {
    kind: 'wallet_recovery_redacted_registration_v1',
    id: registration.id,
    rawId: registration.rawId,
    type: registration.type,
    authenticatorAttachment: registration.authenticatorAttachment ?? null,
    response: {
      clientDataJSON: registration.response.clientDataJSON,
      attestationObject: registration.response.attestationObject,
      transports: [...registration.response.transports],
    },
  };
}

export async function walletRecoveryDurablePayloadFromOperation(
  operation: WalletRecoveryDurableOperationInput,
): Promise<WalletRecoveryDurablePayloadV1> {
  const common = {
    kind: 'wallet_recovery_durable_payload_v1' as const,
    version: WALLET_RECOVERY_DURABLE_PAYLOAD_VERSION,
    recoveryOperationId: String(operation.prepared.recoveryOperationId),
    walletId: operation.walletId,
    reservationId: operation.prepared.reservationId,
    targetDeviceId: operation.prepared.targetDeviceId,
    targetAuthorityId: operation.prepared.targetAuthorityId,
    targetWalletAuthMethodId: operation.prepared.targetWalletAuthMethodId,
    replacementEnvelope: parsePasskeyCustodyEnvelopeRecord(
      operation.recovered.replacementEnvelope,
      'wallet recovery durable replacement envelope',
    ),
    keyManifest: {
      version: 'wallet_recovery_preparation_key_manifest_v1',
      walletId: String(operation.walletId),
      entries: [
        ...operation.recovered.nearKeySets.map((keySet) => keySet.entry),
        ...operation.recovered.ecdsaKeySets.map((keySet) => keySet.entry),
      ],
    },
    nearKeySets: operation.recovered.nearKeySets.map(durableNearKeySetFromRecovered),
    ecdsaKeySets: operation.recovered.ecdsaKeySets.map(durableEcdsaKeySetFromRecovered),
  };
  if (operation.replacement.kind === 'passkey') {
    if (operation.target.kind !== 'passkey') {
      throw new Error('wallet recovery durable payload branch is invalid');
    }
    const registrationOptions = operation.prepared.registration;
    if (!registrationOptions)
      throw new Error('wallet recovery registration options are unavailable');
    const registration = redactedRecoveryRegistration(operation.replacement.registration);
    if (registration.rawId !== operation.replacement.credentialIdB64u) {
      throw new Error('wallet recovery passkey registration rawId changed its credential identity');
    }
    const payload = parseWalletRecoveryDurablePayload({
      ...common,
      target: { kind: 'passkey', rpId: operation.target.rpId },
      replacementId: registrationOptions.replacementId,
      challengeId: registrationOptions.challengeId,
      registration,
    });
    await validateWalletRecoveryDurablePayloadBindings(payload);
    return payload;
  }
  if (operation.target.kind !== 'google_email_otp') {
    throw new Error('wallet recovery durable payload branch is invalid');
  }
  const enrollment = operation.replacement.enrollment;
  if (operation.replacement.factor.walletAuthMethodId !== common.targetWalletAuthMethodId) {
    throw new Error('wallet recovery Email OTP factor method changed its target identity');
  }
  const emailHashHex = await sha256HexUtf8(operation.replacement.verifiedEmail);
  const payload = parseWalletRecoveryDurablePayload({
    ...common,
    target: { kind: 'google_email_otp' },
    // The enrollment id is public identity metadata; the enrollment material intentionally
    // carries only the sealed factor inputs needed by the server.
    enrollment,
    providerSubject: operation.replacement.providerSubject,
    verifiedEmail: operation.replacement.verifiedEmail,
    emailHashHex,
    registrationAuthorityId: operation.replacement.registrationAuthorityId,
    replacementId: operation.replacement.factor.replacementId,
  });
  await validateWalletRecoveryDurablePayloadBindings(payload);
  return payload;
}
