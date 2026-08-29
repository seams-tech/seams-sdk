import type { WalletRecoveryWebContext } from '@/SeamsWeb/signingSurface/ports';
import {
  buildWalletRecoveryCeremonyCustodyJson,
  prepareWalletRecoveryWithCode,
  type PreparedWalletRecovery,
  type WalletRecoveryAttemptFailure,
} from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import {
  finalizeWalletRecovery,
  type WalletRecoveryFinalizeResult,
} from '@/core/rpcClients/relayer/walletRecoveryFinalize';
import {
  verifyWalletRecoveryGoogle,
  verifyWalletRecoveryEmailOtp,
  finalizeWalletRecoveryGoogleEmailOtp,
  type WalletRecoveryGoogleEmailOtpFinalizeResult,
  type WalletRecoveryEmailOtpEnrollmentMaterial,
} from '@/core/rpcClients/relayer/walletRecoveryGoogleEmailOtp';
import { persistRecoveredPasskeyAuthMethodProjectionV1 } from '@/SeamsWeb/operations/authMethods/passkey/localPasskeyProjection';
import { persistFinalizedEmailOtpAuthMethodV1 } from '@/SeamsWeb/operations/authMethods/emailOtp/localEmailOtpProjection';
import type { WalletRecoveryReplacementCredential } from '@/core/signingEngine/walletCustody/walletRecoveryCredential';
import { buildEmailOtpEnvelopeFactor, buildPasskeyEnvelopeFactor } from '@shared/passkey-custody';
import type {
  RecoveredWalletCustodyEcdsaKeySetV1,
  RecoveredWalletCustodyManifestV1,
  RecoveredWalletCustodyNearKeySetV1,
  WalletRecoveryReplacementFactorInput,
} from '@/core/signingEngine/walletCustody/walletRecoveryManifest';
import { WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND } from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { base58Encode, base64UrlEncode } from '@shared/utils/encoders';
import { toAccountId } from '@/core/types/accountIds';
import {
  parseEmailOtpChallengeId,
  parseThresholdEd25519SessionId,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { decodeWalletRecoveryCode } from '@shared/wallet-recovery/recoveryCodes';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { sha256Bytes } from '@shared/utils/digests';
import { NEAR_ED25519_YAO_KEY_VERSION_V1 } from '@shared/utils/registrationIntent';
import type { EmailOtpChallengeDelivery } from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { EmailOtpWorkerOperationMap } from '@/core/signingEngine/workerManager/workerTypes';
import { IndexedDBManager } from '@/core/indexedDB';
import { normalizeThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { computeEcdsaDerivationRoleLocalRelayerKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

const RECOVERY_PREPARE_RETRY_TTL_MS = 5 * 60 * 1000;
// ECDSA-only registration establishes its wallet-scoped passkey at slot 1.
const ECDSA_ONLY_WALLET_SIGNER_SLOT = 1;

export type WalletRecoveryPreparedHandle = {
  readonly kind: 'prepared';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: WalletRecoveryTargetV1;
};

export type WalletRecoveryCredentialCreatedHandle = {
  readonly kind: 'credential_created';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
};

export type WalletRecoveryGoogleVerifiedHandle = {
  readonly kind: 'google_verified';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
  readonly challengeId: string;
  readonly delivery: EmailOtpChallengeDelivery;
  readonly expiresAtMs: number;
};

export type WalletRecoveryEmailOtpVerifiedHandle = {
  readonly kind: 'email_otp_verified';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
  readonly challengeId: string;
};

type WalletRecoveryEmailOtpEnrollment =
  | {
      readonly kind: 'existing';
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
    }
  | {
      readonly kind: 'create';
      readonly providerSubject: string;
      readonly verifiedEmail: string;
      readonly material: WalletRecoveryEmailOtpEnrollmentMaterial;
    };

export type WalletRecoveryCoordinatorRpc = {
  readonly verifyGoogle: typeof verifyWalletRecoveryGoogle;
  readonly verifyEmailOtp: typeof verifyWalletRecoveryEmailOtp;
  readonly finalizeEmailOtp: typeof finalizeWalletRecoveryGoogleEmailOtp;
};

export type WalletRecoveryCoordinatorResult<T> = T | WalletRecoveryAttemptFailure;

export type WalletRecoveryPrepareCoordinatorResult =
  | WalletRecoveryPreparedHandle
  | WalletRecoveryAttemptFailure
  | { readonly kind: 'consumed' };

export type WalletRecoveryCredentialCreationResult =
  | WalletRecoveryCredentialCreatedHandle
  | { readonly kind: 'dismissed' }
  | { readonly kind: 'refused' }
  | { readonly kind: 'transport_uncertain' };

export type WalletRecoveryFinalizeCoordinatorResult =
  | { readonly kind: 'ready_for_sign_in'; readonly walletId: WalletId }
  | WalletRecoveryAttemptFailure;

type RecoveryOperationCommon = {
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly relayUrl: string;
  readonly target: WalletRecoveryTargetV1;
  readonly prepared: PreparedWalletRecovery;
  readonly custodyJson: string;
  readonly recoveryCodeBytes: Uint8Array;
};

type RecoveryPasskeyReplacement = {
  readonly kind: 'passkey';
  readonly registration: WalletRecoveryReplacementCredential['registration'];
  readonly credentialIdB64u: WalletRecoveryReplacementCredential['credentialIdB64u'];
  readonly factorSecret: ArrayBuffer;
};

type RecoveryEmailOtpReplacement = {
  readonly kind: 'email_otp';
  readonly factor: WalletRecoveryReplacementFactorInput;
  readonly enrollment: WalletRecoveryEmailOtpEnrollment;
  readonly providerSubject: string;
  readonly verifiedEmail: string;
};

function isGooglePreparedWalletRecovery(
  prepared: PreparedWalletRecovery,
): prepared is Extract<
  PreparedWalletRecovery,
  { readonly target: { readonly kind: 'google_email_otp' } }
> {
  return prepared.target.kind === 'google_email_otp';
}

type CommittedRecoveryPromotion =
  | Extract<WalletRecoveryFinalizeResult, { readonly kind: 'promoted' }>
  | Extract<WalletRecoveryGoogleEmailOtpFinalizeResult, { readonly kind: 'promoted' }>;

type RecoveryOperation =
  | (RecoveryOperationCommon & {
      readonly stage: 'prepared';
      readonly replacement?: never;
      readonly recovered?: never;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'credential_created';
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
      readonly prepared: Extract<
        PreparedWalletRecovery,
        { readonly target: { readonly kind: 'passkey' } }
      >;
      readonly replacement: RecoveryPasskeyReplacement;
      readonly recovered?: never;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'google_verified';
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
      readonly prepared: Extract<
        PreparedWalletRecovery,
        { readonly target: { readonly kind: 'google_email_otp' } }
      >;
      readonly verification: WalletRecoveryGoogleVerifiedHandle;
      readonly recovered?: never;
      readonly replacement?: never;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'email_otp_verified';
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
      readonly prepared: Extract<
        PreparedWalletRecovery,
        { readonly target: { readonly kind: 'google_email_otp' } }
      >;
      readonly replacement: RecoveryEmailOtpReplacement;
      readonly recovered?: never;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'manifest_recovered';
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
      readonly prepared: Extract<
        PreparedWalletRecovery,
        { readonly target: { readonly kind: 'passkey' } }
      >;
      readonly replacement: RecoveryPasskeyReplacement;
      readonly recovered: RecoveredWalletCustodyManifestV1;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'manifest_recovered';
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
      readonly prepared: Extract<
        PreparedWalletRecovery,
        { readonly target: { readonly kind: 'google_email_otp' } }
      >;
      readonly replacement: RecoveryEmailOtpReplacement;
      readonly recovered: RecoveredWalletCustodyManifestV1;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'promoted_pending_continuity';
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
      readonly prepared: Extract<
        PreparedWalletRecovery,
        { readonly target: { readonly kind: 'passkey' } }
      >;
      readonly replacement: RecoveryPasskeyReplacement;
      readonly recovered: RecoveredWalletCustodyManifestV1;
      readonly committedPromotion: Extract<
        CommittedRecoveryPromotion,
        { readonly authMethod: { readonly kind: 'passkey' } }
      >;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'promoted_pending_continuity';
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
      readonly prepared: Extract<
        PreparedWalletRecovery,
        { readonly target: { readonly kind: 'google_email_otp' } }
      >;
      readonly replacement: RecoveryEmailOtpReplacement;
      readonly recovered: RecoveredWalletCustodyManifestV1;
      readonly committedPromotion: Extract<
        CommittedRecoveryPromotion,
        { readonly authMethod: { readonly kind: 'email_otp' } }
      >;
    });

type RecoveryFinalizationOperation = Extract<
  RecoveryOperation,
  {
    readonly stage:
      | 'credential_created'
      | 'email_otp_verified'
      | 'manifest_recovered'
      | 'promoted_pending_continuity';
  }
>;

function recoveryFinalizationOperation(
  operation: RecoveryOperation | undefined,
  handle: WalletRecoveryCredentialCreatedHandle | WalletRecoveryEmailOtpVerifiedHandle,
): RecoveryFinalizationOperation | null {
  if (
    !operation ||
    operation.stage === 'prepared' ||
    operation.stage === 'google_verified' ||
    operation.walletId !== handle.walletId ||
    operation.target.kind !== handle.target.kind
  ) {
    return null;
  }
  switch (operation.target.kind) {
    case 'passkey':
      return handle.kind === 'credential_created' &&
        handle.target.kind === 'passkey' &&
        operation.target.rpId === handle.target.rpId
        ? operation
        : null;
    case 'google_email_otp':
      return handle.kind === 'email_otp_verified' &&
        handle.target.kind === 'google_email_otp' &&
        operation.target.googleProvider === handle.target.googleProvider
        ? operation
        : null;
  }
}

function createReservationId(): RecoveryCodeReservationId {
  return parseRecoveryCodeReservationId(
    secureRandomId('wallet-recovery-reservation', 32, 'wallet recovery operation reservations'),
  );
}

function pendingPrepareKey(recoveryCodeDigestB64u: string): string {
  return recoveryCodeDigestB64u;
}

const CONSUMED_RECOVERY_CODE_DIGESTS_SESSION_KEY = 'seams:recovery:consumed-code-digests';

function readConsumedRecoveryCodeDigests(): Set<string> {
  try {
    const raw: unknown = JSON.parse(
      sessionStorage.getItem(CONSUMED_RECOVERY_CODE_DIGESTS_SESSION_KEY) ?? '[]',
    );
    if (!Array.isArray(raw)) return new Set();
    return new Set(raw.filter((value): value is string => typeof value === 'string'));
  } catch {
    return new Set();
  }
}

function rememberConsumedRecoveryCodeDigest(digests: Set<string>, digest: string): void {
  digests.add(digest);
  try {
    sessionStorage.setItem(
      CONSUMED_RECOVERY_CODE_DIGESTS_SESSION_KEY,
      JSON.stringify([...digests].slice(-32)),
    );
  } catch {}
}

function zeroizeBuffer(buffer: ArrayBuffer | null): void {
  if (buffer && buffer.byteLength > 0) new Uint8Array(buffer).fill(0);
}

function disposeRecoveryOperation(operation: RecoveryOperation): void {
  operation.recoveryCodeBytes.fill(0);
  switch (operation.stage) {
    case 'prepared':
    case 'google_verified':
      return;
    case 'credential_created':
      zeroizeBuffer(operation.replacement.factorSecret);
      return;
    case 'email_otp_verified':
    case 'manifest_recovered':
    case 'promoted_pending_continuity':
      zeroizeBuffer(
        operation.replacement.kind === 'passkey'
          ? operation.replacement.factorSecret
          : operation.replacement.factor.factorSecret,
      );
      return;
  }
}

function refused(): WalletRecoveryAttemptFailure {
  return { kind: 'refused' };
}

function isCredentialDismissal(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const name = Reflect.get(error, 'name');
  return name === 'NotAllowedError' || name === 'AbortError';
}

function credentialCreatedOperation(
  current: Extract<RecoveryOperation, { stage: 'prepared' }>,
  replacement: WalletRecoveryReplacementCredential,
): Extract<RecoveryOperation, { stage: 'credential_created' }> {
  if (current.target.kind !== 'passkey' || !current.prepared.registration) {
    throw new Error('passkey recovery registration is unavailable');
  }
  return {
    stage: 'credential_created',
    recoveryOperationId: current.recoveryOperationId,
    walletId: current.walletId,
    relayUrl: current.relayUrl,
    target: current.target,
    prepared: current.prepared,
    custodyJson: current.custodyJson,
    recoveryCodeBytes: current.recoveryCodeBytes,
    replacement: {
      kind: 'passkey',
      registration: replacement.registration,
      credentialIdB64u: replacement.credentialIdB64u,
      factorSecret: replacement.factorSecret,
    },
  };
}

function emailOtpVerifiedOperation(
  current: Extract<RecoveryOperation, { stage: 'google_verified' }>,
  replacement: RecoveryEmailOtpReplacement,
): Extract<RecoveryOperation, { stage: 'email_otp_verified' }> {
  return {
    stage: 'email_otp_verified',
    recoveryOperationId: current.recoveryOperationId,
    walletId: current.walletId,
    relayUrl: current.relayUrl,
    target: current.target,
    prepared: current.prepared,
    custodyJson: current.custodyJson,
    recoveryCodeBytes: current.recoveryCodeBytes,
    replacement,
  };
}

function passkeyRecoveryReplacementFactor(
  operation: Extract<RecoveryOperation, { stage: 'credential_created' }>,
): WalletRecoveryReplacementFactorInput {
  const registration = operation.prepared.registration;
  if (!registration) throw new Error('passkey recovery registration is unavailable');
  return {
    replacementId: registration.replacementId,
    walletAuthMethodId: registration.walletAuthMethodId,
    factor: buildPasskeyEnvelopeFactor({
      rpId: registration.rpId,
      credentialIdB64u: operation.replacement.credentialIdB64u,
    }),
    factorSecret: operation.replacement.factorSecret,
  };
}

function passkeyRecoveryChallengeId(
  operation: Extract<RecoveryOperation, { stage: 'credential_created' }>,
): string {
  const registration = operation.prepared.registration;
  if (!registration) throw new Error('passkey recovery registration is unavailable');
  return registration.challengeId;
}

function passkeyManifestRecoveredOperation(
  current: Extract<RecoveryOperation, { stage: 'credential_created' }>,
  recovered: RecoveredWalletCustodyManifestV1,
): Extract<RecoveryOperation, { stage: 'manifest_recovered'; target: { kind: 'passkey' } }> {
  return {
    stage: 'manifest_recovered',
    recoveryOperationId: current.recoveryOperationId,
    walletId: current.walletId,
    relayUrl: current.relayUrl,
    target: current.target,
    prepared: current.prepared,
    custodyJson: current.custodyJson,
    recoveryCodeBytes: current.recoveryCodeBytes,
    replacement: current.replacement,
    recovered,
  };
}

function emailOtpManifestRecoveredOperation(
  current: Extract<RecoveryOperation, { stage: 'email_otp_verified' }>,
  recovered: RecoveredWalletCustodyManifestV1,
): Extract<
  RecoveryOperation,
  { stage: 'manifest_recovered'; target: { kind: 'google_email_otp' } }
> {
  return {
    stage: 'manifest_recovered',
    recoveryOperationId: current.recoveryOperationId,
    walletId: current.walletId,
    relayUrl: current.relayUrl,
    target: current.target,
    prepared: current.prepared,
    custodyJson: current.custodyJson,
    recoveryCodeBytes: current.recoveryCodeBytes,
    replacement: current.replacement,
    recovered,
  };
}

function passkeyPromotedPendingContinuityOperation(
  current: Extract<RecoveryOperation, { stage: 'manifest_recovered'; target: { kind: 'passkey' } }>,
  committedPromotion: Extract<
    CommittedRecoveryPromotion,
    { readonly authMethod: { readonly kind: 'passkey' } }
  >,
): Extract<
  RecoveryOperation,
  { stage: 'promoted_pending_continuity'; target: { kind: 'passkey' } }
> {
  return {
    ...current,
    stage: 'promoted_pending_continuity',
    committedPromotion,
  };
}

function emailOtpPromotedPendingContinuityOperation(
  current: Extract<
    RecoveryOperation,
    { stage: 'manifest_recovered'; target: { kind: 'google_email_otp' } }
  >,
  committedPromotion: Extract<
    CommittedRecoveryPromotion,
    { readonly authMethod: { readonly kind: 'email_otp' } }
  >,
): Extract<
  RecoveryOperation,
  { stage: 'promoted_pending_continuity'; target: { kind: 'google_email_otp' } }
> {
  return {
    ...current,
    stage: 'promoted_pending_continuity',
    committedPromotion,
  };
}

function recoveredPasskeyWalletAuthAuthority(input: {
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): PasskeyWalletAuthAuthority {
  return {
    walletId: input.walletId,
    factor: { kind: 'passkey', credentialIdB64u: input.credentialIdB64u },
    verifier: { kind: 'webauthn', rpId: input.rpId },
    bindingId: input.walletAuthMethodId,
  };
}

async function persistRecoveredNearKeySet(input: {
  readonly context: WalletRecoveryWebContext;
  readonly walletId: WalletId;
  readonly recovered: RecoveredWalletCustodyNearKeySetV1;
}): Promise<void> {
  const basis = input.recovered.entry.recoveryBasis;
  const application = basis.applicationBinding;
  const metadata = input.recovered.metadata;
  await input.context.signingEngine.persistWalletCustodyEd25519Material({
    binding: {
      kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
      applicationBindingDigestB64u: input.recovered.localMaterial.applicationBindingDigestB64u,
      registeredPublicKeyB64u: base64UrlEncode(metadata.registeredPublicKey),
      participantIds: metadata.participantIds,
      stateEpoch: String(metadata.stateEpoch),
      walletId: input.walletId,
      nearAccountId: input.recovered.entry.nearAccountId,
      nearEd25519SigningKeyId: application.near_ed25519_signing_key_id,
      signerSlot: application.key_creation_signer_slot,
      signingWorkerId: metadata.scope.signing_worker_id,
      signingWorkerVerifyingShareB64u: base64UrlEncode(metadata.signingWorkerVerifyingShare),
    },
    sealed: {
      ciphertextB64u: input.recovered.localMaterial.b64u,
      nonceB64u: input.recovered.localMaterial.nonceB64u,
    },
  });
  const thresholdSessionId = parseThresholdEd25519SessionId(metadata.scope.threshold_session_id);
  if (!thresholdSessionId.ok) {
    throw new Error('recovered Ed25519 threshold session id is invalid');
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(basis.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error('recovered Ed25519 runtime policy scope is invalid');
  }
  await input.context.signingEngine.upsertEd25519YaoPublicCapabilityReference({
    walletId: input.walletId,
    nearAccountId: toAccountId(input.recovered.entry.nearAccountId),
    thresholdSessionId: thresholdSessionId.value,
    runtimePolicyScope,
    materialActivation: metadata.materialActivation,
  });
}

async function persistRecoveredEcdsaKeySet(input: {
  readonly context: WalletRecoveryWebContext;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly recovered: RecoveredWalletCustodyEcdsaKeySetV1;
}): Promise<void> {
  const basis = input.recovered.entry.recoveryBasis;
  const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
    walletId: input.walletId,
    signingRootId: basis.signingRootId,
    signingRootVersion: basis.signingRootVersion,
  });
  await input.context.signingEngine.restoreWalletCustodyEcdsaContinuity({
    authority: input.authority,
    chainTargets: basis.chainTargets,
    walletId: input.walletId,
    keyHandle: input.recovered.entry.keyHandle,
    ecdsaThresholdKeyId: basis.ecdsaThresholdKeyId,
    signingRootId: basis.signingRootId,
    signingRootVersion: basis.signingRootVersion,
    relayerKeyId,
    participantIds: basis.participantIds,
    publicCapability: input.recovered.activation.publicCapability,
    activationReceipt: input.recovered.activation.activationReceipt,
    runtimePolicyScope: basis.runtimePolicyScope,
    readyStateBlobB64u: input.recovered.readyStateBlobB64u,
    publicFacts: input.recovered.publicFacts,
  });
}

async function persistRecoveredPasskeyLocalContinuity(input: {
  readonly context: WalletRecoveryWebContext;
  readonly operation: Extract<RecoveryOperation, { stage: 'promoted_pending_continuity' }> & {
    readonly replacement: RecoveryPasskeyReplacement;
    readonly committedPromotion: Extract<
      CommittedRecoveryPromotion,
      { readonly authMethod: { readonly kind: 'passkey' } }
    >;
  };
}): Promise<void> {
  const committedAuthMethod = input.operation.committedPromotion.authMethod;
  const registration = input.operation.prepared.registration;
  if (!registration) throw new Error('passkey recovery registration is unavailable');
  const authority = await walletAuthAuthorityRef({
    authority: recoveredPasskeyWalletAuthAuthority({
      walletId: input.operation.walletId,
      rpId: registration.rpId,
      credentialIdB64u: committedAuthMethod.credentialIdB64u,
      walletAuthMethodId: committedAuthMethod.walletAuthMethodId,
    }),
  });

  const replacement = input.operation.replacement;
  const nearProjection = input.operation.recovered.nearKeySets;
  if (nearProjection.length > 0) {
    for (const recovered of nearProjection) {
      const application = recovered.entry.recoveryBasis.applicationBinding;
      await input.context.signingEngine.storeWalletEd25519RecoveryRegistrationData({
        walletId: input.operation.walletId,
        nearAccountId: toAccountId(recovered.entry.nearAccountId),
        signerSlot: application.key_creation_signer_slot,
        nearEd25519SigningKeyId: application.near_ed25519_signing_key_id,
        operationalPublicKey: `ed25519:${base58Encode(recovered.metadata.registeredPublicKey)}`,
        rpId: registration.rpId,
        credential: replacement.registration,
        credentialPublicKeyB64u: committedAuthMethod.credentialPublicKeyB64u,
        relayerKeyId: recovered.metadata.scope.signing_worker_id,
        keyVersion: NEAR_ED25519_YAO_KEY_VERSION_V1,
        participantIds: [...recovered.metadata.participantIds],
      });
    }
    await persistRecoveredPasskeyAuthMethodProjectionV1({
      kind: 'near',
      authority: input.operation.committedPromotion.authority,
      authMethod: committedAuthMethod,
      credential: {
        id: replacement.registration.id,
        rawId: replacement.registration.rawId,
      },
    });
  } else {
    await persistRecoveredPasskeyAuthMethodProjectionV1({
      kind: 'wallet_only',
      authority: input.operation.committedPromotion.authority,
      authMethod: committedAuthMethod,
      signerSlot: ECDSA_ONLY_WALLET_SIGNER_SLOT,
      credential: {
        id: replacement.registration.id,
        rawId: replacement.registration.rawId,
      },
    });
  }

  await Promise.all([
    ...input.operation.recovered.nearKeySets.map((recovered) =>
      persistRecoveredNearKeySet({
        context: input.context,
        walletId: input.operation.walletId,
        recovered,
      }),
    ),
    ...input.operation.recovered.ecdsaKeySets.map((recovered) =>
      persistRecoveredEcdsaKeySet({
        context: input.context,
        walletId: input.operation.walletId,
        authority,
        recovered,
      }),
    ),
  ]);
}

async function persistRecoveredEmailOtpLocalContinuity(input: {
  readonly context: WalletRecoveryWebContext;
  readonly operation: Extract<RecoveryOperation, { stage: 'promoted_pending_continuity' }> & {
    readonly replacement: RecoveryEmailOtpReplacement;
    readonly committedPromotion: Extract<
      CommittedRecoveryPromotion,
      { readonly authMethod: { readonly kind: 'email_otp' } }
    >;
  };
}): Promise<void> {
  const committedAuthMethod = input.operation.committedPromotion.authMethod;
  const replacement = input.operation.replacement;
  const providerSubject = replacement.providerSubject;
  const emailAddress = replacement.verifiedEmail;
  if (!providerSubject || !emailAddress) {
    throw new Error('Email OTP recovery identity is unavailable');
  }
  const baseAuthority = buildEmailOtpWalletAuthAuthority({
    walletId: input.operation.walletId,
    provider: providerSubject.startsWith('google:') ? 'google' : 'email',
    providerUserId: providerSubject,
    emailHashHex: committedAuthMethod.emailHashHex,
  });
  const localAuthority: EmailOtpWalletAuthAuthority = {
    walletId: baseAuthority.walletId,
    factor: baseAuthority.factor,
    verifier: baseAuthority.verifier,
    bindingId: committedAuthMethod.walletAuthMethodId,
  };
  const authority = await walletAuthAuthorityRef({ authority: localAuthority });
  const nearProjection = input.operation.recovered.nearKeySets;
  if (nearProjection.length > 0) {
    for (const recovered of nearProjection) {
      const application = recovered.entry.recoveryBasis.applicationBinding;
      await input.context.signingEngine.storeWalletEmailOtpEd25519RegistrationData({
        walletId: input.operation.walletId,
        nearAccountId: toAccountId(recovered.entry.nearAccountId),
        signerSlot: application.key_creation_signer_slot,
        nearEd25519SigningKeyId: application.near_ed25519_signing_key_id,
        operationalPublicKey: `ed25519:${base58Encode(recovered.metadata.registeredPublicKey)}`,
        email: emailAddress,
        registrationAuthorityId: providerSubject,
        authority: localAuthority,
        relayerKeyId: recovered.metadata.scope.signing_worker_id,
        keyVersion: NEAR_ED25519_YAO_KEY_VERSION_V1,
        participantIds: [...recovered.metadata.participantIds],
      });
    }
  }
  await persistFinalizedEmailOtpAuthMethodV1({
    walletId: input.operation.walletId,
    walletAuthMethodId: committedAuthMethod.walletAuthMethodId,
    walletAuthorityId: committedAuthMethod.walletAuthorityId,
    emailAddress,
    authority: localAuthority,
  });
  await IndexedDBManager.persistRecoveredWalletAuthority({
    authority: input.operation.committedPromotion.authority,
    authMethod: committedAuthMethod,
    recoveredAtMs: Date.now(),
  });
  await Promise.all([
    ...input.operation.recovered.nearKeySets.map((recovered) =>
      persistRecoveredNearKeySet({
        context: input.context,
        walletId: input.operation.walletId,
        recovered,
      }),
    ),
    ...input.operation.recovered.ecdsaKeySets.map((recovered) =>
      persistRecoveredEcdsaKeySet({
        context: input.context,
        walletId: input.operation.walletId,
        authority,
        recovered,
      }),
    ),
  ]);
}

async function persistRecoveredLocalContinuity(input: {
  readonly context: WalletRecoveryWebContext;
  readonly operation: Extract<RecoveryOperation, { stage: 'promoted_pending_continuity' }>;
}): Promise<void> {
  if (isPromotedPasskeyRecovery(input.operation)) {
    await persistRecoveredPasskeyLocalContinuity({
      context: input.context,
      operation: input.operation,
    });
    return;
  }
  if (isPromotedEmailOtpRecovery(input.operation)) {
    await persistRecoveredEmailOtpLocalContinuity({
      context: input.context,
      operation: input.operation,
    });
    return;
  }
  throw new Error('wallet recovery committed the wrong auth method');
}

type PromotedRecoveryOperation = Extract<
  RecoveryOperation,
  { readonly stage: 'promoted_pending_continuity' }
>;

type ManifestRecoveryOperation = Extract<
  RecoveryOperation,
  { readonly stage: 'manifest_recovered' }
>;

function isPasskeyManifestRecovery(
  operation: ManifestRecoveryOperation,
): operation is Extract<
  ManifestRecoveryOperation,
  { readonly target: { readonly kind: 'passkey' } }
> {
  return operation.target.kind === 'passkey' && operation.replacement.kind === 'passkey';
}

function isEmailOtpManifestRecovery(
  operation: ManifestRecoveryOperation,
): operation is Extract<
  ManifestRecoveryOperation,
  { readonly target: { readonly kind: 'google_email_otp' } }
> {
  return operation.target.kind === 'google_email_otp' && operation.replacement.kind === 'email_otp';
}

function isPasskeyCommittedPromotion(
  promotion: CommittedRecoveryPromotion,
): promotion is Extract<
  CommittedRecoveryPromotion,
  { readonly authMethod: { readonly kind: 'passkey' } }
> {
  return promotion.authMethod.kind === 'passkey';
}

function isEmailOtpCommittedPromotion(
  promotion: CommittedRecoveryPromotion,
): promotion is Extract<
  CommittedRecoveryPromotion,
  { readonly authMethod: { readonly kind: 'email_otp' } }
> {
  return promotion.authMethod.kind === 'email_otp';
}

function isPromotedPasskeyRecovery(
  operation: PromotedRecoveryOperation,
): operation is PromotedRecoveryOperation & {
  readonly replacement: RecoveryPasskeyReplacement;
  readonly committedPromotion: Extract<
    CommittedRecoveryPromotion,
    { readonly authMethod: { readonly kind: 'passkey' } }
  >;
} {
  return (
    operation.replacement.kind === 'passkey' &&
    operation.committedPromotion.authMethod.kind === 'passkey'
  );
}

function isPromotedEmailOtpRecovery(
  operation: PromotedRecoveryOperation,
): operation is PromotedRecoveryOperation & {
  readonly replacement: RecoveryEmailOtpReplacement;
  readonly committedPromotion: Extract<
    CommittedRecoveryPromotion,
    { readonly authMethod: { readonly kind: 'email_otp' } }
  >;
} {
  return (
    operation.replacement.kind === 'email_otp' &&
    operation.committedPromotion.authMethod.kind === 'email_otp'
  );
}

async function releaseRecoveryEmailOtpFactorFromWorker(input: {
  readonly context: WalletRecoveryWebContext;
  readonly relayUrl: string;
  readonly walletId: WalletId;
  readonly recoveryOperationId: string;
  readonly reservationId: string;
}): Promise<EmailOtpWorkerOperationMap['releaseWalletRecoveryEmailOtpFactor']['result']> {
  return await input.context.signingEngine.getSignerWorkerContext().requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'releaseWalletRecoveryEmailOtpFactor',
      payload: {
        relayUrl: input.relayUrl,
        walletId: String(input.walletId),
        recoveryOperationId: input.recoveryOperationId,
        reservationId: input.reservationId,
      },
    },
  });
}

async function finalizePasskeyRecovery(
  operation: Extract<
    RecoveryOperation,
    { stage: 'manifest_recovered'; target: { kind: 'passkey' } }
  >,
): Promise<WalletRecoveryFinalizeResult> {
  const registration = operation.prepared.registration;
  if (!registration) throw new Error('passkey recovery registration is unavailable');
  return await finalizeWalletRecovery({
    relayUrl: operation.relayUrl,
    walletId: operation.walletId,
    reservationId: operation.prepared.reservationId,
    recoveryOperationId: operation.prepared.recoveryOperationId,
    targetDeviceId: operation.prepared.targetDeviceId,
    targetAuthorityId: operation.prepared.targetAuthorityId,
    targetWalletAuthMethodId: operation.prepared.targetWalletAuthMethodId,
    challengeId: registration.challengeId,
    replacementId: registration.replacementId,
    webauthnRegistration: operation.replacement.registration,
    replacementEnvelope: operation.recovered.replacementEnvelope,
    ecdsaMaterialPossessionProofs: operation.recovered.ecdsaKeySets.map((keySet) => ({
      keySetId: keySet.entry.keySetId,
      proof: keySet.activation.possessionProof,
    })),
  });
}

export class WalletRecoveryCoordinator {
  constructor(private readonly rpc: WalletRecoveryCoordinatorRpc | null = null) {}

  readonly #operations = new Map<string, RecoveryOperation>();
  readonly #credentialPrompts = new Map<string, AbortController>();
  readonly #pendingPrepareReservations = new Map<
    string,
    { readonly reservationId: RecoveryCodeReservationId; readonly expiresAtMs: number }
  >();
  readonly #operationRetryKeys = new Map<string, string>();
  readonly #consumedRecoveryCodeDigests = readConsumedRecoveryCodeDigests();
  async prepareWithCode(input: {
    readonly context: WalletRecoveryWebContext;
    readonly relayUrl: string;
    readonly recoveryCode: string;
    readonly target: WalletRecoveryTargetV1;
    readonly signal: AbortSignal;
  }): Promise<WalletRecoveryPrepareCoordinatorResult> {
    this.#pruneExpired();
    if (input.signal.aborted) return refused();
    if (input.target.kind === 'passkey') {
      const rpId = parseWebAuthnRpId(input.context.signingEngine.getRpId());
      if (!rpId.ok || rpId.value !== input.target.rpId) return refused();
    }

    let recoveryCodeBytes: Uint8Array | null = null;
    try {
      recoveryCodeBytes = decodeWalletRecoveryCode(input.recoveryCode);
      const recoveryCodeDigestB64u = base64UrlEncode(await sha256Bytes(recoveryCodeBytes));
      if (this.#consumedRecoveryCodeDigests.has(recoveryCodeDigestB64u)) {
        return { kind: 'consumed' };
      }
      const retryKey = pendingPrepareKey(recoveryCodeDigestB64u);
      const pending = this.#pendingPrepareReservations.get(retryKey);
      const reservationId =
        pending?.expiresAtMs && pending.expiresAtMs > Date.now()
          ? pending.reservationId
          : createReservationId();
      const prepared = await prepareWalletRecoveryWithCode({
        relayUrl: input.relayUrl,
        target: input.target,
        recoveryCodeB64u: base64UrlEncode(recoveryCodeBytes),
        reservationId,
      });
      if (prepared.kind !== 'prepared') {
        if (prepared.kind === 'retryable_conflict' || prepared.kind === 'transport_uncertain') {
          this.#pendingPrepareReservations.set(retryKey, {
            reservationId,
            expiresAtMs: Date.now() + RECOVERY_PREPARE_RETRY_TTL_MS,
          });
        } else {
          this.#pendingPrepareReservations.delete(retryKey);
        }
        return prepared;
      }
      this.#pendingPrepareReservations.delete(retryKey);
      if (input.signal.aborted) {
        this.#pendingPrepareReservations.set(retryKey, {
          reservationId: prepared.reservationId,
          expiresAtMs: prepared.reservationExpiresAtMs,
        });
        return refused();
      }

      const recoveryOperationId = secureRandomId(
        'wallet-recovery-operation',
        24,
        'wallet recovery client operation handles',
      );
      this.#operations.set(recoveryOperationId, {
        stage: 'prepared',
        recoveryOperationId,
        walletId: prepared.walletId,
        relayUrl: input.relayUrl,
        target: input.target,
        prepared,
        custodyJson: buildWalletRecoveryCeremonyCustodyJson({
          walletId: prepared.walletId,
          prepared,
        }),
        recoveryCodeBytes,
      });
      this.#operationRetryKeys.set(recoveryOperationId, retryKey);
      recoveryCodeBytes = null;
      return {
        kind: 'prepared',
        recoveryOperationId,
        walletId: prepared.walletId,
        target: input.target,
      };
    } catch {
      return refused();
    } finally {
      recoveryCodeBytes?.fill(0);
    }
  }

  createPasskey(input: {
    readonly context: WalletRecoveryWebContext;
    readonly operation: WalletRecoveryPreparedHandle;
  }): Promise<WalletRecoveryCredentialCreationResult> {
    this.#pruneExpired();
    const current = this.#operations.get(input.operation.recoveryOperationId);
    if (
      !current ||
      current.stage !== 'prepared' ||
      current.walletId !== input.operation.walletId ||
      current.target.kind !== 'passkey' ||
      input.operation.target.kind !== 'passkey' ||
      current.target.rpId !== input.operation.target.rpId ||
      this.#credentialPrompts.has(current.recoveryOperationId)
    ) {
      return Promise.resolve({ kind: 'refused' });
    }
    if (!current.prepared.registration) return Promise.resolve({ kind: 'refused' });

    const promptController = new AbortController();
    this.#credentialPrompts.set(current.recoveryOperationId, promptController);
    let credentialPromise: Promise<WalletRecoveryReplacementCredential>;
    try {
      credentialPromise = input.context.signingEngine.createWalletRecoveryReplacementCredential({
        walletId: current.walletId,
        registration: current.prepared.registration,
        cancellation: { kind: 'abort_signal', signal: promptController.signal },
      });
    } catch {
      this.cancel(current.recoveryOperationId);
      return Promise.resolve({ kind: 'refused' });
    }
    return this.#finishCredentialCreation({ current, credentialPromise, promptController });
  }

  async verifyGoogle(input: {
    readonly relayUrl: string;
    readonly operation: WalletRecoveryPreparedHandle;
    readonly idToken: string;
  }): Promise<WalletRecoveryCoordinatorResult<WalletRecoveryGoogleVerifiedHandle>> {
    this.#pruneExpired();
    const current = this.#operations.get(input.operation.recoveryOperationId);
    if (
      !this.rpc ||
      !current ||
      current.stage !== 'prepared' ||
      current.target.kind !== 'google_email_otp' ||
      input.operation.target.kind !== 'google_email_otp' ||
      current.walletId !== input.operation.walletId ||
      current.target.googleProvider !== input.operation.target.googleProvider ||
      current.relayUrl !== input.relayUrl
    ) {
      return refused();
    }
    const prepared = current.prepared;
    if (!isGooglePreparedWalletRecovery(prepared)) return refused();
    try {
      const verified = await this.rpc.verifyGoogle({
        relayUrl: current.relayUrl,
        recoveryOperationId: prepared.recoveryOperationId,
        reservationId: prepared.reservationId,
        idToken: input.idToken,
      });
      if (verified.kind !== 'verified') return verified;
      if (verified.recoveryOperationId !== prepared.recoveryOperationId) {
        return { kind: 'transport_uncertain' };
      }
      const handle: WalletRecoveryGoogleVerifiedHandle = {
        kind: 'google_verified',
        recoveryOperationId: current.recoveryOperationId,
        walletId: current.walletId,
        target: current.target,
        challengeId: verified.challengeId,
        delivery: verified.delivery,
        expiresAtMs: verified.expiresAtMs,
      };
      const next: Extract<RecoveryOperation, { stage: 'google_verified' }> = {
        stage: 'google_verified',
        recoveryOperationId: current.recoveryOperationId,
        walletId: current.walletId,
        relayUrl: current.relayUrl,
        target: current.target,
        prepared,
        custodyJson: current.custodyJson,
        recoveryCodeBytes: current.recoveryCodeBytes,
        verification: handle,
      };
      this.#operations.set(next.recoveryOperationId, next);
      return handle;
    } catch {
      return { kind: 'transport_uncertain' };
    }
  }

  async verifyEmailOtp(input: {
    readonly context: WalletRecoveryWebContext;
    readonly operation: WalletRecoveryGoogleVerifiedHandle;
    readonly challengeId: string;
    readonly otpCode: string;
  }): Promise<WalletRecoveryCoordinatorResult<WalletRecoveryEmailOtpVerifiedHandle>> {
    this.#pruneExpired();
    const current = this.#operations.get(input.operation.recoveryOperationId);
    if (
      !this.rpc ||
      !current ||
      current.stage !== 'google_verified' ||
      current.walletId !== input.operation.walletId ||
      current.target.kind !== 'google_email_otp' ||
      input.operation.target.kind !== 'google_email_otp' ||
      current.verification.challengeId !== input.operation.challengeId ||
      input.challengeId !== input.operation.challengeId
    ) {
      return refused();
    }
    const challengeId = parseEmailOtpChallengeId(input.challengeId);
    if (!challengeId.ok) return refused();
    try {
      const verified = await this.rpc.verifyEmailOtp({
        relayUrl: current.relayUrl,
        recoveryOperationId: current.prepared.recoveryOperationId,
        reservationId: current.prepared.reservationId,
        challengeId: challengeId.value,
        otpCode: input.otpCode,
      });
      if (verified.kind !== 'verified') return verified;
      if (
        verified.recoveryOperationId !== current.prepared.recoveryOperationId ||
        verified.challengeId !== input.challengeId
      ) {
        return { kind: 'transport_uncertain' };
      }

      const released = await releaseRecoveryEmailOtpFactorFromWorker({
        context: input.context,
        relayUrl: current.relayUrl,
        walletId: current.walletId,
        recoveryOperationId: current.prepared.recoveryOperationId,
        reservationId: String(current.prepared.reservationId),
      });
      if (released.kind === 'existing') {
        if (
          released.recoveryOperationId !== String(current.prepared.recoveryOperationId) ||
          released.reservationId !== String(current.prepared.reservationId) ||
          released.factorSecret32.byteLength !== 32
        ) {
          zeroizeBuffer(released.factorSecret32);
          return { kind: 'transport_uncertain' };
        }
        const replacement: RecoveryEmailOtpReplacement = {
          kind: 'email_otp',
          factor: {
            replacementId: String(current.prepared.recoveryOperationId),
            walletAuthMethodId: current.prepared.targetWalletAuthMethodId,
            factor: buildEmailOtpEnvelopeFactor({
              enrollmentId: released.enrollmentId,
              enrollmentSealKeyVersion: released.enrollmentSealKeyVersion,
            }),
            factorSecret: released.factorSecret32,
          },
          enrollment: {
            kind: 'existing',
            enrollmentId: released.enrollmentId,
            enrollmentSealKeyVersion: released.enrollmentSealKeyVersion,
          },
          providerSubject: released.providerSubject,
          verifiedEmail: released.verifiedEmail,
        };
        const next = emailOtpVerifiedOperation(current, replacement);
        this.#operations.set(next.recoveryOperationId, next);
        return {
          kind: 'email_otp_verified',
          recoveryOperationId: next.recoveryOperationId,
          walletId: next.walletId,
          target: next.target,
          challengeId: input.challengeId,
        };
      }
      if (released.kind !== 'create') return released;
      if (
        released.recoveryOperationId !== String(current.prepared.recoveryOperationId) ||
        released.reservationId !== String(current.prepared.reservationId)
      ) {
        return { kind: 'transport_uncertain' };
      }

      const clientSecret32 = crypto.getRandomValues(new Uint8Array(32));
      let factorSecret: ArrayBuffer | null = null;
      try {
        const material =
          await input.context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
            relayUrl: current.relayUrl,
            walletId: current.walletId,
            userId: released.providerSubject,
            clientSecret32,
          });
        factorSecret = clientSecret32.slice().buffer;
        const replacement: RecoveryEmailOtpReplacement = {
          kind: 'email_otp',
          factor: {
            replacementId: String(current.prepared.recoveryOperationId),
            walletAuthMethodId: current.prepared.targetWalletAuthMethodId,
            factor: buildEmailOtpEnvelopeFactor({
              enrollmentId: material.enrollmentId,
              enrollmentSealKeyVersion: material.enrollmentSealKeyVersion,
            }),
            factorSecret,
          },
          enrollment: {
            kind: 'create',
            providerSubject: released.providerSubject,
            verifiedEmail: released.verifiedEmail,
            material: material.emailOtpEnrollment,
          },
          providerSubject: released.providerSubject,
          verifiedEmail: released.verifiedEmail,
        };
        const next = emailOtpVerifiedOperation(current, replacement);
        this.#operations.set(next.recoveryOperationId, next);
        factorSecret = null;
        return {
          kind: 'email_otp_verified',
          recoveryOperationId: next.recoveryOperationId,
          walletId: next.walletId,
          target: next.target,
          challengeId: input.challengeId,
        };
      } finally {
        clientSecret32.fill(0);
        if (factorSecret) zeroizeBuffer(factorSecret);
      }
    } catch {
      return { kind: 'refused' };
    }
  }

  async finalize(input: {
    readonly context: WalletRecoveryWebContext;
    readonly operation:
      | WalletRecoveryCredentialCreatedHandle
      | WalletRecoveryEmailOtpVerifiedHandle;
  }): Promise<WalletRecoveryFinalizeCoordinatorResult> {
    this.#pruneExpired();
    let current = recoveryFinalizationOperation(
      this.#operations.get(input.operation.recoveryOperationId),
      input.operation,
    );
    if (!current) return refused();

    try {
      if (current.stage === 'credential_created' || current.stage === 'email_otp_verified') {
        const replacementFactor: WalletRecoveryReplacementFactorInput =
          current.stage === 'credential_created'
            ? passkeyRecoveryReplacementFactor(current)
            : current.replacement.factor;
        const recovered = await input.context.signingEngine.recoverWalletCustodyManifest({
          walletId: current.walletId,
          prepared: current.prepared,
          custodyJson: current.custodyJson,
          recoveryCodeBytes: current.recoveryCodeBytes,
          replacementFactor,
          recoveryChallengeId:
            current.stage === 'credential_created'
              ? passkeyRecoveryChallengeId(current)
              : String(current.prepared.recoveryOperationId),
          relayUrl: current.relayUrl,
        });
        if (this.#operations.get(current.recoveryOperationId) !== current) {
          disposeRecoveryOperation(current);
          return refused();
        }
        if (current.prepared.reservationExpiresAtMs <= Date.now()) {
          this.cancel(current.recoveryOperationId);
          return refused();
        }
        current.recoveryCodeBytes.fill(0);
        zeroizeBuffer(
          current.stage === 'credential_created'
            ? current.replacement.factorSecret
            : current.replacement.factor.factorSecret,
        );
        current =
          current.stage === 'credential_created'
            ? passkeyManifestRecoveredOperation(current, recovered)
            : emailOtpManifestRecoveredOperation(current, recovered);
        this.#operations.set(current.recoveryOperationId, current);
      }

      if (current.stage === 'manifest_recovered') {
        if (!isPasskeyManifestRecovery(current) && !isEmailOtpManifestRecovery(current)) {
          return { kind: 'transport_uncertain' };
        }
        const finalized = isPasskeyManifestRecovery(current)
          ? await finalizePasskeyRecovery(current)
          : this.rpc
            ? await this.rpc.finalizeEmailOtp({
                relayUrl: current.relayUrl,
                recoveryOperationId: current.prepared.recoveryOperationId,
                reservationId: current.prepared.reservationId,
                replacementEnvelope: current.recovered.replacementEnvelope,
                ecdsaMaterialPossessionProofs: current.recovered.ecdsaKeySets.map((keySet) => ({
                  keySetId: keySet.entry.keySetId,
                  proof: keySet.activation.possessionProof,
                })),
                emailOtpEnrollment:
                  current.replacement.enrollment.kind === 'create'
                    ? { kind: 'create', material: current.replacement.enrollment.material }
                    : null,
              })
            : { kind: 'refused' as const };
        if (this.#operations.get(current.recoveryOperationId) !== current) {
          return finalized.kind === 'promoted' ? { kind: 'transport_uncertain' } : finalized;
        }
        if (finalized.kind === 'refused') {
          this.cancel(current.recoveryOperationId);
          return finalized;
        }
        if (finalized.kind !== 'promoted') return finalized;
        if (
          current.replacement.kind === 'passkey' &&
          finalized.authMethod.credentialIdB64u !== current.replacement.credentialIdB64u
        ) {
          return { kind: 'transport_uncertain' };
        }
        if (isPasskeyManifestRecovery(current)) {
          if (!isPasskeyCommittedPromotion(finalized)) return { kind: 'transport_uncertain' };
          current = passkeyPromotedPendingContinuityOperation(current, finalized);
        } else if (isEmailOtpManifestRecovery(current)) {
          if (!isEmailOtpCommittedPromotion(finalized)) return { kind: 'transport_uncertain' };
          current = emailOtpPromotedPendingContinuityOperation(current, finalized);
        } else {
          return { kind: 'transport_uncertain' };
        }
        this.#operations.set(current.recoveryOperationId, current);
      }

      await persistRecoveredLocalContinuity({ context: input.context, operation: current });
      const consumedCodeDigest = this.#operationRetryKeys.get(current.recoveryOperationId);
      if (consumedCodeDigest) {
        rememberConsumedRecoveryCodeDigest(this.#consumedRecoveryCodeDigests, consumedCodeDigest);
      }
      this.#operations.delete(current.recoveryOperationId);
      this.#operationRetryKeys.delete(current.recoveryOperationId);
      disposeRecoveryOperation(current);
      return { kind: 'ready_for_sign_in', walletId: current.walletId };
    } catch {
      const retained = this.#operations.get(input.operation.recoveryOperationId);
      if (retained?.stage === 'promoted_pending_continuity') {
        return { kind: 'transport_uncertain' };
      }
      this.cancel(input.operation.recoveryOperationId);
      return refused();
    }
  }

  async #finishCredentialCreation(input: {
    readonly current: Extract<RecoveryOperation, { stage: 'prepared' }>;
    readonly credentialPromise: Promise<WalletRecoveryReplacementCredential>;
    readonly promptController: AbortController;
  }): Promise<WalletRecoveryCredentialCreationResult> {
    try {
      const replacement = await input.credentialPromise;
      const active = this.#operations.get(input.current.recoveryOperationId);
      if (active !== input.current || input.promptController.signal.aborted) {
        zeroizeBuffer(replacement.factorSecret);
        return { kind: 'dismissed' };
      }
      if (input.current.prepared.reservationExpiresAtMs <= Date.now()) {
        zeroizeBuffer(replacement.factorSecret);
        this.cancel(input.current.recoveryOperationId);
        return { kind: 'refused' };
      }
      const next = credentialCreatedOperation(input.current, replacement);
      this.#operations.set(next.recoveryOperationId, next);
      return {
        kind: 'credential_created',
        recoveryOperationId: next.recoveryOperationId,
        walletId: next.walletId,
        target: next.target,
      };
    } catch (error: unknown) {
      if (input.promptController.signal.aborted || isCredentialDismissal(error)) {
        return { kind: 'dismissed' };
      }
      return { kind: 'transport_uncertain' };
    } finally {
      const activePrompt = this.#credentialPrompts.get(input.current.recoveryOperationId);
      if (activePrompt === input.promptController) {
        this.#credentialPrompts.delete(input.current.recoveryOperationId);
      }
    }
  }

  cancel(recoveryOperationId: string): void {
    this.#credentialPrompts.get(recoveryOperationId)?.abort();
    this.#credentialPrompts.delete(recoveryOperationId);
    const operation = this.#operations.get(recoveryOperationId);
    if (!operation) return;
    const retryKey = this.#operationRetryKeys.get(recoveryOperationId);
    this.#operationRetryKeys.delete(recoveryOperationId);
    if (
      retryKey &&
      operation.stage !== 'promoted_pending_continuity' &&
      operation.prepared.reservationExpiresAtMs > Date.now()
    ) {
      this.#pendingPrepareReservations.set(retryKey, {
        reservationId: operation.prepared.reservationId,
        expiresAtMs: operation.prepared.reservationExpiresAtMs,
      });
    }
    this.#operations.delete(recoveryOperationId);
    disposeRecoveryOperation(operation);
  }

  #pruneExpired(): void {
    const nowMs = Date.now();
    for (const [retryKey, pending] of this.#pendingPrepareReservations) {
      if (pending.expiresAtMs <= nowMs) this.#pendingPrepareReservations.delete(retryKey);
    }
    for (const [operationId, operation] of this.#operations) {
      if (operation.stage === 'promoted_pending_continuity') continue;
      if (operation.prepared.reservationExpiresAtMs > nowMs) continue;
      this.#credentialPrompts.get(operationId)?.abort();
      this.#credentialPrompts.delete(operationId);
      this.#operations.delete(operationId);
      this.#operationRetryKeys.delete(operationId);
      disposeRecoveryOperation(operation);
    }
  }
}
