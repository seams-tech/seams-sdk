import {
  finalizeWalletRecovery,
  replayWalletRecovery,
  type WalletRecoveryFinalizeResult,
} from '@/core/rpcClients/relayer/walletRecoveryFinalize';
import {
  finalizeWalletRecoveryGoogleEmailOtp,
  replayWalletRecoveryGoogleEmailOtp,
  type WalletRecoveryGoogleEmailOtpFinalizeResult,
} from '@/core/rpcClients/relayer/walletRecoveryGoogleEmailOtp';
import type { WalletRecoveryAttemptFailure } from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import {
  prepareWalletRecoveryEmailOtpPublication,
  prepareWalletRecoveryPasskeyPublication,
  type PrepareWalletRecoveryEmailOtpPublicationInput,
  type PrepareWalletRecoveryPasskeyPublicationInput,
  type StoreWalletEcdsaWalletKey,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import { IndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import {
  parseEmailOtpProviderUserId,
  parseThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { base58Encode, base64UrlDecode } from '@shared/utils/encoders';
import { alphabetizeStringify } from '@shared/utils/digests';
import { computeEcdsaDerivationRoleLocalRelayerKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { buildEcdsaRoleLocalPublicFacts } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import {
  prepareWalletCustodyEcdsaContinuity,
  type PreparedImportedWalletCustodyEcdsaContinuity,
} from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import type { Ed25519YaoPublicCapabilityReferenceV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import {
  awaitingPendingWalletRecoveryCommit,
  decryptWalletRecoveryDurablePayload,
  durableEmailEnrollmentReference,
  encryptWalletRecoveryDurablePayload,
  isDurablePasskeyPayload,
  promotedPendingWalletRecoveryCommit,
  requireWalletRecoveryOperationId,
  walletRecoveryDurablePayloadFromOperation,
  type WalletRecoveryDurableEmailOtpPayload,
  type WalletRecoveryDurableOperationInput,
  type WalletRecoveryDurablePasskeyPayload,
  type WalletRecoveryDurablePayloadV1,
  type WalletRecoveryEmailOtpEnrollment,
} from './walletRecoveryJournal';
import {
  buildWalletRecoveryCommittedProjectionV1,
  type WalletRecoveryCommittedProjectionV1,
} from '@shared/wallet-recovery/walletRecoveryCommittedProjection';
import type { PendingWalletRecoveryCommitV1 } from '@/core/indexedDB/pendingWalletRecoveryCommit';
import type { StoreWalletRegistrationPublicationInputV1 } from '@/core/indexedDB/seamsWalletDB/repositories';

type PasskeyRecoveryPromotion = Extract<
  WalletRecoveryFinalizeResult,
  { readonly kind: 'promoted' }
>;
type EmailOtpRecoveryPromotion = Extract<
  WalletRecoveryGoogleEmailOtpFinalizeResult,
  { readonly kind: 'promoted' }
>;

export type WalletRecoveryCommitPromotion =
  | {
      readonly kind: 'passkey';
      readonly payload: WalletRecoveryDurablePasskeyPayload;
      readonly promotion: PasskeyRecoveryPromotion;
    }
  | {
      readonly kind: 'google_email_otp';
      readonly payload: WalletRecoveryDurableEmailOtpPayload;
      readonly promotion: EmailOtpRecoveryPromotion;
    };

type PromotedProjection = Extract<
  PendingWalletRecoveryCommitV1,
  { readonly stage: 'server_promoted' }
>['projection'];

export function committedProjectionFromPromotion(
  input: WalletRecoveryCommitPromotion,
): WalletRecoveryCommittedProjectionV1 {
  const recoveryOperationId = requireWalletRecoveryOperationId(input.payload.recoveryOperationId);
  switch (input.kind) {
    case 'passkey':
      return buildWalletRecoveryCommittedProjectionV1({
        kind: 'passkey',
        storeVersion: input.promotion.storeVersion,
        walletId: input.payload.walletId,
        recoveryOperationId,
        targetDeviceId: input.payload.targetDeviceId,
        targetAuthorityId: input.payload.targetAuthorityId,
        targetWalletAuthMethodId: input.payload.targetWalletAuthMethodId,
        authority: input.promotion.authority,
        authMethod: input.promotion.authMethod,
      });
    case 'google_email_otp': {
      const providerSubject = parseEmailOtpProviderUserId(input.payload.providerSubject);
      if (!providerSubject.ok) throw new Error('wallet recovery provider subject is invalid');
      return buildWalletRecoveryCommittedProjectionV1({
        kind: 'google_email_otp',
        storeVersion: input.promotion.storeVersion,
        walletId: input.payload.walletId,
        recoveryOperationId,
        targetDeviceId: input.payload.targetDeviceId,
        targetAuthorityId: input.payload.targetAuthorityId,
        targetWalletAuthMethodId: input.payload.targetWalletAuthMethodId,
        authority: input.promotion.authority,
        authMethod: input.promotion.authMethod,
        providerSubject: providerSubject.value,
        emailHashHex: input.payload.emailHashHex,
        registrationAuthorityId: input.payload.registrationAuthorityId,
        enrollment: durableEmailEnrollmentReference(input.payload),
      });
    }
  }
}

function ecdsaPossessionProofs(payload: WalletRecoveryDurablePayloadV1) {
  return payload.ecdsaKeySets.map((keySet) => ({
    keySetId: keySet.entry.keySetId,
    proof: keySet.possessionProof,
  }));
}

function webAuthnRegistrationFromPayload(
  payload: WalletRecoveryDurablePasskeyPayload,
): WebAuthnRegistrationCredential {
  return {
    id: payload.registration.id,
    rawId: payload.registration.rawId,
    type: payload.registration.type,
    authenticatorAttachment: payload.registration.authenticatorAttachment ?? undefined,
    response: {
      clientDataJSON: payload.registration.response.clientDataJSON,
      attestationObject: payload.registration.response.attestationObject,
      transports: [...payload.registration.response.transports],
    },
    clientExtensionResults: {
      prf: { results: { first: undefined, second: undefined } },
    },
  };
}

async function finalizeAwaitingCommit(input: {
  readonly relayUrl: string;
  readonly payload: WalletRecoveryDurablePayloadV1;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryCommitPromotion | WalletRecoveryAttemptFailure> {
  const { payload } = input;
  if (isDurablePasskeyPayload(payload)) {
    const promotion = await finalizeWalletRecovery({
      relayUrl: input.relayUrl,
      walletId: String(payload.walletId),
      reservationId: String(payload.reservationId),
      recoveryOperationId: requireWalletRecoveryOperationId(payload.recoveryOperationId),
      targetDeviceId: String(payload.targetDeviceId),
      targetAuthorityId: String(payload.targetAuthorityId),
      targetWalletAuthMethodId: String(payload.targetWalletAuthMethodId),
      challengeId: payload.challengeId,
      replacementId: payload.replacementId,
      webauthnRegistration: webAuthnRegistrationFromPayload(payload),
      replacementEnvelope: payload.replacementEnvelope,
      ecdsaMaterialPossessionProofs: ecdsaPossessionProofs(payload),
      fetchImpl: input.fetchImpl,
    });
    if (promotion.kind !== 'promoted') return promotion;
    return { kind: 'passkey', payload, promotion };
  }
  const promotion = await finalizeWalletRecoveryGoogleEmailOtp({
    relayUrl: input.relayUrl,
    recoveryOperationId: requireWalletRecoveryOperationId(payload.recoveryOperationId),
    reservationId: payload.reservationId,
    walletId: payload.walletId,
    targetDeviceId: payload.targetDeviceId,
    targetAuthorityId: payload.targetAuthorityId,
    targetWalletAuthMethodId: payload.targetWalletAuthMethodId,
    expectedProviderSubject: payload.providerSubject,
    expectedEmailHashHex: payload.emailHashHex,
    expectedRegistrationAuthorityId: payload.registrationAuthorityId,
    replacementEnvelope: payload.replacementEnvelope,
    ecdsaMaterialPossessionProofs: ecdsaPossessionProofs(payload),
    emailOtpEnrollment: emailOtpEnrollmentMaterial(payload.enrollment),
    fetchImpl: input.fetchImpl,
  });
  if (promotion.kind !== 'promoted') return promotion;
  return { kind: 'google_email_otp', payload, promotion };
}

function emailOtpEnrollmentMaterial(enrollment: WalletRecoveryEmailOtpEnrollment) {
  return enrollment.kind === 'create'
    ? { kind: 'create' as const, material: enrollment.material }
    : null;
}

async function replayPromotedCommit(input: {
  readonly relayUrl: string;
  readonly payload: WalletRecoveryDurablePayloadV1;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryCommitPromotion | WalletRecoveryAttemptFailure> {
  const { payload } = input;
  if (isDurablePasskeyPayload(payload)) {
    const promotion = await replayWalletRecovery({
      relayUrl: input.relayUrl,
      walletId: String(payload.walletId),
      reservationId: String(payload.reservationId),
      recoveryOperationId: requireWalletRecoveryOperationId(payload.recoveryOperationId),
      targetDeviceId: String(payload.targetDeviceId),
      targetAuthorityId: String(payload.targetAuthorityId),
      targetWalletAuthMethodId: String(payload.targetWalletAuthMethodId),
      replacementId: payload.replacementId,
      replacementEnvelope: payload.replacementEnvelope,
      fetchImpl: input.fetchImpl,
    });
    if (promotion.kind !== 'promoted') return promotion;
    return { kind: 'passkey', payload, promotion };
  }
  const promotion = await replayWalletRecoveryGoogleEmailOtp({
    relayUrl: input.relayUrl,
    recoveryOperationId: requireWalletRecoveryOperationId(payload.recoveryOperationId),
    reservationId: payload.reservationId,
    walletId: payload.walletId,
    targetDeviceId: payload.targetDeviceId,
    targetAuthorityId: payload.targetAuthorityId,
    targetWalletAuthMethodId: payload.targetWalletAuthMethodId,
    expectedProviderSubject: payload.providerSubject,
    expectedEmailHashHex: payload.emailHashHex,
    expectedRegistrationAuthorityId: payload.registrationAuthorityId,
    replacementEnvelope: payload.replacementEnvelope,
    fetchImpl: input.fetchImpl,
  });
  if (promotion.kind !== 'promoted') return promotion;
  return { kind: 'google_email_otp', payload, promotion };
}

function isWalletRecoveryCommitPromotion(
  value: WalletRecoveryCommitPromotion | WalletRecoveryAttemptFailure,
): value is WalletRecoveryCommitPromotion {
  return value.kind === 'passkey' || value.kind === 'google_email_otp';
}

async function resumeAwaitingCommit(input: {
  readonly relayUrl: string;
  readonly payload: WalletRecoveryDurablePayloadV1;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryCommitPromotion | WalletRecoveryAttemptFailure> {
  // A lost response can leave this row awaiting even after the server commit;
  // probe the credential-free replay before resending the one-shot finalization.
  const replay = await replayPromotedCommit(input);
  if (isWalletRecoveryCommitPromotion(replay) || replay.kind !== 'refused') {
    return replay;
  }
  return await finalizeAwaitingCommit(input);
}

function passkeyAuthority(
  payload: WalletRecoveryDurablePasskeyPayload,
  projection: Extract<PromotedProjection, { readonly kind: 'passkey' }>,
): PasskeyWalletAuthAuthority {
  return {
    walletId: payload.walletId,
    factor: { kind: 'passkey', credentialIdB64u: projection.target.credentialIdB64u },
    verifier: { kind: 'webauthn', rpId: projection.target.rpId },
    bindingId: projection.authMethod.walletAuthMethodId,
  };
}

function emailAuthority(
  payload: WalletRecoveryDurableEmailOtpPayload,
  projection: Extract<PromotedProjection, { readonly kind: 'google_email_otp' }>,
): EmailOtpWalletAuthAuthority {
  const base = buildEmailOtpWalletAuthAuthority({
    walletId: payload.walletId,
    provider: 'google',
    providerUserId: payload.providerSubject,
    emailHashHex: payload.emailHashHex,
  });
  return {
    walletId: base.walletId,
    factor: base.factor,
    verifier: base.verifier,
    bindingId: projection.authMethod.walletAuthMethodId,
  };
}

async function recoveryAuthorityRef(
  payload: WalletRecoveryDurablePayloadV1,
  projection: PromotedProjection,
): Promise<WalletAuthAuthorityRef> {
  if (isDurablePasskeyPayload(payload)) {
    if (projection.kind !== 'passkey') throw new Error('wallet recovery projection branch changed');
    return walletAuthAuthorityRef({ authority: passkeyAuthority(payload, projection) });
  }
  if (projection.kind !== 'google_email_otp') {
    throw new Error('wallet recovery projection branch changed');
  }
  return walletAuthAuthorityRef({ authority: emailAuthority(payload, projection) });
}

async function prepareEcdsaWalletContinuity(input: {
  readonly payload: WalletRecoveryDurablePayloadV1;
  readonly authority: WalletAuthAuthorityRef;
}): Promise<{
  readonly walletKeys: readonly StoreWalletEcdsaWalletKey[];
  readonly ecdsaContinuity: readonly PreparedImportedWalletCustodyEcdsaContinuity[];
}> {
  const keys: StoreWalletEcdsaWalletKey[] = [];
  const ecdsaContinuity: PreparedImportedWalletCustodyEcdsaContinuity[] = [];
  for (const keySet of input.payload.ecdsaKeySets) {
    const entry = keySet.entry;
    const basis = entry.recoveryBasis;
    const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
      walletId: input.payload.walletId,
      signingRootId: basis.signingRootId,
      signingRootVersion: basis.signingRootVersion,
    });
    const prepared = await prepareWalletCustodyEcdsaContinuity({
      authority: input.authority,
      chainTargets: basis.chainTargets,
      walletId: String(input.payload.walletId),
      keyHandle: entry.keyHandle,
      ecdsaThresholdKeyId: basis.ecdsaThresholdKeyId,
      signingRootId: basis.signingRootId,
      signingRootVersion: basis.signingRootVersion,
      relayerKeyId,
      participantIds: basis.participantIds,
      publicCapability: basis.publicCapability,
      activationReceipt: basis.activationReceipt,
      runtimePolicyScope: basis.runtimePolicyScope,
      readyStateBlobB64u: keySet.readyStateBlobB64u,
      publicFacts: keySet.publicFacts,
    });
    ecdsaContinuity.push(prepared);
    for (const chainTarget of basis.chainTargets) {
      keys.push(
        ecdsaWalletKey({
          payload: input.payload,
          keySet,
          chainTarget,
          materialRef: prepared.roleLocalMaterialRef,
          relayerKeyId,
        }),
      );
    }
  }
  return { walletKeys: keys, ecdsaContinuity };
}

function ecdsaWalletKey(input: {
  readonly payload: WalletRecoveryDurablePayloadV1;
  readonly keySet: WalletRecoveryDurablePayloadV1['ecdsaKeySets'][number];
  readonly chainTarget: WalletRecoveryDurablePayloadV1['ecdsaKeySets'][number]['entry']['recoveryBasis']['chainTargets'][number];
  readonly materialRef: StoreWalletEcdsaWalletKey['roleLocalMaterialRef'];
  readonly relayerKeyId: string;
}): StoreWalletEcdsaWalletKey {
  const entry = input.keySet.entry;
  const basis = entry.recoveryBasis;
  const facts = input.keySet.publicFacts;
  const roleLocalPublicFacts: EcdsaRoleLocalPublicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: input.payload.walletId,
    chainTarget: input.chainTarget,
    keyHandle: entry.keyHandle,
    ecdsaThresholdKeyId: basis.ecdsaThresholdKeyId,
    signingRootId: basis.signingRootId,
    signingRootVersion: basis.signingRootVersion,
    applicationBindingDigestB64u: basis.publicCapability.context.application_binding_digest_b64u,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: basis.participantIds,
    contextBinding32B64u: facts.contextBinding32B64u,
    derivationClientSharePublicKey33B64u: facts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: facts.relayerPublicKey33B64u,
    groupPublicKey33B64u: facts.groupPublicKey33B64u,
    ethereumAddress: facts.ethereumAddress,
    publicCapability: basis.publicCapability,
  });
  return {
    keyScope: 'evm-family',
    chainTarget: input.chainTarget,
    walletId: String(input.payload.walletId),
    evmFamilySigningKeySlotId: entry.evmFamilySigningKeySlotId,
    keyHandle: entry.keyHandle,
    ecdsaThresholdKeyId: basis.ecdsaThresholdKeyId,
    signingRootId: basis.signingRootId,
    signingRootVersion: basis.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: facts.groupPublicKey33B64u,
    thresholdOwnerAddress: facts.ethereumAddress,
    relayerKeyId: input.relayerKeyId,
    relayerVerifyingShareB64u: facts.relayerPublicKey33B64u,
    participantIds: basis.participantIds,
    publicCapability: basis.publicCapability,
    roleLocalMaterialRef: input.materialRef,
    ecdsaRoleLocalPublicFacts: roleLocalPublicFacts,
  };
}

function nearKeySet(input: WalletRecoveryDurablePayloadV1) {
  if (input.nearKeySets.length !== 1) {
    throw new Error('wallet recovery requires exactly one NEAR key set');
  }
  return input.nearKeySets[0];
}

function nearCredentialTransports(payload: WalletRecoveryDurablePasskeyPayload): string[] {
  return [...payload.registration.response.transports];
}

function nearOperationalPublicKey(payload: WalletRecoveryDurablePayloadV1): string {
  const near = nearKeySet(payload);
  return `ed25519:${base58Encode(base64UrlDecode(near.binding.registeredPublicKeyB64u))}`;
}

function ed25519PublicCapabilityReference(
  payload: WalletRecoveryDurablePayloadV1,
  keySet: WalletRecoveryDurablePayloadV1['nearKeySets'][number],
): Ed25519YaoPublicCapabilityReferenceV1 {
  const thresholdSessionId = parseThresholdEd25519SessionId(keySet.thresholdSessionId);
  if (!thresholdSessionId.ok) throw new Error('recovery NEAR threshold session id is invalid');
  return {
    walletId: payload.walletId,
    nearAccountId: toAccountId(keySet.binding.nearAccountId),
    thresholdSessionId: thresholdSessionId.value,
    runtimePolicyScope: keySet.runtimePolicyScope,
    materialActivation: routerAbMpcMaterialActivationRefFromWire(keySet.materialActivation),
  };
}

async function buildRecoveryPublication(input: {
  readonly payload: WalletRecoveryDurablePayloadV1;
  readonly projection: PromotedProjection;
  readonly walletKeys: readonly StoreWalletEcdsaWalletKey[];
}): Promise<StoreWalletRegistrationPublicationInputV1> {
  if (isDurablePasskeyPayload(input.payload)) {
    if (input.projection.kind !== 'passkey')
      throw new Error('wallet recovery projection branch changed');
    const common = {
      walletId: input.payload.walletId,
      rpId: input.projection.target.rpId,
      credentialIdB64u: input.projection.target.credentialIdB64u,
      credentialPublicKeyB64u: input.projection.authMethod.credentialPublicKeyB64u,
      transports: nearCredentialTransports(input.payload),
      walletKeys: input.walletKeys,
    };
    if (input.payload.nearKeySets.length === 0) {
      return prepareWalletRecoveryPasskeyPublication({ kind: 'evm_family_ecdsa', ...common });
    }
    const near = nearKeySet(input.payload);
    const args: PrepareWalletRecoveryPasskeyPublicationInput = {
      kind: 'near_ed25519',
      ...common,
      nearAccountId: toAccountId(near.binding.nearAccountId),
      nearEd25519SigningKeyId: near.binding.nearEd25519SigningKeyId,
      signerSlot: near.binding.signerSlot,
      operationalPublicKey: nearOperationalPublicKey(input.payload),
      relayerKeyId: near.binding.signingWorkerId,
      participantIds: near.binding.participantIds,
      custodyMaterials: input.payload.nearKeySets.map((keySet) => ({
        binding: keySet.binding,
        sealed: keySet.sealed,
      })),
    };
    return prepareWalletRecoveryPasskeyPublication(args);
  }
  if (input.projection.kind !== 'google_email_otp') {
    throw new Error('wallet recovery projection branch changed');
  }
  const localAuthority = emailAuthority(input.payload, input.projection);
  const common = {
    walletId: input.payload.walletId,
    email: input.payload.verifiedEmail,
    registrationAuthorityId: input.payload.registrationAuthorityId,
    authority: localAuthority,
    walletKeys: input.walletKeys,
  };
  if (input.payload.nearKeySets.length === 0) {
    return prepareWalletRecoveryEmailOtpPublication({ kind: 'evm_family_ecdsa', ...common });
  }
  const near = nearKeySet(input.payload);
  const args: PrepareWalletRecoveryEmailOtpPublicationInput = {
    kind: 'near_ed25519',
    ...common,
    nearAccountId: toAccountId(near.binding.nearAccountId),
    nearEd25519SigningKeyId: near.binding.nearEd25519SigningKeyId,
    signerSlot: near.binding.signerSlot,
    operationalPublicKey: nearOperationalPublicKey(input.payload),
    relayerKeyId: near.binding.signingWorkerId,
    participantIds: near.binding.participantIds,
    custodyMaterials: input.payload.nearKeySets.map((keySet) => ({
      binding: keySet.binding,
      sealed: keySet.sealed,
    })),
  };
  return prepareWalletRecoveryEmailOtpPublication(args);
}

export async function restoreAndPublishWalletRecoveryCommit(input: {
  readonly pending: Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'server_promoted' }>;
  readonly payload: WalletRecoveryDurablePayloadV1;
}): Promise<void> {
  const projection = input.pending.projection;
  const authority = await recoveryAuthorityRef(input.payload, projection);
  const continuity = await prepareEcdsaWalletContinuity({
    payload: input.payload,
    authority,
  });
  const registration = await buildRecoveryPublication({
    payload: input.payload,
    projection,
    walletKeys: continuity.walletKeys,
  });
  await IndexedDBManager.publishPendingWalletRecoveryCommit({
    pending: input.pending,
    authority: projection.authority,
    authMethod: projection.authMethod,
    registration,
    ecdsaContinuity: continuity.ecdsaContinuity,
    ed25519PublicCapabilityReferences: input.payload.nearKeySets.map((keySet) =>
      ed25519PublicCapabilityReference(input.payload, keySet),
    ),
  });
}

export type WalletRecoveryResumeResult =
  | { readonly kind: 'completed'; readonly recoveryOperationId: string }
  | {
      readonly kind: 'pending';
      readonly recoveryOperationId: string;
      readonly failure: WalletRecoveryAttemptFailure;
    }
  | { readonly kind: 'discarded'; readonly recoveryOperationId: string }
  | { readonly kind: 'corrupt'; readonly recoveryOperationId: string };

export async function resumePendingWalletRecoveries(input: {
  readonly relayUrl: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<readonly WalletRecoveryResumeResult[]> {
  const pending = await IndexedDBManager.listPendingWalletRecoveryCommits();
  const results: WalletRecoveryResumeResult[] = [];
  for (const record of pending) {
    try {
      const payload = await decryptWalletRecoveryDurablePayload(record);
      const promotion =
        record.stage === 'awaiting_server_promotion'
          ? await resumeAwaitingCommit({
              relayUrl: input.relayUrl,
              payload,
              fetchImpl: input.fetchImpl,
            })
          : await replayPromotedCommit({
              relayUrl: input.relayUrl,
              payload,
              fetchImpl: input.fetchImpl,
            });
      if (!isWalletRecoveryCommitPromotion(promotion)) {
        if (promotion.kind === 'refused') {
          await IndexedDBManager.deletePendingWalletRecoveryCommit(record.recoveryOperationId);
          results.push({
            kind: 'discarded',
            recoveryOperationId: String(record.recoveryOperationId),
          });
          continue;
        }
        results.push({
          kind: 'pending',
          recoveryOperationId: String(record.recoveryOperationId),
          failure: promotion,
        });
        continue;
      }
      const commitPromotion = promotion;
      const projection = committedProjectionFromPromotion(commitPromotion);
      const promoted =
        record.stage === 'awaiting_server_promotion'
          ? await IndexedDBManager.advancePendingWalletRecoveryCommit({
              awaiting: record,
              promoted: promotedPendingWalletRecoveryCommit(
                record,
                commitPromotion.payload,
                projection,
                record.updatedAtMs + 1,
              ),
            })
          : record;
      if (
        record.stage === 'server_promoted' &&
        alphabetizeStringify(record.projection) !== alphabetizeStringify(projection)
      ) {
        throw new Error('wallet recovery replay projection changed');
      }
      await restoreAndPublishWalletRecoveryCommit({
        pending: promoted,
        payload: commitPromotion.payload,
      });
      results.push({
        kind: 'completed',
        recoveryOperationId: String(record.recoveryOperationId),
      });
    } catch {
      results.push({
        kind: 'corrupt',
        recoveryOperationId: String(record.recoveryOperationId),
      });
    }
  }
  return results;
}

export async function createAwaitingWalletRecoveryCommit(input: {
  readonly operation: WalletRecoveryDurableOperationInput;
  readonly nowMs?: number;
}): Promise<{
  readonly payload: WalletRecoveryDurablePayloadV1;
  readonly pending: Extract<
    PendingWalletRecoveryCommitV1,
    { readonly stage: 'awaiting_server_promotion' }
  >;
}> {
  const payload = await walletRecoveryDurablePayloadFromOperation(input.operation);
  const localMaterial = await encryptWalletRecoveryDurablePayload(payload);
  return {
    payload,
    pending: awaitingPendingWalletRecoveryCommit(payload, localMaterial, input.nowMs),
  };
}

export async function promoteWalletRecoveryCommit(input: {
  readonly awaiting: Extract<
    PendingWalletRecoveryCommitV1,
    { readonly stage: 'awaiting_server_promotion' }
  >;
  readonly promotion: WalletRecoveryCommitPromotion;
}): Promise<Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'server_promoted' }>> {
  const projection = committedProjectionFromPromotion(input.promotion);
  return IndexedDBManager.advancePendingWalletRecoveryCommit({
    awaiting: input.awaiting,
    promoted: promotedPendingWalletRecoveryCommit(
      input.awaiting,
      input.promotion.payload,
      projection,
      input.awaiting.updatedAtMs + 1,
    ),
  });
}
