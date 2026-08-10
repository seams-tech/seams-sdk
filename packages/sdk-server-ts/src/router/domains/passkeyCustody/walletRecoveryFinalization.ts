import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import type { WalletRecoveryAuthenticatorCommit } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import type { CloudflareD1WebAuthnStore } from '../../cloudflare/d1/webauthn/d1WebAuthnStore';
import type { D1WalletStore } from '../../../core/d1WalletStore';
import type { WalletEcdsaSignerRecord } from '../../../core/WalletStore';
import type { RouterAbEcdsaRegistrationActivationReceiptV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { verifyWebAuthnRegistrationCredentialForIntent } from '../../../core/authService/webauthn';
import type { WebAuthnCredentialBindingRecord } from '../../../core/WebAuthnCredentialBindingStore';
import type { D1PreparedStatementLike } from '../../../storage/tenantRoute';
import {
  consumeReservedRecoveryCode,
  deriveWalletRecoveryKeyLifecycleId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type { WalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletRecoveryActivationVerification } from './walletRecoveryKeyManifest';

/**
 * Promoting the replacement credential a recovery enrolled.
 *
 * **The order is the safety property.** The new envelope is created first and
 * the old ones retired only after it lands. Retiring first would leave a
 * window — and, if the create then failed, a permanent state — where the
 * wallet has no active envelope and no factor opens its custody seed. The
 * user would be holding a working recovery code they had just spent.
 *
 * So a failed create leaves the wallet exactly as it was: still openable by
 * the credential the user is trying to replace, which is the safe direction to
 * fail in. A failed retire leaves both credentials active, which is worth
 * reporting but is not a lockout — the old one can be revoked again.
 *
 * **Promotion is all-or-nothing across the key set.** The activation proof is
 * built from the server's current signer registry and exact recovery receipts.
 * A raw client outcome can never reach this function.
 */

export type WalletRecoveryFinalizationResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      /** Retired alongside the promotion. Empty is normal on a first recovery. */
      readonly retiredEnvelopeIds: readonly string[];
      /**
       * Present when the new envelope landed but a retire did not. The wallet
       * is recovered; an old credential still opens it and should be revoked.
       */
      readonly retireFailures?: readonly string[];
    }
  | { readonly kind: 'refused'; readonly reason: string }
  | { readonly kind: 'conflict'; readonly reason: string }
  | { readonly kind: 'envelope_rejected'; readonly reason: string }
  | { readonly kind: 'registration_rejected'; readonly reason: string };

export async function finalizeRecoveredWalletCredentialV1(input: {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  /** Sealed under the newly enrolled credential, by the client. */
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly challengeId: string;
  readonly replacementId: string;
  readonly replacedCredentialIdB64u: string;
  readonly webauthnRegistration: unknown;
  readonly expectedOrigin: string;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly walletStore: D1WalletStore;
  readonly activationVerification: Extract<
    WalletRecoveryActivationVerification,
    { readonly kind: 'verified' }
  >;
  readonly ecdsaActivationReceipts: readonly {
    readonly keySetId: string;
    readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  }[];
  readonly nowMs: number;
}): Promise<WalletRecoveryFinalizationResult> {
  if (String(input.replacementEnvelope.walletId) !== String(input.walletId)) {
    /* An envelope naming another wallet would install a credential that opens
       someone else's custody. Checked here rather than trusted from the body
       the client sent. */
    return {
      kind: 'envelope_rejected',
      reason: 'the replacement envelope names a different wallet',
    };
  }
  if (
    input.replacementEnvelope.factor.kind !== 'passkey' ||
    String(input.replacementEnvelope.envelopeId) !== input.replacementId
  ) {
    return {
      kind: 'envelope_rejected',
      reason: 'the replacement envelope is not bound to the recovery replacement',
    };
  }

  const challenge = await input.webAuthnStore.readRecoveryRegistrationChallenge(input.challengeId);
  if (!challenge) {
    const replay = await resolveCommittedRecoveryReplayV1({
      envelopeStore: input.envelopeStore,
      walletCustodyCommits: input.walletCustodyCommits,
      walletId: input.walletId,
      reservationId: input.reservationId,
      replacementId: input.replacementId,
      replacementEnvelope: input.replacementEnvelope,
      webAuthnStore: input.webAuthnStore,
      walletStore: input.walletStore,
      ecdsaActivationReceipts: input.ecdsaActivationReceipts,
    });
    if (replay.kind === 'promoted' || replay.kind === 'conflict') return replay;
    return {
      kind: 'registration_rejected',
      reason: replay.reason,
    };
  }
  if (input.activationVerification.keySetIds.length === 0) {
    return { kind: 'refused', reason: 'wallet recovery verified no key capabilities' };
  }
  if (
    challenge.walletId !== String(input.walletId) ||
    challenge.reservationId !== String(input.reservationId) ||
    challenge.replacementId !== input.replacementId ||
    challenge.replacedCredentialIdB64u !== input.replacedCredentialIdB64u ||
    challenge.expiresAtMs <= input.nowMs
  ) {
    return {
      kind: 'registration_rejected',
      reason: 'the replacement registration challenge is bound to another recovery',
    };
  }
  const parsedRpId = parseWebAuthnRpId(challenge.rpId);
  if (!parsedRpId.ok) {
    return {
      kind: 'registration_rejected',
      reason: 'the replacement registration rpId is invalid',
    };
  }
  const verifiedRegistration = await verifyWebAuthnRegistrationCredentialForIntent({
    webauthnRegistration: input.webauthnRegistration,
    expectedChallenge: challenge.challengeB64u,
    expectedOrigin: input.expectedOrigin,
    rpId: parsedRpId.value,
  });
  if (!verifiedRegistration.ok) {
    return { kind: 'registration_rejected', reason: verifiedRegistration.message };
  }
  if (
    input.replacementEnvelope.factor.rpId !== parsedRpId.value ||
    input.replacementEnvelope.factor.credentialIdB64u !==
      verifiedRegistration.credential.credentialIdB64u
  ) {
    return {
      kind: 'envelope_rejected',
      reason: 'the replacement envelope is bound to a different credential',
    };
  }

  const existingAuthenticator = await input.webAuthnStore.readAuthenticator({
    userId: String(input.walletId),
    credentialIdB64u: verifiedRegistration.credential.credentialIdB64u,
  });
  const existingBinding = await input.webAuthnStore.readBindingByCredential({
    rpId: parsedRpId.value,
    credentialIdB64u: verifiedRegistration.credential.credentialIdB64u,
  });
  if (existingAuthenticator || existingBinding) {
    return {
      kind: 'registration_rejected',
      reason: 'the replacement credential is already registered',
    };
  }
  const sourceBinding = await input.webAuthnStore.readBindingByCredentialId(
    input.replacedCredentialIdB64u,
  );
  if (!sourceBinding || sourceBinding.userId !== String(input.walletId)) {
    return {
      kind: 'registration_rejected',
      reason: 'the wallet has no existing credential binding to replace',
    };
  }
  const authenticatorCommit = buildRecoveryAuthenticatorCommit({
    sourceBinding,
    userId: String(input.walletId),
    rpId: parsedRpId.value,
    credential: verifiedRegistration.credential,
    nowMs: input.nowMs,
    challengeDeleteStatement:
      input.webAuthnStore.prepareRecoveryRegistrationChallengeDeleteStatement(input.challengeId),
  });

  const storedRecoverySet = await input.walletCustodyCommits.readRecoveryEnvelopeSet(
    input.walletId as WalletId,
  );
  if (!storedRecoverySet) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const reservedIndex = storedRecoverySet.record.manifestKekWraps.findIndex(
    (wrap) =>
      (wrap.lifecycle.state === 'reserved' || wrap.lifecycle.state === 'consumed') &&
      wrap.lifecycle.reservationId === input.reservationId,
  );
  if (reservedIndex < 0) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const selected = storedRecoverySet.record.manifestKekWraps[reservedIndex];
  if (!selected) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const lifecycle =
    selected.lifecycle.state === 'consumed'
      ? selected.lifecycle
      : consumeReservedRecoveryCode({
          lifecycle: selected.lifecycle,
          reservationId: input.reservationId,
          nowMs: input.nowMs,
        });
  if ('ok' in lifecycle && !lifecycle.ok) {
    return { kind: 'refused', reason: lifecycle.message };
  }
  const consumedLifecycle = 'ok' in lifecycle ? lifecycle.lifecycle : lifecycle;
  if (consumedLifecycle.state !== 'consumed') {
    return { kind: 'refused', reason: 'the recovery code was not consumed' };
  }
  const consumedRecoverySet: WalletRecoveryEnvelopeSetRecord = {
    ...storedRecoverySet.record,
    manifestKekWraps: storedRecoverySet.record.manifestKekWraps.map((wrap, index) =>
      index === reservedIndex ? { ...wrap, lifecycle: consumedLifecycle } : wrap,
    ),
    updatedAtMs: input.nowMs,
  };

  /* Read before the write, so the retire list is the set that was active when
     the promotion was admitted — not whatever exists after it lands, which
     would include the new envelope itself. */
  const existing = await input.envelopeStore.listWalletEnvelopes(
    input.replacementEnvelope.walletId,
  );
  const previouslyActive = existing.filter(
    (envelope) =>
      envelope.lifecycle.state === 'active' &&
      String(envelope.envelopeId) !== String(input.replacementEnvelope.envelopeId),
  );

  const committed = await input.walletCustodyCommits.commitRecoveryPromotion({
    recoverySet: consumedRecoverySet,
    expectedRecoverySetVersion: storedRecoverySet.storeVersion,
    replacementEnvelope: input.replacementEnvelope,
    reservationId: input.reservationId,
    authenticatorCommit,
  });
  if (committed.kind === 'conflict') {
    return { kind: 'conflict', reason: 'the recovery state changed during finalization' };
  }
  if (committed.kind === 'inconsistent') {
    /* Nothing has been retired yet, so the wallet is untouched. */
    return {
      kind: 'envelope_rejected',
      reason: committed.reason,
    };
  }

  const retiredEnvelopeIds: string[] = [];
  const retireFailures: string[] = [];
  for (const envelope of previouslyActive) {
    const retired = await input.envelopeStore.retireEnvelope({
      locator: {
        walletId: envelope.walletId,
        factor: envelope.factor,
        envelopeId: envelope.envelopeId,
      },
      retiredAtMs: input.nowMs,
    });
    if (retired.kind === 'stored') {
      retiredEnvelopeIds.push(String(envelope.envelopeId));
      continue;
    }
    /* Reported, never fatal. The wallet is recovered and openable by the new
       credential; an old one still working is a cleanup task, not a failure
       of the recovery the user just performed. */
    retireFailures.push(String(envelope.envelopeId));
  }

  return {
    kind: 'promoted',
    storeVersion: committed.envelopeStoreVersion,
    retiredEnvelopeIds,
    ...(retireFailures.length > 0 ? { retireFailures } : {}),
  };
}

type RecoveryReplayResolution =
  | Extract<WalletRecoveryFinalizationResult, { readonly kind: 'promoted' }>
  | Extract<WalletRecoveryFinalizationResult, { readonly kind: 'conflict' }>
  | { readonly kind: 'rejected'; readonly reason: string };

type RecoveryReplayInputBase = {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly replacementId: string;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly walletStore: D1WalletStore;
  readonly ecdsaActivationReceipts: readonly {
    readonly keySetId: string;
    readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  }[];
};

const RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE =
  'the replacement registration challenge is unknown, expired, or already used';
const RECOVERY_REPLAY_STATE_CONFLICT =
  'the recovery commit is incomplete; retry finalization or contact support';

export async function resolveCommittedRecoveryReplayV1(
  input: RecoveryReplayInputBase,
): Promise<RecoveryReplayResolution> {
  if (input.replacementEnvelope.factor.kind !== 'passkey') {
    return {
      kind: 'rejected',
      reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE,
    };
  }

  const storedRecoverySet = await input.walletCustodyCommits.readRecoveryEnvelopeSet(
    input.walletId as WalletId,
  );
  if (!storedRecoverySet) {
    return {
      kind: 'rejected',
      reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE,
    };
  }
  const consumedReservations = storedRecoverySet.record.manifestKekWraps.filter(
    (wrap) =>
      wrap.lifecycle.state === 'consumed' && wrap.lifecycle.reservationId === input.reservationId,
  );
  if (consumedReservations.length !== 1) {
    return {
      kind: consumedReservations.length === 0 ? 'rejected' : 'conflict',
      reason:
        consumedReservations.length === 0
          ? RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE
          : RECOVERY_REPLAY_STATE_CONFLICT,
    };
  }

  if (
    String(input.replacementEnvelope.walletId) !== String(input.walletId) ||
    String(input.replacementEnvelope.envelopeId) !== String(input.replacementId) ||
    input.replacementEnvelope.envelopeRevision !== 1 ||
    input.replacementEnvelope.binding.kind !== 'wallet_custody_seed_v1'
  ) {
    return {
      kind: 'rejected',
      reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE,
    };
  }

  const storedEnvelope = await input.envelopeStore.lookupEnvelope({
    walletId: input.walletId as WalletId,
    factor: {
      kind: 'passkey',
      rpId: input.replacementEnvelope.factor.rpId,
      credentialIdB64u: input.replacementEnvelope.factor.credentialIdB64u,
    },
    envelopeId: input.replacementEnvelope.envelopeId,
  });
  if (storedEnvelope.kind !== 'active') {
    return {
      kind: 'rejected',
      reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE,
    };
  }
  if (
    alphabetizeStringify(storedEnvelope.envelope) !==
    alphabetizeStringify(input.replacementEnvelope)
  ) {
    return {
      kind: 'rejected',
      reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE,
    };
  }

  const credentialIdB64u = String(input.replacementEnvelope.factor.credentialIdB64u);
  const rpId = String(input.replacementEnvelope.factor.rpId);
  const [authenticator, binding] = await Promise.all([
    input.webAuthnStore.readAuthenticator({
      userId: String(input.walletId),
      credentialIdB64u,
    }),
    input.webAuthnStore.readBindingByCredential({
      rpId,
      credentialIdB64u,
    }),
  ]);
  if (
    !authenticator ||
    !binding ||
    binding.userId !== String(input.walletId) ||
    binding.rpId !== rpId ||
    binding.credentialIdB64u !== credentialIdB64u ||
    authenticator.credentialIdB64u !== credentialIdB64u
  ) {
    return {
      kind: 'conflict',
      reason: RECOVERY_REPLAY_STATE_CONFLICT,
    };
  }

  try {
    if (!(await committedRecoverySignerStateMatches(input))) {
      return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
    }
  } catch {
    return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
  }

  const envelopes = await input.envelopeStore.listWalletEnvelopes(input.walletId as WalletId);
  const retiredEnvelopeIds = envelopes
    .filter(
      (envelope) =>
        envelope.lifecycle.state === 'retired' &&
        String(envelope.envelopeId) !== String(input.replacementEnvelope.envelopeId),
    )
    .map((envelope) => String(envelope.envelopeId));
  const retireFailures = envelopes
    .filter(
      (envelope) =>
        envelope.lifecycle.state === 'active' &&
        String(envelope.envelopeId) !== String(input.replacementEnvelope.envelopeId),
    )
    .map((envelope) => String(envelope.envelopeId));

  return {
    kind: 'promoted',
    storeVersion: storedEnvelope.storeVersion,
    retiredEnvelopeIds,
    ...(retireFailures.length > 0 ? { retireFailures } : {}),
  };
}

async function committedRecoverySignerStateMatches(
  input: RecoveryReplayInputBase,
): Promise<boolean> {
  const [ed25519Signers, ecdsaSigners] = await Promise.all([
    input.walletStore.listEd25519SignersForWallet({ walletId: input.walletId as WalletId }),
    input.walletStore.listEcdsaSignersForWallet({ walletId: input.walletId as WalletId }),
  ]);
  if (ed25519Signers.length === 0 && ecdsaSigners.length === 0) return false;

  for (const signer of ed25519Signers) {
    const keySetId = `near_ed25519:${signer.signerId}` as const;
    const lifecycleId = await deriveWalletRecoveryKeyLifecycleId({
      reservationId: input.reservationId,
      keySetId,
    });
    const expectedMaterialLifecycleBinding = `${lifecycleId}:material-activation`;
    const capability = signer.activeYaoCapability;
    if (
      capability.version !== 'wallet_ed25519_yao_recovery_capability_v1' ||
      capability.nearAccountId !== signer.nearAccountId ||
      capability.admissionRequest.application_binding.wallet_id !== String(input.walletId) ||
      capability.admissionRequest.application_binding.near_ed25519_signing_key_id !==
        signer.nearEd25519SigningKeyId ||
      capability.admissionRequest.application_binding.signing_root_id !== signer.signingRootId ||
      capability.admissionRequest.application_binding.key_creation_signer_slot !==
        signer.signerSlot ||
      capability.admissionRequest.participant_ids[0] !== signer.participantIds[0] ||
      capability.admissionRequest.participant_ids[1] !== signer.participantIds[1] ||
      capability.admissionRequest.scope.account_id !== String(input.walletId) ||
      capability.admissionRequest.scope.root_share_epoch !== signer.signingRootVersion ||
      capability.admissionRequest.scope.threshold_session_id !== signer.thresholdSessionId ||
      capability.admissionRequest.scope.signing_worker_id !== signer.signingWorkerId ||
      capability.admissionRequest.scope.lifecycle_id !== lifecycleId ||
      capability.admissionRequest.scope.material_activation.lifecycle_binding !==
        expectedMaterialLifecycleBinding ||
      capability.activationResult.binding.lifecycle.lifecycle_id !== lifecycleId ||
      capability.activationResult.binding.lifecycle.account_id !== String(input.walletId) ||
      capability.activationResult.binding.material_activation.lifecycle_binding !==
        expectedMaterialLifecycleBinding ||
      capability.activationResult.binding.lifecycle.root_share_epoch !==
        capability.admissionRequest.scope.root_share_epoch ||
      capability.activationResult.binding.lifecycle.session_id !==
        capability.admissionRequest.scope.threshold_session_id ||
      capability.activationResult.binding.lifecycle.signer_set_id !==
        capability.admissionRequest.scope.signer_set_id ||
      capability.activationResult.binding.lifecycle.selected_server_id !==
        capability.admissionRequest.scope.signing_worker_id ||
      alphabetizeStringify(capability.runtimePolicyScope) !==
        alphabetizeStringify(signer.runtimePolicyScope) ||
      alphabetizeStringify(capability.activationResult.public_receipt.material_activation) !==
        alphabetizeStringify(capability.admissionRequest.scope.material_activation)
    ) {
      return false;
    }
  }

  const ecdsaByKeyHandle = new Map<string, WalletEcdsaSignerRecord[]>();
  for (const signer of ecdsaSigners) {
    const keyHandle = signer.walletKey.keyHandle;
    const existing = ecdsaByKeyHandle.get(keyHandle);
    if (existing) {
      existing.push(signer);
    } else {
      ecdsaByKeyHandle.set(keyHandle, [signer]);
    }
  }
  for (const [keyHandle, signers] of ecdsaByKeyHandle) {
    const keySetId = `evm_family_ecdsa:${keyHandle}` as const;
    const lifecycleId = await deriveWalletRecoveryKeyLifecycleId({
      reservationId: input.reservationId,
      keySetId,
    });
    const first = signers[0];
    if (!first) return false;
    const capability = first.walletKey.publicCapability;
    const activation = first.activationReceipt.ecdsa_activation;
    const matchingReceiptInputs = input.ecdsaActivationReceipts.filter(
      (receipt) => receipt.keySetId === keySetId,
    );
    const expectedUnchangedReceipt = input.ecdsaActivationReceipts.find(
      (receipt) => receipt.keySetId === keySetId,
    )?.activationReceipt;
    if (
      matchingReceiptInputs.length !== 1 ||
      !expectedUnchangedReceipt ||
      alphabetizeStringify(first.activationReceipt) !==
        alphabetizeStringify(expectedUnchangedReceipt) ||
      capability.client_id !== String(input.walletId) ||
      capability.material_activation.material_owner !== String(input.walletId) ||
      capability.material_activation.lifecycle_binding !==
        expectedUnchangedReceipt.ecdsa_activation.material_activation.lifecycle_binding ||
      first.activationReceipt.lifecycle_id !== expectedUnchangedReceipt.lifecycle_id ||
      activation.activation_epoch !== capability.activation_epoch ||
      activation.material_activation.lifecycle_binding !==
        expectedUnchangedReceipt.ecdsa_activation.material_activation.lifecycle_binding ||
      alphabetizeStringify(activation.context) !== alphabetizeStringify(capability.context) ||
      alphabetizeStringify(activation.public_identity) !==
        alphabetizeStringify(capability.public_identity) ||
      alphabetizeStringify(activation.signing_worker) !==
        alphabetizeStringify(capability.signer_set.selected_server) ||
      alphabetizeStringify(activation.material_activation) !==
        alphabetizeStringify(capability.material_activation)
    ) {
      return false;
    }
    for (const signer of signers) {
      if (!sameEcdsaSignerActivation(signer, first)) return false;
    }
    const pending = await input.walletStore.listEcdsaPendingSessionActivationsForLifecycle({
      walletId: input.walletId as WalletId,
      lifecycleId,
    });
    if (pending.length !== 0) return false;
  }
  if (input.ecdsaActivationReceipts.length !== ecdsaByKeyHandle.size) return false;
  return true;
}

function sameEcdsaSignerActivation(
  left: WalletEcdsaSignerRecord,
  right: WalletEcdsaSignerRecord,
): boolean {
  return (
    alphabetizeStringify(left.walletKey.publicCapability) ===
      alphabetizeStringify(right.walletKey.publicCapability) &&
    alphabetizeStringify(left.activationReceipt) === alphabetizeStringify(right.activationReceipt)
  );
}

function buildRecoveryAuthenticatorCommit(input: {
  readonly sourceBinding: {
    readonly rpId: string;
    readonly credentialIdB64u: string;
    readonly userId: string;
    readonly nearAccountId?: string;
    readonly nearEd25519SigningKeyId?: string;
    readonly signerSlot?: number;
    readonly publicKey?: string;
    readonly relayerKeyId?: string;
    readonly keyVersion?: string;
    readonly recoveryExportCapable?: boolean;
    readonly clientParticipantId?: number;
    readonly relayerParticipantId?: number;
    readonly participantIds?: number[];
    readonly runtimePolicyScope?: WebAuthnCredentialBindingRecord['runtimePolicyScope'];
  };
  readonly userId: string;
  readonly rpId: WebAuthnRpId;
  readonly credential: {
    readonly credentialIdB64u: string;
    readonly credentialPublicKeyB64u: string;
    readonly counter: number;
  };
  readonly nowMs: number;
  readonly challengeDeleteStatement: D1PreparedStatementLike;
}): WalletRecoveryAuthenticatorCommit {
  const base = {
    version: 'webauthn_credential_binding_v1' as const,
    rpId: input.rpId,
    credentialIdB64u: input.credential.credentialIdB64u,
    userId: input.userId,
    ...(input.sourceBinding.relayerKeyId ? { relayerKeyId: input.sourceBinding.relayerKeyId } : {}),
    ...(input.sourceBinding.keyVersion ? { keyVersion: input.sourceBinding.keyVersion } : {}),
    ...(typeof input.sourceBinding.recoveryExportCapable === 'boolean'
      ? { recoveryExportCapable: input.sourceBinding.recoveryExportCapable }
      : {}),
    ...(input.sourceBinding.clientParticipantId !== undefined
      ? { clientParticipantId: input.sourceBinding.clientParticipantId }
      : {}),
    ...(input.sourceBinding.relayerParticipantId !== undefined
      ? { relayerParticipantId: input.sourceBinding.relayerParticipantId }
      : {}),
    ...(input.sourceBinding.participantIds
      ? { participantIds: input.sourceBinding.participantIds }
      : {}),
    ...(input.sourceBinding.runtimePolicyScope
      ? { runtimePolicyScope: input.sourceBinding.runtimePolicyScope }
      : {}),
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  };
  const binding: WebAuthnCredentialBindingRecord =
    input.sourceBinding.nearAccountId &&
    input.sourceBinding.nearEd25519SigningKeyId &&
    input.sourceBinding.publicKey &&
    input.sourceBinding.signerSlot !== undefined
      ? {
          ...base,
          nearAccountId: input.sourceBinding.nearAccountId,
          nearEd25519SigningKeyId: input.sourceBinding.nearEd25519SigningKeyId,
          publicKey: input.sourceBinding.publicKey,
          signerSlot: input.sourceBinding.signerSlot,
        }
      : base;
  return {
    userId: input.userId,
    authenticator: {
      credentialIdB64u: input.credential.credentialIdB64u,
      credentialPublicKeyB64u: input.credential.credentialPublicKeyB64u,
      counter: input.credential.counter,
      createdAtMs: input.nowMs,
      updatedAtMs: input.nowMs,
      deviceInfo: unknownWebAuthnAuthenticatorDeviceInfo(),
    },
    binding,
    challengeDeleteStatement: input.challengeDeleteStatement,
  };
}
