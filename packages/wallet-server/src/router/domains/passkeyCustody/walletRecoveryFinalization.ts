import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parseWalletId,
  parseWebAuthnRpId,
  type WalletId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { buildRetiredEnvelopeLifecycle } from '@shared/passkey-custody';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  walletAuthMethodId,
  type WalletAuthMethodRecord,
} from '../../../core/d1WalletAuthMethodStore';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type { CloudflareD1WalletCustodyCommitStore } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import type { WalletRecoveryAuthenticatorCommit } from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import type { CloudflareD1WebAuthnStore } from '../../cloudflare/d1/webauthn/d1WebAuthnStore';
import type { D1WalletStore } from '../../../core/d1WalletStore';
import { verifyWebAuthnRegistrationCredentialForIntent } from '../../../core/authService/webauthn';
import type { WebAuthnCredentialBindingRecord } from '../../../core/WebAuthnCredentialBindingStore';
import type { D1PreparedStatementLike } from '../../../storage/tenantRoute';
import {
  consumeReservedRecoveryCode,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type { WalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import {
  buildWalletRecoveryEcdsaPossessionChallengesV1,
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
} from './walletRecoveryKeyManifest';
import type { WebAuthnRecoveryRegistrationChallengeRecord } from '../../cloudflare/d1/webauthn/d1WebAuthnRecords';

/**
 * Promoting the replacement credential a recovery enrolled.
 *
 * Promotion installs the replacement credential and retires the source state
 * in one guarded D1 transaction. The server rebuilds activation challenges
 * from its current key manifest before that transaction is admitted.
 */

export type WalletRecoveryFinalizationResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
    }
  | { readonly kind: 'refused'; readonly reason: string }
  | { readonly kind: 'conflict'; readonly reason: string }
  | { readonly kind: 'envelope_rejected'; readonly reason: string }
  | { readonly kind: 'registration_rejected'; readonly reason: string };

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

export async function finalizeRecoveredWalletCredentialV1(input: {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  /** Sealed under the newly enrolled credential, by the client. */
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly challengeId: string;
  readonly replacementId: string;
  readonly webauthnRegistration: unknown;
  readonly expectedOrigin: string;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly walletStore: D1WalletStore;
  readonly ecdsaMaterialPossessionProofs: readonly {
    readonly keySetId: string;
    readonly proof: import('@shared/wallet-recovery/walletRecoveryEcdsaPossession').WalletRecoveryEcdsaPossessionProofV1;
  }[];
  readonly nowMs: number;
}): Promise<WalletRecoveryFinalizationResult> {
  const walletId = requireWalletId(input.walletId);
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

  const challenge = await input.webAuthnStore.readRecoveryRegistrationChallenge(
    input.challengeId,
    input.nowMs,
  );
  if (!challenge) {
    const replay = await resolveCommittedRecoveryReplayV1({
      envelopeStore: input.envelopeStore,
      walletCustodyCommits: input.walletCustodyCommits,
      walletId: input.walletId,
      reservationId: input.reservationId,
      replacementId: input.replacementId,
      replacementEnvelope: input.replacementEnvelope,
      webAuthnStore: input.webAuthnStore,
    });
    if (replay.kind === 'promoted' || replay.kind === 'conflict') return replay;
    return {
      kind: 'registration_rejected',
      reason: replay.reason,
    };
  }
  if (
    challenge.walletId !== String(input.walletId) ||
    challenge.reservationId !== String(input.reservationId) ||
    challenge.replacementId !== input.replacementId ||
    challenge.origin !== input.expectedOrigin ||
    challenge.expiresAtMs <= input.nowMs
  ) {
    return {
      kind: 'registration_rejected',
      reason: 'the replacement registration challenge is bound to another recovery',
    };
  }
  const sourceAuthMethod = await sourceAuthMethodForChallenge({
    walletCustodyCommits: input.walletCustodyCommits,
    walletId,
    challenge,
  });
  if (!sourceAuthMethod) {
    return {
      kind: 'registration_rejected',
      reason: 'the wallet source passkey is no longer the active recovery authority',
    };
  }
  const sourceAuthorityRef = await walletAuthAuthorityRef({
    authority: buildPasskeyWalletAuthAuthority({
      walletId,
      rpId: sourceAuthMethod.rpId,
      credentialIdB64u: sourceAuthMethod.credentialIdB64u,
    }),
  });
  if (sourceAuthorityRef.authorityDigest !== challenge.sourceAuthorityDigestB64u) {
    return {
      kind: 'registration_rejected',
      reason: 'the recovery source authority changed',
    };
  }

  let manifest;
  try {
    manifest = await resolveWalletRecoveryKeyManifestV1({
      registry: input.walletStore,
      walletId,
    });
  } catch (error: unknown) {
    return {
      kind: 'refused',
      reason: error instanceof Error ? error.message : 'wallet recovery key manifest unavailable',
    };
  }
  const ecdsaPossessionChallenges = await buildWalletRecoveryEcdsaPossessionChallengesV1({
    manifest,
    walletId,
    reservationId: String(challenge.reservationId),
    replacementId: challenge.replacementId,
    sourceAuthorityDigestB64u: challenge.sourceAuthorityDigestB64u,
    challengeB64u: challenge.challengeB64u,
    expiresAtMs: challenge.expiresAtMs,
  });
  const ecdsaActivationReceipts = manifest.entries.flatMap((entry) =>
    entry.kind === 'evm_family_ecdsa'
      ? [{ keySetId: entry.keySetId, activationReceipt: entry.activationReceipt }]
      : [],
  );
  const activationVerification = await verifyWalletRecoveryKeyActivationsV1({
    registry: input.walletStore,
    walletId,
    recoveryCorrelationId: String(challenge.reservationId),
    replacementId: challenge.replacementId,
    authorityRef: sourceAuthorityRef,
    ecdsaPossessionChallenges: [...ecdsaPossessionChallenges.values()],
    ecdsaActivationReceipts,
    ecdsaMaterialPossessionProofs: input.ecdsaMaterialPossessionProofs,
    nowMs: input.nowMs,
  });
  if (activationVerification.kind !== 'verified') {
    return { kind: 'refused', reason: activationVerification.reason };
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
    expectedOrigin: challenge.origin,
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
  const sourceBinding = await input.webAuthnStore.readBindingByCredential({
    rpId: String(challenge.rpId),
    credentialIdB64u: String(challenge.sourceCredentialIdB64u),
  });
  if (
    !sourceBinding ||
    sourceBinding.userId !== String(input.walletId) ||
    sourceBinding.rpId !== String(challenge.rpId) ||
    sourceBinding.credentialIdB64u !== String(challenge.sourceCredentialIdB64u)
  ) {
    return {
      kind: 'registration_rejected',
      reason: 'the wallet has no existing credential binding to replace',
    };
  }
  const sourceEnvelopeLookup = await input.envelopeStore.lookupEnvelopeForFactor({
    walletId,
    factor: {
      kind: 'passkey',
      rpId: challenge.rpId,
      credentialIdB64u: challenge.sourceCredentialIdB64u,
    },
  });
  if (sourceEnvelopeLookup.kind !== 'active') {
    return {
      kind: 'registration_rejected',
      reason: 'the wallet has no active source custody envelope to replace',
    };
  }
  const sourceEnvelope = {
    ...sourceEnvelopeLookup.envelope,
    lifecycle: buildRetiredEnvelopeLifecycle({
      activatedAtMs: sourceEnvelopeLookup.envelope.lifecycle.activatedAtMs,
      retiredAtMs: input.nowMs,
    }),
    updatedAtMs: input.nowMs,
  };
  const walletAuthMethod: WalletAuthMethodRecord = {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    walletId,
    rpId: parsedRpId.value,
    credentialIdB64u: verifiedRegistration.credential.credentialIdB64u,
    credentialPublicKeyB64u: verifiedRegistration.credential.credentialPublicKeyB64u,
    counter: verifiedRegistration.credential.counter,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  };
  const authenticatorCommit = buildRecoveryAuthenticatorCommit({
    sourceBinding,
    userId: String(input.walletId),
    rpId: parsedRpId.value,
    credential: verifiedRegistration.credential,
    walletAuthMethod,
    nowMs: input.nowMs,
    challengeDeleteStatement:
      input.webAuthnStore.prepareRecoveryRegistrationChallengeDeleteStatement({
        challengeId: input.challengeId,
        record: challenge,
        nowMs: input.nowMs,
      }),
  });

  const storedRecoverySet = await input.walletCustodyCommits.readRecoveryEnvelopeSet(walletId);
  if (!storedRecoverySet) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const reservedIndex = storedRecoverySet.record.manifestKekWraps.findIndex(
    (wrap) =>
      wrap.lifecycle.state === 'reserved' && wrap.lifecycle.reservationId === input.reservationId,
  );
  if (reservedIndex < 0) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const selected = storedRecoverySet.record.manifestKekWraps[reservedIndex];
  if (!selected) {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const lifecycle = consumeReservedRecoveryCode({
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

  const committed = await input.walletCustodyCommits.commitRecoveryPromotion({
    recoverySet: consumedRecoverySet,
    expectedRecoverySetVersion: storedRecoverySet.storeVersion,
    replacementEnvelope: input.replacementEnvelope,
    sourceEnvelope,
    expectedSourceEnvelopeVersion: sourceEnvelopeLookup.storeVersion,
    sourceAuthMethod: {
      record: revokedWalletAuthMethodRecord(sourceAuthMethod, input.nowMs),
      expectedUpdatedAtMs: sourceAuthMethod.updatedAtMs,
      revokedAtMs: input.nowMs,
    },
    reservationId: input.reservationId,
    authenticatorCommit,
  });
  if (committed.kind === 'conflict') {
    return { kind: 'conflict', reason: 'the recovery state changed during finalization' };
  }
  if (committed.kind === 'inconsistent') {
    return {
      kind: 'envelope_rejected',
      reason: committed.reason,
    };
  }

  return {
    kind: 'promoted',
    storeVersion: committed.envelopeStoreVersion,
  };
}

async function sourceAuthMethodForChallenge(input: {
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletId: WalletId;
  readonly challenge: WebAuthnRecoveryRegistrationChallengeRecord;
}): Promise<Extract<WalletAuthMethodRecord, { readonly kind: 'passkey' }> | null> {
  const methods = await input.walletCustodyCommits.listWalletAuthMethods(input.walletId);
  const active = methods.filter((method) => method.status === 'active');
  if (active.length !== 1) return null;
  const method = active[0];
  if (!method || method.kind !== 'passkey') return null;
  if (
    String(walletAuthMethodId(method)) !== String(input.challenge.sourceWalletAuthMethodId) ||
    method.rpId !== input.challenge.rpId ||
    method.credentialIdB64u !== input.challenge.sourceCredentialIdB64u ||
    method.updatedAtMs !== input.challenge.sourceAuthMethodUpdatedAtMs
  ) {
    return null;
  }
  return method;
}

function revokedWalletAuthMethodRecord(
  record: Extract<WalletAuthMethodRecord, { readonly kind: 'passkey' }>,
  revokedAtMs: number,
): Extract<WalletAuthMethodRecord, { readonly kind: 'passkey' }> {
  return {
    version: record.version,
    kind: 'passkey',
    status: 'revoked',
    walletId: record.walletId,
    rpId: record.rpId,
    credentialIdB64u: record.credentialIdB64u,
    credentialPublicKeyB64u: record.credentialPublicKeyB64u,
    counter: record.counter,
    createdAtMs: record.createdAtMs,
    updatedAtMs: revokedAtMs,
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
};

const RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE =
  'the replacement registration challenge is unknown, expired, or already used';
const RECOVERY_REPLAY_STATE_CONFLICT =
  'the recovery commit is incomplete; retry finalization or contact support';

export async function resolveCommittedRecoveryReplayV1(
  input: RecoveryReplayInputBase,
): Promise<RecoveryReplayResolution> {
  const walletId = requireWalletId(input.walletId);
  if (input.replacementEnvelope.factor.kind !== 'passkey') {
    return {
      kind: 'rejected',
      reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE,
    };
  }

  const storedRecoverySet = await input.walletCustodyCommits.readRecoveryEnvelopeSet(walletId);
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
    walletId,
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

  const methods = await input.walletCustodyCommits.listWalletAuthMethods(walletId);
  const activeMethods = methods.filter((method) => method.status === 'active');
  const replacementMethod = activeMethods.length === 1 ? activeMethods[0] : undefined;
  if (
    !replacementMethod ||
    replacementMethod.kind !== 'passkey' ||
    replacementMethod.rpId !== rpId ||
    replacementMethod.credentialIdB64u !== credentialIdB64u
  ) {
    return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
  }
  for (const method of methods) {
    if (method.status !== 'revoked') continue;
    if (
      await input.walletCustodyCommits.hasActiveWalletSessionsForAuthMethod({
        walletId,
        walletAuthMethodId: String(walletAuthMethodId(method)),
      })
    ) {
      return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
    }
  }
  const envelopes = await input.envelopeStore.listWalletEnvelopes(walletId);
  const sourceEnvelopes = envelopes.filter(
    (envelope) =>
      envelope.factor.kind === 'passkey' &&
      envelope.factor.rpId === replacementMethod.rpId &&
      envelope.factor.credentialIdB64u !== replacementMethod.credentialIdB64u,
  );
  const sourceRetired = sourceEnvelopes.some((envelope) => envelope.lifecycle.state === 'retired');
  const otherActive = envelopes.some(
    (envelope) =>
      envelope.lifecycle.state === 'active' &&
      String(envelope.envelopeId) !== String(input.replacementEnvelope.envelopeId),
  );
  if (!sourceRetired || otherActive) {
    return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
  }

  return {
    kind: 'promoted',
    storeVersion: storedEnvelope.storeVersion,
  };
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
  readonly walletAuthMethod: Extract<WalletAuthMethodRecord, { readonly kind: 'passkey' }>;
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
    walletAuthMethod: input.walletAuthMethod,
    challengeDeleteStatement: input.challengeDeleteStatement,
  };
}
