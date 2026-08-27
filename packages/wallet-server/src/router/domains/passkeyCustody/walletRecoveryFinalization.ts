import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  buildFullOwnerPermissionsV1,
  buildActiveWalletAuthorityV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
  type WalletSignerActivationSetV1,
} from '@shared/authorization';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseWalletId,
  parseWebAuthnRpId,
  parseWebAuthnCredentialIdB64u,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
  type WalletRecoveryOperationId,
} from '@shared/utils/domainIds';
import { alphabetizeStringify } from '@shared/utils/digests';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  consumeReservedRecoveryCode,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type { WalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import type { DeviceId } from '@shared/authorization/capabilityKinds';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type {
  PasskeyCustodyEnvelopeLocator,
} from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type {
  CloudflareD1WalletCustodyCommitStore,
  WalletRecoveryAuthenticatorCommit,
} from '../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import type { CloudflareD1WebAuthnStore } from '../../cloudflare/d1/webauthn/d1WebAuthnStore';
import type {
  WebAuthnRecoveryContinuityAnchorRecord,
  WebAuthnRecoveryRegistrationChallengeRecord,
} from '../../cloudflare/d1/webauthn/d1WebAuthnRecords';
import type { D1WalletStore } from '../../../core/d1WalletStore';
import type { WalletEd25519SignerRecord } from '../../../core/WalletStore';
import type { D1WalletAuthorityStore } from '../../cloudflare/d1/wallet/d1WalletAuthorityStore';
import { verifyWebAuthnRegistrationCredentialForIntent } from '../../../core/authService/webauthn';
import type { D1PreparedStatementLike } from '../../../storage/tenantRoute';
import {
  buildWalletRecoveryEcdsaPossessionChallengesV1,
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
  type WalletRecoveryKeyManifestV1,
} from './walletRecoveryKeyManifest';
import type { WalletRecoveryEcdsaPossessionProofV1 } from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import type { WebAuthnCredentialBindingRecord } from '../../../core/WebAuthnCredentialBindingStore';

type ActiveWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly status: 'active' }
>;

type ActivePasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

type ActivePasskeyCustodyEnvelopeRecord = Omit<PasskeyCustodyEnvelopeRecord, 'lifecycle'> & {
  readonly lifecycle: Extract<
    PasskeyCustodyEnvelopeRecord['lifecycle'],
    { readonly state: 'active' }
  >;
};

type ContinuityAnchorRead =
  | {
      readonly kind: 'ready';
      readonly authority: ActiveWalletAuthorityV1;
      readonly method: ActiveWalletAuthMethodRecordV2;
      readonly envelope: ActivePasskeyCustodyEnvelopeRecord;
      readonly authorityRef: WalletAuthAuthorityRef;
    }
  | { readonly kind: 'rejected'; readonly reason: string };

export type WalletRecoveryFinalizationResult =
  | {
      readonly kind: 'promoted';
      readonly storeVersion: string;
      readonly credential: {
        readonly credentialIdB64u: string;
        readonly credentialPublicKeyB64u: string;
        readonly counter: number;
      };
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly walletAuthorityId: WalletAuthorityId;
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

function isActivePasskeyWalletAuthMethodRecordV2(
  method: WalletAuthMethodRecordV2,
): method is ActivePasskeyWalletAuthMethodRecordV2 {
  return method.kind === 'passkey' && method.status === 'active';
}

function requireActivePasskeyWalletAuthMethodRecordV2(
  method: WalletAuthMethodRecordV2,
): ActivePasskeyWalletAuthMethodRecordV2 {
  if (!isActivePasskeyWalletAuthMethodRecordV2(method)) {
    throw new Error('recovery target auth method must be active passkey V2');
  }
  return method;
}

function isActivePasskeyCustodyEnvelopeRecord(
  envelope: PasskeyCustodyEnvelopeRecord,
): envelope is ActivePasskeyCustodyEnvelopeRecord {
  return envelope.lifecycle.state === 'active';
}

function continuityEnvelopeLocator(
  anchor: WebAuthnRecoveryContinuityAnchorRecord,
): PasskeyCustodyEnvelopeLocator {
  switch (anchor.envelope.kind) {
    case 'passkey':
      return {
        walletId: anchor.envelope.walletId,
        envelopeId: anchor.envelope.envelopeId,
        factor: {
          kind: 'passkey',
          rpId: anchor.envelope.rpId,
          credentialIdB64u: anchor.envelope.credentialIdB64u,
        },
      };
    case 'email_otp':
      return {
        walletId: anchor.envelope.walletId,
        envelopeId: anchor.envelope.envelopeId,
        factor: {
          kind: 'email_otp',
          enrollmentId: anchor.envelope.enrollmentId,
          enrollmentSealKeyVersion: anchor.envelope.enrollmentSealKeyVersion,
        },
      };
  }
}

function continuityEnvelopeMatchesAnchor(
  envelope: PasskeyCustodyEnvelopeRecord,
  anchor: WebAuthnRecoveryContinuityAnchorRecord,
): envelope is ActivePasskeyCustodyEnvelopeRecord {
  if (
    !isActivePasskeyCustodyEnvelopeRecord(envelope) ||
    envelope.walletId !== anchor.envelope.walletId ||
    envelope.envelopeId !== anchor.envelope.envelopeId ||
    envelope.binding.kind !== 'wallet_custody_seed_v1' ||
    envelope.ownership.kind !== 'method_bound' ||
    envelope.ownership.walletAuthMethodId !== anchor.walletAuthMethodId ||
    envelope.envelopeRevision !== anchor.envelope.envelopeRevision ||
    envelope.updatedAtMs !== anchor.envelope.updatedAtMs
  ) {
    return false;
  }
  switch (anchor.envelope.kind) {
    case 'passkey':
      return (
        envelope.factor.kind === 'passkey' &&
        envelope.factor.rpId === anchor.envelope.rpId &&
        envelope.factor.credentialIdB64u === anchor.envelope.credentialIdB64u
      );
    case 'email_otp':
      return (
        envelope.factor.kind === 'email_otp' &&
        envelope.factor.enrollmentId === anchor.envelope.enrollmentId &&
        envelope.factor.enrollmentSealKeyVersion === anchor.envelope.enrollmentSealKeyVersion
      );
  }
}

async function readContinuityAnchor(input: {
  readonly walletId: WalletId;
  readonly anchor: WebAuthnRecoveryContinuityAnchorRecord;
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
}): Promise<ContinuityAnchorRead> {
  const authority = await input.walletAuthorityStore.readById(input.anchor.walletAuthorityId);
  if (
    !authority ||
    authority.state !== 'active' ||
    authority.walletId !== input.walletId ||
    String(authority.authorityDigestB64u) !== String(input.anchor.authorityDigestB64u) ||
    authority.provenance.kind !== input.anchor.provenanceKind
  ) {
    return { kind: 'rejected', reason: 'the recovery continuity authority changed' };
  }
  const method = await input.walletCustodyCommits.readWalletAuthMethodById(
    input.anchor.walletAuthMethodId,
  );
  if (
    !method ||
    method.status !== 'active' ||
    method.walletId !== input.walletId ||
    alphabetizeStringify(method) !== alphabetizeStringify(input.anchor.method)
  ) {
    return { kind: 'rejected', reason: 'the recovery continuity method changed' };
  }
  const envelopeLookup = await input.envelopeStore.lookupEnvelope(
    continuityEnvelopeLocator(input.anchor),
  );
  if (
    envelopeLookup.kind !== 'active' ||
    !continuityEnvelopeMatchesAnchor(envelopeLookup.envelope, input.anchor)
  ) {
    return { kind: 'rejected', reason: 'the recovery continuity envelope changed' };
  }
  const authorityRef: WalletAuthAuthorityRef = {
    kind: 'wallet_auth_authority_ref',
    walletId: input.walletId,
    authorityDigest: input.anchor.authorityDigestB64u,
    walletAuthMethodId: input.anchor.walletAuthMethodId,
  };
  return {
    kind: 'ready',
    authority,
    method,
    envelope: envelopeLookup.envelope,
    authorityRef,
  };
}

async function buildRecoveredWalletAuthority(input: {
  readonly walletId: WalletId;
  readonly challenge: WebAuthnRecoveryRegistrationChallengeRecord;
  readonly continuityAuthority: ActiveWalletAuthorityV1;
  readonly manifest: WalletRecoveryKeyManifestV1;
  readonly nowMs: number;
}): Promise<ActiveWalletAuthorityV1> {
  const signerActivations = recoverySignerActivations({
    continuity: input.continuityAuthority.signerActivations,
    manifest: input.manifest,
  });
  const signerActivationSetDigestB64u =
    await computeWalletSignerActivationSetDigestB64u(signerActivations);
  const draft: ActiveWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId: input.challenge.targetAuthorityId,
    walletId: input.walletId,
    principal: {
      kind: 'owner_device',
      deviceId: input.challenge.targetDeviceId,
    },
    provenance: {
      kind: 'wallet_recovery',
      recoveryOperationId: input.challenge.recoveryOperationId,
      continuityAuthorityId: input.continuityAuthority.authorityId,
    },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: input.continuityAuthority.authorityDigestB64u,
    revocationEpoch: 0,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
    state: 'active',
    activatedAtMs: input.nowMs,
  };
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function recoverySignerActivations(input: {
  readonly continuity: WalletSignerActivationSetV1;
  readonly manifest: WalletRecoveryKeyManifestV1;
}): WalletSignerActivationSetV1 {
  const continuityEd25519 = input.continuity.ed25519;
  if (!continuityEd25519) return input.continuity;
  const registeredPublicKeyB64u = continuityEd25519.signer.registeredPublicKeyB64u;
  const entries = input.manifest.entries.filter(
    (entry) =>
      entry.kind === 'near_ed25519' &&
      entry.registeredPublicKeyB64u === registeredPublicKeyB64u &&
      entry.recoveryBasis.capabilityKind === 'recovery',
  );
  if (entries.length !== 1 || entries[0]?.kind !== 'near_ed25519') {
    throw new Error('wallet recovery has no exact fresh Ed25519 activation');
  }
  const ed25519 = {
    kind: 'wallet_ed25519_signer_activation_v1' as const,
    signer: continuityEd25519.signer,
    materialActivation: routerAbMpcMaterialActivationRefFromWire(
      entries[0].recoveryBasis.activeMaterialActivation,
    ),
  };
  const continuityEcdsa = input.continuity.ecdsa;
  if (!continuityEcdsa) {
    return {
      kind: 'wallet_signer_activation_set_v1',
      keyFamilies: ['ed25519'],
      ed25519,
    };
  }
  return {
    kind: 'wallet_signer_activation_set_v1',
    keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
    ed25519,
    ecdsa: continuityEcdsa,
  };
}

function buildRecoveredWalletAuthMethod(input: {
  readonly walletId: WalletId;
  readonly challenge: WebAuthnRecoveryRegistrationChallengeRecord;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
  readonly nowMs: number;
}): ActivePasskeyWalletAuthMethodRecordV2 {
  return requireActivePasskeyWalletAuthMethodRecordV2(
    buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: input.challenge.targetWalletAuthMethodId,
      walletId: input.walletId,
      walletAuthorityId: input.walletAuthorityId,
      kind: 'passkey',
      status: 'active',
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      credentialPublicKeyB64u: input.credentialPublicKeyB64u,
      counter: input.counter,
      createdAtMs: input.nowMs,
      updatedAtMs: input.nowMs,
      activatedAtMs: input.nowMs,
    }),
  );
}

type RecoveryBindingSource = {
  readonly binding: WebAuthnCredentialBindingRecord | null;
  readonly signer: WalletEd25519SignerRecord | null;
};

async function loadRecoveryBindingSource(input: {
  readonly walletId: WalletId;
  readonly anchor: WebAuthnRecoveryContinuityAnchorRecord;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly walletStore: D1WalletStore;
}): Promise<RecoveryBindingSource> {
  let binding: WebAuthnCredentialBindingRecord | null = null;
  if (input.anchor.method.kind === 'passkey') {
    const stored = await input.webAuthnStore.readBindingByCredential({
      rpId: input.anchor.method.rpId,
      credentialIdB64u: input.anchor.method.credentialIdB64u,
    });
    if (
      stored &&
      stored.userId === String(input.walletId) &&
      stored.rpId === String(input.anchor.method.rpId) &&
      stored.credentialIdB64u === String(input.anchor.method.credentialIdB64u)
    ) {
      binding = stored;
    }
  }
  const signers = await input.walletStore.listEd25519SignersForWallet({
    walletId: input.walletId,
  });
  if (signers.length > 1) {
    throw new Error('recovery target cannot resolve one exact wallet Ed25519 signer');
  }
  return { binding, signer: signers[0] ?? null };
}

function buildRecoveredCredentialBinding(input: {
  readonly source: RecoveryBindingSource;
  readonly userId: string;
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: string;
  readonly nowMs: number;
}): WebAuthnCredentialBindingRecord {
  const source = input.source.binding;
  const signer = input.source.signer;
  const base: WebAuthnCredentialBindingRecord = {
    version: 'webauthn_credential_binding_v1',
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
    userId: input.userId,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  };
  if (source) {
    if (
      source.nearAccountId === undefined ||
      source.nearEd25519SigningKeyId === undefined ||
      source.publicKey === undefined ||
      source.signerSlot === undefined
    ) {
      return {
        version: 'webauthn_credential_binding_v1',
        rpId: input.rpId,
        credentialIdB64u: input.credentialIdB64u,
        userId: input.userId,
        ...(source.relayerKeyId ? { relayerKeyId: source.relayerKeyId } : {}),
        ...(source.keyVersion ? { keyVersion: source.keyVersion } : {}),
        ...(typeof source.recoveryExportCapable === 'boolean'
          ? { recoveryExportCapable: source.recoveryExportCapable }
          : {}),
        ...(source.clientParticipantId !== undefined
          ? { clientParticipantId: source.clientParticipantId }
          : {}),
        ...(source.relayerParticipantId !== undefined
          ? { relayerParticipantId: source.relayerParticipantId }
          : {}),
        ...(source.participantIds ? { participantIds: [...source.participantIds] } : {}),
        ...(source.runtimePolicyScope ? { runtimePolicyScope: source.runtimePolicyScope } : {}),
        createdAtMs: input.nowMs,
        updatedAtMs: input.nowMs,
      };
    }
    return {
      version: 'webauthn_credential_binding_v1',
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      userId: input.userId,
      ...(source.relayerKeyId ? { relayerKeyId: source.relayerKeyId } : {}),
      ...(source.keyVersion ? { keyVersion: source.keyVersion } : {}),
      ...(typeof source.recoveryExportCapable === 'boolean'
        ? { recoveryExportCapable: source.recoveryExportCapable }
        : {}),
      ...(source.clientParticipantId !== undefined
        ? { clientParticipantId: source.clientParticipantId }
        : {}),
      ...(source.relayerParticipantId !== undefined
        ? { relayerParticipantId: source.relayerParticipantId }
        : {}),
      ...(source.participantIds ? { participantIds: [...source.participantIds] } : {}),
      ...(source.runtimePolicyScope ? { runtimePolicyScope: source.runtimePolicyScope } : {}),
      nearAccountId: source.nearAccountId,
      nearEd25519SigningKeyId: source.nearEd25519SigningKeyId,
      publicKey: source.publicKey,
      signerSlot: source.signerSlot,
      createdAtMs: input.nowMs,
      updatedAtMs: input.nowMs,
    };
  }
  if (!signer) return base;
  return {
    version: 'webauthn_credential_binding_v1',
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
    userId: input.userId,
    nearAccountId: signer.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    signerSlot: signer.signerSlot,
    publicKey: signer.publicKey,
    relayerKeyId: signer.signingWorkerId,
    keyVersion: signer.keyVersion,
    recoveryExportCapable: signer.recoveryExportCapable,
    clientParticipantId: signer.participantIds[0],
    relayerParticipantId: signer.participantIds[1],
    participantIds: [signer.participantIds[0], signer.participantIds[1]],
    runtimePolicyScope: signer.runtimePolicyScope,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  };
}

function buildRecoveryAuthenticatorCommit(input: {
  readonly userId: string;
  readonly credential: {
    readonly credentialIdB64u: string;
    readonly credentialPublicKeyB64u: string;
    readonly counter: number;
  };
  readonly walletAuthMethod: ActivePasskeyWalletAuthMethodRecordV2;
  readonly binding: WebAuthnCredentialBindingRecord;
  readonly nowMs: number;
  readonly challengeDeleteStatement: D1PreparedStatementLike;
}): WalletRecoveryAuthenticatorCommit {
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
    binding: input.binding,
    walletAuthMethod: input.walletAuthMethod,
    challengeDeleteStatement: input.challengeDeleteStatement,
  };
}

function buildConsumedRecoverySet(input: {
  readonly record: WalletRecoveryEnvelopeSetRecord;
  readonly reservedIndex: number;
  readonly consumedLifecycle: Extract<
    WalletRecoveryEnvelopeSetRecord['manifestKekWraps'][number]['lifecycle'],
    { readonly state: 'consumed' }
  >;
  readonly nowMs: number;
}): WalletRecoveryEnvelopeSetRecord {
  const manifestKekWraps = input.record.manifestKekWraps.map((wrap, index) => {
    if (index !== input.reservedIndex) return wrap;
    return {
      recoveryKeyId: wrap.recoveryKeyId,
      nonceB64u: wrap.nonceB64u,
      wrappedManifestKekB64u: wrap.wrappedManifestKekB64u,
      aadHashB64u: wrap.aadHashB64u,
      lifecycle: input.consumedLifecycle,
    };
  });
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: input.record.walletId,
    manifestKekWraps,
    entries: input.record.entries,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.nowMs,
  };
}

export async function finalizeRecoveredWalletCredentialV1(input: {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly challengeId: string;
  readonly replacementId: string;
  readonly webauthnRegistration: unknown;
  readonly expectedOrigin: string;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly walletStore: D1WalletStore;
  readonly ecdsaMaterialPossessionProofs: readonly {
    readonly keySetId: string;
    readonly proof: WalletRecoveryEcdsaPossessionProofV1;
  }[];
  readonly nowMs: number;
}): Promise<WalletRecoveryFinalizationResult> {
  const walletId = requireWalletId(input.walletId);
  if (
    input.replacementEnvelope.walletId !== walletId ||
    input.replacementEnvelope.factor.kind !== 'passkey' ||
    String(input.replacementEnvelope.envelopeId) !== input.replacementId
  ) {
    return {
      kind: 'envelope_rejected',
      reason: 'the replacement envelope is not bound to this recovery target',
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
      walletAuthorityStore: input.walletAuthorityStore,
      webAuthnStore: input.webAuthnStore,
      walletId: input.walletId,
      reservationId: input.reservationId,
      recoveryOperationId: input.recoveryOperationId,
      targetDeviceId: input.targetDeviceId,
      targetAuthorityId: input.targetAuthorityId,
      targetWalletAuthMethodId: input.targetWalletAuthMethodId,
      replacementId: input.replacementId,
      replacementEnvelope: input.replacementEnvelope,
    });
    if (replay.kind === 'promoted' || replay.kind === 'conflict') return replay;
    return { kind: 'registration_rejected', reason: replay.reason };
  }
  if (
    challenge.walletId !== walletId ||
    challenge.reservationId !== input.reservationId ||
    challenge.recoveryOperationId !== input.recoveryOperationId ||
    challenge.targetDeviceId !== input.targetDeviceId ||
    challenge.targetAuthorityId !== input.targetAuthorityId ||
    challenge.targetWalletAuthMethodId !== input.targetWalletAuthMethodId ||
    String(challenge.replacementId) !== input.replacementId ||
    challenge.origin !== input.expectedOrigin ||
    challenge.expiresAtMs <= input.nowMs
  ) {
    return {
      kind: 'registration_rejected',
      reason: 'the replacement registration challenge is bound to another recovery',
    };
  }
  if (
    input.replacementEnvelope.ownership.kind !== 'method_bound' ||
    input.replacementEnvelope.ownership.walletAuthMethodId !==
      challenge.targetWalletAuthMethodId ||
    input.replacementEnvelope.lifecycle.state !== 'active' ||
    Number(input.replacementEnvelope.envelopeRevision) !== 1
  ) {
    return {
      kind: 'envelope_rejected',
      reason: 'the replacement envelope is bound to another auth method',
    };
  }

  const continuity = await readContinuityAnchor({
    walletId,
    anchor: challenge.continuityAnchor,
    envelopeStore: input.envelopeStore,
    walletCustodyCommits: input.walletCustodyCommits,
    walletAuthorityStore: input.walletAuthorityStore,
  });
  if (continuity.kind === 'rejected') {
    return { kind: 'registration_rejected', reason: continuity.reason };
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
    replacementId: String(challenge.replacementId),
    sourceAuthorityDigestB64u: challenge.continuityAnchor.authorityDigestB64u,
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
    replacementId: String(challenge.replacementId),
    authorityRef: continuity.authorityRef,
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
    return { kind: 'registration_rejected', reason: 'the replacement registration rpId is invalid' };
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
  const replacementCredentialIdB64u = parseWebAuthnCredentialIdB64u(
    verifiedRegistration.credential.credentialIdB64u,
  );
  if (!replacementCredentialIdB64u.ok) {
    return { kind: 'registration_rejected', reason: 'the replacement credential id is invalid' };
  }
  const [existingAuthenticator, existingBinding] = await Promise.all([
    input.webAuthnStore.readAuthenticator({
      userId: String(walletId),
      credentialIdB64u: verifiedRegistration.credential.credentialIdB64u,
    }),
    input.webAuthnStore.readBindingByCredential({
      rpId: parsedRpId.value,
      credentialIdB64u: verifiedRegistration.credential.credentialIdB64u,
    }),
  ]);
  if (existingAuthenticator || existingBinding) {
    return { kind: 'registration_rejected', reason: 'the replacement credential is already registered' };
  }

  let bindingSource: RecoveryBindingSource;
  try {
    bindingSource = await loadRecoveryBindingSource({
      walletId,
      anchor: challenge.continuityAnchor,
      webAuthnStore: input.webAuthnStore,
      walletStore: input.walletStore,
    });
  } catch (error: unknown) {
    return {
      kind: 'refused',
      reason: error instanceof Error ? error.message : 'wallet recovery binding is unavailable',
    };
  }
  const walletAuthMethod = buildRecoveredWalletAuthMethod({
    walletId,
    challenge,
    walletAuthorityId: challenge.targetAuthorityId,
    rpId: parsedRpId.value,
    credentialIdB64u: replacementCredentialIdB64u.value,
    credentialPublicKeyB64u: verifiedRegistration.credential.credentialPublicKeyB64u,
    counter: verifiedRegistration.credential.counter,
    nowMs: input.nowMs,
  });
  const authority = await buildRecoveredWalletAuthority({
    walletId,
    challenge,
    continuityAuthority: continuity.authority,
    manifest,
    nowMs: input.nowMs,
  });
  const binding = buildRecoveredCredentialBinding({
    source: bindingSource,
    userId: String(walletId),
    rpId: parsedRpId.value,
    credentialIdB64u: verifiedRegistration.credential.credentialIdB64u,
    nowMs: input.nowMs,
  });
  const authenticatorCommit = buildRecoveryAuthenticatorCommit({
    userId: String(walletId),
    credential: verifiedRegistration.credential,
    walletAuthMethod,
    binding,
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
  if (!selected || selected.lifecycle.state !== 'reserved') {
    return { kind: 'refused', reason: 'the recovery reservation is unavailable' };
  }
  const consumed = consumeReservedRecoveryCode({
    lifecycle: selected.lifecycle,
    reservationId: input.reservationId,
    nowMs: input.nowMs,
  });
  if (!('ok' in consumed) || !consumed.ok) {
    return {
      kind: 'refused',
      reason: 'message' in consumed ? consumed.message : 'the recovery code was not consumed',
    };
  }
  if (consumed.lifecycle.state !== 'consumed') {
    return { kind: 'refused', reason: 'the recovery code was not consumed' };
  }
  const consumedRecoverySet = buildConsumedRecoverySet({
    record: storedRecoverySet.record,
    reservedIndex,
    consumedLifecycle: consumed.lifecycle,
    nowMs: input.nowMs,
  });
  const committed = await input.walletCustodyCommits.commitRecoveryAuthorityInstall({
    continuityAuthority: continuity.authority,
    authority,
    recoverySet: consumedRecoverySet,
    expectedRecoverySetVersion: storedRecoverySet.storeVersion,
    replacementEnvelope: input.replacementEnvelope,
    reservationId: input.reservationId,
    recoveryKeyId: selected.recoveryKeyId,
    authenticatorCommit,
  });
  if (committed.kind === 'conflict') {
    return { kind: 'conflict', reason: 'the recovery state changed during finalization' };
  }
  if (committed.kind === 'inconsistent') {
    return { kind: 'registration_rejected', reason: committed.reason };
  }
  return {
    kind: 'promoted',
    storeVersion: committed.envelopeStoreVersion,
    credential: {
      credentialIdB64u: walletAuthMethod.credentialIdB64u,
      credentialPublicKeyB64u: walletAuthMethod.credentialPublicKeyB64u,
      counter: walletAuthMethod.counter,
    },
    walletAuthMethodId: walletAuthMethod.walletAuthMethodId,
    walletAuthorityId: walletAuthMethod.walletAuthorityId,
  };
}

type RecoveryReplayResolution =
  | Extract<WalletRecoveryFinalizationResult, { readonly kind: 'promoted' }>
  | Extract<WalletRecoveryFinalizationResult, { readonly kind: 'conflict' }>
  | { readonly kind: 'rejected'; readonly reason: string };

type RecoveryReplayInput = {
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletAuthorityStore: Pick<D1WalletAuthorityStore, 'readById'>;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly replacementId: string;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
};

const RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE =
  'the replacement registration challenge is unknown, expired, or already used';
const RECOVERY_REPLAY_STATE_CONFLICT =
  'the recovery commit is incomplete; retry finalization or contact support';

export async function resolveCommittedRecoveryReplayV1(
  input: RecoveryReplayInput,
): Promise<RecoveryReplayResolution> {
  const walletId = requireWalletId(input.walletId);
  if (
    input.replacementEnvelope.walletId !== walletId ||
    String(input.replacementEnvelope.envelopeId) !== input.replacementId ||
    input.replacementEnvelope.factor.kind !== 'passkey' ||
    input.replacementEnvelope.binding.kind !== 'wallet_custody_seed_v1' ||
    input.replacementEnvelope.lifecycle.state !== 'active' ||
    Number(input.replacementEnvelope.envelopeRevision) !== 1 ||
    input.replacementEnvelope.ownership.kind !== 'method_bound' ||
    input.replacementEnvelope.ownership.walletAuthMethodId !== input.targetWalletAuthMethodId
  ) {
    return { kind: 'rejected', reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE };
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
  if (
    storedEnvelope.kind !== 'active' ||
    alphabetizeStringify(storedEnvelope.envelope) !==
      alphabetizeStringify(input.replacementEnvelope)
  ) {
    return { kind: 'rejected', reason: RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE };
  }
  const recoverySet = await input.walletCustodyCommits.readRecoveryEnvelopeSet(walletId);
  if (!recoverySet) {
    return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
  }
  const consumed = recoverySet.record.manifestKekWraps.filter(
    (wrap) =>
      wrap.lifecycle.state === 'consumed' && wrap.lifecycle.reservationId === input.reservationId,
  );
  if (consumed.length !== 1) {
    return {
      kind: consumed.length === 0 ? 'rejected' : 'conflict',
      reason:
        consumed.length === 0
          ? RECOVERY_REPLAY_CHALLENGE_UNAVAILABLE
          : RECOVERY_REPLAY_STATE_CONFLICT,
    };
  }
  const consumedRecoveryKeyId = consumed[0]?.recoveryKeyId;
  if (!consumedRecoveryKeyId) {
    return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
  }
  const locator = await input.walletCustodyCommits.readRecoveryCodeLocatorByRecoveryKey({
    walletId,
    recoveryKeyId: consumedRecoveryKeyId,
  });
  const credentialIdB64u = String(input.replacementEnvelope.factor.credentialIdB64u);
  const rpId = String(input.replacementEnvelope.factor.rpId);
  const [authenticator, binding, method, authority] = await Promise.all([
    input.webAuthnStore.readAuthenticator({ userId: String(walletId), credentialIdB64u }),
    input.webAuthnStore.readBindingByCredential({ rpId, credentialIdB64u }),
    input.walletCustodyCommits.readWalletAuthMethodById(input.targetWalletAuthMethodId),
    input.walletAuthorityStore.readById(input.targetAuthorityId),
  ]);
  if (
    locator ||
    !authenticator ||
    !binding ||
    binding.userId !== String(walletId) ||
    binding.rpId !== rpId ||
    binding.credentialIdB64u !== credentialIdB64u ||
    authenticator.credentialIdB64u !== credentialIdB64u ||
    !method ||
    !isActivePasskeyWalletAuthMethodRecordV2(method) ||
    method.walletId !== walletId ||
    method.walletAuthorityId !== input.targetAuthorityId ||
    method.walletAuthMethodId !== input.targetWalletAuthMethodId ||
    method.rpId !== input.replacementEnvelope.factor.rpId ||
    method.credentialIdB64u !== input.replacementEnvelope.factor.credentialIdB64u ||
    method.credentialPublicKeyB64u !== authenticator.credentialPublicKeyB64u ||
    method.counter !== authenticator.counter ||
    !authority ||
    authority.state !== 'active' ||
    authority.walletId !== walletId ||
    authority.authorityId !== input.targetAuthorityId ||
    authority.principal.deviceId !== input.targetDeviceId ||
    authority.provenance.kind !== 'wallet_recovery' ||
    authority.provenance.recoveryOperationId !== input.recoveryOperationId ||
    authority.provenance.continuityAuthorityId === input.targetAuthorityId
  ) {
    return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
  }
  const continuityAuthority = await input.walletAuthorityStore.readById(
    authority.provenance.continuityAuthorityId,
  );
  if (
    !continuityAuthority ||
    continuityAuthority.state !== 'active' ||
    continuityAuthority.walletId !== walletId
  ) {
    return { kind: 'conflict', reason: RECOVERY_REPLAY_STATE_CONFLICT };
  }
  return {
    kind: 'promoted',
    storeVersion: storedEnvelope.storeVersion,
    credential: {
      credentialIdB64u: method.credentialIdB64u,
      credentialPublicKeyB64u: method.credentialPublicKeyB64u,
      counter: method.counter,
    },
    walletAuthMethodId: method.walletAuthMethodId,
    walletAuthorityId: method.walletAuthorityId,
  };
}
