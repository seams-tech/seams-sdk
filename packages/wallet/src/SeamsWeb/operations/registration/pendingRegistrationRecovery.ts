import { assertPendingWalletRegistrationIdentity, IndexedDBManager } from '@/core/indexedDB';
import type { PendingWalletRegistrationCommitV1 } from '@/core/indexedDB';
import type {
  PublishPendingWalletRegistrationCommitInputV1,
  StoreWalletRegistrationPublicationInputV1,
  StoreWalletRegistrationFinalizeBatchResult,
} from '@/core/indexedDB/seamsWalletDB/repositories';
import {
  prepareWalletEmailOtpEd25519RegistrationPublication,
  prepareWalletEd25519RegistrationProjectionPublication,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type LoadedWalletCustodyEd25519MaterialV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import {
  completeWalletRegistrationNearProvisioning,
  activateWalletRegistration,
  type WalletRegistrationActivateResponseV2,
  type WalletRegistrationNearProvisioningResponseV2,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  requireEd25519YaoRegistrationPublicResultMatches,
  requireEmailOtpEd25519YaoRegistrationPublicResultMatches,
} from './registrationEd25519Yao';
import { deriveNearProvisioningIdempotencyKey } from './registration';
import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode } from '@shared/utils/base64';
import { mpcMaterialActivationRefsEqual, type WalletId } from '@shared/utils/domainIds';
import { toAccountId } from '@/core/types/accountIds';
import type {
  RegistrationEstablishedSessionProjectionV2,
  RegistrationEstablishedSessionResultV2,
} from '@shared/utils/registrationEstablishedSession';
import { parseEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  PendingEcdsaRegistrationCommit,
  PendingEcdsaOnlyRegistrationCommit,
  PendingEcdsaRegistrationKeyFamilies,
  PendingEcdsaRegistrationRecoveryPorts,
  PendingMixedEcdsaRegistrationCommit,
  PendingRegistrationExactMethod,
  PendingRegistrationRecoverySigningSurface,
} from './pendingEcdsaRegistrationRecoveryValidation';
import {
  assertCanonical,
  isEcdsaRegistrationCommit,
  isMixedEcdsaRegistrationCommit,
  requireCommittedEcdsaRegistrationResponse,
} from './pendingEcdsaRegistrationRecoveryValidation';
import {
  resumePendingEcdsaRegistration as resumePendingEcdsaRegistrationWithPorts,
  type ResumePendingEcdsaRegistrationResult,
} from './pendingEcdsaRegistrationRecovery';
import { unlockPendingEcdsaRegistration } from './pendingEcdsaRegistrationRecoveryUnlock';

export type PendingNearProvisioningCommit = Extract<
  PendingWalletRegistrationCommitV1,
  { readonly operation: 'near_provisioning' }
>;

type PendingEd25519RegistrationCommit =
  | PendingNearProvisioningCommit
  | PendingMixedEcdsaRegistrationCommit;

type FinalizedNearProvisioningResponse = Extract<
  WalletRegistrationNearProvisioningResponseV2,
  { readonly ok: true; readonly kind: 'near_ed25519' }
>;

export type PendingRegistrationRecoveryPorts = {
  readonly listPendingWalletRegistrationCommits: () => Promise<PendingWalletRegistrationCommitV1[]>;
  readonly completeWalletRegistrationNearProvisioning: (
    input: Parameters<typeof completeWalletRegistrationNearProvisioning>[0],
  ) => Promise<WalletRegistrationNearProvisioningResponseV2>;
  readonly publishPendingWalletRegistrationCommit: (
    input: PublishPendingWalletRegistrationCommitInputV1,
  ) => Promise<StoreWalletRegistrationFinalizeBatchResult>;
};

export type PendingRegistrationRecoveryResult =
  | {
      readonly kind: 'published';
      readonly registrationCeremonyId: string;
      readonly walletId: WalletId;
      readonly sessionResult: RegistrationEstablishedSessionResultV2['kind'];
    }
  | {
      readonly kind: 'unlock_required';
      readonly registrationCeremonyId: string;
      readonly walletId: WalletId;
      readonly keyFamilies: PendingEcdsaRegistrationKeyFamilies;
      readonly activationJournalId: PendingEcdsaRegistrationCommit['localMaterial']['ecdsa']['activationJournalId'];
      readonly activationRequestDigestB64u: PendingEcdsaRegistrationCommit['localMaterial']['ecdsa']['activationRequestDigestB64u'];
      readonly clientActivation: PendingEcdsaRegistrationCommit['localMaterial']['ecdsa']['clientActivation'];
      readonly walletAuthMethodId: PendingEcdsaRegistrationCommit['walletAuthMethodId'];
      readonly next: 'unlock_exact_method';
      readonly reason: 'ecdsa_local_finalization';
    }
  | {
      readonly kind: 'failed';
      readonly registrationCeremonyId: string;
      readonly error: Error;
    };

const defaultPendingRegistrationRecoveryPorts: PendingRegistrationRecoveryPorts = {
  listPendingWalletRegistrationCommits: listPendingWalletRegistrationCommits,
  completeWalletRegistrationNearProvisioning: completePendingWalletRegistrationNearProvisioning,
  publishPendingWalletRegistrationCommit: publishPendingWalletRegistrationCommit,
};

async function listPendingWalletRegistrationCommits(): Promise<
  PendingWalletRegistrationCommitV1[]
> {
  await IndexedDBManager.initialize();
  return await IndexedDBManager.listPendingWalletRegistrationCommits();
}

async function completePendingWalletRegistrationNearProvisioning(
  input: Parameters<typeof completeWalletRegistrationNearProvisioning>[0],
): Promise<WalletRegistrationNearProvisioningResponseV2> {
  return await completeWalletRegistrationNearProvisioning(input);
}

async function activatePendingWalletRegistration(
  input: Parameters<typeof activateWalletRegistration>[0],
): ReturnType<typeof activateWalletRegistration> {
  return await activateWalletRegistration(input);
}

async function publishPendingWalletRegistrationCommit(
  input: PublishPendingWalletRegistrationCommitInputV1,
): Promise<StoreWalletRegistrationFinalizeBatchResult> {
  return await IndexedDBManager.publishPendingWalletRegistrationCommit(input);
}

async function publishPendingWalletRegistrationCommitAndRetain(
  input: PublishPendingWalletRegistrationCommitInputV1,
): Promise<StoreWalletRegistrationFinalizeBatchResult> {
  return await IndexedDBManager.publishPendingWalletRegistrationCommitAndRetain(input);
}

async function deletePendingWalletRegistrationCommit(input: {
  readonly registrationCeremonyId: string;
  readonly operation: PendingWalletRegistrationCommitV1['operation'];
}): Promise<void> {
  await IndexedDBManager.deletePendingWalletRegistrationCommit(input);
}

function asError(error: unknown): Error {
  return error instanceof Error
    ? error
    : new Error(String(error || 'pending registration replay failed'));
}

function isNearProvisioningEd25519Commit(
  pending: PendingWalletRegistrationCommitV1,
): pending is PendingNearProvisioningCommit {
  return pending.operation === 'near_provisioning';
}

function pendingCustodyMaterial(
  pending: PendingEd25519RegistrationCommit,
  finalized: FinalizedNearProvisioningResponse,
): LoadedWalletCustodyEd25519MaterialV1 {
  const metadata = pending.localMaterial.ed25519.metadata;
  const localMaterial = pending.localMaterial.ed25519.localMaterial;
  return {
    binding: {
      kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
      applicationBindingDigestB64u: localMaterial.applicationBindingDigestB64u,
      registeredPublicKeyB64u: metadata.registeredPublicKeyB64u,
      participantIds: metadata.participantIds,
      stateEpoch: metadata.stateEpoch,
      walletId: String(finalized.walletId),
      nearAccountId: finalized.ed25519.nearAccountId,
      nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
      signerSlot: finalized.ed25519.signerSlot,
      signingWorkerId: metadata.signingWorkerId,
      signingWorkerVerifyingShareB64u: metadata.signingWorkerVerifyingShareB64u,
    },
    sealed: {
      ciphertextB64u: localMaterial.b64u,
      nonceB64u: localMaterial.nonceB64u,
    },
  };
}

function registeredPublicKeyFromPending(pending: PendingEd25519RegistrationCommit): string {
  const publicKey = base64UrlDecode(pending.localMaterial.ed25519.metadata.registeredPublicKeyB64u);
  if (publicKey.length !== 32) {
    throw new Error('pending registration has an invalid Ed25519 registered public key');
  }
  return `ed25519:${base58Encode(publicKey)}`;
}

function assertFinalizedSignerMatchesPending(
  pending: PendingEd25519RegistrationCommit,
  finalized: FinalizedNearProvisioningResponse,
  clientPublicKey: string,
): void {
  const metadata = pending.localMaterial.ed25519.metadata;
  const commit =
    pending.operation === 'near_provisioning'
      ? pending.localMaterial.custodyCommit
      : pending.localMaterial.ed25519.custodyCommit;
  if (pending.auth.kind === 'passkey') {
    const passkey = requireEd25519YaoRegistrationPublicResultMatches({
      clientPublicKey,
      finalized,
      expectedRpId: pending.auth.rpId,
      expectedWalletId: pending.walletId,
    });
    if (passkey.credentialIdB64u !== pending.auth.credentialIdB64u) {
      throw new Error('pending registration returned a different Passkey credential');
    }
  } else {
    requireEmailOtpEd25519YaoRegistrationPublicResultMatches({
      clientPublicKey,
      finalized,
      expectedRegistrationAuthorityId: pending.auth.registrationAuthorityId,
      expectedWalletId: pending.walletId,
    });
  }
  if (
    finalized.foundingAuthMethod.walletAuthMethodId !== pending.walletAuthMethodId ||
    finalized.foundingAuthMethod.walletId !== pending.walletId ||
    finalized.foundingAuthority.walletId !== pending.walletId ||
    finalized.ed25519.signerSlot !== metadata.signerSlot ||
    finalized.ed25519.nearEd25519SigningKeyId !== metadata.nearEd25519SigningKeyId ||
    finalized.ed25519.participantIds[0] !== metadata.participantIds[0] ||
    finalized.ed25519.participantIds[1] !== metadata.participantIds[1] ||
    finalized.ed25519.routerAbNormalSigning.signingWorkerId !== metadata.signingWorkerId ||
    finalized.ed25519.relayerKeyId !== finalized.ed25519.routerAbNormalSigning.signingWorkerId ||
    finalized.custodyKeyManifestDigestB64u !== commit.keyManifestDigestB64u ||
    (commit.registeredPublicKeyB64u !== undefined &&
      commit.registeredPublicKeyB64u !== metadata.registeredPublicKeyB64u)
  ) {
    throw new Error('pending registration does not match the committed NEAR projection');
  }
  assertPendingWalletRegistrationIdentity(pending, {
    operation: pending.operation,
    walletId: finalized.walletId,
    walletAuthMethodId: finalized.foundingAuthMethod.walletAuthMethodId,
    authority: finalized.authority,
  });
}

function assertEd25519SessionProjectionMatchesPending(
  pending: PendingEd25519RegistrationCommit,
  finalized: FinalizedNearProvisioningResponse,
): void {
  const sessionResult = finalized.registrationEstablishedSession;
  const session = sessionResult.session;
  const ed25519 =
    session.tokens.kind === 'near_ed25519' ||
    session.tokens.kind === 'near_ed25519_and_evm_family_ecdsa'
      ? session.tokens.ed25519
      : null;
  const metadata = pending.localMaterial.ed25519.metadata;
  if (
    session.walletId !== pending.walletId ||
    !ed25519 ||
    ed25519.nearAccountId !== finalized.ed25519.nearAccountId ||
    ed25519.nearEd25519SigningKeyId !== finalized.ed25519.nearEd25519SigningKeyId ||
    ed25519.routerAbNormalSigning.signingWorkerId !== metadata.signingWorkerId ||
    !mpcMaterialActivationRefsEqual(ed25519.materialActivation, metadata.materialActivation)
  ) {
    throw new Error('pending registration does not match the committed Wallet Session projection');
  }
}

function assertNearRegistrationSessionMatchesPending(
  pending: PendingNearProvisioningCommit,
  finalized: FinalizedNearProvisioningResponse,
): void {
  assertEd25519SessionProjectionMatchesPending(pending, finalized);
  const sessionResult = finalized.registrationEstablishedSession;
  if (sessionResult.kind === 'issued') {
    if (
      sessionResult.session.walletSession.walletId !== pending.walletId ||
      sessionResult.session.walletSession.authMethodId !== pending.walletAuthMethodId
    ) {
      throw new Error('pending registration issued a Wallet Session for another auth method');
    }
    return;
  }
  if (sessionResult.next !== 'unlock_exact_method') {
    throw new Error('pending registration replay has an invalid continuation');
  }
}

function assertMixedRegistrationSessionMatchesPending(
  pending: PendingMixedEcdsaRegistrationCommit,
  finalized: FinalizedNearProvisioningResponse,
  initialEcdsaProjection: RegistrationEstablishedSessionProjectionV2,
): void {
  assertEd25519SessionProjectionMatchesPending(pending, finalized);
  const sessionResult = finalized.registrationEstablishedSession;
  const session = sessionResult.session;
  if (
    sessionResult.kind !== 'already_committed' ||
    sessionResult.next !== 'unlock_exact_method' ||
    session.tokens.kind !== 'near_ed25519_and_evm_family_ecdsa' ||
    initialEcdsaProjection.tokens.kind !== 'evm_family_ecdsa'
  ) {
    throw new Error('mixed registration replay did not return its committed session projection');
  }
  assertCanonical(
    {
      walletId: session.walletId,
      authorizationId: session.authorizationId,
      walletSessionId: session.walletSessionId,
      quotaId: session.quotaId,
      expiresAtMs: session.expiresAtMs,
      remainingUses: session.remainingUses,
      walletSessionIdentity: {
        walletId: session.walletSession.walletId,
        authorityId: session.walletSession.authorityId,
        authMethodId: session.walletSession.authMethodId,
        authorizationId: session.walletSession.authorizationId,
        quotaId: session.walletSession.quotaId,
        issuedAtMs: session.walletSession.issuedAtMs,
        expiresAtMs: session.walletSession.expiresAtMs,
      },
      ecdsa: session.tokens.ecdsa,
    },
    {
      walletId: initialEcdsaProjection.walletId,
      authorizationId: initialEcdsaProjection.authorizationId,
      walletSessionId: initialEcdsaProjection.walletSessionId,
      quotaId: initialEcdsaProjection.quotaId,
      expiresAtMs: initialEcdsaProjection.expiresAtMs,
      remainingUses: initialEcdsaProjection.remainingUses,
      walletSessionIdentity: {
        walletId: initialEcdsaProjection.walletSession.walletId,
        authorityId: initialEcdsaProjection.walletSession.authorityId,
        authMethodId: initialEcdsaProjection.walletSession.authMethodId,
        authorizationId: initialEcdsaProjection.walletSession.authorizationId,
        quotaId: initialEcdsaProjection.walletSession.quotaId,
        issuedAtMs: initialEcdsaProjection.walletSession.issuedAtMs,
        expiresAtMs: initialEcdsaProjection.walletSession.expiresAtMs,
      },
      ecdsa: initialEcdsaProjection.tokens.ecdsa,
    },
    'mixed registration NEAR completion changed the committed ECDSA session',
  );
}

function requireFinalizedEd25519Response(
  pending: PendingEd25519RegistrationCommit,
  response: WalletRegistrationNearProvisioningResponseV2,
  expectedCustodyStatus: 'committed' | 'joined',
): FinalizedNearProvisioningResponse {
  if (!response.ok || response.kind !== 'near_ed25519') {
    throw new Error(
      response.ok
        ? 'pending registration replay returned a different signer branch'
        : `pending registration replay failed: ${response.code}`,
    );
  }
  if (response.walletCustody?.status !== expectedCustodyStatus) {
    throw new Error('pending registration replay did not commit the expected wallet custody');
  }
  const clientPublicKey = registeredPublicKeyFromPending(pending);
  assertFinalizedSignerMatchesPending(pending, response, clientPublicKey);
  return response;
}

function requireFinalizedNearProvisioningResponse(
  pending: PendingNearProvisioningCommit,
  response: WalletRegistrationNearProvisioningResponseV2,
): FinalizedNearProvisioningResponse {
  const finalized = requireFinalizedEd25519Response(pending, response, 'committed');
  assertNearRegistrationSessionMatchesPending(pending, finalized);
  return finalized;
}

function requireFinalizedMixedNearProvisioningResponse(
  pending: PendingMixedEcdsaRegistrationCommit,
  response: WalletRegistrationNearProvisioningResponseV2,
  initialEcdsaProjection: RegistrationEstablishedSessionProjectionV2,
): FinalizedNearProvisioningResponse {
  const finalized = requireFinalizedEd25519Response(pending, response, 'joined');
  assertMixedRegistrationSessionMatchesPending(pending, finalized, initialEcdsaProjection);
  return finalized;
}

async function registrationProjectionFromPending(
  pending: PendingEd25519RegistrationCommit,
  finalized: FinalizedNearProvisioningResponse,
): Promise<StoreWalletRegistrationPublicationInputV1> {
  const clientPublicKey = registeredPublicKeyFromPending(pending);
  const common = {
    walletId: pending.walletId,
    nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
    nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
    signerSlot: finalized.ed25519.signerSlot,
    operationalPublicKey: clientPublicKey,
    relayerKeyId: finalized.ed25519.relayerKeyId,
    keyVersion: finalized.ed25519.keyVersion,
    participantIds: finalized.ed25519.participantIds,
    custodyMaterial: pendingCustodyMaterial(pending, finalized),
  } as const;
  if (pending.auth.kind === 'passkey') {
    if (finalized.authMethod.kind !== 'passkey') {
      throw new Error('pending Passkey registration replay returned a non-Passkey auth method');
    }
    return prepareWalletEd25519RegistrationProjectionPublication({
      ...common,
      rpId: pending.auth.rpId,
      credentialIdB64u: pending.auth.credentialIdB64u,
      credentialPublicKeyB64u: finalized.authMethod.credentialPublicKeyB64u,
      transports: pending.auth.transports,
    });
  }
  if (finalized.authMethod.kind !== 'email_otp') {
    throw new Error('pending Email OTP registration replay returned a non-Email OTP auth method');
  }
  const authority = parseEmailOtpWalletAuthAuthority(finalized.authority);
  if (!authority) {
    throw new Error('pending Email OTP registration replay returned an invalid authority');
  }
  return await prepareWalletEmailOtpEd25519RegistrationPublication({
    ...common,
    email: pending.auth.email,
    registrationAuthorityId: pending.auth.registrationAuthorityId,
    authority,
  });
}

function publicationInputFromPending(
  pending: PendingEd25519RegistrationCommit,
  finalized: FinalizedNearProvisioningResponse,
  registration: StoreWalletRegistrationPublicationInputV1,
): PublishPendingWalletRegistrationCommitInputV1 {
  return {
    pending,
    authority: finalized.authority,
    foundingAuthority: {
      authority: finalized.foundingAuthority,
      authMethod: finalized.foundingAuthMethod,
    },
    request: {
      operation: pending.operation,
      registrationCeremonyId: pending.registrationCeremonyId,
      idempotencyKey: pending.idempotencyKey,
      walletId: pending.walletId,
      walletAuthMethodId: pending.walletAuthMethodId,
    },
    ecdsaContinuity: [],
    walletSessionPublication:
      finalized.registrationEstablishedSession.kind === 'issued'
        ? {
            kind: 'issued',
            walletSession: finalized.registrationEstablishedSession.session.walletSession,
            operationCredential:
              finalized.registrationEstablishedSession.session.operationCredential,
          }
        : {
            kind: 'credential_free_projection',
            walletSession: finalized.registrationEstablishedSession.session.walletSession,
          },
    registration,
  };
}

function pendingNearProvisioningAuth(
  pending: PendingEd25519RegistrationCommit,
): Parameters<typeof completeWalletRegistrationNearProvisioning>[0]['auth'] {
  switch (pending.auth.kind) {
    case 'passkey':
      return { kind: 'passkey' };
    case 'email_otp':
      return { kind: 'email_otp', enrollment: pending.auth.enrollment };
    default:
      pending.auth satisfies never;
      throw new Error('pending registration has an unsupported auth method');
  }
}

function pendingNearProvisioningRequest(
  relayerUrl: string,
  pending: PendingNearProvisioningCommit,
): Parameters<typeof completeWalletRegistrationNearProvisioning>[0] {
  return {
    relayerUrl,
    registrationCeremonyId: pending.registrationCeremonyId,
    signedSetup: pending.signedSetup,
    idempotencyKey: pending.idempotencyKey,
    ed25519: { activationReference: pending.localMaterial.ed25519.activationReference },
    auth: pendingNearProvisioningAuth(pending),
    walletCustodyCommit: pending.localMaterial.custodyCommit,
  };
}

async function pendingMixedNearProvisioningRequest(
  relayerUrl: string,
  pending: PendingMixedEcdsaRegistrationCommit,
): Promise<Parameters<typeof completeWalletRegistrationNearProvisioning>[0]> {
  return {
    relayerUrl,
    registrationCeremonyId: pending.registrationCeremonyId,
    signedSetup: pending.signedSetup,
    idempotencyKey: await deriveNearProvisioningIdempotencyKey({
      registrationCeremonyId: pending.registrationCeremonyId,
      activationReference: pending.localMaterial.ed25519.activationReference,
    }),
    ed25519: { activationReference: pending.localMaterial.ed25519.activationReference },
    auth: pendingNearProvisioningAuth(pending),
    walletCustodyCommit: pending.localMaterial.ed25519.custodyCommit,
  };
}

async function completeCredentialFreePendingNearProvisioning(args: {
  readonly relayerUrl: string;
  readonly pending: PendingNearProvisioningCommit;
  readonly ports: PendingRegistrationRecoveryPorts;
}): Promise<FinalizedNearProvisioningResponse> {
  const request = pendingNearProvisioningRequest(args.relayerUrl, args.pending);
  const response = await args.ports.completeWalletRegistrationNearProvisioning(request);
  return requireFinalizedNearProvisioningResponse(args.pending, response);
}

export async function replayPendingNearProvisioning(args: {
  readonly relayerUrl: string;
  readonly pending: PendingNearProvisioningCommit;
  readonly ports: PendingRegistrationRecoveryPorts;
}): Promise<PendingRegistrationRecoveryResult> {
  const finalized = await completeCredentialFreePendingNearProvisioning(args);
  const registration = await registrationProjectionFromPending(args.pending, finalized);
  await args.ports.publishPendingWalletRegistrationCommit(
    publicationInputFromPending(args.pending, finalized, registration),
  );
  return {
    kind: 'published',
    registrationCeremonyId: args.pending.registrationCeremonyId,
    walletId: args.pending.walletId,
    sessionResult: finalized.registrationEstablishedSession.kind,
  };
}

export type PendingMixedRegistrationRecoveryPorts = Pick<
  PendingEcdsaRegistrationRecoveryPorts,
  'activateWalletRegistration' | 'unlockPendingEcdsaRegistration'
> & {
  readonly completeWalletRegistrationNearProvisioning: PendingRegistrationRecoveryPorts['completeWalletRegistrationNearProvisioning'];
  readonly publishPendingWalletRegistrationCommitAndRetain: (
    input: PublishPendingWalletRegistrationCommitInputV1,
  ) => Promise<StoreWalletRegistrationFinalizeBatchResult>;
  readonly deletePendingWalletRegistrationCommit: typeof deletePendingWalletRegistrationCommit;
};

type CapturedMixedActivation = {
  value: Awaited<ReturnType<typeof requireCommittedEcdsaRegistrationResponse>> | null;
};

async function activateAndCaptureMixedRegistration(
  base: {
    readonly pending: PendingMixedEcdsaRegistrationCommit;
    readonly ports: PendingMixedRegistrationRecoveryPorts;
    readonly captured: CapturedMixedActivation;
  },
  input: Parameters<PendingEcdsaRegistrationRecoveryPorts['activateWalletRegistration']>[0],
): Promise<WalletRegistrationActivateResponseV2> {
  const response = await base.ports.activateWalletRegistration(input);
  base.captured.value = await requireCommittedEcdsaRegistrationResponse({
    pending: base.pending,
    response,
  });
  return response;
}

async function retainMixedRegistrationPublication(
  ports: PendingMixedRegistrationRecoveryPorts,
  input: PublishPendingWalletRegistrationCommitInputV1,
): Promise<StoreWalletRegistrationFinalizeBatchResult> {
  return await ports.publishPendingWalletRegistrationCommitAndRetain(input);
}

function requireCapturedMixedActivation(
  captured: CapturedMixedActivation,
): Awaited<ReturnType<typeof requireCommittedEcdsaRegistrationResponse>> {
  if (captured.value === null) throw new Error('mixed registration did not replay Route 3');
  return captured.value;
}

const defaultPendingMixedRegistrationRecoveryPorts: PendingMixedRegistrationRecoveryPorts = {
  activateWalletRegistration: activatePendingWalletRegistration,
  unlockPendingEcdsaRegistration,
  completeWalletRegistrationNearProvisioning: completePendingWalletRegistrationNearProvisioning,
  publishPendingWalletRegistrationCommitAndRetain,
  deletePendingWalletRegistrationCommit,
};

export type PendingMixedRegistrationResumeInput = {
  readonly relayerUrl: string;
  readonly pending: PendingMixedEcdsaRegistrationCommit;
  readonly exactMethod: PendingRegistrationExactMethod;
  readonly signingSurface: PendingRegistrationRecoverySigningSurface;
  readonly ports?: PendingMixedRegistrationRecoveryPorts;
};

export async function resumePendingMixedRegistration(
  args: PendingMixedRegistrationResumeInput,
): Promise<ResumePendingEcdsaRegistrationResult> {
  const ports = args.ports ?? defaultPendingMixedRegistrationRecoveryPorts;
  const captured: CapturedMixedActivation = { value: null };
  const ecdsaPorts: PendingEcdsaRegistrationRecoveryPorts = {
    activateWalletRegistration: activateAndCaptureMixedRegistration.bind(undefined, {
      pending: args.pending,
      ports,
      captured,
    }),
    unlockPendingEcdsaRegistration: ports.unlockPendingEcdsaRegistration,
    publishPendingWalletRegistrationCommit: retainMixedRegistrationPublication.bind(
      undefined,
      ports,
    ),
  };
  let ecdsaResult: ResumePendingEcdsaRegistrationResult;
  switch (args.exactMethod.kind) {
    case 'passkey':
      ecdsaResult = await resumePendingEcdsaRegistrationWithPorts({
        relayerUrl: args.relayerUrl,
        pending: args.pending,
        signingSurface: args.signingSurface,
        exactMethod: args.exactMethod,
        ports: ecdsaPorts,
      });
      break;
    case 'email_otp':
      ecdsaResult = await resumePendingEcdsaRegistrationWithPorts({
        relayerUrl: args.relayerUrl,
        pending: args.pending,
        signingSurface: args.signingSurface,
        exactMethod: args.exactMethod,
        ports: ecdsaPorts,
      });
      break;
    default:
      args.exactMethod satisfies never;
      throw new Error('mixed registration has an unsupported exact method');
  }
  const activated = requireCapturedMixedActivation(captured);
  const request = await pendingMixedNearProvisioningRequest(args.relayerUrl, args.pending);
  const response = await ports.completeWalletRegistrationNearProvisioning(request);
  const finalized = requireFinalizedMixedNearProvisioningResponse(
    args.pending,
    response,
    activated.registrationEstablishedSession.session,
  );
  const registration = await registrationProjectionFromPending(args.pending, finalized);
  await ports.publishPendingWalletRegistrationCommitAndRetain(
    publicationInputFromPending(args.pending, finalized, registration),
  );
  await ports.deletePendingWalletRegistrationCommit({
    registrationCeremonyId: args.pending.registrationCeremonyId,
    operation: args.pending.operation,
  });
  return ecdsaResult;
}

export async function resumePendingNearRegistrations(args: {
  readonly relayerUrl: string;
  readonly ports?: PendingRegistrationRecoveryPorts;
}): Promise<PendingRegistrationRecoveryResult[]> {
  const ports = args.ports || defaultPendingRegistrationRecoveryPorts;
  const pendingRows = await ports.listPendingWalletRegistrationCommits();
  const results: PendingRegistrationRecoveryResult[] = [];
  for (const pending of pendingRows) {
    if (isEcdsaRegistrationCommit(pending) || isMixedEcdsaRegistrationCommit(pending)) {
      results.push({
        kind: 'unlock_required',
        registrationCeremonyId: pending.registrationCeremonyId,
        walletId: pending.walletId,
        keyFamilies: pending.localMaterial.keyFamilies,
        activationJournalId: pending.localMaterial.ecdsa.activationJournalId,
        activationRequestDigestB64u: pending.localMaterial.ecdsa.activationRequestDigestB64u,
        clientActivation: pending.localMaterial.ecdsa.clientActivation,
        walletAuthMethodId: pending.walletAuthMethodId,
        next: 'unlock_exact_method',
        reason: 'ecdsa_local_finalization',
      });
      continue;
    }
    if (!isNearProvisioningEd25519Commit(pending)) continue;
    try {
      results.push(
        await replayPendingNearProvisioning({
          relayerUrl: args.relayerUrl,
          pending,
          ports,
        }),
      );
    } catch (error: unknown) {
      results.push({
        kind: 'failed',
        registrationCeremonyId: pending.registrationCeremonyId,
        error: asError(error),
      });
    }
  }
  return results;
}

export type {
  PendingEcdsaRegistrationCommit,
  PendingRegistrationExactMethod,
  PendingRegistrationRecoverySigningSurface,
} from './pendingEcdsaRegistrationRecoveryValidation';
export { isEcdsaRegistrationCommit } from './pendingEcdsaRegistrationRecoveryValidation';
export type { ResumePendingEcdsaRegistrationResult } from './pendingEcdsaRegistrationRecovery';

const defaultPendingEcdsaRegistrationRecoveryPorts: PendingEcdsaRegistrationRecoveryPorts = {
  activateWalletRegistration: activatePendingWalletRegistration,
  publishPendingWalletRegistrationCommit,
  unlockPendingEcdsaRegistration,
};

export type PendingEcdsaRegistrationResumeInput = {
  readonly relayerUrl: string;
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly exactMethod: PendingRegistrationExactMethod;
  readonly signingSurface: PendingRegistrationRecoverySigningSurface;
  readonly ports?: PendingEcdsaRegistrationRecoveryPorts;
};

export type PendingEcdsaRegistrationResumeRequest = {
  readonly walletId: WalletId | string;
  readonly registrationCeremonyId: string;
  readonly exactMethod: PendingRegistrationExactMethod;
};

export async function resumePendingEcdsaRegistration(
  args: PendingEcdsaRegistrationResumeInput,
): Promise<ResumePendingEcdsaRegistrationResult> {
  const ports = args.ports ?? defaultPendingEcdsaRegistrationRecoveryPorts;
  switch (args.exactMethod.kind) {
    case 'passkey':
      return await resumePendingEcdsaRegistrationWithPorts({
        relayerUrl: args.relayerUrl,
        pending: args.pending,
        signingSurface: args.signingSurface,
        exactMethod: args.exactMethod,
        ports,
      });
    case 'email_otp':
      return await resumePendingEcdsaRegistrationWithPorts({
        relayerUrl: args.relayerUrl,
        pending: args.pending,
        signingSurface: args.signingSurface,
        exactMethod: args.exactMethod,
        ports,
      });
    default:
      args.exactMethod satisfies never;
      throw new Error('pending ECDSA registration has an unsupported exact method');
  }
}

export async function resumePendingEcdsaRegistrationFromStoredCommit(args: {
  readonly relayerUrl: string;
  readonly request: PendingEcdsaRegistrationResumeRequest;
  readonly signingSurface: PendingRegistrationRecoverySigningSurface;
}): Promise<ResumePendingEcdsaRegistrationResult> {
  await IndexedDBManager.initialize();
  const pending = (await IndexedDBManager.listPendingWalletRegistrationCommits()).find(
    (candidate) =>
      candidate.operation === 'registration_activate' &&
      String(candidate.walletId) === String(args.request.walletId) &&
      candidate.registrationCeremonyId === args.request.registrationCeremonyId,
  );
  if (!pending) {
    throw new Error('pending ECDSA registration commit was not found');
  }
  if (isMixedEcdsaRegistrationCommit(pending)) {
    return await resumePendingMixedRegistration({
      relayerUrl: args.relayerUrl,
      pending,
      exactMethod: args.request.exactMethod,
      signingSurface: args.signingSurface,
    });
  }
  if (!isEcdsaRegistrationCommit(pending)) {
    throw new Error('pending registration commit is not ECDSA-enabled');
  }
  return await resumePendingEcdsaRegistration({
    relayerUrl: args.relayerUrl,
    pending,
    exactMethod: args.request.exactMethod,
    signingSurface: args.signingSurface,
  });
}
