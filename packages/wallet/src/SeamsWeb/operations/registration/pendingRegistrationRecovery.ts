import { assertPendingWalletRegistrationIdentity, IndexedDBManager } from '@/core/indexedDB';
import type {
  PendingWalletRegistrationCommitV1,
  PendingWalletRegistrationLocalMaterialV1,
} from '@/core/indexedDB';
import type {
  PublishPendingWalletRegistrationCommitInputV1,
  StoreWalletRegistrationFinalizeBatchResult,
} from '@/core/indexedDB/seamsWalletDB/repositories';
import {
  prepareWalletEd25519RegistrationProjectionPublication,
  type PrepareWalletEd25519RegistrationProjectionPublicationInput,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import {
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type LoadedWalletCustodyEd25519MaterialV1,
} from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import {
  completeWalletRegistrationNearProvisioning,
  type WalletRegistrationNearProvisioningResponseV2,
} from '@/core/rpcClients/relayer/walletRegistration';
import { requireEd25519YaoRegistrationPublicResultMatches } from './registrationEd25519Yao';
import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode } from '@shared/utils/base64';
import { mpcMaterialActivationRefsEqual, type WalletId } from '@shared/utils/domainIds';
import { toAccountId } from '@/core/types/accountIds';
import type { RegistrationEstablishedSessionResultV2 } from '@shared/utils/registrationEstablishedSession';

export type PendingPasskeyNearProvisioningCommit = Extract<
  PendingWalletRegistrationCommitV1,
  { readonly operation: 'near_provisioning' }
> & {
  readonly auth: Extract<PendingWalletRegistrationCommitV1['auth'], { readonly kind: 'passkey' }>;
  readonly localMaterial: Extract<
    PendingWalletRegistrationLocalMaterialV1,
    { readonly keyFamilies: readonly ['ed25519'] }
  >;
};

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

async function publishPendingWalletRegistrationCommit(
  input: PublishPendingWalletRegistrationCommitInputV1,
): Promise<StoreWalletRegistrationFinalizeBatchResult> {
  return await IndexedDBManager.publishPendingWalletRegistrationCommit(input);
}

function asError(error: unknown): Error {
  return error instanceof Error
    ? error
    : new Error(String(error || 'pending registration replay failed'));
}

function isPasskeyNearProvisioningCommit(
  pending: PendingWalletRegistrationCommitV1,
): pending is PendingPasskeyNearProvisioningCommit {
  return (
    pending.operation === 'near_provisioning' &&
    pending.auth.kind === 'passkey' &&
    pending.localMaterial.keyFamilies.length === 1 &&
    pending.localMaterial.keyFamilies[0] === 'ed25519'
  );
}

function pendingCustodyMaterial(
  pending: PendingPasskeyNearProvisioningCommit,
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

function registeredPublicKeyFromPending(pending: PendingPasskeyNearProvisioningCommit): string {
  const publicKey = base64UrlDecode(pending.localMaterial.ed25519.metadata.registeredPublicKeyB64u);
  if (publicKey.length !== 32) {
    throw new Error('pending registration has an invalid Ed25519 registered public key');
  }
  return `ed25519:${base58Encode(publicKey)}`;
}

function assertFinalizedSignerMatchesPending(
  pending: PendingPasskeyNearProvisioningCommit,
  finalized: FinalizedNearProvisioningResponse,
  clientPublicKey: string,
): void {
  const metadata = pending.localMaterial.ed25519.metadata;
  const commit = pending.localMaterial.custodyCommit;
  const passkey = requireEd25519YaoRegistrationPublicResultMatches({
    clientPublicKey,
    finalized,
    expectedRpId: pending.auth.rpId,
    expectedWalletId: pending.walletId,
  });
  if (
    passkey.credentialIdB64u !== pending.auth.credentialIdB64u ||
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
    throw new Error('pending registration does not match the committed Passkey/NEAR projection');
  }
  assertPendingWalletRegistrationIdentity(pending, {
    operation: pending.operation,
    walletId: finalized.walletId,
    walletAuthMethodId: finalized.foundingAuthMethod.walletAuthMethodId,
    authority: finalized.authority,
  });
}

function assertRegistrationSessionMatchesPending(
  pending: PendingPasskeyNearProvisioningCommit,
  finalized: FinalizedNearProvisioningResponse,
): void {
  const sessionResult = finalized.registrationEstablishedSession;
  const session = sessionResult.session;
  const ed25519 = session.tokens.kind === 'near_ed25519' ? session.tokens.ed25519 : null;
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

function requireFinalizedNearProvisioningResponse(
  pending: PendingPasskeyNearProvisioningCommit,
  response: WalletRegistrationNearProvisioningResponseV2,
): FinalizedNearProvisioningResponse {
  if (!response.ok || response.kind !== 'near_ed25519') {
    throw new Error(
      response.ok
        ? 'pending Passkey registration replay returned a different signer branch'
        : `pending Passkey registration replay failed: ${response.code}`,
    );
  }
  if (response.walletCustody?.status !== 'committed') {
    throw new Error('pending Passkey registration replay did not commit wallet custody');
  }
  const clientPublicKey = registeredPublicKeyFromPending(pending);
  assertFinalizedSignerMatchesPending(pending, response, clientPublicKey);
  assertRegistrationSessionMatchesPending(pending, response);
  return response;
}

function registrationProjectionFromPending(
  pending: PendingPasskeyNearProvisioningCommit,
  finalized: FinalizedNearProvisioningResponse,
): PrepareWalletEd25519RegistrationProjectionPublicationInput {
  const clientPublicKey = registeredPublicKeyFromPending(pending);
  if (finalized.authMethod.kind !== 'passkey') {
    throw new Error('pending Passkey registration replay returned a non-Passkey auth method');
  }
  return {
    walletId: pending.walletId,
    nearAccountId: toAccountId(finalized.ed25519.nearAccountId),
    nearEd25519SigningKeyId: finalized.ed25519.nearEd25519SigningKeyId,
    rpId: pending.auth.rpId,
    credentialIdB64u: pending.auth.credentialIdB64u,
    credentialPublicKeyB64u: finalized.authMethod.credentialPublicKeyB64u,
    signerSlot: finalized.ed25519.signerSlot,
    operationalPublicKey: clientPublicKey,
    relayerKeyId: finalized.ed25519.relayerKeyId,
    keyVersion: finalized.ed25519.keyVersion,
    participantIds: finalized.ed25519.participantIds,
    transports: pending.auth.transports,
    custodyMaterial: pendingCustodyMaterial(pending, finalized),
  };
}

function publicationInputFromPending(
  pending: PendingPasskeyNearProvisioningCommit,
  finalized: FinalizedNearProvisioningResponse,
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
    walletSessionPublication:
      finalized.registrationEstablishedSession.kind === 'issued'
        ? {
            kind: 'issued',
            walletSession: finalized.registrationEstablishedSession.session.walletSession,
            operationCredential:
              finalized.registrationEstablishedSession.session.operationCredential,
          }
        : { kind: 'credential_free_projection' },
    registration: prepareWalletEd25519RegistrationProjectionPublication(
      registrationProjectionFromPending(pending, finalized),
    ),
  };
}

function pendingNearProvisioningRequest(
  relayerUrl: string,
  pending: PendingPasskeyNearProvisioningCommit,
): Parameters<typeof completeWalletRegistrationNearProvisioning>[0] {
  return {
    relayerUrl,
    registrationCeremonyId: pending.registrationCeremonyId,
    signedSetup: pending.signedSetup,
    idempotencyKey: pending.idempotencyKey,
    ed25519: { activationReference: pending.localMaterial.ed25519.activationReference },
    auth: { kind: 'passkey' },
    walletCustodyCommit: pending.localMaterial.custodyCommit,
  };
}

async function completeCredentialFreePendingNearProvisioning(args: {
  readonly relayerUrl: string;
  readonly pending: PendingPasskeyNearProvisioningCommit;
  readonly ports: PendingRegistrationRecoveryPorts;
}): Promise<FinalizedNearProvisioningResponse> {
  const request = pendingNearProvisioningRequest(args.relayerUrl, args.pending);
  const response = await args.ports.completeWalletRegistrationNearProvisioning(request);
  return requireFinalizedNearProvisioningResponse(args.pending, response);
}

export async function replayPendingPasskeyNearProvisioning(args: {
  readonly relayerUrl: string;
  readonly pending: PendingPasskeyNearProvisioningCommit;
  readonly ports: PendingRegistrationRecoveryPorts;
}): Promise<PendingRegistrationRecoveryResult> {
  const finalized = await completeCredentialFreePendingNearProvisioning(args);
  await args.ports.publishPendingWalletRegistrationCommit(
    publicationInputFromPending(args.pending, finalized),
  );
  return {
    kind: 'published',
    registrationCeremonyId: args.pending.registrationCeremonyId,
    walletId: args.pending.walletId,
    sessionResult: finalized.registrationEstablishedSession.kind,
  };
}

export async function resumePendingPasskeyNearRegistrations(args: {
  readonly relayerUrl: string;
  readonly ports?: PendingRegistrationRecoveryPorts;
}): Promise<PendingRegistrationRecoveryResult[]> {
  const ports = args.ports || defaultPendingRegistrationRecoveryPorts;
  const pendingRows = await ports.listPendingWalletRegistrationCommits();
  const results: PendingRegistrationRecoveryResult[] = [];
  for (const pending of pendingRows) {
    if (!isPasskeyNearProvisioningCommit(pending)) continue;
    try {
      results.push(
        await replayPendingPasskeyNearProvisioning({
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
