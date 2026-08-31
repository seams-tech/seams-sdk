import { assertPendingWalletRegistrationIdentity } from '@/core/indexedDB';
import type {
  PendingWalletRegistrationCommitV1,
  PendingWalletRegistrationLocalMaterialV1,
} from '@/core/indexedDB';
import type {
  PublishPendingWalletRegistrationCommitInputV1,
  StoreWalletRegistrationFinalizeBatchResult,
} from '@/core/indexedDB/seamsWalletDB/repositories';
import type { RegistrationSigningSurface } from '@/SeamsWeb/signingSurface/types';
import {
  activateWalletRegistration,
  type WalletRegistrationActivateResponseV2,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { WalletCustodyEvmFamilyPublicFacts } from '@shared/passkey-custody';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { alphabetizeStringify, sha256HexUtf8 } from '@shared/utils/digests';
import { parseEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { RegistrationEstablishedSessionResultV2 } from '@shared/utils/registrationEstablishedSession';
import type { RouterAbEcdsaPostRegistrationSessionActivationResponseV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { assertSharedRegistrationEvmFamilyWalletKeyMaterial } from './registrationStrictEcdsa';

export type PendingEcdsaRegistrationKeyFamilies =
  | readonly ['ecdsa_secp256k1']
  | readonly ['ed25519', 'ecdsa_secp256k1'];

type PendingEcdsaOnlyLocalMaterial = Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ecdsa_secp256k1'] }
>;

type PendingMixedLocalMaterial = Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'] }
>;

export type PendingEcdsaOnlyRegistrationCommit = Extract<
  PendingWalletRegistrationCommitV1,
  { readonly operation: 'registration_activate' }
> & {
  readonly signerPlanKind: 'evm_family_ecdsa';
  readonly localMaterial: PendingEcdsaOnlyLocalMaterial;
};

export type PendingMixedEcdsaRegistrationCommit = Extract<
  PendingWalletRegistrationCommitV1,
  { readonly operation: 'registration_activate' }
> & {
  readonly signerPlanKind: 'near_ed25519_and_evm_family_ecdsa';
  readonly localMaterial: PendingMixedLocalMaterial;
};

export type PendingEcdsaRegistrationCommit =
  | PendingEcdsaOnlyRegistrationCommit
  | PendingMixedEcdsaRegistrationCommit;

export type PendingRegistrationExactMethod =
  | { readonly kind: 'passkey'; readonly expectedOrigin: string }
  | { readonly kind: 'email_otp'; readonly otpCode: string; readonly challengeId: string };

export type PendingRegistrationRecoverySigningSurface = Pick<
  RegistrationSigningSurface,
  | 'finalizeWalletRegistrationEcdsaSessions'
  | 'rejoinWalletCustodyEvmFamilyKeySet'
  | 'getAuthenticationCredentialsSerialized'
  | 'getSignerWorkerContext'
>;

export type PendingEcdsaRegistrationUnlockMaterial = {
  readonly session: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

export type PendingEcdsaRegistrationRecoveryPorts = {
  readonly activateWalletRegistration: (
    input: Parameters<typeof activateWalletRegistration>[0],
  ) => Promise<WalletRegistrationActivateResponseV2>;
  readonly publishPendingWalletRegistrationCommit: (
    input: PublishPendingWalletRegistrationCommitInputV1,
  ) => Promise<StoreWalletRegistrationFinalizeBatchResult>;
  readonly unlockPendingEcdsaRegistration: (
    input: PendingEcdsaRegistrationUnlockInput,
  ) => Promise<PendingEcdsaRegistrationUnlockMaterial>;
};

export type CommittedEcdsaRegistrationResponse = Extract<
  WalletRegistrationActivateResponseV2,
  { readonly ok: true; readonly kind: 'evm_family_ecdsa' }
> & {
  readonly registrationEstablishedSession: Extract<
    RegistrationEstablishedSessionResultV2,
    { readonly kind: 'already_committed' }
  >;
};

export type PendingEcdsaRegistrationUnlockInput = {
  readonly relayerUrl: string;
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly response: CommittedEcdsaRegistrationResponse;
  readonly walletKeys: readonly [
    WalletRegistrationEcdsaWalletKey,
    ...WalletRegistrationEcdsaWalletKey[],
  ];
  readonly exactMethod: PendingRegistrationExactMethod;
  readonly signingSurface: PendingRegistrationRecoverySigningSurface;
};

export function isEcdsaRegistrationCommit(
  pending: PendingWalletRegistrationCommitV1,
): pending is PendingEcdsaOnlyRegistrationCommit {
  if (
    pending.operation !== 'registration_activate' ||
    pending.signerPlanKind !== 'evm_family_ecdsa'
  ) {
    return false;
  }
  const families = pending.localMaterial.keyFamilies;
  return families.length === 1 && families[0] === 'ecdsa_secp256k1';
}

export function isMixedEcdsaRegistrationCommit(
  pending: PendingWalletRegistrationCommitV1,
): pending is PendingMixedEcdsaRegistrationCommit {
  if (
    pending.operation !== 'registration_activate' ||
    pending.signerPlanKind !== 'near_ed25519_and_evm_family_ecdsa'
  ) {
    return false;
  }
  const families = pending.localMaterial.keyFamilies;
  return families.length === 2 && families[0] === 'ed25519' && families[1] === 'ecdsa_secp256k1';
}

export function requireEcdsaProjection(
  response: CommittedEcdsaRegistrationResponse,
): Extract<
  CommittedEcdsaRegistrationResponse['registrationEstablishedSession']['session']['tokens'],
  { readonly kind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa' }
> {
  const tokens = response.registrationEstablishedSession.session.tokens;
  if (tokens.kind === 'evm_family_ecdsa' || tokens.kind === 'near_ed25519_and_evm_family_ecdsa') {
    return tokens;
  }
  throw new Error('pending ECDSA activation returned no ECDSA projection');
}

export function pendingEcdsaActivateRequest(
  relayerUrl: string,
  pending: PendingEcdsaOnlyRegistrationCommit,
): Parameters<typeof activateWalletRegistration>[0] {
  const common = {
    relayerUrl,
    registrationCeremonyId: pending.registrationCeremonyId,
    signedSetup: pending.signedSetup,
    idempotencyKey: pending.idempotencyKey,
    walletCustodyCommit: pending.localMaterial.custodyCommit,
    ...(pending.auth.kind === 'email_otp' ? { emailOtpEnrollment: pending.auth.enrollment } : {}),
  };
  const ecdsa = {
    activationCorrelationId: pending.localMaterial.ecdsa.activationJournalId,
    activationRequestDigestB64u: pending.localMaterial.ecdsa.activationRequestDigestB64u,
    clientActivation: pending.localMaterial.ecdsa.clientActivation,
  };
  return { ...common, signerPlanKind: pending.signerPlanKind, ecdsa };
}

export function requireResponseWalletKeys(
  response: CommittedEcdsaRegistrationResponse,
): readonly [WalletRegistrationEcdsaWalletKey, ...WalletRegistrationEcdsaWalletKey[]] {
  const first = response.ecdsa.walletKeys[0];
  if (!first) throw new Error('pending ECDSA activation returned no wallet keys');
  assertSharedRegistrationEvmFamilyWalletKeyMaterial(response.ecdsa.walletKeys);
  return [first, ...response.ecdsa.walletKeys.slice(1)];
}

function ethereumAddressFromActivationIdentity(value: string): string {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) throw new Error('pending ECDSA activation returned an invalid address');
  let hex = '0x';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

export function assertCanonical(actual: unknown, expected: unknown, message: string): void {
  if (alphabetizeStringify(actual) !== alphabetizeStringify(expected)) throw new Error(message);
}

function assertProjectionMatchesPending(
  pending: PendingEcdsaRegistrationCommit,
  response: CommittedEcdsaRegistrationResponse,
  walletKey: WalletRegistrationEcdsaWalletKey,
): void {
  const session = response.registrationEstablishedSession.session;
  const projection = requireEcdsaProjection(response);
  const expectedTokenKind =
    pending.signerPlanKind === 'near_ed25519_and_evm_family_ecdsa'
      ? 'near_ed25519_and_evm_family_ecdsa'
      : 'evm_family_ecdsa';
  assertCanonical(
    [
      response.walletId,
      response.custodyKeyManifestDigestB64u,
      response.walletCustody?.status,
      session.walletId,
      session.walletSession.walletId,
      session.walletSession.authMethodId,
      session.tokens.kind,
      projection.ecdsa.keyHandle,
      projection.ecdsa.thresholdSessionId,
      session.expiresAtMs,
      session.remainingUses,
    ],
    [
      pending.walletId,
      pending.localMaterial.custodyCommit.keyManifestDigestB64u,
      'committed',
      pending.walletId,
      pending.walletId,
      pending.walletAuthMethodId,
      expectedTokenKind,
      walletKey.keyHandle,
      response.ecdsa.bootstrap.thresholdSessionId,
      response.ecdsa.bootstrap.expiresAtMs,
      response.ecdsa.bootstrap.remainingUses,
    ],
    'pending ECDSA activation projection mismatch',
  );
  assertPendingWalletRegistrationIdentity(pending, {
    operation: pending.operation,
    walletId: response.walletId,
    walletAuthMethodId: response.foundingAuthMethod.walletAuthMethodId,
    authority: response.authority,
  });
}

function isCommittedEcdsaRegistrationResponse(
  response: WalletRegistrationActivateResponseV2,
): response is CommittedEcdsaRegistrationResponse {
  return (
    response.ok === true &&
    response.kind === 'evm_family_ecdsa' &&
    response.registrationEstablishedSession.kind === 'already_committed'
  );
}

async function assertAuthMatchesPending(
  pending: PendingEcdsaRegistrationCommit,
  response: CommittedEcdsaRegistrationResponse,
): Promise<void> {
  if (pending.auth.kind === 'passkey') {
    if (
      response.authMethod.kind !== 'passkey' ||
      response.rpId !== pending.auth.rpId ||
      response.authMethod.credentialIdB64u !== pending.auth.credentialIdB64u
    ) {
      throw new Error('pending ECDSA activation returned a different Passkey method');
    }
    return;
  }
  if (
    response.authMethod.kind !== 'email_otp' ||
    response.authMethod.registrationAuthorityId !== pending.auth.registrationAuthorityId
  ) {
    throw new Error('pending ECDSA activation returned a different Email OTP method');
  }
  const authority = parseEmailOtpWalletAuthAuthority(response.authority);
  const emailHashHex = await sha256HexUtf8(pending.auth.email);
  if (
    !authority ||
    authority.factor.providerUserId !== pending.auth.providerSubject ||
    authority.verifier.emailHashHex.toLowerCase() !== emailHashHex.toLowerCase()
  ) {
    throw new Error('pending ECDSA activation returned a different Email OTP identity');
  }
}

function assertActivationFacts(
  pending: PendingEcdsaRegistrationCommit,
  response: CommittedEcdsaRegistrationResponse,
  walletKey: WalletRegistrationEcdsaWalletKey,
): void {
  const activation = response.ecdsa.activation;
  const receipt = activation.ecdsa_activation;
  const identity = receipt.public_identity;
  const client = pending.localMaterial.ecdsa.clientActivation;
  assertCanonical(
    {
      correlationId: activation.activation_correlation_id,
      requestDigest: base64UrlEncode(Uint8Array.from(activation.activation_request_digest.bytes)),
      transcriptDigest: base64UrlEncode(Uint8Array.from(activation.transcript_digest.bytes)),
      client: {
        contextBinding: identity.context_binding_b64u,
        derivationShare: identity.derivation_client_share_public_key33_b64u,
        retry: identity.client_share_retry_counter,
      },
      publicIdentity: response.ecdsa.bootstrap.publicIdentity,
      applicationBinding: receipt.context.application_binding_digest_b64u,
      activationIdentity: {
        relayer: identity.server_public_key33_b64u,
        group: identity.threshold_public_key33_b64u,
        address: ethereumAddressFromActivationIdentity(identity.ethereum_address20_b64u),
        retry: identity.server_share_retry_counter,
      },
    },
    {
      correlationId: pending.localMaterial.ecdsa.activationJournalId,
      requestDigest: pending.localMaterial.ecdsa.activationRequestDigestB64u,
      transcriptDigest: client.proofTranscriptDigestB64u,
      client: {
        contextBinding: client.contextBinding32B64u,
        derivationShare: client.derivationClientSharePublicKey33B64u,
        retry: client.clientShareRetryCounter,
      },
      publicIdentity: {
        derivationClientSharePublicKey33B64u: client.derivationClientSharePublicKey33B64u,
        relayerPublicKey33B64u: walletKey.relayerVerifyingShareB64u,
        groupPublicKey33B64u: walletKey.thresholdEcdsaPublicKeyB64u,
        ethereumAddress: walletKey.thresholdOwnerAddress.toLowerCase(),
      },
      applicationBinding: response.ecdsa.bootstrap.applicationBindingDigestB64u,
      activationIdentity: {
        relayer: walletKey.relayerVerifyingShareB64u,
        group: walletKey.thresholdEcdsaPublicKeyB64u,
        address: walletKey.thresholdOwnerAddress,
        retry: walletKey.relayerShareRetryCounter,
      },
    },
    'pending ECDSA activation facts mismatch',
  );
  assertCanonical(
    [
      response.ecdsa.bootstrap.walletId,
      response.ecdsa.bootstrap.keyHandle,
      response.ecdsa.bootstrap.ecdsaThresholdKeyId,
      response.ecdsa.bootstrap.evmFamilySigningKeySlotId,
      response.ecdsa.bootstrap.signingRootId,
      response.ecdsa.bootstrap.signingRootVersion,
      response.ecdsa.bootstrap.thresholdEcdsaPublicKeyB64u,
      response.ecdsa.bootstrap.ethereumAddress.toLowerCase(),
      response.ecdsa.bootstrap.relayerKeyId,
      response.ecdsa.bootstrap.relayerVerifyingShareB64u,
      response.ecdsa.bootstrap.clientShareRetryCounter,
      response.ecdsa.bootstrap.relayerShareRetryCounter,
    ],
    [
      walletKey.walletId,
      walletKey.keyHandle,
      walletKey.ecdsaThresholdKeyId,
      walletKey.evmFamilySigningKeySlotId,
      walletKey.signingRootId,
      walletKey.signingRootVersion,
      walletKey.thresholdEcdsaPublicKeyB64u,
      walletKey.thresholdOwnerAddress.toLowerCase(),
      walletKey.relayerKeyId,
      walletKey.relayerVerifyingShareB64u,
      walletKey.clientShareRetryCounter,
      walletKey.relayerShareRetryCounter,
    ],
    'pending ECDSA bootstrap changed committed key identity',
  );
}

function assertProjectionEcdsaFacts(response: CommittedEcdsaRegistrationResponse): void {
  const projection = requireEcdsaProjection(response).ecdsa;
  const receipt = response.ecdsa.activation.ecdsa_activation;
  if (
    !mpcMaterialActivationRefsEqual(
      projection.materialActivation,
      routerAbMpcMaterialActivationRefFromWire(receipt.material_activation),
    ) ||
    alphabetizeStringify(projection.routerAbEcdsaDerivationNormalSigning) !==
      alphabetizeStringify(response.ecdsa.bootstrap.routerAbEcdsaDerivationNormalSigning)
  ) {
    throw new Error('pending ECDSA activation facts do not match the committed projection');
  }
}

export async function requireCommittedEcdsaRegistrationResponse(args: {
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly response: WalletRegistrationActivateResponseV2;
}): Promise<CommittedEcdsaRegistrationResponse> {
  const response = args.response;
  if (!isCommittedEcdsaRegistrationResponse(response)) {
    throw new Error(
      response.ok
        ? 'pending ECDSA activation replay did not return a committed projection'
        : 'pending ECDSA activation replay failed',
    );
  }
  const walletKey = requireResponseWalletKeys(response)[0];
  assertProjectionMatchesPending(args.pending, response, walletKey);
  await assertAuthMatchesPending(args.pending, response);
  assertActivationFacts(args.pending, response, walletKey);
  assertProjectionEcdsaFacts(response);
  if (response.nearProvisioning !== undefined) {
    throw new Error('ECDSA-only registration unexpectedly has deferred NEAR provisioning');
  }
  return response;
}
