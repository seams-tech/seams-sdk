import {
  buildActiveSigningLaneLifecycle,
  buildActiveWalletKeyLifecycle,
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildOwnerEmailOtpSigningLaneRecord,
  buildOwnerPasskeySigningLaneRecord,
  parseWalletKeyVersion,
} from '@shared/signing-lanes/recordParsers';
import {
  deriveEvmFamilySigningKeySlotId,
  parseLaneShareEpoch,
  parseSigningLaneId,
  parseWalletKeyId,
  type SigningLaneRecord,
  type WalletKeyRecord,
} from '@shared/signing-lanes';
import {
  buildOwnerLaneParticipantContinuityV1,
  computeOwnerLaneParticipantBindingDigestV1,
  parseWalletSignerId,
} from '@shared/signing-lanes/ownerContinuity';
import {
  parseEd25519PublicKeyB64u,
  parseKeyCreationSignerSlot,
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  MpcMaterialActivationRef,
  ProviderSubject,
  WalletAuthMethodId,
  WalletId,
} from '@shared/utils/domainIds';
import {
  parseEmailOtpProviderUserId,
  parseMpcSigningWorkerRef,
  parseWebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseNearEd25519SigningKeyId,
  walletAuthMethodRecordId,
  type WalletAuthMethodRecord,
} from '@shared/utils/registrationIntent';
import {
  routerAbMpcMaterialActivationRefFromWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { base58Encode } from '@shared/utils/base58';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type {
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
  WalletSignerRecord,
} from '../WalletStore';

const SOURCE_IDENTITY_DOMAIN = 'seams/wallet-execution-lane/source-identity/v1';
const ED25519_RECEIPT_DOMAIN = 'seams/wallet-execution-lane/ed25519-receipt/v1';

export type ActiveOwnerWalletExecutionLaneProjection = {
  readonly kind: 'active_owner_wallet_execution_lane_projection_v1';
  readonly walletKey: WalletKeyRecord;
  readonly lane: Extract<
    SigningLaneRecord,
    { readonly laneKind: 'owner_passkey' | 'owner_email_otp' }
  >;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly verifiedActivationReceiptDigestB64u: DigestB64u;
};

export type WalletExecutionLaneProjectionRefusalReason =
  | 'auth_method_missing'
  | 'auth_method_ambiguous'
  | 'auth_method_inactive'
  | 'auth_method_mismatch'
  | 'signer_missing'
  | 'signer_ambiguous'
  | 'signer_conflict'
  | 'signer_invalid';

export type WalletExecutionLaneProjectionResult =
  | {
      readonly kind: 'projected';
      readonly projection: ActiveOwnerWalletExecutionLaneProjection;
    }
  | {
      readonly kind: 'refused';
      readonly reason: WalletExecutionLaneProjectionRefusalReason;
    };

export interface WalletExecutionLaneProjectionSource {
  listWalletAuthMethods(input: {
    readonly walletId: WalletId;
  }): Promise<readonly WalletAuthMethodRecord[]>;
  listWalletSigners(input: { readonly walletId: WalletId }): Promise<readonly WalletSignerRecord[]>;
}

export type WalletExecutionLaneAuthSource =
  | {
      readonly kind: 'passkey';
      readonly credentialIdB64u: string;
    }
  | {
      readonly kind: 'oidc_provider';
      readonly providerId: 'google_oidc' | 'oidc';
      readonly providerSubject: ProviderSubject;
    };

export async function resolveWalletAuthMethodIdForAuthority(input: {
  readonly walletId: WalletId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly authSource: WalletExecutionLaneAuthSource;
  readonly authMethods: readonly WalletAuthMethodRecord[];
}): Promise<WalletAuthMethodId | null> {
  const matches: WalletAuthMethodId[] = [];
  for (const authMethod of input.authMethods) {
    if (authMethod.walletId !== input.walletId || authMethod.status !== 'active') continue;
    const authority = walletAuthorityForAuthMethod(authMethod, input.authSource);
    if (!authority) continue;
    const candidateRef = await walletAuthAuthorityRef({ authority });
    if (
      candidateRef.walletId === input.authorityRef.walletId &&
      candidateRef.authorityDigest === input.authorityRef.authorityDigest
    ) {
      matches.push(walletAuthMethodRecordId(authMethod));
    }
  }
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

export async function resolveActiveOwnerWalletExecutionLane(input: {
  readonly source: WalletExecutionLaneProjectionSource;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
}): Promise<WalletExecutionLaneProjectionResult> {
  const [authMethods, signers] = await Promise.all([
    input.source.listWalletAuthMethods({ walletId: input.walletId }),
    input.source.listWalletSigners({ walletId: input.walletId }),
  ]);
  const matchingAuthMethods = authMethods.filter(
    (record) => String(walletAuthMethodRecordId(record)) === String(input.walletAuthMethodId),
  );
  if (matchingAuthMethods.length === 0) return refused('auth_method_missing');
  if (matchingAuthMethods.length !== 1) return refused('auth_method_ambiguous');
  const authMethod = matchingAuthMethods[0];
  if (!authMethod) return refused('auth_method_missing');
  if (authMethod.walletId !== input.walletId) return refused('auth_method_mismatch');
  if (authMethod.status !== 'active') return refused('auth_method_inactive');

  const matchingSigners = signers.filter((signer) =>
    signerMatchesMaterialActivation(signer, input.expectedMaterialActivation),
  );
  if (matchingSigners.length === 0) return refused('signer_missing');
  try {
    return {
      kind: 'projected',
      projection: await projectActiveOwnerWalletExecutionLane({
        walletId: input.walletId,
        walletAuthMethodId: input.walletAuthMethodId,
        authMethod,
        signers: matchingSigners,
        expectedMaterialActivation: input.expectedMaterialActivation,
      }),
    };
  } catch (error) {
    return refused(
      error instanceof SignerProjectionConflictError ? 'signer_conflict' : 'signer_invalid',
    );
  }
}

export async function projectActiveOwnerWalletExecutionLane(input: {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authMethod: WalletAuthMethodRecord;
  readonly signers: readonly WalletSignerRecord[];
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
}): Promise<ActiveOwnerWalletExecutionLaneProjection> {
  if (
    input.authMethod.walletId !== input.walletId ||
    String(walletAuthMethodRecordId(input.authMethod)) !== String(input.walletAuthMethodId) ||
    input.authMethod.status !== 'active'
  ) {
    throw new Error('wallet auth method does not authorize the requested owner lane');
  }
  if (input.signers.length === 0) throw new Error('wallet signer is required');
  const first = input.signers[0];
  if (!first) throw new Error('wallet signer is required');
  if (first.walletId !== input.walletId) throw new Error('wallet signer changed wallet');

  return first.version === 'wallet_signer_ed25519_v1'
    ? await projectEd25519OwnerLane({
        ...input,
        signers: requireOnlyEd25519Signer(input.signers),
      })
    : await projectEcdsaOwnerLane({
        ...input,
        signers: requireOnlyEcdsaSigners(input.signers),
      });
}

async function projectEd25519OwnerLane(input: {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authMethod: WalletAuthMethodRecord;
  readonly signers: readonly [WalletEd25519SignerRecord];
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
}): Promise<ActiveOwnerWalletExecutionLaneProjection> {
  const signer = input.signers[0];
  const capability = signer.activeYaoCapability;
  const receipt = capability.activationResult.public_receipt;
  const scope = capability.admissionRequest.scope;
  const application = capability.admissionRequest.application_binding;
  const receiptActivation = receipt.material_activation;
  if (
    application.wallet_id !== input.walletId ||
    scope.account_id !== input.walletId ||
    signer.signingWorkerId !== scope.signing_worker_id ||
    signer.publicKey !==
      `ed25519:${base58Encode(Uint8Array.from(receipt.registered_public_key))}` ||
    signer.participantIds[0] !== capability.admissionRequest.participant_ids[0] ||
    signer.participantIds[1] !== capability.admissionRequest.participant_ids[1] ||
    !sameRouterAbMpcMaterialActivationRef(
      receiptActivation,
      capability.admissionRequest.scope.material_activation,
    )
  ) {
    throw new Error('Ed25519 signer continuity is invalid');
  }
  assertExpectedActivation(receiptActivation, input.expectedMaterialActivation);
  const materialActivation = routerAbMpcMaterialActivationRefFromWire(receiptActivation);
  const sourceIdentityDigestB64u = await digestPublicIdentity({
    keyFamily: 'ed25519',
    walletId: input.walletId,
    signerId: signer.signerId,
    capability,
    receipt,
  });
  const activationReceiptDigestB64u = await digestValue(ED25519_RECEIPT_DOMAIN, receipt);
  const ownerParticipantContinuity = await ownerContinuity({
    signerId: signer.signerId,
    participantIds: signer.participantIds,
    signingWorkerId: signer.signingWorkerId,
    custodyKeyManifestDigestB64u: signer.custodyKeyManifestDigestB64u,
    sourceIdentityDigestB64u,
  });
  const walletKeyId = requireParsed(
    parseWalletKeyId(`wallet-key:ed25519:${input.walletId}:${signer.nearEd25519SigningKeyId}`),
  );
  const walletKey = buildEd25519WalletKeyRecord({
    walletId: input.walletId,
    walletKeyId,
    walletKeyVersion: parseWalletKeyVersion(`wallet-key-version:${signer.keyVersion}`),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(signer.nearEd25519SigningKeyId),
    keyCreationSignerSlot: parseKeyCreationSignerSlot(signer.signerSlot),
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
      base64UrlEncode(Uint8Array.from(receipt.registered_public_key)),
    ),
    lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: signer.updatedAtMs }),
  });
  const lane = await buildOwnerLane({
    walletId: input.walletId,
    walletKeyId,
    walletAuthMethodId: input.walletAuthMethodId,
    authMethod: input.authMethod,
    laneShareEpoch: scope.root_share_epoch,
    activatedAtMs: signer.updatedAtMs,
    activationReceiptDigestB64u,
    ownerParticipantContinuity,
  });
  return {
    kind: 'active_owner_wallet_execution_lane_projection_v1',
    walletKey,
    lane,
    materialActivation,
    verifiedActivationReceiptDigestB64u: activationReceiptDigestB64u,
  };
}

async function projectEcdsaOwnerLane(input: {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authMethod: WalletAuthMethodRecord;
  readonly signers: readonly WalletEcdsaSignerRecord[];
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
}): Promise<ActiveOwnerWalletExecutionLaneProjection> {
  const signer = input.signers[0];
  if (!signer) throw new Error('ECDSA signer is required');
  assertEcdsaReceiptContinuity(signer);
  assertExpectedActivation(
    signer.walletKey.publicCapability.material_activation,
    input.expectedMaterialActivation,
  );
  for (const candidate of input.signers.slice(1)) assertSameEcdsaWalletKey(signer, candidate);
  const materialActivation = routerAbMpcMaterialActivationRefFromWire(
    signer.walletKey.publicCapability.material_activation,
  );
  const sourceIdentityDigestB64u = await digestPublicIdentity({
    keyFamily: 'ecdsa_secp256k1',
    walletId: input.walletId,
    keyHandle: signer.walletKey.keyHandle,
    publicCapability: signer.walletKey.publicCapability,
    activationReceipt: signer.activationReceipt,
  });
  const activationReceiptDigestB64u = parseDigestB64u(
    signer.activationReceipt.ecdsa_activation.activation_digest_b64u,
  );
  const ownerParticipantContinuity = await ownerContinuity({
    signerId: `ecdsa-key:${signer.walletKey.keyHandle}`,
    participantIds: signer.walletKey.participantIds,
    signingWorkerId: signer.activationReceipt.ecdsa_activation.signing_worker.server_id,
    custodyKeyManifestDigestB64u: signer.custodyKeyManifestDigestB64u,
    sourceIdentityDigestB64u,
  });
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: input.walletId,
    signingRootId: signer.walletKey.signingRootId,
    signingRootVersion: signer.walletKey.signingRootVersion,
  });
  const walletKeyId = requireParsed(
    parseWalletKeyId(`wallet-key:ecdsa:${input.walletId}:${evmFamilySigningKeySlotId}`),
  );
  const walletKey = buildEvmFamilyWalletKeyRecord({
    walletId: input.walletId,
    walletKeyId,
    walletKeyVersion: parseWalletKeyVersion(
      `wallet-key-version:${signer.walletKey.signingRootVersion}`,
    ),
    evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      signer.walletKey.thresholdEcdsaPublicKeyB64u,
    ),
    evmAddress: signer.walletKey.thresholdOwnerAddress,
    lifecycle: buildActiveWalletKeyLifecycle({
      activatedAtMs: signer.activationReceipt.ecdsa_activation.activated_at_ms,
    }),
  });
  const lane = await buildOwnerLane({
    walletId: input.walletId,
    walletKeyId,
    walletAuthMethodId: input.walletAuthMethodId,
    authMethod: input.authMethod,
    laneShareEpoch: signer.walletKey.publicCapability.activation_epoch,
    activatedAtMs: signer.activationReceipt.ecdsa_activation.activated_at_ms,
    activationReceiptDigestB64u,
    ownerParticipantContinuity,
  });
  return {
    kind: 'active_owner_wallet_execution_lane_projection_v1',
    walletKey,
    lane,
    materialActivation,
    verifiedActivationReceiptDigestB64u: activationReceiptDigestB64u,
  };
}

async function buildOwnerLane(input: {
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyRecord['walletKeyId'];
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authMethod: WalletAuthMethodRecord;
  readonly laneShareEpoch: string;
  readonly activatedAtMs: number;
  readonly activationReceiptDigestB64u: DigestB64u;
  readonly ownerParticipantContinuity: Awaited<ReturnType<typeof ownerContinuity>>;
}): Promise<ActiveOwnerWalletExecutionLaneProjection['lane']> {
  const participantBindingDigestB64u = await computeOwnerLaneParticipantBindingDigestV1(
    input.ownerParticipantContinuity,
  );
  const laneId = requireParsed(
    parseSigningLaneId(
      `signing-lane:${input.authMethod.kind}:${input.walletKeyId}:${input.walletAuthMethodId}`,
    ),
  );
  const base = {
    walletId: input.walletId,
    walletKeyId: input.walletKeyId,
    laneId,
    laneShareEpoch: requireParsed(parseLaneShareEpoch(input.laneShareEpoch)),
    participantBindingDigestB64u,
    walletAuthMethodId: input.walletAuthMethodId,
    ownerParticipantContinuity: input.ownerParticipantContinuity,
    lifecycle: buildActiveSigningLaneLifecycle({
      revocationEpoch: 0,
      activatedAtMs: input.activatedAtMs,
      activationReceiptDigestB64u: input.activationReceiptDigestB64u,
    }),
  };
  switch (input.authMethod.kind) {
    case 'passkey':
      return buildOwnerPasskeySigningLaneRecord(base);
    case 'email_otp':
      return buildOwnerEmailOtpSigningLaneRecord(base);
  }
}

async function ownerContinuity(input: {
  readonly signerId: string;
  readonly participantIds: readonly [number, number];
  readonly signingWorkerId: string;
  readonly custodyKeyManifestDigestB64u: string;
  readonly sourceIdentityDigestB64u: DigestB64u;
}) {
  const signingWorkerId = requireParsed(parseMpcSigningWorkerRef(input.signingWorkerId));
  return buildOwnerLaneParticipantContinuityV1({
    signerId: parseWalletSignerId(input.signerId),
    participantIds: input.participantIds,
    signingWorkerId,
    custodyKeyManifestDigestB64u: parseDigestB64u(input.custodyKeyManifestDigestB64u),
    sourceIdentityDigestB64u: input.sourceIdentityDigestB64u,
  });
}

function requireOnlyEd25519Signer(
  signers: readonly WalletSignerRecord[],
): readonly [WalletEd25519SignerRecord] {
  if (signers.length !== 1 || signers[0]?.version !== 'wallet_signer_ed25519_v1') {
    throw new SignerProjectionConflictError();
  }
  return [signers[0]];
}

function requireOnlyEcdsaSigners(
  signers: readonly WalletSignerRecord[],
): readonly WalletEcdsaSignerRecord[] {
  const ecdsaSigners: WalletEcdsaSignerRecord[] = [];
  for (const signer of signers) {
    if (signer.version !== 'wallet_signer_ecdsa_v1') {
      throw new SignerProjectionConflictError();
    }
    ecdsaSigners.push(signer);
  }
  return ecdsaSigners;
}

function signerMatchesMaterialActivation(
  signer: WalletSignerRecord,
  expected: MpcMaterialActivationRef,
): boolean {
  const wire =
    signer.version === 'wallet_signer_ed25519_v1'
      ? signer.activeYaoCapability.activationResult.public_receipt.material_activation
      : signer.walletKey.publicCapability.material_activation;
  try {
    return sameMaterialActivation(routerAbMpcMaterialActivationRefFromWire(wire), expected);
  } catch {
    return false;
  }
}

function assertExpectedActivation(
  wire: WalletEcdsaSignerRecord['walletKey']['publicCapability']['material_activation'],
  expected: MpcMaterialActivationRef,
): void {
  const actual = routerAbMpcMaterialActivationRefFromWire(wire);
  if (!sameMaterialActivation(actual, expected)) {
    throw new Error('wallet signer material activation changed');
  }
}

function assertEcdsaReceiptContinuity(signer: WalletEcdsaSignerRecord): void {
  const capability = signer.walletKey.publicCapability;
  const activation = signer.activationReceipt.ecdsa_activation;
  if (
    capability.client_id !== String(signer.walletId) ||
    capability.material_activation.material_owner !== String(signer.walletId) ||
    activation.activation_epoch !== capability.activation_epoch ||
    alphabetizeStringify(activation.context) !== alphabetizeStringify(capability.context) ||
    alphabetizeStringify(activation.public_identity) !==
      alphabetizeStringify(capability.public_identity) ||
    alphabetizeStringify(activation.signing_worker) !==
      alphabetizeStringify(capability.signer_set.selected_server) ||
    !sameRouterAbMpcMaterialActivationRef(
      activation.material_activation,
      capability.material_activation,
    )
  ) {
    throw new Error('ECDSA activation receipt does not match the public capability');
  }
}

function assertSameEcdsaWalletKey(
  expected: WalletEcdsaSignerRecord,
  candidate: WalletEcdsaSignerRecord,
): void {
  assertEcdsaReceiptContinuity(candidate);
  if (
    expected.walletId !== candidate.walletId ||
    expected.walletKey.keyHandle !== candidate.walletKey.keyHandle ||
    expected.walletKey.signingRootId !== candidate.walletKey.signingRootId ||
    expected.walletKey.signingRootVersion !== candidate.walletKey.signingRootVersion ||
    expected.custodyKeyManifestDigestB64u !== candidate.custodyKeyManifestDigestB64u ||
    alphabetizeStringify(expected.walletKey.publicCapability) !==
      alphabetizeStringify(candidate.walletKey.publicCapability) ||
    alphabetizeStringify(expected.activationReceipt) !==
      alphabetizeStringify(candidate.activationReceipt) ||
    expected.walletKey.participantIds[0] !== candidate.walletKey.participantIds[0] ||
    expected.walletKey.participantIds[1] !== candidate.walletKey.participantIds[1]
  ) {
    throw new SignerProjectionConflictError();
  }
}

async function digestPublicIdentity(value: unknown): Promise<DigestB64u> {
  return await digestValue(SOURCE_IDENTITY_DOMAIN, value);
}

async function digestValue(domain: string, value: unknown): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(`${domain}\u0000${alphabetizeStringify(value)}`)),
  );
}

function sameMaterialActivation(
  left: MpcMaterialActivationRef,
  right: MpcMaterialActivationRef,
): boolean {
  return (
    left.activationId === right.activationId &&
    left.capability === right.capability &&
    left.materialOwner === right.materialOwner &&
    left.keyBinding === right.keyBinding &&
    left.lifecycleBinding === right.lifecycleBinding &&
    left.signingWorker === right.signingWorker
  );
}

function requireParsed<T>(
  result: { readonly ok: true; readonly value: T } | { readonly ok: false },
): T {
  if (result.ok) return result.value;
  throw new Error('wallet execution lane identity is invalid');
}

function refused(
  reason: WalletExecutionLaneProjectionRefusalReason,
): Extract<WalletExecutionLaneProjectionResult, { readonly kind: 'refused' }> {
  return { kind: 'refused', reason };
}

class SignerProjectionConflictError extends Error {}

function walletAuthorityForAuthMethod(
  authMethod: WalletAuthMethodRecord,
  authSource: WalletExecutionLaneAuthSource,
): WalletAuthAuthority | null {
  const bindingId = walletAuthMethodRecordId(authMethod);
  if (authMethod.kind === 'passkey') {
    if (
      authSource.kind !== 'passkey' ||
      authSource.credentialIdB64u !== authMethod.credentialIdB64u
    ) {
      return null;
    }
    const credentialId = parseWebAuthnCredentialIdB64u(authMethod.credentialIdB64u);
    if (!credentialId.ok) return null;
    return {
      walletId: authMethod.walletId,
      factor: { kind: 'passkey', credentialIdB64u: credentialId.value },
      verifier: { kind: 'webauthn', rpId: authMethod.rpId },
      bindingId,
    };
  }
  if (authSource.kind !== 'oidc_provider') return null;
  const providerUserId = parseEmailOtpProviderUserId(authSource.providerSubject);
  if (!providerUserId.ok) return null;
  return {
    walletId: authMethod.walletId,
    factor: {
      kind: 'email_otp',
      provider: authSource.providerId === 'google_oidc' ? 'google' : 'email',
      providerUserId: providerUserId.value,
    },
    verifier: {
      kind: 'email_otp_wallet_auth_method',
      emailHashHex: authMethod.emailHashHex,
    },
    bindingId,
  };
}
