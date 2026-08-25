import type {
  LinkedDeviceOwnerAuthorizationSourceV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';
import {
  buildWalletSessionLinkedDeviceOwnerAuthorizationV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  hasDelegatedWalletPermissionV1,
  validateDelegatedWalletAuthorityAttenuationV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import {
  mpcMaterialActivationRefsEqual,
  parseProviderSubject,
  parseEcdsaRelayerKeyId,
  type WalletAuthMethodId,
} from '@shared/utils/domainIds';
import { parseSecp256k1CompressedPublicKeyB64u } from '@shared/passkey-custody/primitives';
import { deriveRouterAbEd25519YaoApplicationBindingDigestV1 } from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type { ActiveLaneProtocolSourceV1 } from '@shared/signing-lanes/rotation';
import type {
  ActiveOwnerWalletExecutionLaneProjection,
  WalletExecutionLaneProjectionSource,
  WalletExecutionLaneProjectionResult,
} from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import {
  resolveActiveOwnerWalletExecutionLane,
  resolveWalletAuthMethodIdForAuthority,
} from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import type { WalletExecutionLaneAuthSource } from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { walletAuthorityDigestsMatchV1 } from '@shared/authorization/walletAuthority';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../../../core/ThresholdService/validation';
import type {
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
} from '../../../../core/WalletStore';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import type {
  LinkedDeviceOwnerAuthorizationContextV1,
  LinkedDeviceOwnerAuthorizationPortV1,
  LinkedDeviceSourceKeyManifestDigestsV1,
  LinkedDeviceSessionRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import { sourceKeyManifestDigestForFamilyV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  DeviceLinkingOwnerAuthorizationResponseV1,
  DeviceLinkingOwnerAuthorizationRouteServiceV1,
  DeviceLinkingOwnerWalletSessionContextV1,
} from '../../../../router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type {
  LinkedDeviceOwnerSourceChildResolutionRequestV1,
  LinkedDeviceOwnerSourceChildResolutionV1,
  LinkedDeviceOwnerSourceChildResolverV1,
  D1LinkedDeviceTargetPlannerOptionsV1,
  D1LinkedDeviceTargetPlannerV1,
} from './d1LinkedDeviceTargetPlanner';
import type { VerifiedLinkSourceReadV1 } from './d1LinkedDeviceVerifiedLinkBuilder';
import type { D1LinkedDeviceSessionStoreV1 } from './d1LinkedDeviceSessionStore';
import { D1LinkedDeviceTargetPlannerV1 as TargetPlanner } from './d1LinkedDeviceTargetPlanner';
import { computeLinkedDevicePublicKeyDigestV1 } from '../../../../core/deviceLinking/requestProof';
import type {
  ExactAdministeredSignerManifestV1,
  ExactAdministeredSignerV1,
} from '@shared/device-linking/delegatedActivationPlan';

const ENROLLMENT_ID_DOMAIN_V1 = 'seams/linked-device/enrollment-identity/v1';

export type D1LinkedDeviceOwnerAuthorizationMetadataV1 = {
  readonly walletId: WalletId;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly expiresAtMs: number;
};

export type D1LinkedDeviceVerifiedOwnerSourceFactsV1 = {
  readonly signerManifest: ExactAdministeredSignerManifestV1;
  readonly keyManifestDigestsB64u: LinkedDeviceSourceKeyManifestDigestsV1;
};

/**
 * D1 supplies the authenticated session and exact source-lane projection. The
 * provider validates those facts against the active V2 authority and signers;
 * no link-specific planning record is created.
 */
export type D1LinkedDeviceOwnerAuthorizationMetadataSourceV1 = {
  readVerifiedOwnerSourceFactsV1(input: {
    readonly walletId: WalletId;
    readonly walletSessionId: string;
    readonly authorizationId: string;
    readonly requestedAtMs: number;
  }): Promise<D1LinkedDeviceVerifiedOwnerSourceFactsV1>;
  readApprovedOwnerContextV1(input: {
    readonly walletId: WalletId;
    readonly linkSessionId: string;
    readonly keyFamily: ExactAdministeredSignerV1['keyFamily'];
  }): Promise<DeviceLinkingOwnerWalletSessionContextV1 | null>;
  readOwnerSourceChildV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly request: LinkedDeviceOwnerSourceChildResolutionRequestV1;
  }): Promise<LinkedDeviceOwnerSourceChildResolutionV1 | null>;
};

export type D1LinkedDeviceOwnerSourceChildReaderV1 = Pick<
  D1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
  'readOwnerSourceChildV1'
>;

export type D1LinkedDeviceOwnerSourceChildReaderOptionsV1 = {
  readonly walletAuthMethodStore: Pick<D1WalletAuthMethodStore, 'listForWalletV2'>;
  readonly walletStore: Pick<
    D1WalletStore,
    'listEd25519SignersForWallet' | 'listEcdsaSignersForWallet'
  >;
};

/** Builds authoritative source-child facts directly from the wallet stores. */
export function createD1LinkedDeviceOwnerSourceChildReaderV1(
  options: D1LinkedDeviceOwnerSourceChildReaderOptionsV1,
): D1LinkedDeviceOwnerSourceChildReaderV1 {
  const projectionSource = new D1LinkedDeviceOwnerSourceProjectionSourceV1(options);
  return {
    readOwnerSourceChildV1: readD1LinkedDeviceOwnerSourceChildV1.bind(undefined, projectionSource),
  };
}

class D1LinkedDeviceOwnerSourceProjectionSourceV1 implements WalletExecutionLaneProjectionSource {
  constructor(private readonly options: D1LinkedDeviceOwnerSourceChildReaderOptionsV1) {}

  async listWalletAuthMethods(input: {
    readonly walletId: WalletId;
  }): Promise<readonly WalletAuthMethodRecordV2[]> {
    return await this.options.walletAuthMethodStore.listForWalletV2({
      walletId: input.walletId,
    });
  }

  async listWalletSigners(input: {
    readonly walletId: WalletId;
  }): Promise<readonly (WalletEd25519SignerRecord | WalletEcdsaSignerRecord)[]> {
    const [ed25519, ecdsa] = await Promise.all([
      this.options.walletStore.listEd25519SignersForWallet({ walletId: input.walletId }),
      this.options.walletStore.listEcdsaSignersForWallet({ walletId: input.walletId }),
    ]);
    return [...ed25519, ...ecdsa];
  }
}

class WalletExecutionLaneProjectionSnapshotV1 implements WalletExecutionLaneProjectionSource {
  constructor(
    private readonly authMethods: readonly WalletAuthMethodRecordV2[],
    private readonly signers: readonly (WalletEd25519SignerRecord | WalletEcdsaSignerRecord)[],
  ) {}

  async listWalletAuthMethods(): Promise<readonly WalletAuthMethodRecordV2[]> {
    return this.authMethods;
  }

  async listWalletSigners(): Promise<
    readonly (WalletEd25519SignerRecord | WalletEcdsaSignerRecord)[]
  > {
    return this.signers;
  }
}

async function readD1LinkedDeviceOwnerSourceChildV1(
  projectionSource: WalletExecutionLaneProjectionSource,
  input: Parameters<D1LinkedDeviceOwnerAuthorizationMetadataSourceV1['readOwnerSourceChildV1']>[0],
): Promise<LinkedDeviceOwnerSourceChildResolutionV1 | null> {
  if (input.owner.walletId !== input.request.approval.walletId) return null;
  if (input.request.sourceSigner.walletId !== input.owner.walletId) return null;

  const [authMethods, signers] = await Promise.all([
    projectionSource.listWalletAuthMethods({ walletId: input.owner.walletId }),
    projectionSource.listWalletSigners({ walletId: input.owner.walletId }),
  ]);
  const walletAuthMethodId = await ownerWalletAuthMethodIdV1({
    owner: input.owner,
    authMethods,
  });
  if (!walletAuthMethodId) return null;

  const resolved = await resolveExactSourceSignerProjectionV1({
    authMethods,
    signers,
    walletId: input.owner.walletId,
    walletAuthMethodId,
    sourceSigner: input.request.sourceSigner,
  });
  if (
    !resolved ||
    resolved.signer.custodyKeyManifestDigestB64u !== input.owner.keyManifestDigestB64u
  ) {
    return null;
  }

  return await sourceChildResolutionFromSignerV1({
    signer: resolved.signer,
    projection: resolved.projection,
  });
}

async function resolveExactSourceSignerProjectionV1(input: {
  readonly authMethods: readonly WalletAuthMethodRecordV2[];
  readonly signers: readonly (WalletEd25519SignerRecord | WalletEcdsaSignerRecord)[];
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly sourceSigner: ExactAdministeredSignerV1;
}): Promise<{
  readonly signer: WalletEd25519SignerRecord | WalletEcdsaSignerRecord;
  readonly projection: ActiveOwnerWalletExecutionLaneProjection;
} | null> {
  for (const signer of input.signers) {
    if (signer.walletId !== input.walletId) continue;
    if (
      (input.sourceSigner.keyFamily === 'ed25519' &&
        signer.version !== 'wallet_signer_ed25519_v1') ||
      (input.sourceSigner.keyFamily === 'ecdsa_secp256k1' &&
        signer.version !== 'wallet_signer_ecdsa_v1')
    ) {
      continue;
    }
    const wire =
      signer.version === 'wallet_signer_ed25519_v1'
        ? signer.activeYaoCapability.activationResult.public_receipt.material_activation
        : signer.walletKey.publicCapability.material_activation;
    let materialActivation;
    try {
      materialActivation = routerAbMpcMaterialActivationRefFromWire(wire);
    } catch {
      continue;
    }
    const projected = await resolveActiveOwnerWalletExecutionLane({
      source: new WalletExecutionLaneProjectionSnapshotV1(input.authMethods, input.signers),
      walletId: input.walletId,
      walletAuthMethodId: input.walletAuthMethodId,
      expectedMaterialActivation: materialActivation,
    });
    if (
      projected.kind === 'projected' &&
      projectionMatchesExactSignerV1(projected.projection, input.sourceSigner)
    ) {
      return { signer, projection: projected.projection };
    }
  }
  return null;
}

function projectionMatchesExactSignerV1(
  projection: ActiveOwnerWalletExecutionLaneProjection,
  signer: ExactAdministeredSignerV1,
): boolean {
  if (
    projection.walletKey.walletId !== signer.walletId ||
    projection.walletKey.walletKeyId !== signer.walletKeyId ||
    projection.walletKey.keyFamily !== signer.keyFamily
  ) {
    return false;
  }
  if (signer.keyFamily === 'ed25519') {
    return (
      projection.walletKey.keyFamily === 'ed25519' &&
      projection.walletKey.registeredPublicKeyB64u === signer.registeredPublicKeyB64u
    );
  }
  return (
    projection.walletKey.keyFamily === 'ecdsa_secp256k1' &&
    projection.walletKey.thresholdPublicKey33B64u === signer.thresholdPublicKey33B64u &&
    projection.walletKey.evmAddress === signer.evmAddress
  );
}

async function ownerWalletAuthMethodIdV1(input: {
  readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
  readonly authMethods: readonly WalletAuthMethodRecordV2[];
}): Promise<WalletAuthMethodId | null> {
  switch (input.owner.curve) {
    case 'ed25519':
      return input.owner.authority.bindingId;
    case 'ecdsa':
      return await resolveWalletAuthMethodIdForAuthority({
        walletId: input.owner.walletId,
        authorityRef: input.owner.walletAuthAuthorityRef,
        authSource: input.owner.authSource,
        authMethods: input.authMethods,
      });
    default:
      return assertNeverOwnerCurveV1(input.owner);
  }
}

async function sourceChildResolutionFromSignerV1(input: {
  readonly signer: WalletEd25519SignerRecord | WalletEcdsaSignerRecord;
  readonly projection: ActiveOwnerWalletExecutionLaneProjection;
}): Promise<LinkedDeviceOwnerSourceChildResolutionV1 | null> {
  const source = ownerLaneProtocolSourceV1(input.projection);
  if (input.signer.version === 'wallet_signer_ed25519_v1') {
    if (input.projection.walletKey.keyFamily !== 'ed25519') return null;
    if (input.signer.activeYaoCapability.activationResult.binding.operation !== 'registration') {
      return null;
    }
    const capability = input.signer.activeYaoCapability;
    if (capability.version !== 'wallet_ed25519_yao_registration_capability_v1') return null;
    const application = capability.admissionRequest.application_binding;
    const applicationBindingDigestB64u = parseDigestB64u(
      base64UrlEncode(
        Uint8Array.from(await deriveRouterAbEd25519YaoApplicationBindingDigestV1(application)),
      ),
    );
    const stableContextBindingB64u = parseDigestB64u(
      base64UrlEncode(
        Uint8Array.from(capability.activationResult.binding.stable_key_context_binding),
      ),
    );
    return {
      walletKeyId: input.projection.walletKey.walletKeyId,
      source,
      keyFamily: 'ed25519',
      applicationBindingDigestB64u,
      registeredPublicKeyB64u: input.projection.walletKey.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: input.projection.walletKey.nearEd25519SigningKeyId,
      keyCreationSignerSlot: input.projection.walletKey.keyCreationSignerSlot,
      stableContextBindingB64u,
      sourceBinding: capability.activationResult.binding,
      applicationBinding: application,
    };
  }

  if (input.projection.walletKey.keyFamily !== 'ecdsa_secp256k1') {
    return null;
  }
  try {
    const relayerKeyId = parseEcdsaRelayerKeyId(input.signer.walletKey.relayerKeyId);
    if (!relayerKeyId.ok) return null;
    return {
      walletKeyId: input.projection.walletKey.walletKeyId,
      source,
      keyFamily: 'ecdsa_secp256k1',
      evmFamilySigningKeySlotId: input.projection.walletKey.evmFamilySigningKeySlotId,
      thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
        input.signer.walletKey.thresholdEcdsaPublicKeyB64u,
      ),
      evmAddress: input.signer.walletKey.thresholdOwnerAddress,
      sourceHolderVerifyingShare33B64u: parseSecp256k1CompressedPublicKeyB64u(
        input.signer.walletKey.derivationClientSharePublicKey33B64u,
      ),
      sourceServerVerifyingShare33B64u: parseSecp256k1CompressedPublicKeyB64u(
        input.signer.walletKey.relayerVerifyingShareB64u,
      ),
      applicationBindingDigestB64u: parseDigestB64u(
        input.signer.activationReceipt.ecdsa_activation.context.application_binding_digest_b64u,
      ),
      clientShareRetryCounter:
        input.signer.activationReceipt.ecdsa_activation.public_identity.client_share_retry_counter,
    };
  } catch {
    return null;
  }
}

function ownerLaneProtocolSourceV1(
  projection: ActiveOwnerWalletExecutionLaneProjection,
): ActiveLaneProtocolSourceV1 {
  return {
    sourceKind: 'owner_registration',
    laneKind: projection.lane.laneKind,
    laneId: projection.lane.laneId,
    laneShareEpoch: projection.lane.laneShareEpoch,
    revocationEpoch: projection.lane.lifecycle.revocationEpoch,
    participantBindingDigestB64u: projection.lane.participantBindingDigestB64u,
    materialActivation: projection.materialActivation,
    ownerParticipantContinuity: projection.lane.ownerParticipantContinuity,
  };
}

function assertNeverOwnerCurveV1(value: never): never {
  throw new Error(`unsupported owner curve: ${String(value)}`);
}

export type D1LinkedDeviceOwnerAuthorizationMetadataSourceOptionsV1 = {
  readonly sessionStore: Pick<D1LinkedDeviceSessionStoreV1, 'getSessionV1'>;
  readonly readVerifiedSourceV1: (input: {
    readonly walletId: WalletId;
    readonly walletSessionId: string;
    readonly authorizationId: string;
    readonly keyFamily: ExactAdministeredSignerV1['keyFamily'];
    readonly requestedAtMs: number;
  }) => Promise<VerifiedLinkSourceReadV1>;
  readonly readOwnerSourceChildV1: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1['readOwnerSourceChildV1'];
  readonly nowV1?: () => number;
};

async function readVerifiedOwnerSourceFactsV1(
  readVerifiedSourceV1: D1LinkedDeviceOwnerAuthorizationMetadataSourceOptionsV1['readVerifiedSourceV1'],
  input: {
    readonly walletId: WalletId;
    readonly walletSessionId: string;
    readonly authorizationId: string;
    readonly requestedAtMs: number;
  },
): Promise<D1LinkedDeviceVerifiedOwnerSourceFactsV1> {
  const readFamily = async (
    keyFamily: ExactAdministeredSignerV1['keyFamily'],
  ): Promise<VerifiedLinkSourceReadV1> =>
    await readVerifiedSourceV1({
      ...input,
      keyFamily,
    });
  let first: VerifiedLinkSourceReadV1;
  let firstFamily: ExactAdministeredSignerV1['keyFamily'];
  try {
    first = await readFamily('ed25519');
    firstFamily = 'ed25519';
  } catch {
    first = await readFamily('ecdsa_secp256k1');
    firstFamily = 'ecdsa_secp256k1';
  }
  const manifest = first.signerManifest;
  const digests: Partial<Record<ExactAdministeredSignerV1['keyFamily'], DigestB64u>> = {
    [firstFamily]: first.keyManifestDigestB64u,
  };
  for (const keyFamily of manifest.keyFamilies) {
    if (keyFamily === firstFamily) continue;
    const source = await readFamily(keyFamily);
    if (
      source.authority.authorityId !== first.authority.authorityId ||
      source.authMethod.walletAuthMethodId !== first.authMethod.walletAuthMethodId ||
      alphabetizeStringify(source.signerManifest) !== alphabetizeStringify(manifest)
    ) {
      throw new Error('verified owner source facts changed between signer families');
    }
    digests[keyFamily] = source.keyManifestDigestB64u;
  }
  if (manifest.keyFamilies.length === 1 && manifest.keyFamilies[0] === 'ed25519') {
    if (!digests.ed25519) throw new Error('verified Ed25519 source digest is missing');
    return { signerManifest: manifest, keyManifestDigestsB64u: { ed25519: digests.ed25519 } };
  }
  if (manifest.keyFamilies.length === 1 && manifest.keyFamilies[0] === 'ecdsa_secp256k1') {
    if (!digests.ecdsa_secp256k1) throw new Error('verified ECDSA source digest is missing');
    return {
      signerManifest: manifest,
      keyManifestDigestsB64u: { ecdsa_secp256k1: digests.ecdsa_secp256k1 },
    };
  }
  if (!digests.ed25519 || !digests.ecdsa_secp256k1) {
    throw new Error('verified combined source digests are incomplete');
  }
  return {
    signerManifest: manifest,
    keyManifestDigestsB64u: {
      ed25519: digests.ed25519,
      ecdsa_secp256k1: digests.ecdsa_secp256k1,
    },
  };
}

/** Rehydrates the request-scoped owner context from link approval and D1. */
export function createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1(
  options: D1LinkedDeviceOwnerAuthorizationMetadataSourceOptionsV1,
): D1LinkedDeviceOwnerAuthorizationMetadataSourceV1 {
  const nowV1 = options.nowV1 ?? Date.now;
  return {
    readVerifiedOwnerSourceFactsV1: async (input) =>
      await readVerifiedOwnerSourceFactsV1(options.readVerifiedSourceV1, input),
    readApprovedOwnerContextV1: async (input) => {
      const linkSessionId = parseLinkDeviceSessionId(input.linkSessionId);
      if (!linkSessionId.ok) return null;
      const session = await options.sessionStore.getSessionV1(linkSessionId.value);
      if (!session?.approvalTranscript || !session.claimTranscript) return null;
      const approval = session.approvalTranscript.value;
      if (
        session.linkSessionId !== linkSessionId.value ||
        approval.linkSessionId !== linkSessionId.value ||
        session.claimTranscript.value.walletId !== input.walletId ||
        approval.walletId !== input.walletId ||
        approval.ownerAuthorization.kind !== 'wallet_session'
      ) {
        return null;
      }
      if (
        !session.approvalTranscript.sourceSignerManifest.keyFamilies.some(
          (family) => family === input.keyFamily,
        )
      ) {
        return null;
      }
      const nowMs = nowV1();
      let source: VerifiedLinkSourceReadV1;
      try {
        source = await options.readVerifiedSourceV1({
          walletId: input.walletId,
          walletSessionId: String(approval.ownerAuthorization.walletSessionId),
          authorizationId: String(approval.ownerAuthorization.authorizationId),
          keyFamily: input.keyFamily,
          requestedAtMs: nowMs,
        });
      } catch {
        return null;
      }
      const approvedSourceDigest = sourceKeyManifestDigestForFamilyV1(
        session.approvalTranscript.sourceKeyManifestDigestsB64u,
        input.keyFamily,
      );
      if (!approvedSourceDigest || approvedSourceDigest !== source.keyManifestDigestB64u) {
        return null;
      }
      return await ownerContextFromVerifiedSourceV1({
        source,
        walletId: input.walletId,
        ownerAuthorization: approval.ownerAuthorization,
        keyManifestDigestB64u: source.keyManifestDigestB64u,
        curve: input.keyFamily === 'ecdsa_secp256k1' ? 'ecdsa' : 'ed25519',
        expiresAtMs: Math.min(approval.expiresAtMs, source.expiresAtMs),
        nowMs,
      });
    },
    readOwnerSourceChildV1: options.readOwnerSourceChildV1,
  };
}

async function ownerContextFromVerifiedSourceV1(input: {
  readonly source: VerifiedLinkSourceReadV1;
  readonly walletId: WalletId;
  readonly ownerAuthorization: Extract<
    LinkedDeviceOwnerAuthorizationSourceV1,
    { readonly kind: 'wallet_session' }
  >;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly curve: 'ed25519' | 'ecdsa';
  readonly expiresAtMs: number;
  readonly nowMs: number;
}): Promise<DeviceLinkingOwnerWalletSessionContextV1 | null> {
  if (
    !Number.isSafeInteger(input.nowMs) ||
    input.nowMs < 0 ||
    input.expiresAtMs <= input.nowMs ||
    input.source.expiresAtMs <= input.nowMs ||
    input.source.authority.walletId !== input.walletId ||
    input.source.authMethod.walletId !== input.walletId ||
    input.source.authMethod.walletAuthorityId !== input.source.authority.authorityId ||
    !(await walletAuthorityDigestsMatchV1(input.source.authority))
  ) {
    return null;
  }
  const authorityData = walletAuthAuthorityFromVerifiedSourceV1(input.source);
  if (!authorityData) return null;
  const base = {
    walletId: input.walletId,
    walletSessionId: input.ownerAuthorization.walletSessionId,
    authorizationId: input.ownerAuthorization.authorizationId,
    expiresAtMs: input.expiresAtMs,
    permission: buildFullOwnerDelegatedWalletAuthorityV1(),
    keyManifestDigestB64u: input.keyManifestDigestB64u,
  } as const;
  switch (input.curve) {
    case 'ed25519':
      return {
        ...base,
        curve: 'ed25519',
        authority: authorityData.authority,
        authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(
          authorityData.authority,
        ),
      };
    case 'ecdsa':
      return {
        ...base,
        curve: 'ecdsa',
        walletAuthAuthorityRef: await walletAuthAuthorityRef({
          authority: authorityData.authority,
        }),
        authSource: authorityData.authSource,
      };
  }
}

function walletAuthAuthorityFromVerifiedSourceV1(source: VerifiedLinkSourceReadV1): {
  readonly authority: WalletAuthAuthority;
  readonly authSource: WalletExecutionLaneAuthSource;
} | null {
  if (source.authMethod.kind === 'passkey') {
    try {
      const derived = buildPasskeyWalletAuthAuthority({
        walletId: source.authority.walletId,
        rpId: source.authMethod.rpId,
        credentialIdB64u: source.authMethod.credentialIdB64u,
      });
      const authority: WalletAuthAuthority = {
        ...derived,
        bindingId: source.authMethod.walletAuthMethodId,
      };
      return {
        authority,
        authSource: {
          kind: 'passkey',
          credentialIdB64u: authority.factor.credentialIdB64u,
        },
      };
    } catch {
      return null;
    }
  }
  const providerSubject = parseProviderSubject(String(source.principalId));
  if (!providerSubject.ok) return null;
  try {
    const derived = buildEmailOtpWalletAuthAuthority({
      walletId: source.authority.walletId,
      provider: String(source.principalId).startsWith('google:') ? 'google' : 'email',
      providerUserId: providerSubject.value,
      emailHashHex: source.authMethod.emailHashHex,
    });
    const authority: WalletAuthAuthority = {
      ...derived,
      bindingId: source.authMethod.walletAuthMethodId,
    };
    return {
      authority,
      authSource: {
        kind: 'oidc_provider',
        providerId: authority.factor.provider === 'google' ? 'google_oidc' : 'oidc',
        providerSubject: providerSubject.value,
      },
    };
  } catch {
    return null;
  }
}

export type D1LinkedDeviceOwnerAuthorizationProviderOptionsV1 = {
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1;
  readonly targetPlanner: Pick<D1LinkedDeviceTargetPlannerOptionsV1, 'preparationTtlMs'>;
  readonly nowV1?: () => number;
};

export type D1LinkedDeviceOwnerAuthorizationProviderV1 = {
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  readonly ownerAuthorizationRoute: DeviceLinkingOwnerAuthorizationRouteServiceV1;
  readonly ownerSourceResolver: LinkedDeviceOwnerSourceChildResolverV1;
  readonly targetPlanner: D1LinkedDeviceTargetPlannerV1;
};

export function createD1LinkedDeviceOwnerAuthorizationProviderV1(
  options: D1LinkedDeviceOwnerAuthorizationProviderOptionsV1,
): D1LinkedDeviceOwnerAuthorizationProviderV1 {
  const nowV1 = options.nowV1 ?? Date.now;
  const ownerSourceResolver = createD1LinkedDeviceOwnerSourceResolverV1({
    walletRegistration: options.walletRegistration,
    metadata: options.metadata,
    nowV1,
  });
  const ownerAuthorization = createOwnerAuthorizationPortV1(nowV1, options.metadata);
  const targetPlanner = new TargetPlanner({
    preparationTtlMs: options.targetPlanner.preparationTtlMs,
    resolveOwnerSourceChildV1: ownerSourceResolver.resolveOwnerSourceChildV1,
  });
  return {
    ownerAuthorization,
    ownerAuthorizationRoute: createOwnerAuthorizationRouteV1({
      nowV1,
      metadata: options.metadata,
    }),
    ownerSourceResolver,
    targetPlanner,
  };
}

function createOwnerAuthorizationPortV1(
  nowV1: () => number,
  metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
): LinkedDeviceOwnerAuthorizationPortV1 {
  return {
    authorizeOwnerClaimV1: async (input) => {
      const payload = parseQrLinkedDeviceSessionPayloadV5(input.payload);
      const ownerError = validateOwnerContext(input.owner, input.requestedAtMs, nowV1);
      if (ownerError) return ownerError;
      const attenuationError = requestedAuthorityAttenuationError(
        input.owner.permission,
        payload.requestedPermission,
      );
      if (attenuationError) return denied('unauthorized', attenuationError);
      if (input.requestedAtMs < payload.issuedAtMs || input.requestedAtMs >= payload.expiresAtMs) {
        return denied('expired', 'linked-device QR session is outside its lifetime');
      }
      const deviceDigestB64u = await computeLinkedDevicePublicKeyDigestV1(
        payload.devicePublicKeyB64u,
      );
      const enrollmentDigestB64u = parseDigestB64u(
        base64UrlEncode(
          await sha256BytesUtf8(
            `${ENROLLMENT_ID_DOMAIN_V1}\u0000${alphabetizeStringify({
              walletId: input.owner.walletId,
              linkSessionId: payload.linkSessionId,
              linkPublicKeyB64u: payload.linkPublicKeyB64u,
              devicePublicKeyB64u: payload.devicePublicKeyB64u,
            })}`,
          ),
        ),
      );
      const enrollmentId = parseRequired(
        parseLinkedDeviceEnrollmentId(`linked-enrollment:${enrollmentDigestB64u}`),
        'linked-device enrollment identity',
      );
      const deviceId = parseRequired(
        parseLinkedDeviceId(`linked-device:${deviceDigestB64u}`),
        'linked-device device identity',
      );
      const claimExpiresAtMs = Math.min(payload.expiresAtMs, input.owner.expiresAtMs);
      if (claimExpiresAtMs <= input.requestedAtMs) {
        return denied('expired', 'owner Wallet Session expires before the link claim');
      }
      return {
        kind: 'authorized',
        identity: {
          walletId: input.owner.walletId,
          enrollmentId,
          deviceId,
          claimExpiresAtMs,
        },
      };
    },
    authorizeOwnerApprovalV1: async (input) => {
      const ownerError = validateOwnerContext(input.owner, input.requestedAtMs, nowV1);
      if (ownerError) return ownerError;
      const attenuationError = requestedAuthorityAttenuationError(
        input.owner.permission,
        input.approval.permission,
      );
      if (attenuationError) return denied('unauthorized', attenuationError);
      if (!isOwnerApprovalAuthorizationSession(input.session)) {
        return denied('invalid', 'linked-device approval session is outside its owner phase');
      }
      if (
        input.session.claimTranscript.value.walletId !== input.owner.walletId ||
        input.approval.walletId !== input.owner.walletId ||
        input.approval.linkSessionId !== input.session.linkSessionId ||
        input.approval.enrollmentId !== input.session.claimTranscript.value.enrollmentId ||
        input.approval.deviceId !== input.session.claimTranscript.value.deviceId ||
        input.approval.linkPublicKeyB64u !== input.session.qrPayload.linkPublicKeyB64u ||
        input.approval.devicePublicKeyB64u !== input.session.qrPayload.devicePublicKeyB64u ||
        input.requestedAtMs < input.approval.approvedAtMs ||
        input.requestedAtMs >= input.approval.expiresAtMs ||
        input.approval.expiresAtMs > input.session.qrPayload.expiresAtMs
      ) {
        return denied('invalid', 'owner approval identity does not match the claimed session');
      }
      if (!ownerAuthorizationSourceMatchesContext(input.approval.ownerAuthorization, input.owner)) {
        return denied('unauthorized', 'owner approval source does not match the Wallet Session');
      }
      let sourceFacts: D1LinkedDeviceVerifiedOwnerSourceFactsV1;
      try {
        sourceFacts = await metadata.readVerifiedOwnerSourceFactsV1({
          walletId: input.owner.walletId,
          walletSessionId: String(input.approval.ownerAuthorization.walletSessionId),
          authorizationId: String(input.approval.ownerAuthorization.authorizationId),
          requestedAtMs: input.requestedAtMs,
        });
      } catch {
        return denied('unauthorized', 'owner source key manifest is unavailable or ambiguous');
      }
      return {
        kind: 'authorized',
        sourceSignerManifest: sourceFacts.signerManifest,
        sourceKeyManifestDigestsB64u: sourceFacts.keyManifestDigestsB64u,
      };
    },
  };
}

function createOwnerAuthorizationRouteV1(input: {
  readonly nowV1: () => number;
  readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1;
}): DeviceLinkingOwnerAuthorizationRouteServiceV1 {
  return {
    authorizeOwnerForLinkingV1: async (request) => {
      const ownerError = validateOwnerContext(request.owner, request.requestedAtMs, input.nowV1);
      if (ownerError) throw new Error(ownerError.message);
      const payload = parseQrLinkedDeviceSessionPayloadV5(request.payload);
      const attenuationError = requestedAuthorityAttenuationError(
        request.owner.permission,
        payload.requestedPermission,
      );
      if (attenuationError) throw new Error(attenuationError);
      const sourceFacts = await input.metadata.readVerifiedOwnerSourceFactsV1({
        walletId: request.owner.walletId,
        walletSessionId: String(request.owner.walletSessionId),
        authorizationId: String(request.owner.authorizationId),
        requestedAtMs: request.requestedAtMs,
      });
      const metadata = normalizeOwnerAuthorizationMetadataV1(
        {
          walletId: request.owner.walletId,
          ownerAuthorization: ownerAuthorizationSourceForContext(request.owner),
          expiresAtMs: Math.min(payload.expiresAtMs, request.owner.expiresAtMs),
        },
        request.owner,
        payload,
      );
      return {
        authentication: {
          kind: 'link_session_authenticated_request_v1',
          source: ownerAuthorizationSourceForContext(request.owner),
          proofDigestB64u: request.bodyDigestB64u,
        },
        walletId: metadata.walletId,
        ownerAuthorization: metadata.ownerAuthorization,
        sourceSignerManifest: sourceFacts.signerManifest,
        expiresAtMs: metadata.expiresAtMs,
      } satisfies DeviceLinkingOwnerAuthorizationResponseV1;
    },
  };
}

function createD1LinkedDeviceOwnerSourceResolverV1(input: {
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1;
  readonly nowV1: () => number;
}): LinkedDeviceOwnerSourceChildResolverV1 {
  return {
    resolveOwnerSourceChildV1: async (request) => {
      const owner = await resolveApprovedOwnerContextV1(input.metadata, request);
      assertApprovedOwnerContext(request, owner, input.nowV1());
      const resolution = await input.metadata.readOwnerSourceChildV1({ owner, request });
      if (!resolution) throw new Error('authoritative linked-device source facts are unavailable');
      const projection = await projectOwnerLaneV1(input.walletRegistration, owner, resolution);
      assertResolutionMatchesOwnerProjectionV1(resolution, projection);
      if (
        request.sourceSigner.walletKeyId !== resolution.walletKeyId ||
        request.sourceSigner.keyFamily !== resolution.keyFamily
      ) {
        throw new Error('linked-device source signer does not match the active owner projection');
      }
      return resolution;
    },
  };
}

async function resolveApprovedOwnerContextV1(
  metadata: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
  request: LinkedDeviceOwnerSourceChildResolutionRequestV1,
): Promise<DeviceLinkingOwnerWalletSessionContextV1> {
  const identity = sourceRequestIdentity(request);
  const owner = await metadata.readApprovedOwnerContextV1(identity);
  if (!owner) throw new Error('approved owner Wallet Session context is unavailable');
  return owner;
}

function sourceRequestIdentity(request: LinkedDeviceOwnerSourceChildResolutionRequestV1): {
  readonly walletId: WalletId;
  readonly linkSessionId: string;
  readonly keyFamily: ExactAdministeredSignerV1['keyFamily'];
} {
  return {
    walletId: request.approval.walletId,
    linkSessionId: String(request.approval.linkSessionId),
    keyFamily: request.sourceSigner.keyFamily,
  };
}

function assertApprovedOwnerContext(
  request: LinkedDeviceOwnerSourceChildResolutionRequestV1,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  nowMs: number,
): void {
  const identity = sourceRequestIdentity(request);
  if (
    owner.walletId !== identity.walletId ||
    !Number.isSafeInteger(nowMs) ||
    nowMs >= owner.expiresAtMs
  ) {
    throw new Error('approved owner Wallet Session context is expired or mismatched');
  }
  if (!hasDelegatedWalletPermissionV1(owner.permission, 'link_devices')) {
    throw new Error('approved owner Wallet Session authority does not contain link_devices');
  }
  if (request.kind === 'preparation') {
    const attenuationError = requestedAuthorityAttenuationError(
      owner.permission,
      request.approval.permission,
    );
    if (attenuationError) throw new Error(attenuationError);
  }
  if (
    request.kind === 'preparation' &&
    !ownerAuthorizationSourceMatchesContext(request.approval.ownerAuthorization, owner)
  ) {
    throw new Error('approved owner Wallet Session source does not match the approval');
  }
}

async function projectOwnerLaneV1(
  walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
): Promise<ActiveOwnerWalletExecutionLaneProjection> {
  const authorization =
    owner.curve === 'ed25519'
      ? { kind: 'wallet_auth_method' as const, walletAuthMethodId: owner.authority.bindingId }
      : {
          kind: 'authority_ref' as const,
          authorityRef: owner.walletAuthAuthorityRef,
          authSource: owner.authSource,
        };
  const result: WalletExecutionLaneProjectionResult =
    await walletRegistration.resolveActiveOwnerWalletExecutionLane({
      walletId: owner.walletId,
      authorization,
      expectedMaterialActivation: resolution.source.materialActivation,
    });
  if (result.kind !== 'projected') {
    throw new Error(`active owner source lane projection refused: ${result.reason}`);
  }
  return result.projection;
}

function assertResolutionMatchesOwnerProjectionV1(
  resolution: LinkedDeviceOwnerSourceChildResolutionV1,
  projection: ActiveOwnerWalletExecutionLaneProjection,
): void {
  const lane = projection.lane;
  if (
    resolution.walletKeyId !== projection.walletKey.walletKeyId ||
    resolution.source.laneId !== lane.laneId ||
    resolution.source.laneKind !== lane.laneKind ||
    resolution.source.laneShareEpoch !== lane.laneShareEpoch ||
    resolution.source.revocationEpoch !== lane.lifecycle.revocationEpoch ||
    resolution.source.participantBindingDigestB64u !== lane.participantBindingDigestB64u ||
    !mpcMaterialActivationRefsEqual(
      resolution.source.materialActivation,
      projection.materialActivation,
    )
  ) {
    throw new Error('linked-device source facts do not match the active owner projection');
  }
  if (resolution.keyFamily !== projection.walletKey.keyFamily) {
    throw new Error('linked-device source key family does not match the owner projection');
  }
  if (resolution.keyFamily === 'ed25519') {
    if (
      projection.walletKey.keyFamily !== 'ed25519' ||
      resolution.registeredPublicKeyB64u !== projection.walletKey.registeredPublicKeyB64u ||
      resolution.nearEd25519SigningKeyId !== projection.walletKey.nearEd25519SigningKeyId ||
      resolution.keyCreationSignerSlot !== projection.walletKey.keyCreationSignerSlot
    ) {
      throw new Error('Ed25519 linked-device source facts do not match the owner projection');
    }
  }
}

function normalizeOwnerAuthorizationMetadataV1(
  metadata: D1LinkedDeviceOwnerAuthorizationMetadataV1,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  payload: QrLinkedDeviceSessionPayloadV5,
): D1LinkedDeviceOwnerAuthorizationMetadataV1 {
  if (metadata.walletId !== owner.walletId) {
    throw new Error('owner authorization metadata walletId does not match the Wallet Session');
  }
  const ownerAuthorization = metadata.ownerAuthorization;
  if (!ownerAuthorizationSourceMatchesContext(ownerAuthorization, owner)) {
    throw new Error('owner authorization metadata source does not match the Wallet Session');
  }
  if (
    !Number.isSafeInteger(metadata.expiresAtMs) ||
    metadata.expiresAtMs <= 0 ||
    metadata.expiresAtMs > payload.expiresAtMs ||
    metadata.expiresAtMs > owner.expiresAtMs
  ) {
    throw new Error('owner authorization metadata expiry is invalid');
  }
  return {
    walletId: owner.walletId,
    ownerAuthorization,
    expiresAtMs: metadata.expiresAtMs,
  };
}

function ownerAuthorizationSourceForContext(
  owner: DeviceLinkingOwnerWalletSessionContextV1,
): LinkedDeviceOwnerAuthorizationSourceV1 {
  return buildWalletSessionLinkedDeviceOwnerAuthorizationV1({
    walletSessionId: owner.walletSessionId,
    authorizationId: owner.authorizationId,
  });
}

function ownerAuthorizationSourceMatchesContext(
  source: LinkedDeviceOwnerAuthorizationSourceV1,
  owner: Pick<LinkedDeviceOwnerAuthorizationContextV1, 'walletSessionId' | 'authorizationId'>,
): boolean {
  return (
    source.kind === 'wallet_session' &&
    String(source.walletSessionId) === String(owner.walletSessionId) &&
    String(source.authorizationId) === String(owner.authorizationId)
  );
}

function validateOwnerContext(
  owner: Pick<
    LinkedDeviceOwnerAuthorizationContextV1,
    'walletId' | 'walletSessionId' | 'authorizationId' | 'expiresAtMs' | 'permission'
  >,
  requestedAtMs: number,
  nowV1: () => number,
): {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid';
  readonly message: string;
} | null {
  if (
    !owner.walletId ||
    !parseWalletSessionId(owner.walletSessionId).ok ||
    !parseWalletSessionAuthorizationId(owner.authorizationId).ok ||
    !Number.isSafeInteger(owner.expiresAtMs) ||
    !Number.isSafeInteger(requestedAtMs) ||
    requestedAtMs < 0 ||
    requestedAtMs >= owner.expiresAtMs ||
    nowV1() >= owner.expiresAtMs ||
    !hasDelegatedWalletPermissionV1(owner.permission, 'link_devices')
  ) {
    return denied('invalid', 'owner Wallet Session context is invalid or expired');
  }
  return null;
}

function requestedAuthorityAttenuationError(
  parent: DelegatedWalletAuthorityV1,
  child: DelegatedWalletAuthorityV1,
): string | null {
  if (!hasDelegatedWalletPermissionV1(parent, 'link_devices')) {
    return 'owner Wallet Session authority does not contain link_devices';
  }
  const result = validateDelegatedWalletAuthorityAttenuationV1({ parent, child });
  return result.ok ? null : result.error.message;
}

function denied(
  code: 'unauthorized' | 'expired' | 'invalid',
  message: string,
): {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid';
  readonly message: string;
} {
  return { kind: 'denied', code, message };
}

function isOwnerApprovalAuthorizationSession(
  session: LinkedDeviceSessionRecordV1,
): session is Extract<
  LinkedDeviceSessionRecordV1,
  {
    readonly state: {
      readonly state: 'claimed' | 'awaiting_source_contribution';
    };
  }
> {
  switch (session.state.state) {
    case 'claimed':
    case 'awaiting_source_contribution':
      return true;
    default:
      return false;
  }
}

function parseRequired<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label}: ${result.error.message}`);
}
