import type {
  QrLinkedDeviceSessionPayloadV5,
  LinkedDeviceOwnerSourceLaneV1,
} from '@shared/device-linking/contracts';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLaneShareEpoch,
  parseSigningLaneId,
  type LaneOperationId,
  type LaneOperationIdempotencyKey,
  type LaneShareEpoch,
  type SigningLaneId,
} from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import {
  deriveRouterAbEd25519YaoApplicationBindingDigestV1,
  deriveRouterAbEd25519YaoStableContextBindingV1,
} from '@shared/utils/routerAbEd25519Yao';
import { parseSdkEcdsaDerivationThresholdKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseEcdsaRelayerKeyId } from '@shared/signing-lanes/ids';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';
import {
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  WalletEcdsaSignerRecord,
  WalletEd25519SignerRecord,
} from '../../../../core/WalletStore';
import type { ActiveOwnerWalletExecutionLaneProjection } from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import type { DeviceLinkingOwnerWalletSessionContextV1 } from '../../../../router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type { D1LinkedDeviceOwnerAuthorizationMetadataV1 } from './d1LinkedDeviceOwnerAuthorizationProvider';
import type {
  D1LinkedDeviceOwnerPlanningDeploymentChildV1,
  D1LinkedDeviceOwnerPlanningDeploymentPlanV1,
  D1LinkedDeviceOwnerPlanningDeploymentPortV1,
} from './d1LinkedDeviceOwnerPlanningSnapshotWriter';

type NonEmpty<T> = readonly [T, ...T[]];

export type D1LinkedDeviceOwnerPlanningWalletSourceV1 = {
  listEd25519SignersForWallet(input: {
    readonly walletId: WalletId;
  }): Promise<readonly WalletEd25519SignerRecord[]>;
  listEcdsaSignersForWallet(input: {
    readonly walletId: WalletId;
  }): Promise<readonly WalletEcdsaSignerRecord[]>;
};

export type D1LinkedDeviceOwnerPlanningDeploymentOptionsV1 = {
  readonly walletSource: D1LinkedDeviceOwnerPlanningWalletSourceV1;
};

/**
 * Produces the source-only owner planning record from authenticated lane hints
 * and the durable signer records. IDs are derived from the QR identity so a
 * retry of the same link session replays the same approval metadata.
 */
export class D1LinkedDeviceOwnerPlanningDeploymentV1 implements D1LinkedDeviceOwnerPlanningDeploymentPortV1 {
  private readonly walletSource: D1LinkedDeviceOwnerPlanningWalletSourceV1;

  constructor(options: D1LinkedDeviceOwnerPlanningDeploymentOptionsV1) {
    this.walletSource = options.walletSource;
  }

  async planOwnerPlanningV1(input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly payload: QrLinkedDeviceSessionPayloadV5;
    readonly orderedOwnerSourceLaneHints: NonEmpty<LinkedDeviceOwnerSourceLaneV1>;
    readonly projections: NonEmpty<ActiveOwnerWalletExecutionLaneProjection>;
  }): Promise<D1LinkedDeviceOwnerPlanningDeploymentPlanV1> {
    if (input.orderedOwnerSourceLaneHints.length !== input.projections.length) {
      throw new Error('owner planning hints and projections are out of order');
    }
    const policyDigestB64u = await digestDomainV1('policy', {
      permission: input.payload.requestedPermission,
    });
    const operationId = await parseOperationIdFromDigest(
      'linked-device-owner-operation',
      await digestDomainV1('operation', {
        linkSessionId: String(input.payload.linkSessionId),
        walletId: String(input.owner.walletId),
      }),
      parseLaneOperationId,
    );
    const idempotencyKey = await parseOperationIdFromDigest(
      'linked-device-owner-idempotency',
      await digestDomainV1('idempotency', {
        linkSessionId: String(input.payload.linkSessionId),
        walletId: String(input.owner.walletId),
      }),
      parseLaneOperationIdempotencyKey,
    );
    const orderedKeyBindings = requireNonEmpty(
      await Promise.all(
        input.projections.map(async (projection, index) => {
          const target = await targetIdentityV1({
            linkSessionId: String(input.payload.linkSessionId),
            walletId: String(input.owner.walletId),
            walletKeyId: String(projection.walletKey.walletKeyId),
            index,
          });
          return {
            walletKeyId: projection.walletKey.walletKeyId,
            keyFamily: projection.walletKey.keyFamily,
            sourceKind: 'owner_registration' as const,
            sourceLaneKind: projection.lane.laneKind,
            sourceLaneId: projection.lane.laneId,
            sourceLaneShareEpoch: projection.lane.laneShareEpoch,
            sourceRevocationEpoch: projection.lane.lifecycle.revocationEpoch,
            ownerParticipantContinuity: projection.lane.ownerParticipantContinuity,
            targetLaneId: target.laneId,
            targetLaneShareEpoch: target.laneShareEpoch,
          };
        }),
      ),
      'owner planning key bindings',
    );
    const protocolVersions = requireNonEmpty(
      input.projections.map((projection) => ({
        keyFamily: projection.walletKey.keyFamily,
        version: 'rotatable_signing_lane_protocol_v1' as const,
      })),
      'owner planning protocol versions',
    );
    const metadata: D1LinkedDeviceOwnerAuthorizationMetadataV1 = {
      walletId: input.owner.walletId,
      policyDigestB64u,
      operationId,
      idempotencyKey,
      orderedKeyBindings,
      protocolVersions,
      expiresAtMs: Math.min(input.owner.expiresAtMs, input.payload.expiresAtMs),
    };
    if (metadata.expiresAtMs <= input.payload.issuedAtMs) {
      throw new Error('owner planning metadata has no remaining lifetime');
    }
    const orderedChildren = requireNonEmpty(
      await Promise.all(
        input.projections.map(
          async (projection, index) =>
            await this.buildDeploymentChildV1({
              projection,
              hint: input.orderedOwnerSourceLaneHints[index]!,
              index,
              input,
            }),
        ),
      ),
      'owner planning deployment children',
    );
    return { metadata, orderedChildren };
  }

  private async buildDeploymentChildV1(input: {
    readonly projection: ActiveOwnerWalletExecutionLaneProjection;
    readonly hint: LinkedDeviceOwnerSourceLaneV1;
    readonly index: number;
    readonly input: {
      readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
      readonly payload: QrLinkedDeviceSessionPayloadV5;
      readonly orderedOwnerSourceLaneHints: NonEmpty<LinkedDeviceOwnerSourceLaneV1>;
      readonly projections: NonEmpty<ActiveOwnerWalletExecutionLaneProjection>;
    };
  }): Promise<D1LinkedDeviceOwnerPlanningDeploymentChildV1> {
    if (
      input.projection.walletKey.keyFamily !== input.hint.keyFamily ||
      input.projection.walletKey.walletId !== input.input.owner.walletId
    ) {
      throw new Error(`owner planning source ${input.index} differs from its authenticated hint`);
    }
    if (input.hint.keyFamily === 'ed25519') {
      const signers = await this.walletSource.listEd25519SignersForWallet({
        walletId: input.input.owner.walletId,
      });
      const matches = signers.filter(
        (signer) =>
          `wallet-key:ed25519:${signer.walletId}:${signer.nearEd25519SigningKeyId}` ===
          String(input.projection.walletKey.walletKeyId),
      );
      if (matches.length !== 1) {
        throw new Error(
          `authoritative Ed25519 signer for owner source ${input.index} is unavailable`,
        );
      }
      const signer = matches[0]!;
      if (
        signer.nearEd25519SigningKeyId !== input.projection.walletKey.nearEd25519SigningKeyId ||
        signer.signerSlot !== input.projection.walletKey.keyCreationSignerSlot ||
        base64UrlEncode(
          Uint8Array.from(
            signer.activeYaoCapability.activationResult.public_receipt.registered_public_key,
          ),
        ) !== String(input.projection.walletKey.registeredPublicKeyB64u) ||
        !materialActivationMatchesProjection(
          input.projection,
          signer.activeYaoCapability.activationResult.public_receipt.material_activation,
        )
      ) {
        throw new Error(`authoritative Ed25519 signer for owner source ${input.index} changed`);
      }
      const stableContextBindingB64u = base64UrlEncode(
        Uint8Array.from(
          await deriveRouterAbEd25519YaoStableContextBindingV1(
            signer.activeYaoCapability.admissionRequest.application_binding,
            signer.activeYaoCapability.admissionRequest.participant_ids,
          ),
        ),
      );
      const applicationBindingDigestB64u = base64UrlEncode(
        Uint8Array.from(
          await deriveRouterAbEd25519YaoApplicationBindingDigestV1(
            signer.activeYaoCapability.admissionRequest.application_binding,
          ),
        ),
      );
      return {
        keyFamily: 'ed25519',
        applicationBindingDigestB64u,
        stableContextBindingB64u,
      };
    }
    const signers = await this.walletSource.listEcdsaSignersForWallet({
      walletId: input.input.owner.walletId,
    });
    const matches = signers.filter(
      (signer) =>
        walletKeyIdForEcdsaSigner(signer) === String(input.projection.walletKey.walletKeyId),
    );
    if (matches.length === 0) {
      throw new Error(`authoritative ECDSA signer for owner source ${input.index} is unavailable`);
    }
    const signer = requireConsistentEcdsaSigner(matches, input.index);
    if (
      signer.walletKey.thresholdEcdsaPublicKeyB64u !==
        String(input.projection.walletKey.thresholdPublicKey33B64u) ||
      signer.walletKey.thresholdOwnerAddress !== input.projection.walletKey.evmAddress ||
      !materialActivationMatchesProjection(
        input.projection,
        signer.walletKey.publicCapability.material_activation,
      )
    ) {
      throw new Error(`authoritative ECDSA signer for owner source ${input.index} changed`);
    }
    const sourceManifest = input.hint.ecdsaSourceManifest;
    if (!sourceManifest)
      throw new Error(`ECDSA owner source ${input.index} has no manifest identity`);
    return {
      keyFamily: 'ecdsa_secp256k1',
      sourceCapability: {
        manifestId: sourceManifest.manifestId,
        manifestRevision: sourceManifest.manifestRevision,
        serverGeneration: signer.activationReceipt.server_generation,
        ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(
          signer.walletKey.ecdsaThresholdKeyId,
        ),
        relayerKeyId: parseRequired(
          parseEcdsaRelayerKeyId(signer.walletKey.relayerKeyId),
          `ECDSA owner source ${input.index}.relayerKeyId`,
        ),
      },
      sourceHolderVerifyingShare33B64u: signer.walletKey.derivationClientSharePublicKey33B64u,
      sourceServerVerifyingShare33B64u: signer.walletKey.relayerVerifyingShareB64u,
    };
  }
}

function walletKeyIdForEcdsaSigner(signer: WalletEcdsaSignerRecord): string {
  const slot = deriveEvmFamilySigningKeySlotId({
    walletId: signer.walletId,
    signingRootId: signer.walletKey.signingRootId,
    signingRootVersion: signer.walletKey.signingRootVersion,
  });
  return `wallet-key:ecdsa:${signer.walletId}:${slot}`;
}

function requireConsistentEcdsaSigner(
  signers: readonly WalletEcdsaSignerRecord[],
  index: number,
): WalletEcdsaSignerRecord {
  const first = signers[0];
  if (!first) throw new Error(`ECDSA owner source ${index} has no signer`);
  for (const signer of signers.slice(1)) {
    if (
      signer.walletKey.keyHandle !== first.walletKey.keyHandle ||
      signer.walletKey.ecdsaThresholdKeyId !== first.walletKey.ecdsaThresholdKeyId ||
      signer.walletKey.relayerKeyId !== first.walletKey.relayerKeyId ||
      signer.walletKey.relayerVerifyingShareB64u !== first.walletKey.relayerVerifyingShareB64u ||
      signer.walletKey.derivationClientSharePublicKey33B64u !==
        first.walletKey.derivationClientSharePublicKey33B64u ||
      signer.walletKey.contextBinding32B64u !== first.walletKey.contextBinding32B64u
    ) {
      throw new Error(`ECDSA owner source ${index} has conflicting signer records`);
    }
  }
  return first;
}

function materialActivationMatchesProjection(
  projection: ActiveOwnerWalletExecutionLaneProjection,
  wire: Parameters<typeof sameRouterAbMpcMaterialActivationRef>[1],
): boolean {
  return sameRouterAbMpcMaterialActivationRef(
    routerAbMpcMaterialActivationRefToWire(projection.materialActivation),
    wire,
  );
}

async function targetIdentityV1(input: {
  readonly linkSessionId: string;
  readonly walletId: string;
  readonly walletKeyId: string;
  readonly index: number;
}): Promise<{ readonly laneId: SigningLaneId; readonly laneShareEpoch: LaneShareEpoch }> {
  const seed = {
    linkSessionId: input.linkSessionId,
    walletId: input.walletId,
    walletKeyId: input.walletKeyId,
    index: input.index,
  };
  const laneDigest = await digestDomainV1('target-lane', seed);
  const epochDigest = await digestDomainV1('target-epoch', seed);
  return {
    laneId: parseRequired(
      parseSigningLaneId(`lane:linked-device:${base64UrlEncode(await digestBytes(laneDigest))}`),
      'target lane id',
    ),
    laneShareEpoch: parseRequired(
      parseLaneShareEpoch(`epoch:linked-device:${base64UrlEncode(await digestBytes(epochDigest))}`),
      'target lane epoch',
    ),
  };
}

async function parseOperationIdFromDigest<T>(
  prefix: string,
  digest: DigestB64u,
  parser: (
    raw: unknown,
  ) =>
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): Promise<T> {
  return parseRequired(parser(`${prefix}:${base64UrlEncode(await digestBytes(digest))}`), prefix);
}

async function digestDomainV1(domain: string, value: unknown): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        `seams/linked-device/owner-planning/${domain}/v1\u0000${alphabetizeStringify(value)}`,
      ),
    ),
  );
}

async function digestBytes(digest: DigestB64u): Promise<Uint8Array> {
  return base64UrlDecode(digest);
}

function requireNonEmpty<T>(values: readonly T[], label: string): NonEmpty<T> {
  const first = values[0];
  if (first === undefined) throw new Error(`${label} must not be empty`);
  return [first, ...values.slice(1)];
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
