import type {
  AuthorizationGrantPort,
  IssuedLinkedDeviceWalletSession,
} from '../../../../authorization/service';
import type {
  ActiveLinkedDeviceEnrollmentExecutionRecordV1,
  ActiveLinkedDeviceExecutionProjectionV1,
  LinkedDeviceExecutionAdmissionResolverV1,
  LinkedDeviceExecutionProjectionResult,
} from '../../../domains/signingOperations/walletExecutionAdmission';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import {
  buildActiveSigningLaneLifecycle,
  buildActiveWalletKeyLifecycle,
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildLinkedDeviceSigningLaneRecord,
  parseWalletKeyVersion,
} from '@shared/signing-lanes/recordParsers';
import type {
  LaneProductEpochRecordV1,
  LaneProtocolRecordV1,
} from '@shared/signing-lanes';
import { computeLaneParticipantSetBindingDigestV1 } from '@shared/signing-lanes/participantDigest';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseLaneEnrollmentId, type LaneEnrollmentId } from '@shared/signing-lanes/ids';
import {
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import { parseWebAuthnCredentialIdB64u, type WebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';
import { LaneLifecycleStoreNormalSigningLaneMaterialResolverV1 } from '../../signingLanes/cloudflareLaneCurveExecution';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId, MpcMaterialActivationRef } from '@shared/utils/domainIds';

export type D1LinkedDeviceCredentialResolverV1 = {
  readLinkedDeviceCredentialIdV1(input: {
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
  }): Promise<WebAuthnCredentialIdB64u | string | null>;
};

export type D1LinkedDeviceExecutionAdmissionResolverOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly authorization: Pick<
    AuthorizationGrantPort,
    'readLinkedDeviceWalletSessionAuthorization'
  >;
  readonly credentials: D1LinkedDeviceCredentialResolverV1;
  readonly nowV1: () => number;
};

/**
 * Projects one active linked lane from the scoped D1 lane records and grant
 * record. Every identity used by SigningWorker is selected by the complete
 * wallet/enrollment/lane/material tuple supplied by the claimed operation.
 */
export class D1LinkedDeviceExecutionAdmissionResolverV1
  implements LinkedDeviceExecutionAdmissionResolverV1
{
  private readonly authorization: D1LinkedDeviceExecutionAdmissionResolverOptionsV1['authorization'];
  private readonly credentials: D1LinkedDeviceCredentialResolverV1;
  private readonly nowV1: () => number;
  private readonly lanes: CloudflareD1LaneLifecycleStore;
  private readonly materialResolver: LaneLifecycleStoreNormalSigningLaneMaterialResolverV1;

  constructor(options: D1LinkedDeviceExecutionAdmissionResolverOptionsV1) {
    this.authorization = options.authorization;
    this.credentials = options.credentials;
    this.nowV1 = options.nowV1;
    this.lanes = new CloudflareD1LaneLifecycleStore({
      database: options.database,
      scope: options.scope,
      now: options.nowV1,
    });
    this.materialResolver = new LaneLifecycleStoreNormalSigningLaneMaterialResolverV1(this.lanes);
  }

  async resolveActiveLinkedDeviceExecutionV1(
    input: Parameters<
      LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
    >[0],
  ): Promise<LinkedDeviceExecutionProjectionResult> {
    try {
      const nowMs = this.nowV1();
      const laneEnrollmentId = parseLaneEnrollmentId(String(input.enrollmentId));
      if (!laneEnrollmentId.ok) return refused('linked_enrollment_mismatch');
      const product = await this.lanes.getProductEpoch({
        walletId: input.walletId,
        walletKeyId: input.walletKeyId,
        laneId: input.laneId,
        laneShareEpoch: input.laneShareEpoch,
      });
      if (!product || product.state !== 'active') return refused('lane_inactive');
      if (
        product.walletId !== input.walletId ||
        product.walletKeyId !== input.walletKeyId ||
        product.laneId !== input.laneId ||
        product.laneShareEpoch !== input.laneShareEpoch ||
        String(product.enrollmentId) !== String(laneEnrollmentId.value) ||
        !sameMaterialActivation(product.materialActivation, input.materialActivation)
      ) {
        return refused('linked_product_mismatch');
      }

      const material = await this.materialResolver.resolveV1({
        lookup: {
          walletId: input.walletId,
          walletKeyId: input.walletKeyId,
          laneId: input.laneId,
          laneShareEpoch: input.laneShareEpoch,
        },
        materialActivation: input.materialActivation,
        keyFamily: product.keyFamily,
      });
      const protocol = await this.lanes.getProtocol(product.operationId);
      if (!protocol || protocol.value.lifecycle.state !== 'active') {
        return refused('lane_inactive');
      }
      const issued = await this.authorization.readLinkedDeviceWalletSessionAuthorization({
        tenantId: input.tenantId,
        deviceId: input.deviceId,
        authorizationId: input.authorizationId,
        walletSessionId: input.walletSessionId,
        quotaId: input.quotaId,
        nowMs,
      });
      if (!issued) return refused('authorization_grant_mismatch');
      return await this.projectActiveExecution({
        input,
        issued,
        product,
        protocol: protocol.value,
        material,
        laneEnrollmentId: laneEnrollmentId.value,
      });
    } catch {
      return refused('linked_execution_unavailable');
    }
  }

  private async projectActiveExecution(projectionInput: {
    readonly input: Parameters<
      LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']
    >[0];
    readonly issued: IssuedLinkedDeviceWalletSession;
    readonly product: Extract<LaneProductEpochRecordV1, { readonly state: 'active' }>;
    readonly protocol: LaneProtocolRecordV1;
    readonly material: Awaited<ReturnType<LaneLifecycleStoreNormalSigningLaneMaterialResolverV1['resolveV1']>>;
    readonly laneEnrollmentId: LaneEnrollmentId;
  }): Promise<LinkedDeviceExecutionProjectionResult> {
    const { input, issued, product, protocol, material, laneEnrollmentId } = projectionInput;
    const authorization = issued.authorization;
    const quota = issued.quota;
    if (
      authorization.tenantId !== input.tenantId ||
      authorization.walletId !== input.walletId ||
      authorization.enrollmentId !== input.enrollmentId ||
      authorization.deviceId !== input.deviceId ||
      authorization.authorizationGrantRef.authorizationId !== input.authorizationId ||
      authorization.walletSessionId !== input.walletSessionId ||
      authorization.quotaId !== input.quotaId ||
      quota.tenantId !== input.tenantId ||
      quota.walletSessionId !== authorization.walletSessionId ||
      quota.quotaId !== authorization.quotaId ||
      quota.remainingUses <= 0
    ) {
      return refused('authorization_grant_mismatch');
    }
    if (authorization.expiresAtMs <= this.nowV1() || quota.expiresAtMs <= this.nowV1()) {
      return refused('authorization_expired');
    }
    if (authorization.revocationEpoch !== product.revocationEpoch) {
      return refused('revocation_epoch_mismatch');
    }
    if (
      product.walletId !== authorization.walletId ||
      String(product.enrollmentId) !== String(laneEnrollmentId) ||
      product.laneKind !== 'linked_device'
    ) {
      return refused('linked_product_mismatch');
    }
    const manifestDigest = parseDigestB64u(product.aggregateManifestDigestB64u);
    if (String(manifestDigest) !== String(authorization.keyManifestDigestB64u)) {
      return refused('linked_product_mismatch');
    }
    const credentialRaw = await this.credentials.readLinkedDeviceCredentialIdV1({
      walletId: input.walletId,
      enrollmentId: input.enrollmentId,
      deviceId: input.deviceId,
    });
    if (!credentialRaw) return refused('linked_execution_unavailable');
    const credentialId = parseCredentialId(credentialRaw);
    const participantBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
      holderParticipant: product.holderParticipant,
      signingWorkerParticipant: product.signingWorkerParticipant,
    });
    if (participantBindingDigestB64u !== product.participantSetBindingDigestB64u) {
      return refused('linked_participant_mismatch');
    }
    const activationReceiptDigestB64u = parseDigestB64u(
      product.aggregateActivationReceiptDigestB64u,
    );
    const lane = buildLinkedDeviceSigningLaneRecord({
      walletId: product.walletId,
      walletKeyId: product.walletKeyId,
      laneId: product.laneId,
      laneShareEpoch: product.laneShareEpoch,
      participantBindingDigestB64u,
      holderParticipant: product.holderParticipant,
      serverParticipant: product.signingWorkerParticipant,
      lifecycle: buildActiveSigningLaneLifecycle({
        revocationEpoch: product.revocationEpoch,
        activatedAtMs: product.activatedAtMs,
        activationReceiptDigestB64u,
      }),
      linkedDeviceId: input.deviceId,
    });
    const walletKey = buildWalletKey(protocol, product);
    const enrollment: ActiveLinkedDeviceEnrollmentExecutionRecordV1 = {
      kind: 'active_linked_device_enrollment_v1',
      walletId: product.walletId,
      enrollmentId: input.enrollmentId,
      deviceId: input.deviceId,
      keyManifestDigestB64u: manifestDigest,
      credentialIdB64u: credentialId,
      revocationEpoch: product.revocationEpoch,
      lifecycle: { state: 'active', activatedAtMs: product.activatedAtMs },
    };
    const projection: ActiveLinkedDeviceExecutionProjectionV1 = {
      kind: 'active_linked_device_execution_projection_v1',
      authorization,
      enrollment,
      walletKey,
      lane,
      product,
      materialActivation: product.materialActivation,
      verifiedLaneParticipantBindingDigestB64u: participantBindingDigestB64u,
      verifiedActivationReceiptDigestB64u: activationReceiptDigestB64u,
      materialSource: material.source,
    };
    return { kind: 'projected', projection };
  }
}

function buildWalletKey(
  protocol: LaneProtocolRecordV1,
  product: Extract<LaneProductEpochRecordV1, { readonly state: 'active' }>,
) {
  const version = parseWalletKeyVersion(`wallet-key-version:linked-device:${String(product.laneShareEpoch)}`);
  if (protocol.job.keyFamily === 'ed25519') {
    return buildEd25519WalletKeyRecord({
      walletId: product.walletId,
      walletKeyId: product.walletKeyId,
      walletKeyVersion: version,
      nearEd25519SigningKeyId: protocol.job.nearEd25519SigningKeyId,
      keyCreationSignerSlot: protocol.job.keyCreationSignerSlot,
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(protocol.job.registeredPublicKeyB64u),
      lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: product.activatedAtMs }),
    });
  }
  return buildEvmFamilyWalletKeyRecord({
    walletId: product.walletId,
    walletKeyId: product.walletKeyId,
    walletKeyVersion: version,
    evmFamilySigningKeySlotId: protocol.job.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      protocol.job.thresholdPublicKey33B64u,
    ),
    evmAddress: protocol.job.evmAddress,
    lifecycle: buildActiveWalletKeyLifecycle({ activatedAtMs: product.activatedAtMs }),
  });
}

function parseCredentialId(raw: WebAuthnCredentialIdB64u | string): WebAuthnCredentialIdB64u {
  const parsed = parseWebAuthnCredentialIdB64u(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function sameMaterialActivation(left: MpcMaterialActivationRef, right: MpcMaterialActivationRef): boolean {
  return (
    left.activationId === right.activationId &&
    left.capability === right.capability &&
    left.materialOwner === right.materialOwner &&
    left.keyBinding === right.keyBinding &&
    left.lifecycleBinding === right.lifecycleBinding &&
    left.signingWorker === right.signingWorker
  );
}

function refused(
  reason: Extract<LinkedDeviceExecutionProjectionResult, { readonly kind: 'refused' }>['reason'],
): LinkedDeviceExecutionProjectionResult {
  return { kind: 'refused', reason };
}
