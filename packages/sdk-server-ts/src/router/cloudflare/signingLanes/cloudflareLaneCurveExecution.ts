import type {
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  Ed25519YaoLaneJobV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  LaneServerRetirementReceiptV1,
  LaneHolderPackageWireV1,
  LaneProductEpochActiveV1,
  LaneProductEpochRevocationPendingV1,
  LaneProductEpochRevokedV1,
  LaneProtocolLifecycle,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import { encodeLaneProtocolCommitReceiptV1 } from '@shared/signing-lanes/rotationDigests';
import {
  parseLaneProtocolCommitReceiptV1,
  parseLaneServerActivationReceiptV1,
  parseRevokeSigningLaneV1,
} from '@shared/signing-lanes/rotationParsers';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256Bytes } from '@shared/utils/digests';
import { parseEcdsaLifecycleId } from '@shared/utils/ecdsaCapabilityActivation';
import {
  buildMpcMaterialActivationRef,
  mpcMaterialActivationRefsEqual,
  parseMpcSigningWorkerRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type {
  LaneLifecycleCurveExecutionPortsV1,
  LaneLifecycleRetirementExecutionV1,
} from '../../../core/signingLanes/LaneLifecycleApplicationService';
import type { LaneLifecycleStore } from '../../../core/signingLanes/LaneLifecycleStore';
import {
  buildEcdsaServerRetirementRequestV1,
  parseAndVerifyEcdsaServerRetirementEffectV1,
  type EcdsaServerRetirementBindingV1,
} from '../../../core/signingLanes/ecdsaServerRetirement';
import {
  buildEd25519ServerRetirementRequestV1,
  parseAndVerifyEd25519ServerRetirementEffectV1,
  type Ed25519ServerRetirementBindingV1,
} from '../../../core/signingLanes/ed25519ServerRetirement';
import type {
  EcdsaSigningWorkerLaneMaterialIdentityV1,
  SigningWorkerLaneMaterialIdentityV1,
} from '../../../core/signingLanes/signingWorkerLaneMaterialIdentity';
import type { CloudflareEd25519LaneProtocolTransportV1 } from './cloudflareLaneProtocolCommitter';

type LaneMaterialMutationOutcomeV1 = 'applied' | 'replayed';

export type SigningWorkerLaneProtocolCommitProjectionV1 = {
  readonly kind: 'signing_worker_lane_protocol_commit_projection_v1';
  readonly outcome: LaneMaterialMutationOutcomeV1;
  readonly receipt: LaneProtocolCommitReceiptV1;
};

export type SigningWorkerLaneServerActivationProjectionV1 = {
  readonly kind: 'signing_worker_lane_server_activation_projection_v1';
  readonly outcome: LaneMaterialMutationOutcomeV1;
  readonly receipt: LaneServerActivationReceiptV1;
};

export type SigningWorkerLaneRetirementProjectionV1 = {
  readonly kind: 'signing_worker_lane_retirement_projection_v1';
  readonly outcome: LaneMaterialMutationOutcomeV1;
  readonly command: RevokeSigningLaneV1;
  readonly retirementEffectBindingDigestB64u: string;
  readonly retirementReceipt: LaneServerRetirementReceiptV1;
};

/**
 * Receipt-only projection of the private SigningWorker material journal. The
 * encrypted active record and all plaintext material are intentionally absent.
 */
export interface SigningWorkerLaneMaterialReceiptPortV1 {
  commitEcdsaProtocolV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
    readonly holderPackage: Extract<
      LaneHolderPackageWireV1,
      { kind: 'ecdsa_additive_lane_holder_package_v1' }
    >;
    readonly encryptedDeltaPackageJson: string;
  }): Promise<SigningWorkerLaneProtocolCommitProjectionV1>;
  activateServerMaterialV1(
    input:
      | {
          readonly curve: 'ed25519_yao';
          readonly job: Ed25519YaoLaneJobV1;
          readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
          readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
        }
      | {
          readonly curve: 'ecdsa_additive';
          readonly job: EcdsaAdditiveLaneJobV1;
          readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
          readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
        },
  ): Promise<SigningWorkerLaneServerActivationProjectionV1>;
  retireServerMaterialV1(input: {
    readonly curve: 'ed25519_yao' | 'ecdsa_additive';
    readonly command: RevokeSigningLaneV1;
  }): Promise<SigningWorkerLaneRetirementProjectionV1>;
}

export const CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_EXECUTE_PATH_V1 =
  '/router-ab/internal/signing-worker/ecdsa-additive-lane/execute' as const;
export const CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_ACTIVATE_PATH_V1 =
  '/router-ab/internal/signing-worker/ecdsa-additive-lane/activate' as const;
export const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_LANE_ACTIVATE_PATH_V1 =
  '/router-ab/internal/signing-worker/ed25519-yao-lane/activate' as const;
export const CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_RETIRE_PATH_V1 =
  '/router-ab/internal/signing-worker/ecdsa-additive-lane/retire' as const;
export const CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_LANE_RETIRE_PATH_V1 =
  '/router-ab/internal/signing-worker/ed25519-yao-lane/retire' as const;

export interface EcdsaLanePrivateBindingResolverPortV1 {
  resolveSourceMaterialV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
  }): Promise<CloudflareEcdsaLaneSourceMaterialV1>;
  resolveActivationBindingV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  }): Promise<{
    readonly identity: EcdsaSigningWorkerLaneMaterialIdentityV1;
    readonly targetMaterialActivation: MpcMaterialActivationRef;
  }>;
  resolveRetirementBindingV1(input: {
    readonly command: RevokeSigningLaneV1;
  }): Promise<EcdsaServerRetirementBindingV1>;
}

export interface Ed25519LanePrivateBindingResolverPortV1 {
  resolveRetirementBindingV1(input: {
    readonly command: RevokeSigningLaneV1;
  }): Promise<Ed25519ServerRetirementBindingV1>;
}

export class LaneLifecycleStoreEd25519LanePrivateBindingResolverV1 implements Ed25519LanePrivateBindingResolverPortV1 {
  constructor(
    private readonly lifecycleStore: Pick<LaneLifecycleStore, 'getProductEpoch' | 'getProtocol'>,
  ) {}

  async resolveRetirementBindingV1(input: {
    readonly command: RevokeSigningLaneV1;
  }): Promise<Ed25519ServerRetirementBindingV1> {
    const product = await this.lifecycleStore.getProductEpoch({
      walletId: input.command.walletId,
      walletKeyId: input.command.walletKeyId,
      laneId: input.command.laneId,
      laneShareEpoch: input.command.laneShareEpoch,
    });
    if (
      product === null ||
      product.keyFamily !== 'ed25519' ||
      (product.state !== 'active' &&
        product.state !== 'revocation_pending' &&
        product.state !== 'revoked') ||
      !retirementProductMatchesCommandV1(product, input.command)
    ) {
      throw new Error('Ed25519 retirement source product is not the exact active epoch');
    }
    const protocol = await this.lifecycleStore.getProtocol(product.operationId);
    if (
      protocol === null ||
      protocol.value.lifecycle.state !== 'active' ||
      protocol.value.job.keyFamily !== 'ed25519'
    ) {
      throw new Error('Ed25519 retirement protocol is not active');
    }
    return {
      identity: ed25519IdentityFromActiveProductV1(product, protocol.value.lifecycle),
    };
  }
}

export type CloudflareEcdsaLaneSourceMaterialV1 =
  | {
      readonly kind: 'lane_material';
      readonly lookup: {
        readonly identity: EcdsaSigningWorkerLaneMaterialIdentityV1;
        readonly admittedLaneIdentityDigestB64u: DigestB64u;
      };
    }
  | {
      readonly kind: 'registration_activation';
      readonly lookup: {
        readonly accountId: EcdsaAdditiveLaneJobV1['walletId'];
        readonly materialActivationId: EcdsaAdditiveLaneJobV1['source']['materialActivation']['activationId'];
        readonly signingWorkerId: EcdsaAdditiveLaneJobV1['source']['signingWorkerParticipantId'];
      };
    };

export class LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1 implements EcdsaLanePrivateBindingResolverPortV1 {
  constructor(
    private readonly lifecycleStore: Pick<LaneLifecycleStore, 'getProductEpoch' | 'getProtocol'>,
  ) {}

  async resolveSourceMaterialV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
  }): Promise<CloudflareEcdsaLaneSourceMaterialV1> {
    const product = await this.lifecycleStore.getProductEpoch({
      walletId: input.job.walletId,
      walletKeyId: input.job.walletKeyId,
      laneId: input.job.source.laneId,
      laneShareEpoch: input.job.source.laneShareEpoch,
    });
    if (isRegistrationBackedSourceLane(input.job.source.laneKind)) {
      if (product !== null) {
        throw new Error('ECDSA registration-backed source conflicts with a lane product epoch');
      }
      return {
        kind: 'registration_activation',
        lookup: {
          accountId: input.job.walletId,
          materialActivationId: input.job.source.materialActivation.activationId,
          signingWorkerId: input.job.source.signingWorkerParticipantId,
        },
      };
    }
    if (product === null) {
      throw new Error('ECDSA lane-backed source product epoch is missing');
    }
    if (
      product.state !== 'active' ||
      product.keyFamily !== 'ecdsa_secp256k1' ||
      product.holderParticipant.participantId !== input.job.source.holderParticipantId ||
      product.signingWorkerParticipant.participantId !==
        input.job.source.signingWorkerParticipantId ||
      product.signingWorkerParticipant.recipientKeyId !==
        input.job.source.signingWorkerRecipientKeyId ||
      !mpcMaterialActivationRefsEqual(
        product.materialActivation,
        input.job.source.materialActivation,
      )
    ) {
      throw new Error('ECDSA source product epoch does not match the admitted job');
    }
    const protocol = await this.lifecycleStore.getProtocol(product.operationId);
    if (protocol === null || protocol.value.lifecycle.state !== 'active') {
      throw new Error('ECDSA source product protocol is not active');
    }
    const identity = identityFromActiveProductV1(product, protocol.value.lifecycle);
    return {
      kind: 'lane_material',
      lookup: {
        identity,
        admittedLaneIdentityDigestB64u: await digestSigningWorkerLaneIdentityV1(identity),
      },
    };
  }

  async resolveActivationBindingV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  }): Promise<{
    readonly identity: EcdsaSigningWorkerLaneMaterialIdentityV1;
    readonly targetMaterialActivation: MpcMaterialActivationRef;
  }> {
    const receipt = parseLaneProtocolCommitReceiptV1(input.protocolCommitReceipt);
    const identity = await identityFromProtocolReceiptV1(input.job, receipt);
    return {
      identity,
      targetMaterialActivation: buildMpcMaterialActivationRef({
        activationId: input.job.targetMaterialActivationId,
        capability: input.job.source.materialActivation.capability,
        materialOwner: input.job.source.materialActivation.materialOwner,
        keyBinding: input.job.source.materialActivation.keyBinding,
        lifecycleBinding: input.job.source.materialActivation.lifecycleBinding,
        signingWorker: targetSigningWorkerRefV1(input.job),
      }),
    };
  }

  async resolveRetirementBindingV1(input: {
    readonly command: RevokeSigningLaneV1;
  }): Promise<EcdsaServerRetirementBindingV1> {
    const product = await this.lifecycleStore.getProductEpoch({
      walletId: input.command.walletId,
      walletKeyId: input.command.walletKeyId,
      laneId: input.command.laneId,
      laneShareEpoch: input.command.laneShareEpoch,
    });
    if (
      product === null ||
      product.keyFamily !== 'ecdsa_secp256k1' ||
      (product.state !== 'active' &&
        product.state !== 'revocation_pending' &&
        product.state !== 'revoked') ||
      !retirementProductMatchesCommandV1(product, input.command)
    ) {
      throw new Error('ECDSA retirement source product is not the exact active epoch');
    }
    const protocol = await this.lifecycleStore.getProtocol(product.operationId);
    if (
      protocol === null ||
      protocol.value.lifecycle.state !== 'active' ||
      protocol.value.job.keyFamily !== 'ecdsa_secp256k1'
    ) {
      throw new Error('ECDSA retirement protocol is not active');
    }
    const job = protocol.value.job;
    return {
      identity: identityFromActiveProductV1(product, protocol.value.lifecycle),
      manifest: {
        manifestId: job.targetCapability.manifestId,
        manifestRevision: job.targetCapability.manifestRevision,
      },
      materialActivation: product.materialActivation,
      serverGeneration: job.sourceCapability.serverGeneration,
      lifecycleId: parseEcdsaLifecycleId(product.materialActivation.lifecycleBinding),
    };
  }
}

function targetSigningWorkerRefV1(
  job: EcdsaAdditiveLaneJobV1,
): MpcMaterialActivationRef['signingWorker'] {
  const parsed = parseMpcSigningWorkerRef(job.targetSigningWorker.participantId);
  if (!parsed.ok) {
    throw new Error(`ECDSA target SigningWorker is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

function isRegistrationBackedSourceLane(
  laneKind: EcdsaAdditiveLaneJobV1['source']['laneKind'],
): boolean {
  switch (laneKind) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'recovery':
    case 'break_glass':
      return true;
    case 'linked_device':
    case 'delegated_execution':
      return false;
  }
}

export type CloudflareSigningWorkerEcdsaLaneTransportOptionsV1 = {
  readonly signingWorker: { fetch(request: Request): Promise<Response> };
  readonly internalServiceAuth: string;
  readonly bindingResolver: EcdsaLanePrivateBindingResolverPortV1;
  readonly retirementTransport: Pick<
    SigningWorkerLaneMaterialReceiptPortV1,
    'retireServerMaterialV1'
  >;
};

export type CloudflareSigningWorkerEcdsaRetirementTransportOptionsV1 = {
  readonly signingWorker: { fetch(request: Request): Promise<Response> };
  readonly internalServiceAuth: string;
  readonly bindingResolver: Pick<
    EcdsaLanePrivateBindingResolverPortV1,
    'resolveRetirementBindingV1'
  >;
  readonly ed25519BindingResolver: Ed25519LanePrivateBindingResolverPortV1;
};

export class CloudflareSigningWorkerEcdsaRetirementTransportV1 implements Pick<
  SigningWorkerLaneMaterialReceiptPortV1,
  'retireServerMaterialV1'
> {
  private readonly internalServiceAuth: string;

  constructor(private readonly options: CloudflareSigningWorkerEcdsaRetirementTransportOptionsV1) {
    this.internalServiceAuth = requiredText(options.internalServiceAuth, 'internalServiceAuth');
  }

  async retireServerMaterialV1(input: {
    readonly curve: 'ed25519_yao' | 'ecdsa_additive';
    readonly command: RevokeSigningLaneV1;
  }): Promise<SigningWorkerLaneRetirementProjectionV1> {
    if (input.curve === 'ed25519_yao') {
      const binding = await this.options.ed25519BindingResolver.resolveRetirementBindingV1({
        command: input.command,
      });
      const request = buildEd25519ServerRetirementRequestV1({
        command: input.command,
        binding,
      });
      const raw = await postSigningWorkerJsonV1({
        binding: this.options.signingWorker,
        internalServiceAuth: this.internalServiceAuth,
        path: CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_LANE_RETIRE_PATH_V1,
        body: request,
      });
      const effect = await parseAndVerifyEd25519ServerRetirementEffectV1({ raw, request });
      return {
        kind: 'signing_worker_lane_retirement_projection_v1',
        outcome: effect.outcome,
        command: input.command,
        retirementEffectBindingDigestB64u: effect.retirementEffectBindingDigestB64u,
        retirementReceipt: effect.receipt,
      };
    }
    const binding = await this.options.bindingResolver.resolveRetirementBindingV1({
      command: input.command,
    });
    const request = buildEcdsaServerRetirementRequestV1({ command: input.command, binding });
    const raw = await postSigningWorkerJsonV1({
      binding: this.options.signingWorker,
      internalServiceAuth: this.internalServiceAuth,
      path: CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_RETIRE_PATH_V1,
      body: request,
    });
    const effect = await parseAndVerifyEcdsaServerRetirementEffectV1({
      raw,
      expectation: {
        manifest: binding.manifest,
        materialActivation: binding.materialActivation,
        walletKeyId: input.command.walletKeyId,
        laneId: input.command.laneId,
        laneShareEpoch: input.command.laneShareEpoch,
        revocationEpoch: input.command.expectedRevocationEpoch,
        retirementReason: request.retirementReason,
        retirementCorrelationId: request.retirementCorrelationId,
        retirementRequestDigestB64u: request.retirementRequestDigestB64u,
        serverGeneration: binding.serverGeneration,
        lifecycleId: binding.lifecycleId,
        retirementEffectBindingDigestB64u: request.retirementEffectBindingDigestB64u,
      },
    });
    return {
      kind: 'signing_worker_lane_retirement_projection_v1',
      outcome: effect.outcome,
      command: input.command,
      retirementEffectBindingDigestB64u: effect.retirementEffectBindingDigestB64u,
      retirementReceipt: effect.receipt,
    };
  }
}

export class CloudflareSigningWorkerEcdsaLaneTransportV1 implements SigningWorkerLaneMaterialReceiptPortV1 {
  private readonly internalServiceAuth: string;

  constructor(private readonly options: CloudflareSigningWorkerEcdsaLaneTransportOptionsV1) {
    this.internalServiceAuth = requiredText(options.internalServiceAuth, 'internalServiceAuth');
  }

  async commitEcdsaProtocolV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
    readonly holderPackage: Extract<
      LaneHolderPackageWireV1,
      { kind: 'ecdsa_additive_lane_holder_package_v1' }
    >;
    readonly encryptedDeltaPackageJson: string;
  }): Promise<SigningWorkerLaneProtocolCommitProjectionV1> {
    const sourceMaterial = await this.options.bindingResolver.resolveSourceMaterialV1({
      job: input.job,
    });
    const holderPackage = parseJsonRecord(
      input.holderPackage.ecdsaEncryptedMaterialEnvelopeJson,
      'holderPackage.ecdsaEncryptedMaterialEnvelopeJson',
    );
    const encryptedDelta = parseJsonRecord(
      input.encryptedDeltaPackageJson,
      'encryptedDeltaPackageJson',
    );
    const response = await postSigningWorkerJsonV1({
      binding: this.options.signingWorker,
      internalServiceAuth: this.internalServiceAuth,
      path: CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_EXECUTE_PATH_V1,
      body: {
        job: input.job,
        holderRound: input.holderRound,
        holderPackage,
        encryptedDelta,
        sourceMaterial,
      },
    });
    const effect = exactRecord(response, ['outcome', 'receipt'], 'ecdsaLaneExecuteEffect');
    return {
      kind: 'signing_worker_lane_protocol_commit_projection_v1',
      outcome: parseMutationOutcome(
        Reflect.get(effect, 'outcome'),
        'ecdsaLaneExecuteEffect.outcome',
      ),
      receipt: parseLaneProtocolCommitReceiptV1(Reflect.get(effect, 'receipt')),
    };
  }

  async activateServerMaterialV1(
    input:
      | {
          readonly curve: 'ed25519_yao';
          readonly job: Ed25519YaoLaneJobV1;
          readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
          readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
        }
      | {
          readonly curve: 'ecdsa_additive';
          readonly job: EcdsaAdditiveLaneJobV1;
          readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
          readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
        },
  ): Promise<SigningWorkerLaneServerActivationProjectionV1> {
    const binding =
      input.curve === 'ecdsa_additive'
        ? await this.options.bindingResolver.resolveActivationBindingV1({
            job: input.job,
            protocolCommitReceipt: input.protocolCommitReceipt,
          })
        : await buildEd25519ActivationBindingV1({
            job: input.job,
            protocolCommitReceipt: input.protocolCommitReceipt,
          });
    const response = await postSigningWorkerJsonV1({
      binding: this.options.signingWorker,
      internalServiceAuth: this.internalServiceAuth,
      path:
        input.curve === 'ecdsa_additive'
          ? CLOUDFLARE_SIGNING_WORKER_ECDSA_LANE_ACTIVATE_PATH_V1
          : CLOUDFLARE_SIGNING_WORKER_ED25519_YAO_LANE_ACTIVATE_PATH_V1,
      body: {
        identity: binding.identity,
        targetMaterialActivation: binding.targetMaterialActivation,
        holderDeliveryReceipt: input.holderDeliveryReceipt,
      },
    });
    const effect = exactRecord(
      response,
      ['outcome', 'receipt'],
      input.curve === 'ecdsa_additive' ? 'ecdsaLaneActivateEffect' : 'ed25519LaneActivateEffect',
    );
    return {
      kind: 'signing_worker_lane_server_activation_projection_v1',
      outcome: parseMutationOutcome(
        Reflect.get(effect, 'outcome'),
        input.curve === 'ecdsa_additive'
          ? 'ecdsaLaneActivateEffect.outcome'
          : 'ed25519LaneActivateEffect.outcome',
      ),
      receipt: parseLaneServerActivationReceiptV1(Reflect.get(effect, 'receipt')),
    };
  }

  async retireServerMaterialV1(input: {
    readonly curve: 'ed25519_yao' | 'ecdsa_additive';
    readonly command: RevokeSigningLaneV1;
  }): Promise<SigningWorkerLaneRetirementProjectionV1> {
    return await this.options.retirementTransport.retireServerMaterialV1(input);
  }
}

export type CloudflareLaneCurveExecutionOptionsV1 = {
  readonly ed25519Transport: CloudflareEd25519LaneProtocolTransportV1;
  readonly signingWorker: SigningWorkerLaneMaterialReceiptPortV1;
};

export function createCloudflareLaneCurveExecutionPortsV1(
  options: CloudflareLaneCurveExecutionOptionsV1,
): LaneLifecycleCurveExecutionPortsV1 {
  return {
    ed25519: {
      async executeProtocolCommitV1(input) {
        const execution = await options.ed25519Transport.executeProtocolCommitV1(input);
        return parseLaneProtocolCommitReceiptV1(execution.receipt);
      },
      async executeServerActivationV1(input) {
        const projection = await options.signingWorker.activateServerMaterialV1({
          curve: 'ed25519_yao',
          ...input,
        });
        requireProjection(projection, 'signing_worker_lane_server_activation_projection_v1');
        return parseLaneServerActivationReceiptV1(projection.receipt);
      },
      async executeServerRetirementV1(input) {
        return retirementExecution(
          await options.signingWorker.retireServerMaterialV1({
            curve: 'ed25519_yao',
            command: input.command,
          }),
        );
      },
    },
    ecdsa: {
      async executeProtocolCommitV1(input) {
        const projection = await options.signingWorker.commitEcdsaProtocolV1(input);
        requireProjection(projection, 'signing_worker_lane_protocol_commit_projection_v1');
        return parseLaneProtocolCommitReceiptV1(projection.receipt);
      },
      async executeServerActivationV1(input) {
        const projection = await options.signingWorker.activateServerMaterialV1({
          curve: 'ecdsa_additive',
          ...input,
        });
        requireProjection(projection, 'signing_worker_lane_server_activation_projection_v1');
        return parseLaneServerActivationReceiptV1(projection.receipt);
      },
      async executeServerRetirementV1(input) {
        return retirementExecution(
          await options.signingWorker.retireServerMaterialV1({
            curve: 'ecdsa_additive',
            command: input.command,
          }),
        );
      },
    },
  };
}

function retirementExecution(
  projection: SigningWorkerLaneRetirementProjectionV1,
): LaneLifecycleRetirementExecutionV1 {
  requireProjection(projection, 'signing_worker_lane_retirement_projection_v1');
  const command = parseRevokeSigningLaneV1(projection.command);
  if (
    typeof projection.retirementEffectBindingDigestB64u !== 'string' ||
    projection.retirementEffectBindingDigestB64u.length === 0
  )
    throw new Error('SigningWorker lane retirement effect binding digest is invalid');
  return {
    kind: 'lane_lifecycle_retirement_execution_v1',
    command,
    retirementEffectBindingDigestB64u: parseDigestB64u(
      projection.retirementEffectBindingDigestB64u,
    ),
    retirementReceipt: projection.retirementReceipt,
  };
}

function requireProjection(
  projection: {
    readonly kind: string;
    readonly outcome: string;
  },
  expectedKind:
    | 'signing_worker_lane_protocol_commit_projection_v1'
    | 'signing_worker_lane_server_activation_projection_v1'
    | 'signing_worker_lane_retirement_projection_v1',
): void {
  if (projection.kind !== expectedKind) {
    throw new Error('SigningWorker lane material projection kind is invalid');
  }
  if (projection.outcome !== 'applied' && projection.outcome !== 'replayed') {
    throw new Error('SigningWorker lane material projection outcome is invalid');
  }
}

function requiredText(value: string, label: string): string {
  const normalized = value.trim();
  if (normalized.length === 0) throw new Error(`${label} is required`);
  return normalized;
}

function requiredTextValue(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return requiredText(value, label);
}

function identityFromActiveProductV1(
  product:
    | LaneProductEpochActiveV1
    | LaneProductEpochRevocationPendingV1
    | LaneProductEpochRevokedV1,
  lifecycle: Extract<LaneProtocolLifecycle, { state: 'active' }>,
): EcdsaSigningWorkerLaneMaterialIdentityV1 {
  if (product.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA source product has the wrong key family');
  }
  return {
    operationId: product.operationId,
    enrollmentId: product.enrollmentId,
    walletId: product.walletId,
    walletKeyId: product.walletKeyId,
    targetLaneId: product.laneId,
    targetLaneShareEpoch: product.laneShareEpoch,
    targetMaterialActivationId: product.targetMaterialActivationId,
    keyFamily: 'ecdsa_secp256k1',
    holderParticipantBindingDigestB64u: product.holderParticipant.participantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u:
      product.signingWorkerParticipant.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: product.holderParticipant.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: product.signingWorkerParticipant.hpkePublicKeyDigestB64u,
    transcriptHashB64u: parseDigestB64u(lifecycle.transcriptHashB64u),
    protocolCommitReceiptDigestB64u: parseDigestB64u(lifecycle.protocolCommitReceiptDigestB64u),
  };
}

function ed25519IdentityFromActiveProductV1(
  product:
    | LaneProductEpochActiveV1
    | LaneProductEpochRevocationPendingV1
    | LaneProductEpochRevokedV1,
  lifecycle: Extract<LaneProtocolLifecycle, { state: 'active' }>,
): SigningWorkerLaneMaterialIdentityV1<'ed25519'> {
  if (product.keyFamily !== 'ed25519') {
    throw new Error('Ed25519 source product has the wrong key family');
  }
  return {
    operationId: product.operationId,
    enrollmentId: product.enrollmentId,
    walletId: product.walletId,
    walletKeyId: product.walletKeyId,
    targetLaneId: product.laneId,
    targetLaneShareEpoch: product.laneShareEpoch,
    targetMaterialActivationId: product.targetMaterialActivationId,
    keyFamily: 'ed25519',
    holderParticipantBindingDigestB64u: product.holderParticipant.participantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u:
      product.signingWorkerParticipant.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: product.holderParticipant.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: product.signingWorkerParticipant.hpkePublicKeyDigestB64u,
    transcriptHashB64u: parseDigestB64u(lifecycle.transcriptHashB64u),
    protocolCommitReceiptDigestB64u: parseDigestB64u(lifecycle.protocolCommitReceiptDigestB64u),
  };
}

function retirementProductMatchesCommandV1(
  product:
    | LaneProductEpochActiveV1
    | LaneProductEpochRevocationPendingV1
    | LaneProductEpochRevokedV1,
  command: RevokeSigningLaneV1,
): boolean {
  if (product.state === 'active') {
    return product.revocationEpoch === command.expectedRevocationEpoch;
  }
  return (
    product.revocationEpoch === command.expectedRevocationEpoch + 1 &&
    product.retirementEffectBindingDigestB64u === command.retirementEffectBindingDigestB64u
  );
}

async function identityFromProtocolReceiptV1(
  job: EcdsaAdditiveLaneJobV1,
  receipt: LaneProtocolCommitReceiptV1,
): Promise<EcdsaSigningWorkerLaneMaterialIdentityV1> {
  if (
    receipt.operationId !== job.operationId ||
    receipt.enrollmentId !== job.enrollmentId ||
    receipt.walletId !== job.walletId ||
    receipt.walletKeyId !== job.walletKeyId ||
    receipt.targetLaneId !== job.target.laneId ||
    receipt.targetLaneShareEpoch !== job.target.laneShareEpoch ||
    receipt.targetMaterialActivationId !== job.targetMaterialActivationId ||
    receipt.keyFamily !== 'ecdsa_secp256k1'
  ) {
    throw new Error('ECDSA protocol receipt does not match the admitted job');
  }
  return {
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    targetLaneId: job.target.laneId,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    keyFamily: 'ecdsa_secp256k1',
    holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: job.targetSigningWorker.hpkePublicKeyDigestB64u,
    transcriptHashB64u: parseDigestB64u(receipt.transcriptHashB64u),
    protocolCommitReceiptDigestB64u: parseDigestB64u(
      base64UrlEncode(await sha256Bytes(encodeLaneProtocolCommitReceiptV1(receipt))),
    ),
  };
}

async function buildEd25519ActivationBindingV1(input: {
  readonly job: Ed25519YaoLaneJobV1;
  readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
}): Promise<{
  readonly identity: SigningWorkerLaneMaterialIdentityV1<'ed25519'>;
  readonly targetMaterialActivation: MpcMaterialActivationRef;
}> {
  const receipt = parseLaneProtocolCommitReceiptV1(input.protocolCommitReceipt);
  if (
    receipt.operationId !== input.job.operationId ||
    receipt.enrollmentId !== input.job.enrollmentId ||
    receipt.walletId !== input.job.walletId ||
    receipt.walletKeyId !== input.job.walletKeyId ||
    receipt.targetLaneId !== input.job.target.laneId ||
    receipt.targetLaneShareEpoch !== input.job.target.laneShareEpoch ||
    receipt.targetMaterialActivationId !== input.job.targetMaterialActivationId ||
    receipt.keyFamily !== 'ed25519'
  ) {
    throw new Error('Ed25519 protocol receipt does not match the admitted job');
  }
  const targetSigningWorker = parseMpcSigningWorkerRef(input.job.targetSigningWorker.participantId);
  if (!targetSigningWorker.ok) {
    throw new Error(
      `Ed25519 target SigningWorker is invalid: ${targetSigningWorker.error.message}`,
    );
  }
  return {
    identity: {
      operationId: input.job.operationId,
      enrollmentId: input.job.enrollmentId,
      walletId: input.job.walletId,
      walletKeyId: input.job.walletKeyId,
      targetLaneId: input.job.target.laneId,
      targetLaneShareEpoch: input.job.target.laneShareEpoch,
      targetMaterialActivationId: input.job.targetMaterialActivationId,
      keyFamily: 'ed25519',
      holderParticipantBindingDigestB64u: input.job.targetHolder.participantBindingDigestB64u,
      signingWorkerParticipantBindingDigestB64u:
        input.job.targetSigningWorker.participantBindingDigestB64u,
      holderRecipientKeyDigestB64u: input.job.targetHolder.hpkePublicKeyDigestB64u,
      serverRecipientKeyDigestB64u: input.job.targetSigningWorker.hpkePublicKeyDigestB64u,
      transcriptHashB64u: parseDigestB64u(receipt.transcriptHashB64u),
      protocolCommitReceiptDigestB64u: parseDigestB64u(
        base64UrlEncode(await sha256Bytes(encodeLaneProtocolCommitReceiptV1(receipt))),
      ),
    },
    targetMaterialActivation: buildMpcMaterialActivationRef({
      activationId: input.job.targetMaterialActivationId,
      capability: input.job.source.materialActivation.capability,
      materialOwner: input.job.source.materialActivation.materialOwner,
      keyBinding: input.job.source.materialActivation.keyBinding,
      lifecycleBinding: input.job.source.materialActivation.lifecycleBinding,
      signingWorker: targetSigningWorker.value,
    }),
  };
}

async function digestSigningWorkerLaneIdentityV1(
  identity: EcdsaSigningWorkerLaneMaterialIdentityV1,
): Promise<DigestB64u> {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [encoder.encode('seams/signing-worker/lane-material-identity/v1')];
  for (const value of [
    identity.operationId,
    identity.enrollmentId,
    identity.walletId,
    identity.walletKeyId,
    identity.targetLaneId,
    identity.targetLaneShareEpoch,
    identity.targetMaterialActivationId,
    identity.keyFamily,
    identity.holderParticipantBindingDigestB64u,
    identity.signingWorkerParticipantBindingDigestB64u,
    identity.holderRecipientKeyDigestB64u,
    identity.serverRecipientKeyDigestB64u,
    identity.transcriptHashB64u,
    identity.protocolCommitReceiptDigestB64u,
  ]) {
    const encoded = encoder.encode(value);
    chunks.push(u64Length(encoded.length), encoded);
  }
  let length = 0;
  for (const chunk of chunks) length += chunk.length;
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(bytes)));
}

function u64Length(value: number): Uint8Array {
  let remaining = BigInt(value);
  const bytes = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

type EcdsaLaneEncryptedPayloadWireV1 = {
  readonly kind: 'ecdsa_additive_lane_encrypted_payload_v1';
  readonly recipientPublicKeyB64u: string;
  readonly aadDigestB64u: string;
  readonly encappedKeyB64u: string;
  readonly ciphertextB64u: string;
};

function parseJsonRecord(value: string, label: string): EcdsaLaneEncryptedPayloadWireV1 {
  let parsed: unknown;
  try {
    parsed = JSON.parse(requiredText(value, label));
  } catch {
    throw new Error(`${label} must contain valid JSON`);
  }
  const record = exactObject(
    parsed,
    ['kind', 'recipientPublicKeyB64u', 'aadDigestB64u', 'encappedKeyB64u', 'ciphertextB64u'],
    label,
  );
  if (Reflect.get(record, 'kind') !== 'ecdsa_additive_lane_encrypted_payload_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  return {
    kind: 'ecdsa_additive_lane_encrypted_payload_v1',
    recipientPublicKeyB64u: requiredTextValue(
      Reflect.get(record, 'recipientPublicKeyB64u'),
      `${label}.recipientPublicKeyB64u`,
    ),
    aadDigestB64u: requiredTextValue(
      Reflect.get(record, 'aadDigestB64u'),
      `${label}.aadDigestB64u`,
    ),
    encappedKeyB64u: requiredTextValue(
      Reflect.get(record, 'encappedKeyB64u'),
      `${label}.encappedKeyB64u`,
    ),
    ciphertextB64u: requiredTextValue(
      Reflect.get(record, 'ciphertextB64u'),
      `${label}.ciphertextB64u`,
    ),
  };
}

function requireObject(value: unknown, label: string): object {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function exactObject(value: unknown, fields: readonly string[], label: string): object {
  const record = requireObject(value, label);
  const allowed = new Set(fields);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`${label}.${key} is unsupported`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) throw new Error(`${label}.${field} is required`);
  }
  return record;
}

function exactRecord(value: unknown, fields: readonly string[], label: string): object {
  return exactObject(value, fields, label);
}

function parseMutationOutcome(value: unknown, label: string): LaneMaterialMutationOutcomeV1 {
  if (value === 'applied' || value === 'replayed') return value;
  throw new Error(`${label} is invalid`);
}

async function postSigningWorkerJsonV1(input: {
  readonly binding: { fetch(request: Request): Promise<Response> };
  readonly internalServiceAuth: string;
  readonly path: string;
  readonly body: object;
}): Promise<unknown> {
  const response = await input.binding.fetch(
    new Request(`https://signing-worker.router-ab.internal${input.path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-router-ab-internal-service-auth': input.internalServiceAuth,
      },
      body: JSON.stringify(input.body),
    }),
  );
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`SigningWorker lane endpoint returned HTTP ${response.status}`);
  }
  try {
    return body.length === 0 ? null : JSON.parse(body);
  } catch {
    throw new Error('SigningWorker lane endpoint returned invalid JSON');
  }
}
