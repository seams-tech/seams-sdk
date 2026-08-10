import {
  computeEcdsaServerRetirementReceiptDigestV1,
  parseEcdsaServerRetirementReceiptV1,
} from '@shared/signing-lanes';
import type {
  EcdsaManifestIdentity,
  EcdsaServerRetirementReceiptV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import type { CorrelationId, DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  type LaneShareEpoch,
  type MpcMaterialActivationRef,
  type SigningLaneId,
  type WalletKeyId,
} from '@shared/utils/domainIds';
import type {
  EcdsaLifecycleId,
  EcdsaServerGeneration,
} from '@shared/utils/ecdsaCapabilityActivation';
import type { EcdsaSigningWorkerLaneMaterialIdentityV1 } from './signingWorkerLaneMaterialIdentity';

export type EcdsaServerRetirementBindingV1 = {
  readonly identity: EcdsaSigningWorkerLaneMaterialIdentityV1;
  readonly manifest: EcdsaManifestIdentity;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly serverGeneration: EcdsaServerGeneration;
  readonly lifecycleId: EcdsaLifecycleId;
};

export type EcdsaServerRetirementExpectationV1 = {
  readonly manifest: EcdsaManifestIdentity;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly revocationEpoch: number;
  readonly retirementReason: EcdsaServerRetirementReceiptV1['retirementReason'];
  readonly retirementCorrelationId: CorrelationId;
  readonly retirementRequestDigestB64u: DigestB64u;
  readonly serverGeneration: EcdsaServerGeneration;
  readonly lifecycleId: EcdsaLifecycleId;
  /** Gateway's pre-authorized effect fence. It is distinct from receiptDigestB64u. */
  readonly retirementEffectBindingDigestB64u: DigestB64u;
};

export type EcdsaServerRetirementRequestV1 = {
  readonly identity: EcdsaSigningWorkerLaneMaterialIdentityV1;
  readonly manifest: EcdsaManifestIdentity;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly revocationEpoch: number;
  readonly retirementReason: EcdsaServerRetirementReceiptV1['retirementReason'];
  readonly retirementCorrelationId: CorrelationId;
  readonly retirementRequestDigestB64u: DigestB64u;
  readonly retirementEffectBindingDigestB64u: DigestB64u;
  readonly serverGeneration: EcdsaServerGeneration;
  readonly lifecycleId: EcdsaLifecycleId;
};

export type EcdsaServerRetirementEffectV1 = {
  readonly outcome: 'applied' | 'replayed';
  readonly receipt: EcdsaServerRetirementReceiptV1;
  /** The effect fence that the Gateway completion must retain. */
  readonly retirementReceiptDigestB64u: DigestB64u;
};

export function buildEcdsaServerRetirementRequestV1(input: {
  readonly command: RevokeSigningLaneV1;
  readonly binding: EcdsaServerRetirementBindingV1;
}): EcdsaServerRetirementRequestV1 {
  assertIdentityMatchesCommand(input.binding, input.command);
  const retirementReason = retirementReasonForCommand(input.command.reason);
  const request: EcdsaServerRetirementRequestV1 = {
    identity: input.binding.identity,
    manifest: input.binding.manifest,
    materialActivation: input.binding.materialActivation,
    revocationEpoch: input.command.expectedRevocationEpoch,
    retirementReason,
    retirementCorrelationId: input.command.retirementCorrelationId,
    retirementRequestDigestB64u: parseDigestB64u(input.command.retirementRequestDigestB64u),
    retirementEffectBindingDigestB64u: parseDigestB64u(
      input.command.retirementEffectBindingDigestB64u,
    ),
    serverGeneration: input.binding.serverGeneration,
    lifecycleId: input.binding.lifecycleId,
  };
  return request;
}

function assertIdentityMatchesCommand(
  binding: EcdsaServerRetirementBindingV1,
  command: RevokeSigningLaneV1,
): void {
  const identity = binding.identity;
  if (
    identity.keyFamily !== 'ecdsa_secp256k1' ||
    identity.walletId !== command.walletId ||
    identity.walletKeyId !== command.walletKeyId ||
    identity.targetLaneId !== command.laneId ||
    identity.targetLaneShareEpoch !== command.laneShareEpoch ||
    identity.targetMaterialActivationId !== binding.materialActivation.activationId
  ) {
    throw new Error('ECDSA retirement binding identity does not match the authorized command');
  }
}

export async function parseAndVerifyEcdsaServerRetirementEffectV1(input: {
  readonly raw: unknown;
  readonly expectation: EcdsaServerRetirementExpectationV1;
  readonly label?: string;
}): Promise<EcdsaServerRetirementEffectV1> {
  const label = input.label ?? 'ecdsaLaneRetireEffect';
  const effect = exactEffectEnvelope(input.raw, label);
  const outcome = parseOutcome(effect.outcome, `${label}.outcome`);
  const receipt = parseEcdsaServerRetirementReceiptV1(effect.receipt, `${label}.receipt`);
  assertReceiptMatchesExpectation(receipt, input.expectation);
  const canonicalDigest = await computeEcdsaServerRetirementReceiptDigestV1(receipt);
  if (receipt.receiptDigestB64u !== canonicalDigest) {
    throw new Error(`${label}.receipt.receiptDigestB64u does not match its canonical digest`);
  }
  return {
    outcome,
    receipt,
    retirementReceiptDigestB64u: input.expectation.retirementEffectBindingDigestB64u,
  };
}

export function assertEcdsaServerRetirementReceiptMatchesExpectationV1(
  receipt: EcdsaServerRetirementReceiptV1,
  expectation: EcdsaServerRetirementExpectationV1,
): void {
  assertReceiptMatchesExpectation(receipt, expectation);
}

function assertReceiptMatchesExpectation(
  receipt: EcdsaServerRetirementReceiptV1,
  expectation: EcdsaServerRetirementExpectationV1,
): void {
  if (
    receipt.manifest.manifestId !== expectation.manifest.manifestId ||
    receipt.manifest.manifestRevision !== expectation.manifest.manifestRevision ||
    !mpcMaterialActivationRefsEqual(receipt.materialActivation, expectation.materialActivation) ||
    receipt.walletKeyId !== expectation.walletKeyId ||
    receipt.laneId !== expectation.laneId ||
    receipt.laneShareEpoch !== expectation.laneShareEpoch ||
    receipt.revocationEpoch !== expectation.revocationEpoch ||
    receipt.retirementReason !== expectation.retirementReason ||
    receipt.retirementCorrelationId !== expectation.retirementCorrelationId ||
    receipt.retirementRequestDigestB64u !== expectation.retirementRequestDigestB64u ||
    receipt.serverGeneration !== expectation.serverGeneration ||
    receipt.lifecycleId !== expectation.lifecycleId
  ) {
    throw new Error('ECDSA retirement receipt does not match the admitted lane binding');
  }
}

function retirementReasonForCommand(
  reason: RevokeSigningLaneV1['reason'],
): EcdsaServerRetirementReceiptV1['retirementReason'] {
  switch (reason) {
    case 'user_revoked':
    case 'policy_revoked':
      return 'lane_revoked';
    case 'device_compromise':
      return 'device_compromise';
    case 'agent_compromise':
      return 'agent_compromise';
    case 'rotation':
      return 'rotation';
  }
}

type EcdsaServerRetirementEffectEnvelopeV1 = {
  readonly outcome: unknown;
  readonly receipt: unknown;
};

function exactEffectEnvelope(value: unknown, label: string): EcdsaServerRetirementEffectEnvelopeV1 {
  if (!isObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  const fields = ['outcome', 'receipt'] as const;
  const allowed = new Set<string>(fields);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${label}.${key} is unsupported`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(value, field)) throw new Error(`${label}.${field} is required`);
  }
  return {
    outcome: Reflect.get(value, 'outcome'),
    receipt: Reflect.get(value, 'receipt'),
  };
}

function isObject(value: unknown): value is object {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseOutcome(value: unknown, label: string): 'applied' | 'replayed' {
  if (value === 'applied' || value === 'replayed') return value;
  throw new Error(`${label} is invalid`);
}
