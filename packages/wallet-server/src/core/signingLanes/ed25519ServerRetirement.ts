import {
  computeEd25519ServerRetirementReceiptDigestV1,
  parseEd25519ServerRetirementReceiptV1,
} from '@shared/signing-lanes';
import type {
  Ed25519ServerRetirementReceiptV1,
  RevokeSigningLaneV1,
  SigningWorkerLaneMaterialIdentityV1,
} from '@shared/signing-lanes';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';

export type Ed25519ServerRetirementBindingV1 = {
  readonly identity: SigningWorkerLaneMaterialIdentityV1<'ed25519'>;
};

export type Ed25519ServerRetirementRequestV1 = {
  readonly identity: SigningWorkerLaneMaterialIdentityV1<'ed25519'>;
  readonly revocationEpoch: number;
  readonly retirementReason: Ed25519ServerRetirementReceiptV1['retirementReason'];
  readonly retirementCorrelationId: RevokeSigningLaneV1['retirementCorrelationId'];
  readonly retirementRequestDigestB64u: DigestB64u;
  readonly retirementEffectBindingDigestB64u: DigestB64u;
};

export type Ed25519ServerRetirementEffectV1 = {
  readonly outcome: 'applied' | 'replayed';
  readonly receipt: Ed25519ServerRetirementReceiptV1;
  readonly retirementEffectBindingDigestB64u: DigestB64u;
  readonly retirementReceiptDigestB64u: DigestB64u;
};

export function buildEd25519ServerRetirementRequestV1(input: {
  readonly command: RevokeSigningLaneV1;
  readonly binding: Ed25519ServerRetirementBindingV1;
}): Ed25519ServerRetirementRequestV1 {
  assertIdentityMatchesCommand(input.binding.identity, input.command);
  return {
    identity: input.binding.identity,
    revocationEpoch: input.command.expectedRevocationEpoch,
    retirementReason: retirementReasonForCommand(input.command.reason),
    retirementCorrelationId: input.command.retirementCorrelationId,
    retirementRequestDigestB64u: parseDigestB64u(input.command.retirementRequestDigestB64u),
    retirementEffectBindingDigestB64u: parseDigestB64u(
      input.command.retirementEffectBindingDigestB64u,
    ),
  };
}

export async function parseAndVerifyEd25519ServerRetirementEffectV1(input: {
  readonly raw: unknown;
  readonly request: Ed25519ServerRetirementRequestV1;
  readonly label?: string;
}): Promise<Ed25519ServerRetirementEffectV1> {
  const label = input.label ?? 'ed25519LaneRetireEffect';
  const envelope = exactEffectEnvelope(input.raw, label);
  const outcome = parseOutcome(envelope.outcome, `${label}.outcome`);
  const receipt = parseEd25519ServerRetirementReceiptV1(envelope.receipt, `${label}.receipt`);
  assertReceiptMatchesRequest(receipt, input.request);
  const canonicalDigest = await computeEd25519ServerRetirementReceiptDigestV1(receipt);
  if (receipt.receiptDigestB64u !== canonicalDigest) {
    throw new Error(`${label}.receipt.receiptDigestB64u does not match its canonical digest`);
  }
  return {
    outcome,
    receipt,
    retirementEffectBindingDigestB64u: input.request.retirementEffectBindingDigestB64u,
    retirementReceiptDigestB64u: canonicalDigest,
  };
}

export function assertEd25519ServerRetirementReceiptMatchesRequestV1(
  receipt: Ed25519ServerRetirementReceiptV1,
  request: Ed25519ServerRetirementRequestV1,
): void {
  assertReceiptMatchesRequest(receipt, request);
}

function assertIdentityMatchesCommand(
  identity: SigningWorkerLaneMaterialIdentityV1<'ed25519'>,
  command: RevokeSigningLaneV1,
): void {
  if (
    identity.keyFamily !== 'ed25519' ||
    identity.walletId !== command.walletId ||
    identity.walletKeyId !== command.walletKeyId ||
    identity.targetLaneId !== command.laneId ||
    identity.targetLaneShareEpoch !== command.laneShareEpoch
  ) {
    throw new Error('Ed25519 retirement binding identity does not match the authorized command');
  }
}

function assertReceiptMatchesRequest(
  receipt: Ed25519ServerRetirementReceiptV1,
  request: Ed25519ServerRetirementRequestV1,
): void {
  if (
    !identitiesEqual(receipt.identity, request.identity) ||
    receipt.revocationEpoch !== request.revocationEpoch ||
    receipt.retirementReason !== request.retirementReason ||
    receipt.retirementCorrelationId !== request.retirementCorrelationId ||
    receipt.retirementRequestDigestB64u !== request.retirementRequestDigestB64u
  ) {
    throw new Error('Ed25519 retirement receipt does not match the admitted lane binding');
  }
}

function identitiesEqual(
  left: SigningWorkerLaneMaterialIdentityV1<'ed25519'>,
  right: SigningWorkerLaneMaterialIdentityV1<'ed25519'>,
): boolean {
  return (
    left.operationId === right.operationId &&
    left.enrollmentId === right.enrollmentId &&
    left.walletId === right.walletId &&
    left.walletKeyId === right.walletKeyId &&
    left.targetLaneId === right.targetLaneId &&
    left.targetLaneShareEpoch === right.targetLaneShareEpoch &&
    left.targetMaterialActivationId === right.targetMaterialActivationId &&
    left.keyFamily === right.keyFamily &&
    left.holderParticipantBindingDigestB64u === right.holderParticipantBindingDigestB64u &&
    left.signingWorkerParticipantBindingDigestB64u ===
      right.signingWorkerParticipantBindingDigestB64u &&
    left.holderRecipientKeyDigestB64u === right.holderRecipientKeyDigestB64u &&
    left.serverRecipientKeyDigestB64u === right.serverRecipientKeyDigestB64u &&
    left.transcriptHashB64u === right.transcriptHashB64u &&
    left.protocolCommitReceiptDigestB64u === right.protocolCommitReceiptDigestB64u
  );
}

function retirementReasonForCommand(
  reason: RevokeSigningLaneV1['reason'],
): Ed25519ServerRetirementReceiptV1['retirementReason'] {
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

function exactEffectEnvelope(
  value: unknown,
  label: string,
): { readonly outcome: unknown; readonly receipt: unknown } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
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

function parseOutcome(value: unknown, label: string): 'applied' | 'replayed' {
  if (value === 'applied' || value === 'replayed') return value;
  throw new Error(`${label} is invalid`);
}
