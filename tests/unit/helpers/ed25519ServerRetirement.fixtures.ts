import type {
  Ed25519ServerRetirementReceiptV1,
  RevokeSigningLaneV1,
  SigningWorkerLaneMaterialIdentityV1,
} from '../../../packages/shared-ts/src/signing-lanes';
import {
  computeEd25519ServerRetirementReceiptDigestV1,
  computeLaneProtocolCommitReceiptDigestV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotationDigests';
import {
  parseEd25519ServerRetirementReceiptV1,
  parseSigningWorkerLaneMaterialIdentityV1,
} from '../../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import { buildR102LaneJob, buildR102ProtocolCommitReceipt } from './r102LaneGateway.fixtures';

export async function buildR102Ed25519LaneMaterialIdentityFixture(): Promise<
  SigningWorkerLaneMaterialIdentityV1<'ed25519'>
> {
  const job = buildR102LaneJob('ed25519-retirement');
  const protocolReceipt = buildR102ProtocolCommitReceipt(job);
  return parseSigningWorkerLaneMaterialIdentityV1(
    {
      operationId: job.operationId,
      enrollmentId: job.enrollmentId,
      walletId: job.walletId,
      walletKeyId: job.walletKeyId,
      targetLaneId: job.target.laneId,
      targetLaneShareEpoch: job.target.laneShareEpoch,
      targetMaterialActivationId: job.targetMaterialActivationId,
      keyFamily: 'ed25519',
      holderParticipantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
      signingWorkerParticipantBindingDigestB64u:
        job.targetSigningWorker.participantBindingDigestB64u,
      holderRecipientKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      serverRecipientKeyDigestB64u: job.targetSigningWorker.hpkePublicKeyDigestB64u,
      transcriptHashB64u: protocolReceipt.transcriptHashB64u,
      protocolCommitReceiptDigestB64u:
        await computeLaneProtocolCommitReceiptDigestV1(protocolReceipt),
    },
    'ed25519',
  );
}

export async function buildR102Ed25519ServerRetirementReceiptFixture(input: {
  readonly command: RevokeSigningLaneV1;
  readonly identity: SigningWorkerLaneMaterialIdentityV1<'ed25519'>;
  readonly retiredAtMs?: number;
}): Promise<Ed25519ServerRetirementReceiptV1> {
  const receipt = parseEd25519ServerRetirementReceiptV1({
    kind: 'ed25519_server_retirement_receipt_v1',
    identity: input.identity,
    revocationEpoch: input.command.expectedRevocationEpoch,
    retirementReason: retirementReason(input.command.reason),
    retirementCorrelationId: input.command.retirementCorrelationId,
    retirementRequestDigestB64u: input.command.retirementRequestDigestB64u,
    receiptDigestB64u: parseDigestB64u(Buffer.alloc(32).toString('base64url')),
    retiredAtMs: input.retiredAtMs ?? input.command.requestedAtMs,
  });
  return parseEd25519ServerRetirementReceiptV1({
    ...receipt,
    receiptDigestB64u: await computeEd25519ServerRetirementReceiptDigestV1(receipt),
  });
}

export function buildR102Ed25519RetirementParityReceiptFixture(): Ed25519ServerRetirementReceiptV1 {
  return parseEd25519ServerRetirementReceiptV1({
    kind: 'ed25519_server_retirement_receipt_v1',
    identity: {
      operationId: 'operation-ed-retire',
      enrollmentId: 'enrollment-ed-retire',
      walletId: 'wallet-ed-retire',
      walletKeyId: 'wallet-key-ed-retire',
      targetLaneId: 'lane-ed-retire',
      targetLaneShareEpoch: 'epoch-ed-retire',
      targetMaterialActivationId: 'activation-ed-retire',
      keyFamily: 'ed25519',
      holderParticipantBindingDigestB64u: parityDigest(1),
      signingWorkerParticipantBindingDigestB64u: parityDigest(2),
      holderRecipientKeyDigestB64u: parityDigest(3),
      serverRecipientKeyDigestB64u: parityDigest(4),
      transcriptHashB64u: parityDigest(5),
      protocolCommitReceiptDigestB64u: parityDigest(6),
    },
    revocationEpoch: 7,
    retirementReason: 'lane_revoked',
    retirementCorrelationId: 'correlation-ed-retire',
    retirementRequestDigestB64u: parityDigest(8),
    receiptDigestB64u: parityDigest(0),
    retiredAtMs: 9_000,
  });
}

function parityDigest(value: number) {
  return parseDigestB64u(Buffer.alloc(32, value).toString('base64url'));
}

function retirementReason(
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
