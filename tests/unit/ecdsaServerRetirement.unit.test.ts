import { expect, test } from '@playwright/test';
import {
  buildEcdsaServerRetirementRequestV1,
  parseAndVerifyEcdsaServerRetirementEffectV1,
  type EcdsaServerRetirementExpectationV1,
} from '../../packages/sdk-server-ts/src/core/signingLanes/ecdsaServerRetirement';
import type { EcdsaSigningWorkerLaneMaterialIdentityV1 } from '../../packages/sdk-server-ts/src/core/signingLanes/signingWorkerLaneMaterialIdentity';
import type { EcdsaServerRetirementReceiptV1 } from '../../packages/shared-ts/src/signing-lanes';
import {
  buildRevokeSigningLaneV1,
  parseEcdsaServerRetirementReceiptV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  computeEcdsaServerRetirementReceiptDigestV1,
  encodeEcdsaServerRetirementReceiptCanonicalPayloadV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationDigests';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import {
  parseCorrelationId,
  parseDigestB64u,
} from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { parseSigningLaneId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  buildR102EcdsaLaneJob,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';
import { buildR102EcdsaServerRetirementReceipt } from './helpers/ecdsaServerRetirement.fixtures';

const REQUEST_DIGEST_B64U = parseDigestB64u(Buffer.alloc(32, 0x31).toString('base64url'));
const EFFECT_BINDING_DIGEST_B64U = parseDigestB64u(Buffer.alloc(32, 0x32).toString('base64url'));

function commandFor(job: ReturnType<typeof buildR102EcdsaLaneJob>) {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return buildRevokeSigningLaneV1({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    expectedRevocationEpoch: 7,
    reason: 'user_revoked',
    retirementCorrelationId: parseCorrelationId('correlation-r102-retirement'),
    retirementRequestDigestB64u: REQUEST_DIGEST_B64U,
    retirementEffectBindingDigestB64u: EFFECT_BINDING_DIGEST_B64U,
    requestedAtMs: 8_000,
  });
}

function identityFor(
  job: ReturnType<typeof buildR102EcdsaLaneJob>,
  targetLaneId = job.target.laneId,
): EcdsaSigningWorkerLaneMaterialIdentityV1 {
  const digest = parseDigestB64u(Buffer.alloc(32).toString('base64url'));
  const parsedLaneId = parseSigningLaneId(targetLaneId);
  if (!parsedLaneId.ok) throw new Error(parsedLaneId.error.message);
  return {
    operationId: job.operationId,
    enrollmentId: job.enrollmentId,
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    targetLaneId: parsedLaneId.value,
    targetLaneShareEpoch: job.target.laneShareEpoch,
    targetMaterialActivationId: job.targetMaterialActivationId,
    keyFamily: 'ecdsa_secp256k1',
    holderParticipantBindingDigestB64u: digest,
    signingWorkerParticipantBindingDigestB64u: digest,
    holderRecipientKeyDigestB64u: digest,
    serverRecipientKeyDigestB64u: digest,
    transcriptHashB64u: digest,
    protocolCommitReceiptDigestB64u: digest,
  };
}

function expectationFor(
  job: ReturnType<typeof buildR102EcdsaLaneJob>,
  command: ReturnType<typeof commandFor>,
): EcdsaServerRetirementExpectationV1 {
  return {
    manifest: {
      manifestId: job.targetCapability.manifestId,
      manifestRevision: job.targetCapability.manifestRevision,
    },
    materialActivation: buildR102ServerActivationReceipt(job).targetMaterialActivation,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    revocationEpoch: command.expectedRevocationEpoch,
    retirementReason: 'lane_revoked',
    retirementCorrelationId: command.retirementCorrelationId,
    retirementRequestDigestB64u: command.retirementRequestDigestB64u,
    serverGeneration: job.sourceCapability.serverGeneration,
    lifecycleId: 'lifecycle-r102-retirement',
    retirementEffectBindingDigestB64u: command.retirementEffectBindingDigestB64u,
  };
}

function effectFor(receipt: EcdsaServerRetirementReceiptV1, outcome: 'applied' | 'replayed') {
  return { outcome, receipt };
}

test('verifies the canonical ECDSA retirement receipt before returning the Gateway effect fence', async () => {
  const job = buildR102EcdsaLaneJob('retirement-valid');
  if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  const command = commandFor(job);
  const receipt = await buildR102EcdsaServerRetirementReceipt(job, {
    revocationEpoch: command.expectedRevocationEpoch,
    retirementRequestDigestB64u: command.retirementRequestDigestB64u,
  });
  const verified = await parseAndVerifyEcdsaServerRetirementEffectV1({
    raw: effectFor(receipt, 'applied'),
    expectation: expectationFor(job, command),
  });

  expect(verified.outcome).toBe('applied');
  expect(verified.receipt).toEqual(receipt);
  expect(verified.retirementReceiptDigestB64u).toBe(command.retirementEffectBindingDigestB64u);
  const request = buildEcdsaServerRetirementRequestV1({
    command,
    binding: {
      identity: identityFor(job),
      manifest: expectationFor(job, command).manifest,
      materialActivation: expectationFor(job, command).materialActivation,
      serverGeneration: expectationFor(job, command).serverGeneration,
      lifecycleId: expectationFor(job, command).lifecycleId,
    },
  });
  expect(request.retirementEffectBindingDigestB64u).toBe(command.retirementEffectBindingDigestB64u);
  expect(request.retirementReason).toBe('lane_revoked');

  expect(() =>
    buildEcdsaServerRetirementRequestV1({
      command,
      binding: {
        identity: identityFor(job, `${job.target.laneId}-substituted`),
        manifest: expectationFor(job, command).manifest,
        materialActivation: expectationFor(job, command).materialActivation,
        serverGeneration: expectationFor(job, command).serverGeneration,
        lifecycleId: expectationFor(job, command).lifecycleId,
      },
    }),
  ).toThrow('binding identity does not match');
});

test('accepts an exact replay and rejects receipt substitution', async () => {
  const job = buildR102EcdsaLaneJob('retirement-replay');
  if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  const command = commandFor(job);
  const receipt = await buildR102EcdsaServerRetirementReceipt(job, {
    revocationEpoch: command.expectedRevocationEpoch,
    retirementRequestDigestB64u: command.retirementRequestDigestB64u,
  });
  const expectation = expectationFor(job, command);
  const replayed = await parseAndVerifyEcdsaServerRetirementEffectV1({
    raw: effectFor(receipt, 'replayed'),
    expectation,
  });
  expect(replayed.outcome).toBe('replayed');

  const substitutions: Array<[string, EcdsaServerRetirementReceiptV1]> = [
    ['manifest', { ...receipt, manifest: { ...receipt.manifest, manifestRevision: 2 } }],
    [
      'source manifest substitution',
      {
        ...receipt,
        manifest: { ...receipt.manifest, manifestId: job.sourceCapability.manifestId },
      },
    ],
    [
      'activation',
      {
        ...receipt,
        materialActivation: {
          ...receipt.materialActivation,
          activationId: 'substituted-activation',
        },
      },
    ],
    ['lane', { ...receipt, laneId: 'substituted-lane' }],
    ['epoch', { ...receipt, revocationEpoch: receipt.revocationEpoch + 1 }],
    [
      'correlation',
      {
        ...receipt,
        retirementCorrelationId: 'substituted-correlation',
      },
    ],
    [
      'request digest',
      {
        ...receipt,
        retirementRequestDigestB64u: Buffer.alloc(32, 0x41).toString('base64url'),
      },
    ],
    ['server generation', { ...receipt, serverGeneration: 'substituted-generation' }],
    ['lifecycle', { ...receipt, lifecycleId: 'substituted-lifecycle' }],
  ];
  for (const [field, substituted] of substitutions) {
    await expect(
      parseAndVerifyEcdsaServerRetirementEffectV1({
        raw: effectFor(substituted, 'replayed'),
        expectation,
      }),
    ).rejects.toThrow('does not match the admitted lane binding');
    expect(field.length).toBeGreaterThan(0);
  }
});

test('rejects a receipt whose self digest was substituted', async () => {
  const job = buildR102EcdsaLaneJob('retirement-digest');
  if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  const command = commandFor(job);
  const receipt = await buildR102EcdsaServerRetirementReceipt(job, {
    revocationEpoch: command.expectedRevocationEpoch,
    retirementRequestDigestB64u: command.retirementRequestDigestB64u,
  });
  await expect(
    parseAndVerifyEcdsaServerRetirementEffectV1({
      raw: effectFor(
        { ...receipt, receiptDigestB64u: Buffer.alloc(32, 0x42).toString('base64url') },
        'applied',
      ),
      expectation: expectationFor(job, command),
    }),
  ).rejects.toThrow('does not match its canonical digest');
});

test('matches the Rust ECDSA retirement canonical digest vector', async () => {
  const receipt = parseEcdsaServerRetirementReceiptV1({
    kind: 'ecdsa_server_retirement_receipt_v1',
    manifest: { manifestId: 'manifest-1', manifestRevision: 1 },
    materialActivation: {
      kind: 'mpc_material_activation_ref',
      activationId: 'activation-1',
      capability: 'capability-1',
      materialOwner: 'wallet-1',
      keyBinding: 'key-binding-1',
      lifecycleBinding: 'lifecycle-binding-1',
      signingWorker: 'worker-1',
    },
    walletKeyId: 'wallet-key-1',
    laneId: 'owner-lane',
    laneShareEpoch: 'epoch-1',
    revocationEpoch: 2,
    retirementReason: 'rotation',
    retirementCorrelationId: 'retirement-1',
    retirementRequestDigestB64u: Buffer.alloc(32, 22).toString('base64url'),
    serverGeneration: 'generation-1',
    lifecycleId: 'lifecycle-1',
    receiptDigestB64u: 'tJ6cqtqwFRbT5OjrT23nQ9RgTdebD9M6p7ALDl8tne8',
    retiredAt: '2026-08-11T00:00:00.000Z',
  });
  expect(await computeEcdsaServerRetirementReceiptDigestV1(receipt)).toBe(
    'tJ6cqtqwFRbT5OjrT23nQ9RgTdebD9M6p7ALDl8tne8',
  );
  expect(base64UrlEncode(encodeEcdsaServerRetirementReceiptCanonicalPayloadV1(receipt))).toBe(
    'AAAAOXNlYW1zL3JvdGF0YWJsZS1zaWduaW5nLWxhbmVzL2VjZHNhLXJldGlyZW1lbnQtcmVjZWlwdC92MQAAACJlY2RzYV9zZXJ2ZXJfcmV0aXJlbWVudF9yZWNlaXB0X3YxAAAACm1hbmlmZXN0LTEAAAAAAAAAAQAAAH8AAAAbbXBjX21hdGVyaWFsX2FjdGl2YXRpb25fcmVmAAAADGFjdGl2YXRpb24tMQAAAAxjYXBhYmlsaXR5LTEAAAAId2FsbGV0LTEAAAANa2V5LWJpbmRpbmctMQAAABNsaWZlY3ljbGUtYmluZGluZy0xAAAACHdvcmtlci0xAAAADHdhbGxldC1rZXktMQAAAApvd25lci1sYW5lAAAAB2Vwb2NoLTEAAAAAAAAAAgAAAAhyb3RhdGlvbgAAAAxyZXRpcmVtZW50LTEAAAAgFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYAAAAMZ2VuZXJhdGlvbi0xAAAAC2xpZmVjeWNsZS0xAAAAGDIwMjYtMDgtMTFUMDA6MDA6MDAuMDAwWg',
  );
});
