import { expect, test } from '@playwright/test';
import {
  buildEd25519ServerRetirementRequestV1,
  parseAndVerifyEd25519ServerRetirementEffectV1,
} from '../../packages/sdk-server-ts/src/core/signingLanes/ed25519ServerRetirement';
import { buildRevokeSigningLaneV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  parseCorrelationId,
  parseDigestB64u,
} from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildR102Ed25519LaneMaterialIdentityFixture,
  buildR102Ed25519RetirementParityReceiptFixture,
  buildR102Ed25519ServerRetirementReceiptFixture,
} from './helpers/ed25519ServerRetirement.fixtures';
import { computeEd25519ServerRetirementReceiptDigestV1 } from '../../packages/shared-ts/src/signing-lanes/rotationDigests';

const REQUEST_DIGEST = parseDigestB64u(Buffer.alloc(32, 4).toString('base64url'));
const EFFECT_DIGEST = parseDigestB64u(Buffer.alloc(32, 5).toString('base64url'));

test('matches the frozen Rust Ed25519 retirement receipt digest', async () => {
  await expect(
    computeEd25519ServerRetirementReceiptDigestV1(buildR102Ed25519RetirementParityReceiptFixture()),
  ).resolves.toBe('rEHBCD9-zcjh-AJaYGWpqHXEf0kexF32bOfXRMuMjEI');
});

test('verifies the exact Ed25519 private retirement receipt and replay', async () => {
  const identity = await buildR102Ed25519LaneMaterialIdentityFixture();
  const command = buildRevokeSigningLaneV1({
    walletId: identity.walletId,
    walletKeyId: identity.walletKeyId,
    laneId: identity.targetLaneId,
    laneShareEpoch: identity.targetLaneShareEpoch,
    expectedRevocationEpoch: 3,
    reason: 'device_compromise',
    retirementCorrelationId: parseCorrelationId('ed25519-retirement-correlation'),
    retirementRequestDigestB64u: REQUEST_DIGEST,
    retirementEffectBindingDigestB64u: EFFECT_DIGEST,
    requestedAtMs: 9_000,
  });
  const request = buildEd25519ServerRetirementRequestV1({
    command,
    binding: { identity },
  });
  const receipt = await buildR102Ed25519ServerRetirementReceiptFixture({ command, identity });

  await expect(
    parseAndVerifyEd25519ServerRetirementEffectV1({
      raw: { outcome: 'replayed', receipt },
      request,
    }),
  ).resolves.toMatchObject({
    outcome: 'replayed',
    retirementEffectBindingDigestB64u: EFFECT_DIGEST,
    retirementReceiptDigestB64u: receipt.receiptDigestB64u,
  });
});

test('rejects identity and self-digest substitution', async () => {
  const identity = await buildR102Ed25519LaneMaterialIdentityFixture();
  const command = buildRevokeSigningLaneV1({
    walletId: identity.walletId,
    walletKeyId: identity.walletKeyId,
    laneId: identity.targetLaneId,
    laneShareEpoch: identity.targetLaneShareEpoch,
    expectedRevocationEpoch: 3,
    reason: 'device_compromise',
    retirementCorrelationId: parseCorrelationId('ed25519-retirement-correlation'),
    retirementRequestDigestB64u: REQUEST_DIGEST,
    retirementEffectBindingDigestB64u: EFFECT_DIGEST,
    requestedAtMs: 9_000,
  });
  const request = buildEd25519ServerRetirementRequestV1({ command, binding: { identity } });
  const receipt = await buildR102Ed25519ServerRetirementReceiptFixture({ command, identity });

  await expect(
    parseAndVerifyEd25519ServerRetirementEffectV1({
      raw: {
        outcome: 'applied',
        receipt: {
          ...receipt,
          identity: { ...receipt.identity, transcriptHashB64u: EFFECT_DIGEST },
        },
      },
      request,
    }),
  ).rejects.toThrow('does not match the admitted lane binding');
  await expect(
    parseAndVerifyEd25519ServerRetirementEffectV1({
      raw: {
        outcome: 'applied',
        receipt: { ...receipt, receiptDigestB64u: EFFECT_DIGEST },
      },
      request,
    }),
  ).rejects.toThrow('canonical digest');
});
