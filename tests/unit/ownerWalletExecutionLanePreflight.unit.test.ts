import { expect, test } from '@playwright/test';
import { buildOwnerWalletExecutionEvidenceFixture } from './helpers/walletExecutionLane.fixtures';
import { parseOwnerWalletExecutionLaneProjectionResponseV1 } from '../../packages/wallet/src/core/rpcClients/relayer/ownerWalletExecutionLanePreflight';

test('parses the exact authoritative owner execution-lane projection', async () => {
  const evidence = await buildOwnerWalletExecutionEvidenceFixture();
  const projection = parseOwnerWalletExecutionLaneProjectionResponseV1(
    {
      ok: true,
      projection: {
        kind: 'active_owner_wallet_execution_lane_projection_v1',
        walletKey: evidence.walletKey,
        lane: evidence.lane,
        materialActivation: evidence.materialActivation,
        verifiedActivationReceiptDigestB64u: evidence.verifiedActivationReceiptDigestB64u,
      },
    },
    'ecdsa_secp256k1',
  );

  expect(projection.walletKey.walletKeyId).toBe(evidence.walletKey.walletKeyId);
  expect(projection.lane.laneId).toBe(evidence.lane.laneId);
  expect(projection.materialActivation).toEqual(evidence.materialActivation);
});

test('rejects a projection for another key family', async () => {
  const evidence = await buildOwnerWalletExecutionEvidenceFixture();
  expect(() =>
    parseOwnerWalletExecutionLaneProjectionResponseV1(
      {
        ok: true,
        projection: {
          kind: 'active_owner_wallet_execution_lane_projection_v1',
          walletKey: evidence.walletKey,
          lane: evidence.lane,
          materialActivation: evidence.materialActivation,
          verifiedActivationReceiptDigestB64u: evidence.verifiedActivationReceiptDigestB64u,
        },
      },
      'ed25519',
    ),
  ).toThrow('identity is inconsistent');
});
