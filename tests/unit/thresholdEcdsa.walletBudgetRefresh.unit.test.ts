import { expect, test } from '@playwright/test';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  type LocalRouterAbEcdsaHssNormalSigningSeedResult,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';

const walletId = 'cedar-zenith-pghgtw';
const signingRootId = 'proj_mqykdxtp_o2hgej:dev';
const signingRootVersion = 'default';
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId,
  signingRootId,
  signingRootVersion,
});

function assertSeedOk(result: LocalRouterAbEcdsaHssNormalSigningSeedResult): asserts result is Extract<
  LocalRouterAbEcdsaHssNormalSigningSeedResult,
  { ok: true }
> {
  expect(result, JSON.stringify(result)).toMatchObject({ ok: true });
}

test('ECDSA warm-up can refresh one signing grant onto a new threshold session', async () => {
  const { svc } = createThresholdSigningServiceForUnitTests({});
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId,
    evmFamilySigningKeySlotId,
    signingRootId,
    signingRootVersion,
  });
  const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletId,
    evmFamilySigningKeySlotId,
  });
  const base = {
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    walletKeyVersion: 'threshold-ecdsa-hss-v1',
    derivationVersion: 1,
    relayerKeyId,
    signingGrantId: 'wss_shared_ecdsa_wallet_budget_refresh',
    participantIds: [1, 2],
    remainingUses: 3,
  } as const;

  const first = await svc.seedLocalRouterAbEcdsaHssNormalSigningSession({
    ...base,
    thresholdSessionId: 'tehss_budget_refresh_first',
    thresholdExpiresAtMs: Date.now() + 60_000,
  });
  assertSeedOk(first);

  const second = await svc.seedLocalRouterAbEcdsaHssNormalSigningSession({
    ...base,
    thresholdSessionId: 'tehss_budget_refresh_second',
    thresholdExpiresAtMs: Date.now() + 60_000,
  });
  assertSeedOk(second);
  expect(second.signingGrantId).toBe(base.signingGrantId);
  expect(second.thresholdSessionId).toBe('tehss_budget_refresh_second');
});
