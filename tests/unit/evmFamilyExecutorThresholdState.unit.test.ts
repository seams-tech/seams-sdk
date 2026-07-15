import { expect, test } from '@playwright/test';
import { resolvePreparedEvmFamilyThresholdOwnerAddress } from '@/core/signingEngine/flows/signEvmFamily/executorThresholdState';
import { toThresholdOwnerAddress } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

test.describe('EVM-family executor threshold identity', () => {
  test('retains the exact lane owner address while sealed material is being restored', () => {
    const laneThresholdOwnerAddress = toThresholdOwnerAddress(`0x${'11'.repeat(20)}`);

    expect(
      resolvePreparedEvmFamilyThresholdOwnerAddress({
        laneThresholdOwnerAddress,
        publicIdentityContinuity: { kind: 'lane_identity_only' },
      }),
    ).toBe(laneThresholdOwnerAddress);
  });

  test('accepts verified material only when it belongs to the exact lane owner', () => {
    const laneThresholdOwnerAddress = toThresholdOwnerAddress(`0x${'22'.repeat(20)}`);

    expect(
      resolvePreparedEvmFamilyThresholdOwnerAddress({
        laneThresholdOwnerAddress,
        publicIdentityContinuity: {
          kind: 'verified_material_identity',
          verifiedMaterialThresholdOwnerAddress: laneThresholdOwnerAddress,
        },
      }),
    ).toBe(laneThresholdOwnerAddress);
  });

  test('rejects restored material belonging to a different owner address', () => {
    const laneThresholdOwnerAddress = toThresholdOwnerAddress(`0x${'33'.repeat(20)}`);
    const substitutedThresholdOwnerAddress = toThresholdOwnerAddress(`0x${'44'.repeat(20)}`);

    expect(() =>
      resolvePreparedEvmFamilyThresholdOwnerAddress({
        laneThresholdOwnerAddress,
        publicIdentityContinuity: {
          kind: 'verified_material_identity',
          verifiedMaterialThresholdOwnerAddress: substitutedThresholdOwnerAddress,
        },
      }),
    ).toThrow('prepared material owner address does not match the exact signing lane');
  });
});
