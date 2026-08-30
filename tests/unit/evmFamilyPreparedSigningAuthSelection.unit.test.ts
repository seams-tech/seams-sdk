import { expect, test } from '@playwright/test';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyTransactionSigningIntent,
  resolveEvmFamilyTransactionAuthSelectionPolicy,
} from '@/core/signingEngine/flows/signEvmFamily/preparedSigning';
import { selectEvmFamilyEcdsaMaterialCandidate } from '@/core/signingEngine/session/identity/selectLane';
import {
  AVAILABLE_LANES_ECDSA_TARGET,
  AVAILABLE_LANES_WALLET_ID,
  authorizationRequiredCanonicalEcdsaAvailableLane,
  canonicalEcdsaAvailableLane,
  readAvailableLanesFixture,
} from './helpers/availableSigningLanes.fixtures';

// The shared-key restore-lane case is gone with
// `resolveEvmFamilyEcdsaRestoreMaterialLane`. It asserted that a restore lane
// carried the source chain's exact identity while reusing the transaction
// lane's session and grant ids -- identifiers an ExactEcdsaSigningLaneIdentity
// no longer carries at all. Restored material is selected by manifest and
// sealed runtime now, so the invariant has no record-shaped form to test.

const walletId = toWalletId('wallet.testnet');
const signingTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});

test.describe('EVM-family prepared signing auth selection', () => {
  test('binds the transaction intent to the selected capability factor', () => {
    const intent = buildEvmFamilyTransactionSigningIntent({
      walletId,
      signingTarget,
      operationUsesNeeded: 1,
      authSelectionPolicy: resolveEvmFamilyTransactionAuthSelectionPolicy({
        candidateAuthMethod: 'passkey',
      }),
    });

    expect(intent).toMatchObject({
      walletId,
      curve: 'ecdsa',
      chain: 'evm',
      chainTarget: signingTarget,
      operationUsesNeeded: 1,
      authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
    });
  });

  test('derives account-class policy from the selected candidate auth method', () => {
    expect(
      resolveEvmFamilyTransactionAuthSelectionPolicy({
        candidateAuthMethod: 'email_otp',
      }),
    ).toEqual({
      kind: 'account_class',
      authMethod: 'email_otp',
    });
    expect(
      resolveEvmFamilyTransactionAuthSelectionPolicy({
        candidateAuthMethod: 'passkey',
      }),
    ).toEqual({
      kind: 'account_class',
      authMethod: 'passkey',
    });
  });

  test('selects exact canonical material without constructing an authorized lane', async () => {
    const materialRecord = authorizationRequiredCanonicalEcdsaAvailableLane({
      chainTarget: AVAILABLE_LANES_ECDSA_TARGET,
      thresholdOwnerAddress: `0x${'ab'.repeat(20)}`,
      authMethod: 'passkey',
      ecdsaThresholdKeyId: 'auth-required-material',
    });
    const availableLanes = await readAvailableLanesFixture({
      walletId: AVAILABLE_LANES_WALLET_ID,
      ecdsaChainTargets: [AVAILABLE_LANES_ECDSA_TARGET],
      canonicalEcdsaLanes: [materialRecord],
    });
    const intent = buildEvmFamilyTransactionSigningIntent({
      walletId: toWalletId(AVAILABLE_LANES_WALLET_ID),
      signingTarget: AVAILABLE_LANES_ECDSA_TARGET,
      operationUsesNeeded: 1,
      authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
    });

    const selected = selectEvmFamilyEcdsaMaterialCandidate({ intent, availableLanes });

    if (!selected.ok) {
      throw new Error(
        `material selection failed: ${JSON.stringify({
          failure: selected.failure,
          lanes: availableLanes.ecdsa,
        })}`,
      );
    }
    expect(selected.kind).toBe('authorization_required');
    if (selected.kind !== 'authorization_required') {
      throw new Error('expected authorization-required material selection');
    }
    expect(selected.candidate.authorizationState).toBe('authorization_required');
    expect(selected.candidate.materialActivation.activationId).toBe(
      materialRecord.materialActivation.activationId,
    );
    expect(selected.candidate.chainTarget).toEqual(AVAILABLE_LANES_ECDSA_TARGET);
    expect(selected.lane).toBeUndefined();
  });

  test('constructs a selected lane only for an authorized material candidate', async () => {
    const materialRecord = canonicalEcdsaAvailableLane({
      chainTarget: AVAILABLE_LANES_ECDSA_TARGET,
      thresholdOwnerAddress: `0x${'cd'.repeat(20)}`,
      authMethod: 'passkey',
      ecdsaThresholdKeyId: 'authorized-material',
    });
    const availableLanes = await readAvailableLanesFixture({
      walletId: AVAILABLE_LANES_WALLET_ID,
      ecdsaChainTargets: [AVAILABLE_LANES_ECDSA_TARGET],
      canonicalEcdsaLanes: [materialRecord],
    });
    const intent = buildEvmFamilyTransactionSigningIntent({
      walletId: toWalletId(AVAILABLE_LANES_WALLET_ID),
      signingTarget: AVAILABLE_LANES_ECDSA_TARGET,
      operationUsesNeeded: 1,
      authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
    });

    const selected = selectEvmFamilyEcdsaMaterialCandidate({ intent, availableLanes });

    if (!selected.ok) throw new Error(`material selection failed: ${selected.failure.kind}`);
    expect(selected.kind).toBe('authorized');
    if (selected.kind !== 'authorized') throw new Error('expected authorized material selection');
    expect(selected.candidate.authorizationState).toBe('authorized');
    if (!materialRecord.authorization) throw new Error('expected exact material authorization');
    expect(selected.lane.authorization.session.walletSessionId).toBe(
      materialRecord.authorization.session.walletSessionId,
    );
    expect(selected.lane.materialActivation.activationId).toBe(
      materialRecord.materialActivation.activationId,
    );
  });
});
