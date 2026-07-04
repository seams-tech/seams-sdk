import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyTransactionSigningIntent,
  resolveEvmFamilyEcdsaRestoreMaterialLane,
  resolveEvmFamilyTransactionAuthSelectionPolicy,
} from '@/core/signingEngine/flows/signEvmFamily/preparedSigning';
import type { EcdsaLaneCandidate } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildTempoTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { exactEcdsaSigningLaneIdentityFromSelectedLane } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';

const walletId = toWalletId('wallet.testnet');
const signingTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});

test.describe('EVM-family prepared signing auth selection', () => {
  test('keeps initial transaction intent auth-neutral', () => {
    const intent = buildEvmFamilyTransactionSigningIntent({
      walletId,
      signingTarget,
      operationUsesNeeded: 1,
      authSelectionPolicy: resolveEvmFamilyTransactionAuthSelectionPolicy({}),
    });

    expect(intent).toMatchObject({
      walletId,
      curve: 'ecdsa',
      chain: 'evm',
      chainTarget: signingTarget,
      operationUsesNeeded: 1,
      authSelectionPolicy: { kind: 'any' },
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

  test('uses source chain exact identity for shared-key material restore', () => {
    const tempoTarget = {
      kind: 'tempo' as const,
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    };
    const key = buildEvmFamilyEcdsaKeyIdentity({
      walletId,
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId,
        signingRootId: 'proj_local:dev',
        signingRootVersion: 'default',
      }),
      ecdsaThresholdKeyId: 'ek-shared-restore',
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'ab'.repeat(20)}`,
    });
    const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-shared-restore');
    const passkeyAuth = {
      kind: 'passkey' as const,
      rpId: toRpId('example.localhost'),
      credentialIdB64u: 'credential-shared-restore',
    };
    const laneCandidate: EcdsaLaneCandidate = {
      kind: 'lane_candidate',
      auth: passkeyAuth,
      curve: 'ecdsa',
      chain: 'tempo',
      walletId,
      key,
      keyHandle,
      chainTarget: tempoTarget,
      signingGrantId: 'grant-shared-restore',
      thresholdSessionId: 'threshold-shared-restore',
      state: 'deferred',
      remainingUses: null,
      expiresAtMs: null,
      updatedAtMs: 1,
      source: 'evm_family_shared_key',
      sourceChainTarget: signingTarget,
    };
    const transactionLane = buildTempoTransactionSigningLane({
      key,
      keyHandle,
      walletId,
      auth: passkeyAuth,
      chainTarget: tempoTarget,
      signingGrantId: SigningSessionIds.signingGrant(laneCandidate.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
        laneCandidate.thresholdSessionId,
      ),
      storageSource: 'login',
    });

    const restoreMaterialLane = resolveEvmFamilyEcdsaRestoreMaterialLane({
      laneCandidate,
      transactionLane,
    });
    const restoreIdentity = exactEcdsaSigningLaneIdentityFromSelectedLane(restoreMaterialLane);
    const transactionIdentity = exactEcdsaSigningLaneIdentityFromSelectedLane(transactionLane);

    expect(transactionIdentity.signer.chainTarget).toEqual(tempoTarget);
    expect(restoreIdentity.signer.chainTarget).toEqual(signingTarget);
    expect(restoreIdentity.signer.chainTarget).toEqual(laneCandidate.sourceChainTarget);
    expect(restoreIdentity.signingGrantId).toEqual(transactionIdentity.signingGrantId);
    expect(restoreIdentity.thresholdSessionId).toEqual(transactionIdentity.thresholdSessionId);
  });
});
