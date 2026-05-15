import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import {
  restoreEcdsaSessionForExport,
  type ExportLaneSelectionDeps,
} from '../../client/src/core/signingEngine/flows/recovery/exportLaneSelection';
import {
  thresholdEcdsaChainTargetKey,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
} from '../../client/src/core/signingEngine/session/availability/availableSigningLanes';

const WALLET_ID = 'alice.testnet';
const SUBJECT_ID = toWalletSubjectId(WALLET_ID);
const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

function ecdsaLane(
  overrides: Partial<ConcreteAvailableEcdsaSigningLane>,
): ConcreteAvailableEcdsaSigningLane {
  return {
    subjectId: SUBJECT_ID,
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: EVM_TARGET,
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'root-1',
    signingRootVersion: 'default',
    state: 'ready',
    walletSigningSessionId: 'wallet-session-1',
    thresholdSessionId: 'threshold-session-1',
    remainingUses: 3,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'runtime_session_record',
    ...overrides,
  };
}

function availableLanes(lanes: ConcreteAvailableEcdsaSigningLane[]): AvailableSigningLanes {
  const targetKey = thresholdEcdsaChainTargetKey(EVM_TARGET);
  return {
    walletId: toAccountId(WALLET_ID),
    generation: 1,
    ecdsa: {
      targets: [EVM_TARGET],
      lanesByTarget: {
        [targetKey]: lanes[0] || { curve: 'ecdsa', chainTarget: EVM_TARGET, state: 'missing' },
      },
      candidatesByTarget: {
        [targetKey]: lanes,
      },
    },
    lanes: {
      ed25519: {
        near: { curve: 'ed25519', chain: 'near', state: 'missing' },
      },
    },
    candidates: {
      ed25519: {
        near: [],
      },
    },
  };
}

function depsFor(lanes: ConcreteAvailableEcdsaSigningLane[]): ExportLaneSelectionDeps {
  return {
    readPersistedAvailableSigningLanes: async () => availableLanes([]),
    readPersistedAvailableSigningLanesForTargets: async () => availableLanes(lanes),
    restorePasskeyPersistedSessionForSigning: async () => {
      throw new Error('restore should not run for ready ECDSA export lanes');
    },
    restoreEmailOtpPersistedSessionForSigning: async () => {
      throw new Error('restore should not run for ready ECDSA export lanes');
    },
  };
}

test.describe('ECDSA export lane selection', () => {
  test('collapses duplicate live sessions for the same ECDSA key identity', async () => {
    const runtimeAndDurableLane = ecdsaLane({
      source: 'runtime_and_durable',
      walletSigningSessionId: 'wallet-session-runtime-durable',
      thresholdSessionId: 'threshold-session-runtime-durable',
      remainingUses: 2,
      updatedAtMs: 1_800_000_000_000,
    });
    const runtimeOnlyLane = ecdsaLane({
      source: 'runtime_session_record',
      walletSigningSessionId: 'wallet-session-runtime-only',
      thresholdSessionId: 'threshold-session-runtime-only',
      remainingUses: 3,
      updatedAtMs: 1_800_000_001_000,
    });

    const selected = await restoreEcdsaSessionForExport(
      depsFor([runtimeAndDurableLane, runtimeOnlyLane]),
      {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        signingTarget: EVM_TARGET,
      },
    );

    expect(selected.thresholdSessionId).toBe('threshold-session-runtime-durable');
    expect(selected.walletSigningSessionId).toBe('wallet-session-runtime-durable');
  });

  test('keeps different ECDSA key identities ambiguous for export', async () => {
    await expect(
      restoreEcdsaSessionForExport(
        depsFor([
          ecdsaLane({ ecdsaThresholdKeyId: 'ecdsa-key-1' }),
          ecdsaLane({
            ecdsaThresholdKeyId: 'ecdsa-key-2',
            walletSigningSessionId: 'wallet-session-2',
            thresholdSessionId: 'threshold-session-2',
          }),
        ]),
        {
          walletId: WALLET_ID,
          subjectId: SUBJECT_ID,
          signingTarget: EVM_TARGET,
        },
      ),
    ).rejects.toThrow(
      '[SigningEngine][ecdsa-export] exact lane selection failed: ambiguous_candidates',
    );
  });
});
