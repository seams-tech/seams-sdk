import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import {
  restoreEcdsaSessionForExport,
  restoreNearEd25519SessionForExport,
  type ExportLaneSelectionDeps,
} from '../../client/src/core/signingEngine/flows/recovery/exportLaneSelection';
import {
  thresholdEcdsaChainTargetKey,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  AvailableEd25519SigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../client/src/core/signingEngine/session/availability/availableSigningLanes';
import {
  buildPasskeyEcdsaAuthBinding,
  buildEvmFamilyEcdsaKeyIdentity,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  type EvmFamilyEcdsaKeyHandle,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const WALLET_ID = 'alice.testnet';
const SUBJECT_ID = toWalletSubjectId(WALLET_ID);
const RP_ID = 'localhost';
const THRESHOLD_OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const OTHER_THRESHOLD_OWNER_ADDRESS = '0x2222222222222222222222222222222222222222';
const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const TEST_ECDSA_KEY_HANDLE = 'ehss-key-export-lane-test' as EvmFamilyEcdsaKeyHandle;
const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};
const TEMPO_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

type EcdsaLaneOverrides = Partial<ConcreteAvailableEcdsaSigningLane> & {
  ecdsaThresholdKeyId?: string;
  thresholdOwnerAddress?: string;
  authBindingRpId?: string;
  keyRpId?: string;
};

function ecdsaLane(overrides: EcdsaLaneOverrides): ConcreteAvailableEcdsaSigningLane {
  const {
    key: keyOverride,
    source,
    sourceChainTarget,
    publicFacts: publicFactsOverride,
    ecdsaThresholdKeyId,
    thresholdOwnerAddress,
    authBindingRpId,
    keyRpId,
    ...laneOverrides
  } = overrides;
  const lane = {
    authMethod: 'passkey' as const,
    curve: 'ecdsa' as const,
    chainTarget: EVM_TARGET,
    state: 'ready' as const,
    walletSigningSessionId: 'wallet-session-1',
    thresholdSessionId: 'threshold-session-1',
    remainingUses: 3,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    ...laneOverrides,
  };
  const key =
    keyOverride ||
    buildEvmFamilyEcdsaKeyIdentity({
      walletId: WALLET_ID,
      subjectId: SUBJECT_ID,
      rpId: keyRpId || RP_ID,
      ecdsaThresholdKeyId: ecdsaThresholdKeyId || 'ecdsa-key-1',
      signingRootId: 'root-1',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: thresholdOwnerAddress || THRESHOLD_OWNER_ADDRESS,
    });
  const publicFacts =
    publicFactsOverride ||
    buildVerifiedEcdsaPublicFacts({
      keyHandle:
        `${TEST_ECDSA_KEY_HANDLE}-${String(key.ecdsaThresholdKeyId)}-${String(
          key.signingRootId,
        )}-${String(key.signingRootVersion)}` as EvmFamilyEcdsaKeyHandle,
      publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      participantIds: key.participantIds,
      thresholdOwnerAddress: key.thresholdOwnerAddress,
    });
  const resolvedKey =
    lane.authMethod === 'passkey'
      ? buildResolvedEvmFamilyEcdsaKey({
          walletId: key.walletId,
          publicFacts,
          authBinding: buildPasskeyEcdsaAuthBinding({ rpId: authBindingRpId || key.rpId }),
        })
      : null;
  if (source === 'evm_family_shared_key') {
    if (lane.authMethod === 'passkey') {
      return {
        ...lane,
        authMethod: 'passkey',
        key,
        publicFacts,
        resolvedKey: resolvedKey!,
        source,
        sourceChainTarget: sourceChainTarget || EVM_TARGET,
      };
    }
    return {
      ...lane,
      authMethod: 'email_otp',
      key,
      publicFacts,
      source,
      sourceChainTarget: sourceChainTarget || EVM_TARGET,
    };
  }
  if (lane.authMethod === 'passkey') {
    return {
      ...lane,
      authMethod: 'passkey',
      key,
      publicFacts,
      resolvedKey: resolvedKey!,
      source: source || 'runtime_session_record',
    };
  }
  return {
    ...lane,
    authMethod: 'email_otp',
    key,
    publicFacts,
    source: source || 'runtime_session_record',
  };
}

function availableLanes(
  lanes: ConcreteAvailableEcdsaSigningLane[],
  ed25519Lanes: AvailableEd25519SigningLane[] = [],
): AvailableSigningLanes {
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
        near: ed25519Lanes[0] || { curve: 'ed25519', chain: 'near', state: 'missing' },
      },
    },
    candidates: {
      ed25519: {
        near: ed25519Lanes,
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

function depsForTargets(
  candidatesByTarget: Record<string, ConcreteAvailableEcdsaSigningLane[]>,
  restoreCalls?: { passkeyChainTargets: ThresholdEcdsaChainTarget[] },
): ExportLaneSelectionDeps {
  return {
    readPersistedAvailableSigningLanes: async () => availableLanes([]),
    readPersistedAvailableSigningLanesForTargets: async () => {
      const targets = [EVM_TARGET, TEMPO_TARGET];
      return {
        walletId: toAccountId(WALLET_ID),
        generation: 1,
        ecdsa: {
          targets,
          lanesByTarget: Object.fromEntries(
            targets.map((target) => {
              const targetKey = thresholdEcdsaChainTargetKey(target);
              return [
                targetKey,
                candidatesByTarget[targetKey]?.[0] || {
                  curve: 'ecdsa',
                  chainTarget: target,
                  state: 'missing',
                },
              ];
            }),
          ),
          candidatesByTarget,
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
    },
    restorePasskeyPersistedSessionForSigning: async (args) => {
      if (!restoreCalls) throw new Error('restore should not run for ready ECDSA export lanes');
      if (args.curve !== 'ecdsa') {
        throw new Error('expected ECDSA restore for ECDSA export lanes');
      }
      restoreCalls.passkeyChainTargets.push(args.chainTarget);
      return { attempted: 1, restored: 1, deferred: 0 };
    },
    restoreEmailOtpPersistedSessionForSigning: async () => {
      throw new Error('restore should not run for ready ECDSA export lanes');
    },
  };
}

function ed25519Lane(
  overrides: Partial<AvailableEd25519SigningLane>,
): AvailableEd25519SigningLane {
  return {
    authMethod: 'passkey',
    curve: 'ed25519',
    chain: 'near',
    state: 'restorable',
    walletSigningSessionId: 'wallet-ed25519-session-1',
    thresholdSessionId: 'threshold-ed25519-session-1',
    remainingUses: 1,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'durable_sealed_record',
    ...overrides,
  };
}

function depsForEd25519(
  lanes: AvailableEd25519SigningLane[],
  restoreCalls: { passkey: number; emailOtp: number },
): ExportLaneSelectionDeps {
  return {
    readPersistedAvailableSigningLanes: async () => availableLanes([], lanes),
    readPersistedAvailableSigningLanesForTargets: async () => availableLanes([]),
    restorePasskeyPersistedSessionForSigning: async () => {
      restoreCalls.passkey += 1;
      return { attempted: 1, restored: 1, deferred: 0 };
    },
    restoreEmailOtpPersistedSessionForSigning: async () => {
      restoreCalls.emailOtp += 1;
      return { attempted: 1, restored: 1, deferred: 0 };
    },
  };
}

test.describe('Ed25519 export lane selection', () => {
  test('prefers Email OTP export when duplicate passkey and OTP lanes share identity', async () => {
    const restoreCalls = { passkey: 0, emailOtp: 0 };
    const selected = await restoreNearEd25519SessionForExport(
      depsForEd25519(
        [
          ed25519Lane({
            authMethod: 'passkey',
            walletSigningSessionId: 'wallet-ed25519-passkey',
            thresholdSessionId: 'threshold-ed25519-shared',
          }),
          ed25519Lane({
            authMethod: 'email_otp',
            walletSigningSessionId: 'wallet-ed25519-email',
            thresholdSessionId: 'threshold-ed25519-shared',
          }),
        ],
        restoreCalls,
      ),
      { nearAccountId: toAccountId(WALLET_ID) },
    );

    expect(selected.authMethod).toBe('email_otp');
    expect(selected.walletSigningSessionId).toBe('wallet-ed25519-email');
    expect(restoreCalls.emailOtp).toBe(1);
    expect(restoreCalls.passkey).toBe(0);
  });
});

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
        rpId: RP_ID,
        signingTarget: EVM_TARGET,
      },
    );

    expect(selected.session.thresholdSessionId).toBe('threshold-session-runtime-durable');
    expect(selected.session.walletSigningSessionId).toBe('wallet-session-runtime-durable');
    expect(selected.key.keyScope).toBe('evm-family');
    expect(selected.key.thresholdOwnerAddress).toBe(THRESHOLD_OWNER_ADDRESS);
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
          rpId: RP_ID,
          signingTarget: EVM_TARGET,
        },
      ),
    ).rejects.toThrow(
      '[SigningEngine][ecdsa-export] exact lane selection failed: ambiguous_candidates',
    );
  });

  test('keeps owner-address drift ambiguous for the same ECDSA key id', async () => {
    await expect(
      restoreEcdsaSessionForExport(
        depsFor([
          ecdsaLane({ thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS }),
          ecdsaLane({
            thresholdOwnerAddress: OTHER_THRESHOLD_OWNER_ADDRESS,
            walletSigningSessionId: 'wallet-session-2',
            thresholdSessionId: 'threshold-session-2',
          }),
        ]),
        {
          walletId: WALLET_ID,
          rpId: RP_ID,
          signingTarget: EVM_TARGET,
        },
      ),
    ).rejects.toThrow(
      '[SigningEngine][ecdsa-export] exact lane selection failed: ambiguous_candidates',
    );
  });

  test('selects ready Email OTP export lane when stale passkey lane also exists', async () => {
    const selected = await restoreEcdsaSessionForExport(
      depsFor([
        ecdsaLane({
          authMethod: 'passkey',
          state: 'exhausted',
          walletSigningSessionId: 'wallet-session-passkey',
          thresholdSessionId: 'threshold-session-passkey',
          remainingUses: 0,
          updatedAtMs: 1_800_000_001_000,
        }),
        ecdsaLane({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wallet-session-email',
          thresholdSessionId: 'threshold-session-email',
          remainingUses: 2,
          updatedAtMs: 1_800_000_000_000,
        }),
      ]),
      {
        walletId: WALLET_ID,
        rpId: RP_ID,
        signingTarget: EVM_TARGET,
      },
    );

    expect(selected.session.authMethod).toBe('email_otp');
    expect(selected.session.thresholdSessionId).toBe('threshold-session-email');
    expect(selected.session.walletSigningSessionId).toBe('wallet-session-email');
  });

  test('uses passkey auth binding rpId for export selection', async () => {
    const selected = await restoreEcdsaSessionForExport(
      depsFor([
        ecdsaLane({
          keyRpId: 'stale-key-rp.localhost',
          authBindingRpId: RP_ID,
          walletSigningSessionId: 'wallet-session-passkey-auth-binding',
          thresholdSessionId: 'threshold-session-passkey-auth-binding',
        }),
      ]),
      {
        walletId: WALLET_ID,
        rpId: RP_ID,
        signingTarget: EVM_TARGET,
      },
    );

    expect(selected.session.authMethod).toBe('passkey');
    expect(selected.session.walletSigningSessionId).toBe('wallet-session-passkey-auth-binding');
  });

  test('selects active export lane when exhausted duplicate lane has the same shared key', async () => {
    const selected = await restoreEcdsaSessionForExport(
      depsFor([
        ecdsaLane({
          state: 'exhausted',
          walletSigningSessionId: 'wallet-session-exhausted',
          thresholdSessionId: 'threshold-session-exhausted',
          remainingUses: 0,
          updatedAtMs: 1_800_000_001_000,
        }),
        ecdsaLane({
          state: 'ready',
          walletSigningSessionId: 'wallet-session-active',
          thresholdSessionId: 'threshold-session-active',
          remainingUses: 2,
          updatedAtMs: 1_800_000_000_000,
        }),
      ]),
      {
        walletId: WALLET_ID,
        rpId: RP_ID,
        signingTarget: EVM_TARGET,
      },
    );

    expect(selected.session.thresholdSessionId).toBe('threshold-session-active');
    expect(selected.session.walletSigningSessionId).toBe('wallet-session-active');
  });

  test('resolves shared-key target lane to concrete source material', async () => {
    const sourceLane = ecdsaLane({
      chainTarget: EVM_TARGET,
      walletSigningSessionId: 'wallet-session-evm-source',
      thresholdSessionId: 'threshold-session-evm-source',
    });
    const sharedTempoLane = ecdsaLane({
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: EVM_TARGET,
      state: 'deferred',
      walletSigningSessionId: sourceLane.walletSigningSessionId,
      thresholdSessionId: sourceLane.thresholdSessionId,
      updatedAtMs: sourceLane.updatedAtMs,
    });
    const selected = await restoreEcdsaSessionForExport(
      depsForTargets({
        [thresholdEcdsaChainTargetKey(EVM_TARGET)]: [sourceLane],
        [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [sharedTempoLane],
      }),
      {
        walletId: WALLET_ID,
        rpId: RP_ID,
        signingTarget: TEMPO_TARGET,
      },
    );

    expect(selected.session.chainTarget).toEqual(EVM_TARGET);
    expect(selected.session.thresholdSessionId).toBe('threshold-session-evm-source');
    expect(selected.key.keyScope).toBe('evm-family');
  });

  test('restores the concrete source target for shared-key ECDSA export lanes', async () => {
    const restoreCalls = { passkeyChainTargets: [] as ThresholdEcdsaChainTarget[] };
    const sourceLane = ecdsaLane({
      chainTarget: EVM_TARGET,
      source: 'durable_sealed_record',
      state: 'restorable',
      walletSigningSessionId: 'wallet-session-evm-source',
      thresholdSessionId: 'threshold-session-evm-source',
    });
    const sharedTempoLane = ecdsaLane({
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: EVM_TARGET,
      state: 'deferred',
      walletSigningSessionId: sourceLane.walletSigningSessionId,
      thresholdSessionId: sourceLane.thresholdSessionId,
      updatedAtMs: sourceLane.updatedAtMs,
    });

    await restoreEcdsaSessionForExport(
      depsForTargets(
        {
          [thresholdEcdsaChainTargetKey(EVM_TARGET)]: [sourceLane],
          [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [sharedTempoLane],
        },
        restoreCalls,
      ),
      {
        walletId: WALLET_ID,
        rpId: RP_ID,
        signingTarget: TEMPO_TARGET,
      },
    );

    expect(restoreCalls.passkeyChainTargets).toEqual([EVM_TARGET]);
  });

  test('uses shared-key target lane when source material is absent from export inventory', async () => {
    const restoreCalls = { passkeyChainTargets: [] as ThresholdEcdsaChainTarget[] };
    const sharedTempoLane = ecdsaLane({
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: EVM_TARGET,
      state: 'deferred',
      walletSigningSessionId: 'wallet-session-shared-only',
      thresholdSessionId: 'threshold-session-shared-only',
    });

    const selected = await restoreEcdsaSessionForExport(
      depsForTargets(
        {
          [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [sharedTempoLane],
        },
        restoreCalls,
      ),
      {
        walletId: WALLET_ID,
        rpId: RP_ID,
        signingTarget: TEMPO_TARGET,
      },
    );

    expect(selected.session.chainTarget).toEqual(EVM_TARGET);
    expect(selected.session.thresholdSessionId).toBe('threshold-session-shared-only');
    expect(restoreCalls.passkeyChainTargets).toEqual([EVM_TARGET]);
  });
});
