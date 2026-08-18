import { expect, test } from '@playwright/test';
import {
  resolveExactKeyExportLane,
  resolveEcdsaSessionForExport,
  type ExportLaneSelectionDeps,
} from '../../packages/wallet/src/core/signingEngine/flows/recovery/exportLaneSelection';
import {
  thresholdEcdsaChainTargetKey,
  nearAccountRefFromAccountId,
  toWalletId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '../../packages/wallet/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEd25519SigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../packages/wallet/src/core/signingEngine/session/availability/availableSigningLanes';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '../../packages/wallet/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { toRpId } from '../../packages/wallet/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  authorizationRequiredCanonicalEcdsaAvailableLane,
  canonicalEcdsaAvailableLane,
} from './helpers/availableSigningLanes.fixtures';
import { resolveCanonicalPasskeyEcdsaExportMaterialForLane } from '@/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { availableLaneEd25519Authorization } from './helpers/availableSigningLanes.fixtures';

const WALLET_ID = 'alice.testnet';
const RP_ID = 'localhost';
const PASSKEY_CREDENTIAL_ID = 'credential-export-lane';
const EMAIL_OTP_PROVIDER_SUBJECT_ID = 'google:export-lane';
const THRESHOLD_OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
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
const NEAR_ACCOUNT = nearAccountRefFromAccountId('alice.testnet');
const NEAR_ED25519_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString('ed25519ks_export_lane');
const ED25519_MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'ed25519-export-lane',
  WALLET_ID,
);
const ED25519_AUTHORIZATION = availableLaneEd25519Authorization({
  walletId: WALLET_ID,
  identitySeed: 'export-lane',
  authMethod: 'passkey',
});

function passkeySigningAuth(rpId = toRpId(RP_ID)) {
  return {
    kind: 'passkey' as const,
    rpId,
    credentialIdB64u: PASSKEY_CREDENTIAL_ID,
  };
}

function emailOtpSigningAuth() {
  return {
    kind: 'email_otp' as const,
    providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
  };
}

function ecdsaLane(
  overrides: Partial<Parameters<typeof canonicalEcdsaAvailableLane>[0]> = {},
): ConcreteAvailableEcdsaSigningLane {
  return canonicalEcdsaAvailableLane({
    chainTarget: overrides.chainTarget || EVM_TARGET,
    thresholdOwnerAddress: overrides.thresholdOwnerAddress || THRESHOLD_OWNER_ADDRESS,
    authMethod: overrides.authMethod,
    state: overrides.state,
    ecdsaThresholdKeyId: overrides.ecdsaThresholdKeyId,
    keyHandle: overrides.keyHandle,
    remainingUses: overrides.remainingUses,
    expiresAtMs: overrides.expiresAtMs,
    updatedAtMs: overrides.updatedAtMs,
    walletId: overrides.walletId,
  });
}

function availableLanes(lanes: ConcreteAvailableEcdsaSigningLane[]): AvailableSigningLanes {
  const targetKey = thresholdEcdsaChainTargetKey(EVM_TARGET);
  return {
    walletId: toWalletId(WALLET_ID),
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

async function readEcdsaLanesFixture(
  lanes: ConcreteAvailableEcdsaSigningLane[],
  _args: unknown,
): Promise<AvailableSigningLanes> {
  return availableLanes(lanes);
}

function depsFor(lanes: ConcreteAvailableEcdsaSigningLane[]): ExportLaneSelectionDeps {
  const read = readEcdsaLanesFixture.bind(undefined, lanes);
  return {
    readPersistedAvailableSigningLanesForTargets: read,
    readOwnerScopedAvailableSigningLanesForTargets: read,
  };
}

function ed25519Lane(
  overrides: Partial<Extract<ConcreteAvailableEd25519SigningLane, { authorizationState: 'authorized' }>> = {},
): Extract<ConcreteAvailableEd25519SigningLane, { authorizationState: 'authorized' }> {
  return {
    auth: passkeySigningAuth(),
    curve: 'ed25519',
    chain: 'near',
    materialActivation: ED25519_MATERIAL_ACTIVATION,
    walletId: toWalletId(WALLET_ID),
    nearAccountId: NEAR_ACCOUNT.accountId,
    nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
    signerSlot: 1,
    state: 'ready',
    thresholdSessionId: 'threshold-session-ed25519-export',
    remainingUses: 3,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'durable_sealed_record',
    authorizationState: 'authorized',
    authorization: ED25519_AUTHORIZATION,
    ...overrides,
  };
}

function deferredEd25519Lane(
  overrides: Partial<
    Extract<ConcreteAvailableEd25519SigningLane, { authorizationState: 'authorization_required' }>
  > = {},
): Extract<
  ConcreteAvailableEd25519SigningLane,
  { authorizationState: 'authorization_required' }
> {
  return {
    auth: passkeySigningAuth(),
    curve: 'ed25519',
    chain: 'near',
    materialActivation: ED25519_MATERIAL_ACTIVATION,
    walletId: toWalletId(WALLET_ID),
    nearAccountId: NEAR_ACCOUNT.accountId,
    nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
    signerSlot: 1,
    state: 'deferred',
    thresholdSessionId: 'threshold-session-ed25519-export',
    source: 'durable_sealed_record',
    authorizationState: 'authorization_required',
    ...overrides,
  };
}

async function readEd25519LanesFixture(
  lanes: ConcreteAvailableEd25519SigningLane[],
  _args: unknown,
): Promise<AvailableSigningLanes> {
  const canonicalLane = lanes.find((lane) => lane.authorizationState === 'authorized');
  return {
    walletId: toWalletId(WALLET_ID),
    generation: 1,
    ecdsa: {
      targets: [],
      lanesByTarget: {},
      candidatesByTarget: {},
    },
    lanes: {
      ed25519: {
        near: canonicalLane || { curve: 'ed25519', chain: 'near', state: 'missing' },
      },
    },
    candidates: {
      ed25519: {
        near: lanes,
      },
    },
  };
}

function depsForEd25519(lanes: ConcreteAvailableEd25519SigningLane[]): ExportLaneSelectionDeps {
  const read = readEd25519LanesFixture.bind(undefined, lanes);
  return {
    readPersistedAvailableSigningLanesForTargets: read,
    readOwnerScopedAvailableSigningLanesForTargets: read,
  };
}

async function readTargetLanesFixture(
  candidatesByTarget: Record<string, ConcreteAvailableEcdsaSigningLane[]>,
  _args: unknown,
): Promise<AvailableSigningLanes> {
  const targets = [EVM_TARGET, TEMPO_TARGET];
  return {
    walletId: toWalletId(WALLET_ID),
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
}

function depsForTargets(
  candidatesByTarget: Record<string, ConcreteAvailableEcdsaSigningLane[]>,
): ExportLaneSelectionDeps {
  const read = readTargetLanesFixture.bind(undefined, candidatesByTarget);
  return {
    readPersistedAvailableSigningLanesForTargets: read,
    readOwnerScopedAvailableSigningLanesForTargets: read,
  };
}

function ecdsaLaneIdentity(
  lane: ConcreteAvailableEcdsaSigningLane,
  chainTarget: ThresholdEcdsaChainTarget = lane.chainTarget,
) {
  return exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: lane.key.walletId,
      chainTarget,
      keyHandle: lane.publicFacts.keyHandle,
      key: lane.key,
      materialActivation: lane.materialActivation,
    }),
    auth: lane.auth,
  });
}

function expectEd25519ExportMaterialIdentity(lane: ConcreteAvailableEd25519SigningLane) {
  return expect.objectContaining({
    kind: 'exact_ed25519_export_material',
    auth: lane.auth,
    thresholdSessionId: lane.thresholdSessionId,
  });
}

test.describe('Ed25519 export lane selection', () => {
  test('selects one exact ready passkey Router A/B lane', async () => {
    const lane = ed25519Lane();

    const selected = await resolveExactKeyExportLane(depsForEd25519([lane]), {
      kind: 'ed25519',
      walletSession: walletSessionRefFromSession({
        walletId: WALLET_ID,
        walletSessionUserId: WALLET_ID,
      }),
      nearAccount: NEAR_ACCOUNT,
    });

    expect(selected).toEqual({
      kind: 'ed25519',
      laneIdentity: expectEd25519ExportMaterialIdentity(lane),
      materialActivation: lane.materialActivation,
    });
    expect(selected.laneIdentity).not.toHaveProperty('walletSessionId');
    expect(selected.laneIdentity).not.toHaveProperty('quotaId');
  });

  test('selects an exact restorable durable passkey Router A/B lane after refresh', async () => {
    const lane = ed25519Lane({
      state: 'restorable',
      source: 'durable_sealed_record',
    });

    const selected = await resolveExactKeyExportLane(depsForEd25519([lane]), {
      kind: 'ed25519',
      walletSession: walletSessionRefFromSession({
        walletId: WALLET_ID,
        walletSessionUserId: WALLET_ID,
      }),
      nearAccount: NEAR_ACCOUNT,
    });

    expect(selected).toEqual({
      kind: 'ed25519',
      laneIdentity: expectEd25519ExportMaterialIdentity(lane),
      materialActivation: lane.materialActivation,
    });
  });

  test('selects one exact ready Email OTP Router A/B lane', async () => {
    const lane = ed25519Lane({ auth: emailOtpSigningAuth() });

    const selected = await resolveExactKeyExportLane(depsForEd25519([lane]), {
      kind: 'ed25519',
      walletSession: walletSessionRefFromSession({
        walletId: WALLET_ID,
        walletSessionUserId: WALLET_ID,
      }),
      nearAccount: NEAR_ACCOUNT,
    });

    expect(selected).toEqual({
      kind: 'ed25519',
      laneIdentity: expectEd25519ExportMaterialIdentity(lane),
      materialActivation: lane.materialActivation,
    });
  });

  test('keeps fresh-passkey export available after signing budget expiry or exhaustion', async () => {
    for (const state of ['expired', 'exhausted'] as const) {
      const lane = ed25519Lane({
        state,
        source: 'durable_sealed_record',
        remainingUses: state === 'exhausted' ? 0 : 3,
      });

      await expect(
        resolveExactKeyExportLane(depsForEd25519([lane]), {
          kind: 'ed25519',
          walletSession: walletSessionRefFromSession({
            walletId: WALLET_ID,
            walletSessionUserId: WALLET_ID,
          }),
          nearAccount: NEAR_ACCOUNT,
        }),
      ).resolves.toEqual({
        kind: 'ed25519',
        laneIdentity: expectEd25519ExportMaterialIdentity(lane),
        materialActivation: lane.materialActivation,
      });
    }
  });

  test('uses the canonical current activation when historical owner material remains', async () => {
    const supersededActivation = buildMpcMaterialActivationRefFixture(
      'ed25519-export-lane-superseded',
      WALLET_ID,
    );
    const currentOwner = ed25519Lane();
    await expect(
      resolveExactKeyExportLane(
        depsForEd25519([
          currentOwner,
          deferredEd25519Lane({
            materialActivation: supersededActivation,
            thresholdSessionId: 'threshold-session-ed25519-export-superseded',
          }),
        ]),
        {
          kind: 'ed25519',
          walletSession: walletSessionRefFromSession({
            walletId: WALLET_ID,
            walletSessionUserId: WALLET_ID,
          }),
          nearAccount: NEAR_ACCOUNT,
        },
      ),
    ).resolves.toEqual({
      kind: 'ed25519',
      laneIdentity: expectEd25519ExportMaterialIdentity(currentOwner),
      materialActivation: currentOwner.materialActivation,
    });
  });

  test('ignores historical material for the same exact owner credential and signer slot', async () => {
    const currentOwner = ed25519Lane();
    const historicalOwner = ed25519Lane({
      materialActivation: buildMpcMaterialActivationRefFixture(
        'ed25519-export-lane-historical',
        WALLET_ID,
      ),
      thresholdSessionId: 'threshold-session-ed25519-export-historical',
      updatedAtMs: 1_700_000_000_000,
    });

    await expect(
      resolveExactKeyExportLane(depsForEd25519([currentOwner, historicalOwner]), {
        kind: 'ed25519',
        walletSession: walletSessionRefFromSession({
          walletId: WALLET_ID,
          walletSessionUserId: WALLET_ID,
        }),
        nearAccount: NEAR_ACCOUNT,
      }),
    ).resolves.toEqual({
      kind: 'ed25519',
      laneIdentity: expectEd25519ExportMaterialIdentity(currentOwner),
      materialActivation: currentOwner.materialActivation,
    });
  });

});

test.describe('ECDSA export lane selection', () => {
  test('selects a canonical passkey lane when reusable ECDSA authorization is absent', async () => {
    const lane = authorizationRequiredCanonicalEcdsaAvailableLane({
      authMethod: 'passkey',
      chainTarget: EVM_TARGET,
      thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
    });

    const selected = await resolveExactKeyExportLane(depsFor([lane]), {
      kind: 'ecdsa',
      walletSession: walletSessionRefFromSession({
        walletId: WALLET_ID,
        walletSessionUserId: WALLET_ID,
      }),
      chainTarget: EVM_TARGET,
    });

    expect(selected).toEqual({
      kind: 'ecdsa',
      laneIdentity: ecdsaLaneIdentity(lane),
    });

    const resolved = await resolveEcdsaSessionForExport(depsFor([lane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(lane),
    });
    expect(resolved).toMatchObject({
      authorizationState: 'authorization_required',
      authMethod: 'passkey',
      material: { kind: 'sealed_worker_material' },
    });
    expect(resolved).not.toHaveProperty('authorization');

    const material = resolveCanonicalPasskeyEcdsaExportMaterialForLane({
      deps: {
        exportArtifactsByLane: new Map(),
        relayerUrl: 'https://relay.example.test',
      },
      exportLane: resolved,
    });
    expect(material).toMatchObject({
      kind: 'fresh_passkey_needs_authorization',
      chainTarget: EVM_TARGET,
      existingRoleLocalMaterial: {
        materialActivation: lane.capability.manifest.activation.materialActivation,
      },
      relayerUrl: 'https://relay.example.test',
    });
  });

  test('selects ready Email OTP ECDSA export lanes after registration without restore', async () => {
    const evmLane = ecdsaLane({
      authMethod: 'email_otp',
      chainTarget: EVM_TARGET,
      state: 'ready',
    });
    const tempoLane = ecdsaLane({
      authMethod: 'email_otp',
      chainTarget: TEMPO_TARGET,
      state: 'ready',
    });
    const deps = depsForTargets({
      [thresholdEcdsaChainTargetKey(EVM_TARGET)]: [evmLane],
      [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [tempoLane],
    });

    const selectedEvm = await resolveEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(evmLane),
    });
    const selectedTempo = await resolveEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: TEMPO_TARGET,
      laneIdentity: ecdsaLaneIdentity(tempoLane),
    });

    expect(selectedEvm).toMatchObject({
      authMethod: 'email_otp',
      chainTarget: EVM_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
    expect(selectedTempo).toMatchObject({
      authMethod: 'email_otp',
      chainTarget: TEMPO_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
  });

  test('selects ready passkey ECDSA export lanes after registration without restore', async () => {
    const evmLane = ecdsaLane({
      authMethod: 'passkey',
      chainTarget: EVM_TARGET,
      state: 'ready',
    });
    const tempoLane = ecdsaLane({
      authMethod: 'passkey',
      chainTarget: TEMPO_TARGET,
      state: 'ready',
    });
    const deps = depsForTargets({
      [thresholdEcdsaChainTargetKey(EVM_TARGET)]: [evmLane],
      [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [tempoLane],
    });

    const selectedEvm = await resolveEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(evmLane),
    });
    const selectedTempo = await resolveEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: TEMPO_TARGET,
      laneIdentity: ecdsaLaneIdentity(tempoLane),
    });

    expect(selectedEvm).toMatchObject({
      authMethod: 'passkey',
      chainTarget: EVM_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
    expect(selectedTempo).toMatchObject({
      authMethod: 'passkey',
      chainTarget: TEMPO_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
  });

  test('keeps Email OTP ECDSA export material pending until route auth provides material', async () => {
    const lane = ecdsaLane({
      authMethod: 'email_otp',
      chainTarget: EVM_TARGET,
      state: 'deferred',
    });

    const selected = await resolveEcdsaSessionForExport(depsFor([lane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(lane),
    });

    expect(selected.material).toEqual({
      kind: 'material_pending',
      reason: 'email_otp_route_auth',
    });
  });

  test('selects deferred canonical Email OTP material after reusable quota exhaustion', async () => {
    const lane = authorizationRequiredCanonicalEcdsaAvailableLane({
      authMethod: 'email_otp',
      chainTarget: EVM_TARGET,
      thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
    });

    const selected = await resolveEcdsaSessionForExport(depsFor([lane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(lane),
    });

    expect(selected).toMatchObject({
      authorizationState: 'authorization_required',
      authMethod: 'email_otp',
      material: { kind: 'material_pending', reason: 'email_otp_route_auth' },
    });
    expect(selected).not.toHaveProperty('authorization');
  });

  test('rejects AccountMenu ECDSA export resolution when inventory has multiple ECDSA keys', async () => {
    const requestedKeyLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-account-menu-1',
    });
    const otherKeyLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-account-menu-2',
    });

    await expect(
      resolveExactKeyExportLane(depsFor([requestedKeyLane, otherKeyLane]), {
        kind: 'ecdsa',
        walletSession: walletSessionRefFromSession({
          walletId: WALLET_ID,
          walletSessionUserId: WALLET_ID,
        }),
        chainTarget: EVM_TARGET,
      }),
    ).rejects.toThrow('exact lane selection failed: ambiguous_material');
  });

  test('rejects duplicate canonical capabilities for the same ECDSA key identity', async () => {
    const runtimeLane = ecdsaLane({
      remainingUses: 2,
      updatedAtMs: 1_800_000_000_000,
    });
    const runtimeOnlyLane = ecdsaLane({
      remainingUses: 3,
      updatedAtMs: 1_800_000_001_000,
    });

    await expect(
      resolveEcdsaSessionForExport(depsFor([runtimeLane, runtimeOnlyLane]), {
        walletId: WALLET_ID,
        signingTarget: EVM_TARGET,
        laneIdentity: ecdsaLaneIdentity(runtimeLane),
      }),
    ).rejects.toThrow('exact lane selection failed: ambiguous_material');
  });

  test('selects requested ECDSA key identity when inventory has different key identities', async () => {
    const requestedLane = ecdsaLane({ ecdsaThresholdKeyId: 'ecdsa-key-1' });
    const otherLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-2',
    });
    const selected = await resolveEcdsaSessionForExport(depsFor([otherLane, requestedLane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(requestedLane),
    });

    expect(selected.key.ecdsaThresholdKeyId).toBe('ecdsa-key-1');
  });

  test('selects the requested exact ECDSA export lane when inventory has other lanes', async () => {
    const requestedLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-requested',
    });
    const otherLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-other',
    });

    const selected = await resolveEcdsaSessionForExport(depsFor([otherLane, requestedLane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(requestedLane),
    });

    expect(selected.key.ecdsaThresholdKeyId).toBe('ecdsa-key-requested');
  });

  test('rejects stale and ready ECDSA export lanes without auth ranking', async () => {
    const staleLane = ecdsaLane({
      authMethod: 'passkey',
      state: 'exhausted',
      remainingUses: 0,
      updatedAtMs: 1_800_000_001_000,
    });
    const readyDuplicateLane = ecdsaLane({
      remainingUses: 2,
      updatedAtMs: 1_800_000_000_000,
    });
    await expect(
      resolveEcdsaSessionForExport(depsFor([staleLane, readyDuplicateLane]), {
        walletId: WALLET_ID,
        signingTarget: EVM_TARGET,
        laneIdentity: ecdsaLaneIdentity(staleLane),
      }),
    ).rejects.toThrow('exact lane selection failed: ambiguous_material');
  });

  test('preserves the passkey auth binding for export selection', async () => {
    const lane = ecdsaLane();
    const selected = await resolveEcdsaSessionForExport(depsFor([lane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(lane),
    });

    expect(selected.authMethod).toBe('passkey');
    expect(selected.laneIdentity.auth).toEqual(lane.auth);
  });

  test('rejects active and exhausted duplicate ECDSA export lanes', async () => {
    const exhaustedLane = ecdsaLane({
      state: 'exhausted',
      remainingUses: 0,
      updatedAtMs: 1_800_000_001_000,
    });
    const activeDuplicateLane = ecdsaLane({
      state: 'ready',
      remainingUses: 2,
      updatedAtMs: 1_800_000_000_000,
    });
    await expect(
      resolveEcdsaSessionForExport(depsFor([exhaustedLane, activeDuplicateLane]), {
        walletId: WALLET_ID,
        signingTarget: EVM_TARGET,
        laneIdentity: ecdsaLaneIdentity(exhaustedLane),
      }),
    ).rejects.toThrow('exact lane selection failed: ambiguous_material');
  });
});
