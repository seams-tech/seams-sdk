import { expect, test } from '@playwright/test';
import {
  resolveExactKeyExportLane,
  restoreEcdsaSessionForExport,
  restoreNearEd25519SessionForExport,
  type ExportLaneSelectionDeps,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  AvailableEd25519SigningLane,
  ConcreteAvailableEd25519SigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes';
import {
  buildPasskeyEcdsaAuthBinding,
  buildEvmFamilyEcdsaKeyIdentity,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  toRpId,
  type EvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildNamedNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
} from '@shared/utils/walletCapabilityBindings';
import { parseNamedNearAccountId } from '@shared/utils/near';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialKeyId,
} from '../../packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands';

const WALLET_ID = 'alice.testnet';
const RP_ID = 'localhost';
const PASSKEY_CREDENTIAL_ID = 'credential-export-lane';
const EMAIL_OTP_PROVIDER_SUBJECT_ID = 'google:export-lane';
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

function namedNearAccountIdForTest(value: string) {
  const parsed = parseNamedNearAccountId(value);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

const NEAR_EXPORT_SIGNER = buildNearEd25519SignerBinding({
  account: buildNamedNearAccountBinding({
    wallet: buildWalletIdentity({ walletId: walletIdFromString(WALLET_ID) }),
    nearAccountId: namedNearAccountIdForTest(WALLET_ID),
  }),
  nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(WALLET_ID),
  signerSlot: 1,
});

type EcdsaLaneOverrides = Partial<ConcreteAvailableEcdsaSigningLane> & {
  ecdsaThresholdKeyId?: string;
  thresholdOwnerAddress?: string;
  authBindingRpId?: string;
  authMethod?: 'email_otp' | 'passkey';
};

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

function ecdsaLane(overrides: EcdsaLaneOverrides): ConcreteAvailableEcdsaSigningLane {
  const {
    key: keyOverride,
    source,
    sourceChainTarget,
    publicFacts: publicFactsOverride,
    ecdsaThresholdKeyId,
    thresholdOwnerAddress,
    authBindingRpId,
    auth: authOverride,
    authMethod: authMethodOverride,
    resolvedKey: _resolvedKeyOverride,
    ...laneOverrides
  } = overrides;
  const authMethod = authMethodOverride || authOverride?.kind || 'passkey';
  const passkeyRpId = toRpId(authBindingRpId || RP_ID);
  const lane = {
    curve: 'ecdsa' as const,
    chainTarget: EVM_TARGET,
    state: 'ready' as const,
    signingGrantId: 'wallet-session-1',
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
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: WALLET_ID,
        signingRootId: 'root-1',
        signingRootVersion: 'default',
      }),
      ecdsaThresholdKeyId: ecdsaThresholdKeyId || 'ecdsa-key-1',
      signingRootId: 'root-1',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: thresholdOwnerAddress || THRESHOLD_OWNER_ADDRESS,
    });
  const publicFacts =
    publicFactsOverride ||
    buildVerifiedEcdsaPublicFacts({
      keyHandle: `${TEST_ECDSA_KEY_HANDLE}-${String(key.ecdsaThresholdKeyId)}-${String(
        key.signingRootId,
      )}-${String(key.signingRootVersion)}` as EvmFamilyEcdsaKeyHandle,
      publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      participantIds: key.participantIds,
      thresholdOwnerAddress: key.thresholdOwnerAddress,
    });
  if (source === 'evm_family_shared_key') {
    if (authMethod === 'passkey') {
      const auth =
        authOverride?.kind === 'passkey' ? authOverride : passkeySigningAuth(passkeyRpId);
      const resolvedKey = buildResolvedEvmFamilyEcdsaKey({
        walletId: key.walletId,
        publicFacts,
        authBinding: buildPasskeyEcdsaAuthBinding({
          rpId: passkeyRpId,
          credentialIdB64u: PASSKEY_CREDENTIAL_ID,
        }),
      });
      return {
        ...lane,
        auth,
        key,
        publicFacts,
        resolvedKey,
        source,
        sourceChainTarget: sourceChainTarget || EVM_TARGET,
      };
    }
    const auth = authOverride?.kind === 'email_otp' ? authOverride : emailOtpSigningAuth();
    return {
      ...lane,
      auth,
      key,
      publicFacts,
      source,
      sourceChainTarget: sourceChainTarget || EVM_TARGET,
    };
  }
  if (authMethod === 'passkey') {
    const auth = authOverride?.kind === 'passkey' ? authOverride : passkeySigningAuth(passkeyRpId);
    const resolvedKey = buildResolvedEvmFamilyEcdsaKey({
      walletId: key.walletId,
      publicFacts,
      authBinding: buildPasskeyEcdsaAuthBinding({
        rpId: passkeyRpId,
        credentialIdB64u: PASSKEY_CREDENTIAL_ID,
      }),
    });
    return {
      ...lane,
      auth,
      key,
      publicFacts,
      resolvedKey,
      source: source || 'runtime_session_record',
    };
  }
  const auth = authOverride?.kind === 'email_otp' ? authOverride : emailOtpSigningAuth();
  return {
    ...lane,
    auth,
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
    },
    restorePasskeyPersistedSessionForSigning: async (args) => {
      if (!restoreCalls) throw new Error('restore should not run for ready ECDSA export lanes');
      if (args.curve !== 'ecdsa') {
        throw new Error('expected ECDSA restore for ECDSA export lanes');
      }
      restoreCalls.passkeyChainTargets.push(args.chainTarget);
      return { kind: 'completed', attempted: 1, restored: 1, deferred: 0 };
    },
    restoreEmailOtpPersistedSessionForSigning: async () => {
      throw new Error('restore should not run for ready ECDSA export lanes');
    },
  };
}

function ed25519Lane(
  overrides: Partial<ConcreteAvailableEd25519SigningLane> & {
    authMethod?: 'email_otp' | 'passkey';
  },
): ConcreteAvailableEd25519SigningLane {
  const { auth: authOverride, authMethod: authMethodOverride, ...laneOverrides } = overrides;
  const authMethod = authMethodOverride || 'passkey';
  const auth =
    authOverride ||
    (authMethod === 'passkey'
      ? {
          kind: 'passkey' as const,
          rpId: toRpId(RP_ID),
          credentialIdB64u: PASSKEY_CREDENTIAL_ID,
        }
      : {
          kind: 'email_otp' as const,
          providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
        });
  return {
    auth,
    curve: 'ed25519',
    chain: 'near',
    walletId: NEAR_EXPORT_SIGNER.account.wallet.walletId,
    nearAccountId: NEAR_EXPORT_SIGNER.account.nearAccountId,
    nearEd25519SigningKeyId: NEAR_EXPORT_SIGNER.nearEd25519SigningKeyId,
    state: 'restorable',
    signingGrantId: 'wallet-ed25519-session-1',
    thresholdSessionId: 'threshold-ed25519-session-1',
    material: {
      kind: laneOverrides.state === 'ready' ? 'loaded_worker_material' : 'sealed_worker_material',
      identity: {
        bindingDigest: parseEd25519WorkerMaterialBindingDigest(
          'ed25519-worker-material-binding-digest-test',
        ),
        materialKeyId: parseEd25519WorkerMaterialKeyId('ed25519-worker-material-key-test'),
      },
    },
    remainingUses: 1,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'durable_sealed_record',
    ...laneOverrides,
    signerSlot: laneOverrides.signerSlot ?? NEAR_EXPORT_SIGNER.signerSlot,
  };
}

function ed25519LaneIdentity(lane: ConcreteAvailableEd25519SigningLane) {
  return exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      nearEd25519SigningKeyId: lane.nearEd25519SigningKeyId,
      signerSlot: lane.signerSlot,
    }),
    auth: lane.auth,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
  });
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
    }),
    auth: lane.auth,
    signingGrantId: lane.signingGrantId,
    thresholdSessionId: lane.thresholdSessionId,
  });
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
      return { kind: 'completed', attempted: 1, restored: 1, deferred: 0 };
    },
    restoreEmailOtpPersistedSessionForSigning: async () => {
      restoreCalls.emailOtp += 1;
      return { kind: 'completed', attempted: 1, restored: 1, deferred: 0 };
    },
  };
}

test.describe('Ed25519 export lane selection', () => {
  test('selects ready Email OTP Ed25519 export lane after registration without restore', async () => {
    const restoreCalls = { passkey: 0, emailOtp: 0 };
    const lane = ed25519Lane({
      authMethod: 'email_otp',
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-ed25519-email-registration',
      thresholdSessionId: 'threshold-ed25519-email-registration',
    });
    const selected = await restoreNearEd25519SessionForExport(
      depsForEd25519([lane], restoreCalls),
      { signer: NEAR_EXPORT_SIGNER, laneIdentity: ed25519LaneIdentity(lane) },
    );

    expect(selected.authMethod).toBe('email_otp');
    expect(selected.signingGrantId).toBe('wallet-ed25519-email-registration');
    expect(selected.material.kind).toBe('loaded_worker_material');
    expect(restoreCalls).toEqual({ passkey: 0, emailOtp: 0 });
  });

  test('selects ready passkey Ed25519 export lane after registration without restore', async () => {
    const restoreCalls = { passkey: 0, emailOtp: 0 };
    const lane = ed25519Lane({
      authMethod: 'passkey',
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-ed25519-passkey-registration',
      thresholdSessionId: 'threshold-ed25519-passkey-registration',
    });
    const selected = await restoreNearEd25519SessionForExport(
      depsForEd25519([lane], restoreCalls),
      { signer: NEAR_EXPORT_SIGNER, laneIdentity: ed25519LaneIdentity(lane) },
    );

    expect(selected.authMethod).toBe('passkey');
    expect(selected.signingGrantId).toBe('wallet-ed25519-passkey-registration');
    expect(selected.material.kind).toBe('loaded_worker_material');
    expect(restoreCalls).toEqual({ passkey: 0, emailOtp: 0 });
  });

  test('restores sealed passkey Ed25519 export material by material branch', async () => {
    const restoreCalls = { passkey: 0, emailOtp: 0 };
    const lane = ed25519Lane({
      authMethod: 'passkey',
      state: 'restorable',
      source: 'durable_sealed_record',
      signingGrantId: 'wallet-ed25519-passkey-restorable',
      thresholdSessionId: 'threshold-ed25519-passkey-restorable',
    });
    const selected = await restoreNearEd25519SessionForExport(
      depsForEd25519([lane], restoreCalls),
      { signer: NEAR_EXPORT_SIGNER, laneIdentity: ed25519LaneIdentity(lane) },
    );

    expect(selected.material.kind).toBe('sealed_worker_material');
    expect(restoreCalls).toEqual({ passkey: 1, emailOtp: 0 });
  });

  test('restores expired passkey Ed25519 export lanes as fresh-auth anchors', async () => {
    const restoreCalls = { passkey: 0, emailOtp: 0 };
    const lane = ed25519Lane({
      authMethod: 'passkey',
      state: 'expired',
      source: 'durable_sealed_record',
      signingGrantId: 'wallet-ed25519-passkey-expired',
      thresholdSessionId: 'threshold-ed25519-passkey-expired',
      expiresAtMs: Date.now() - 1_000,
      remainingUses: 3,
    });
    const selected = await restoreNearEd25519SessionForExport(
      depsForEd25519([lane], restoreCalls),
      { signer: NEAR_EXPORT_SIGNER, laneIdentity: ed25519LaneIdentity(lane) },
    );

    expect(selected.state).toBe('expired');
    expect(selected.material.kind).toBe('sealed_worker_material');
    expect(restoreCalls).toEqual({ passkey: 1, emailOtp: 0 });
  });

  test('rejects duplicate Ed25519 export lanes without auth ranking', async () => {
    const restoreCalls = { passkey: 0, emailOtp: 0 };
    const lane = ed25519Lane({
      authMethod: 'passkey',
      signingGrantId: 'wallet-ed25519-passkey',
      thresholdSessionId: 'threshold-ed25519-shared',
    });
    const duplicateLane = ed25519Lane({
      auth: lane.auth,
      signingGrantId: lane.signingGrantId,
      thresholdSessionId: lane.thresholdSessionId,
      updatedAtMs: 1_800_000_001_000,
    });
    await expect(
      restoreNearEd25519SessionForExport(depsForEd25519([lane, duplicateLane], restoreCalls), {
        signer: NEAR_EXPORT_SIGNER,
        laneIdentity: ed25519LaneIdentity(lane),
      }),
    ).rejects.toThrow('exact lane selection failed: duplicate_records');

    expect(restoreCalls.emailOtp).toBe(0);
    expect(restoreCalls.passkey).toBe(0);
  });

  test('resolves AccountMenu Ed25519 export from the canonical lane when runtime candidates share a grant', async () => {
    const restoreCalls = { passkey: 0, emailOtp: 0 };
    const canonicalLane = ed25519Lane({
      authMethod: 'passkey',
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-ed25519-shared-grant',
      thresholdSessionId: 'threshold-ed25519-current',
      remainingUses: 1,
      updatedAtMs: 1_800_000_010_000,
    });
    const olderLane = ed25519Lane({
      auth: canonicalLane.auth,
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: canonicalLane.signingGrantId,
      thresholdSessionId: 'threshold-ed25519-previous',
      remainingUses: 3,
      updatedAtMs: 1_800_000_000_000,
    });

    const resolved = await resolveExactKeyExportLane(
      depsForEd25519([canonicalLane, olderLane], restoreCalls),
      {
        kind: 'near',
        walletSession: walletSessionRefFromSession({
          walletId: WALLET_ID,
          walletSessionUserId: WALLET_ID,
        }),
        nearAccount: nearAccountRefFromAccountId(NEAR_EXPORT_SIGNER.account.nearAccountId),
      },
    );

    expect(resolved.kind).toBe('near');
    expect(resolved.laneIdentity.thresholdSessionId).toBe('threshold-ed25519-current');
    expect(resolved.laneIdentity.signingGrantId).toBe('wallet-ed25519-shared-grant');
  });
});

test.describe('ECDSA export lane selection', () => {
  test('selects ready Email OTP ECDSA export lanes after registration without restore', async () => {
    const evmLane = ecdsaLane({
      authMethod: 'email_otp',
      chainTarget: EVM_TARGET,
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-ecdsa-email-evm-registration',
      thresholdSessionId: 'threshold-ecdsa-email-evm-registration',
    });
    const tempoLane = ecdsaLane({
      authMethod: 'email_otp',
      chainTarget: TEMPO_TARGET,
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-ecdsa-email-tempo-registration',
      thresholdSessionId: 'threshold-ecdsa-email-tempo-registration',
    });
    const deps = depsForTargets({
      [thresholdEcdsaChainTargetKey(EVM_TARGET)]: [evmLane],
      [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [tempoLane],
    });

    const selectedEvm = await restoreEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(evmLane),
    });
    const selectedTempo = await restoreEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: TEMPO_TARGET,
      laneIdentity: ecdsaLaneIdentity(tempoLane),
    });

    expect(selectedEvm.session).toMatchObject({
      authMethod: 'email_otp',
      signingGrantId: 'wallet-ecdsa-email-evm-registration',
      thresholdSessionId: 'threshold-ecdsa-email-evm-registration',
      chainTarget: EVM_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
    expect(selectedTempo.session).toMatchObject({
      authMethod: 'email_otp',
      signingGrantId: 'wallet-ecdsa-email-tempo-registration',
      thresholdSessionId: 'threshold-ecdsa-email-tempo-registration',
      chainTarget: TEMPO_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
  });

  test('selects ready passkey ECDSA export lanes after registration without restore', async () => {
    const restoreCalls = { passkeyChainTargets: [] as ThresholdEcdsaChainTarget[] };
    const evmLane = ecdsaLane({
      authMethod: 'passkey',
      chainTarget: EVM_TARGET,
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-ecdsa-passkey-evm-registration',
      thresholdSessionId: 'threshold-ecdsa-passkey-evm-registration',
    });
    const tempoLane = ecdsaLane({
      authMethod: 'passkey',
      chainTarget: TEMPO_TARGET,
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-ecdsa-passkey-tempo-registration',
      thresholdSessionId: 'threshold-ecdsa-passkey-tempo-registration',
    });
    const deps = depsForTargets(
      {
        [thresholdEcdsaChainTargetKey(EVM_TARGET)]: [evmLane],
        [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [tempoLane],
      },
      restoreCalls,
    );

    const selectedEvm = await restoreEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(evmLane),
    });
    const selectedTempo = await restoreEcdsaSessionForExport(deps, {
      walletId: WALLET_ID,
      signingTarget: TEMPO_TARGET,
      laneIdentity: ecdsaLaneIdentity(tempoLane),
    });

    expect(selectedEvm.session).toMatchObject({
      authMethod: 'passkey',
      signingGrantId: 'wallet-ecdsa-passkey-evm-registration',
      thresholdSessionId: 'threshold-ecdsa-passkey-evm-registration',
      chainTarget: EVM_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
    expect(selectedTempo.session).toMatchObject({
      authMethod: 'passkey',
      signingGrantId: 'wallet-ecdsa-passkey-tempo-registration',
      thresholdSessionId: 'threshold-ecdsa-passkey-tempo-registration',
      chainTarget: TEMPO_TARGET,
      material: { kind: 'loaded_worker_material' },
    });
    expect(restoreCalls.passkeyChainTargets).toEqual([]);
  });

  test('keeps Email OTP ECDSA export material pending until route auth provides material', async () => {
    const lane = ecdsaLane({
      authMethod: 'email_otp',
      chainTarget: EVM_TARGET,
      state: 'restorable',
      source: 'durable_sealed_record',
      signingGrantId: 'wallet-ecdsa-email-restorable',
      thresholdSessionId: 'threshold-ecdsa-email-restorable',
    });

    const selected = await restoreEcdsaSessionForExport(depsFor([lane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(lane),
    });

    expect(selected.session.material).toEqual({
      kind: 'material_pending',
      reason: 'email_otp_route_auth',
    });
  });

  test('rejects raw AccountMenu Email OTP ECDSA export duplicates before canonical availability', async () => {
    const viableLane = ecdsaLane({
      authMethod: 'email_otp',
      chainTarget: EVM_TARGET,
      state: 'restorable',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-session-email-otp-current',
      thresholdSessionId: 'threshold-ecdsa-email-otp-current',
      remainingUses: 3,
      updatedAtMs: 1_800_000_000_000,
    });
    const exhaustedLane = ecdsaLane({
      auth: viableLane.auth,
      key: viableLane.key,
      publicFacts: viableLane.publicFacts,
      chainTarget: EVM_TARGET,
      state: 'exhausted',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-session-email-otp-exhausted',
      thresholdSessionId: 'threshold-ecdsa-email-otp-exhausted',
      remainingUses: 0,
      updatedAtMs: 1_800_000_010_000,
    });

    await expect(
      resolveExactKeyExportLane(depsFor([viableLane, exhaustedLane]), {
        kind: 'ecdsa',
        walletSession: walletSessionRefFromSession({
          walletId: WALLET_ID,
          walletSessionUserId: WALLET_ID,
        }),
        chainTarget: EVM_TARGET,
      }),
    ).rejects.toThrow('exact lane selection failed: ambiguous_material');
  });

  test('rejects AccountMenu ECDSA export resolution when inventory has multiple ECDSA keys', async () => {
    const requestedKeyLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-account-menu-1',
      signingGrantId: 'wallet-session-account-menu-1',
      thresholdSessionId: 'threshold-session-account-menu-1',
    });
    const otherKeyLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-account-menu-2',
      signingGrantId: 'wallet-session-account-menu-2',
      thresholdSessionId: 'threshold-session-account-menu-2',
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

  test('rejects duplicate live sessions for the same ECDSA key identity', async () => {
    const auth = passkeySigningAuth();
    const runtimeLane = ecdsaLane({
      auth,
      source: 'runtime_session_record',
      signingGrantId: 'wallet-session-runtime-durable',
      thresholdSessionId: 'threshold-session-runtime-durable',
      remainingUses: 2,
      updatedAtMs: 1_800_000_000_000,
    });
    const runtimeOnlyLane = ecdsaLane({
      source: 'runtime_session_record',
      signingGrantId: runtimeLane.signingGrantId,
      thresholdSessionId: runtimeLane.thresholdSessionId,
      auth,
      key: runtimeLane.key,
      publicFacts: runtimeLane.publicFacts,
      remainingUses: 3,
      updatedAtMs: 1_800_000_001_000,
    });

    await expect(
      restoreEcdsaSessionForExport(depsFor([runtimeLane, runtimeOnlyLane]), {
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
      signingGrantId: 'wallet-session-2',
      thresholdSessionId: 'threshold-session-2',
    });
    const selected = await restoreEcdsaSessionForExport(depsFor([otherLane, requestedLane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(requestedLane),
    });

    expect(selected.key.ecdsaThresholdKeyId).toBe('ecdsa-key-1');
  });

  test('selects the requested exact ECDSA export lane when inventory has other lanes', async () => {
    const requestedLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-requested',
      signingGrantId: 'wallet-session-requested',
      thresholdSessionId: 'threshold-session-requested',
    });
    const otherLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-other',
      signingGrantId: 'wallet-session-other',
      thresholdSessionId: 'threshold-session-other',
    });

    const selected = await restoreEcdsaSessionForExport(depsFor([otherLane, requestedLane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(requestedLane),
    });

    expect(selected.session.signingGrantId).toBe('wallet-session-requested');
    expect(selected.key.ecdsaThresholdKeyId).toBe('ecdsa-key-requested');
  });

  test('rejects duplicate exact ECDSA lanes with owner-address drift', async () => {
    const auth = passkeySigningAuth();
    const lane = ecdsaLane({ auth, thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS });
    const duplicateLane = ecdsaLane({
      auth,
      key: lane.key,
      publicFacts: lane.publicFacts,
      signingGrantId: lane.signingGrantId,
      thresholdSessionId: lane.thresholdSessionId,
      thresholdOwnerAddress: OTHER_THRESHOLD_OWNER_ADDRESS,
      updatedAtMs: 1_800_000_001_000,
    });
    await expect(
      restoreEcdsaSessionForExport(depsFor([lane, duplicateLane]), {
        walletId: WALLET_ID,
        signingTarget: EVM_TARGET,
        laneIdentity: ecdsaLaneIdentity(lane),
      }),
    ).rejects.toThrow(
      '[SigningEngine][ecdsa-export] exact lane selection failed: ambiguous_material',
    );
  });

  test('rejects stale and ready ECDSA export lanes without auth ranking', async () => {
    const auth = passkeySigningAuth();
    const staleLane = ecdsaLane({
      auth,
      authMethod: 'passkey',
      state: 'exhausted',
      signingGrantId: 'wallet-session-passkey',
      thresholdSessionId: 'threshold-session-passkey',
      remainingUses: 0,
      updatedAtMs: 1_800_000_001_000,
    });
    const readyDuplicateLane = ecdsaLane({
      auth,
      key: staleLane.key,
      publicFacts: staleLane.publicFacts,
      signingGrantId: staleLane.signingGrantId,
      thresholdSessionId: staleLane.thresholdSessionId,
      remainingUses: 2,
      updatedAtMs: 1_800_000_000_000,
    });
    await expect(
      restoreEcdsaSessionForExport(depsFor([staleLane, readyDuplicateLane]), {
        walletId: WALLET_ID,
        signingTarget: EVM_TARGET,
        laneIdentity: ecdsaLaneIdentity(staleLane),
      }),
    ).rejects.toThrow('exact lane selection failed: ambiguous_material');
  });

  test('uses passkey auth binding rpId for export selection', async () => {
    const lane = ecdsaLane({
      authBindingRpId: RP_ID,
      signingGrantId: 'wallet-session-passkey-auth-binding',
      thresholdSessionId: 'threshold-session-passkey-auth-binding',
    });
    const selected = await restoreEcdsaSessionForExport(depsFor([lane]), {
      walletId: WALLET_ID,
      signingTarget: EVM_TARGET,
      laneIdentity: ecdsaLaneIdentity(lane),
    });

    expect(selected.session.authMethod).toBe('passkey');
    expect(selected.session.signingGrantId).toBe('wallet-session-passkey-auth-binding');
  });

  test('rejects active and exhausted duplicate ECDSA export lanes', async () => {
    const auth = passkeySigningAuth();
    const exhaustedLane = ecdsaLane({
      auth,
      state: 'exhausted',
      signingGrantId: 'wallet-session-exhausted',
      thresholdSessionId: 'threshold-session-exhausted',
      remainingUses: 0,
      updatedAtMs: 1_800_000_001_000,
    });
    const activeDuplicateLane = ecdsaLane({
      auth,
      key: exhaustedLane.key,
      publicFacts: exhaustedLane.publicFacts,
      state: 'ready',
      signingGrantId: exhaustedLane.signingGrantId,
      thresholdSessionId: exhaustedLane.thresholdSessionId,
      remainingUses: 2,
      updatedAtMs: 1_800_000_000_000,
    });
    await expect(
      restoreEcdsaSessionForExport(depsFor([exhaustedLane, activeDuplicateLane]), {
        walletId: WALLET_ID,
        signingTarget: EVM_TARGET,
        laneIdentity: ecdsaLaneIdentity(exhaustedLane),
      }),
    ).rejects.toThrow('exact lane selection failed: ambiguous_material');
  });

  test('resolves shared-key target lane to concrete source material', async () => {
    const sourceLane = ecdsaLane({
      chainTarget: EVM_TARGET,
      signingGrantId: 'wallet-session-evm-source',
      thresholdSessionId: 'threshold-session-evm-source',
    });
    const sharedTempoLane = ecdsaLane({
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: EVM_TARGET,
      state: 'deferred',
      signingGrantId: sourceLane.signingGrantId,
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
        signingTarget: TEMPO_TARGET,
        laneIdentity: ecdsaLaneIdentity(sharedTempoLane),
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
      signingGrantId: 'wallet-session-evm-source',
      thresholdSessionId: 'threshold-session-evm-source',
    });
    const sharedTempoLane = ecdsaLane({
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: EVM_TARGET,
      state: 'deferred',
      signingGrantId: sourceLane.signingGrantId,
      thresholdSessionId: sourceLane.thresholdSessionId,
      updatedAtMs: sourceLane.updatedAtMs,
    });

    const selected = await restoreEcdsaSessionForExport(
      depsForTargets(
        {
          [thresholdEcdsaChainTargetKey(EVM_TARGET)]: [sourceLane],
          [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [sharedTempoLane],
        },
        restoreCalls,
      ),
      {
        walletId: WALLET_ID,
        signingTarget: TEMPO_TARGET,
        laneIdentity: ecdsaLaneIdentity(sharedTempoLane),
      },
    );

    expect(selected.session.material.kind).toBe('sealed_worker_material');
    expect(restoreCalls.passkeyChainTargets).toEqual([EVM_TARGET]);
  });

  test('uses shared-key target lane when source material is absent from export inventory', async () => {
    const restoreCalls = { passkeyChainTargets: [] as ThresholdEcdsaChainTarget[] };
    const sharedTempoLane = ecdsaLane({
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: EVM_TARGET,
      state: 'deferred',
      signingGrantId: 'wallet-session-shared-only',
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
        signingTarget: TEMPO_TARGET,
        laneIdentity: ecdsaLaneIdentity(sharedTempoLane),
      },
    );

    expect(selected.session.chainTarget).toEqual(EVM_TARGET);
    expect(selected.session.thresholdSessionId).toBe('threshold-session-shared-only');
    expect(selected.session.material.kind).toBe('sealed_worker_material');
    expect(restoreCalls.passkeyChainTargets).toEqual([EVM_TARGET]);
  });
});
