import { expect, test } from '@playwright/test';
import {
  resolveExactKeyExportLane,
  resolveEcdsaSessionForExport,
  type ExportLaneSelectionDeps,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection';
import {
  thresholdEcdsaChainTargetKey,
  nearAccountRefFromAccountId,
  toWalletId,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
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
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import type { EcdsaReauthAnchorPublicRestore } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import { runtimeEcdsaRouterAbNormalSigningState } from './helpers/availableSigningLanes.fixtures';

const WALLET_ID = 'alice.testnet';
const RP_ID = 'localhost';
const PASSKEY_CREDENTIAL_ID = 'credential-export-lane';
const EMAIL_OTP_PROVIDER_SUBJECT_ID = 'google:export-lane';
const THRESHOLD_OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const OTHER_THRESHOLD_OWNER_ADDRESS = '0x2222222222222222222222222222222222222222';
const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const TEST_ECDSA_KEY_HANDLE = 'ederivation-key-export-lane-test' as EvmFamilyEcdsaKeyHandle;
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

type EcdsaLaneCommonOverrides = Partial<
  Pick<
    ConcreteAvailableEcdsaSigningLane,
    | 'key'
    | 'publicFacts'
    | 'chainTarget'
    | 'state'
    | 'signingGrantId'
    | 'thresholdSessionId'
    | 'remainingUses'
    | 'expiresAtMs'
    | 'updatedAtMs'
  >
> & {
  ecdsaThresholdKeyId?: string;
  thresholdOwnerAddress?: string;
  authBindingRpId?: string;
};

type EcdsaLaneAuthOverrides =
  | {
      authMethod?: 'passkey';
      auth?: Extract<ConcreteAvailableEcdsaSigningLane['auth'], { kind: 'passkey' }>;
    }
  | {
      authMethod: 'email_otp';
      auth?: Extract<ConcreteAvailableEcdsaSigningLane['auth'], { kind: 'email_otp' }>;
    };

type EcdsaLaneSourceOverrides =
  | {
      source?: 'runtime_session_record';
      sourceChainTarget?: never;
    }
  | {
      source: 'durable_sealed_record';
      sourceChainTarget?: never;
    }
  | {
      source: 'evm_family_shared_key';
      sourceChainTarget?: ThresholdEcdsaChainTarget;
    };

type EcdsaLaneOverrides = EcdsaLaneCommonOverrides &
  EcdsaLaneAuthOverrides &
  EcdsaLaneSourceOverrides;

type EcdsaLaneCommon = Pick<
  ConcreteAvailableEcdsaSigningLane,
  | 'key'
  | 'publicFacts'
  | 'curve'
  | 'chainTarget'
  | 'state'
  | 'signingGrantId'
  | 'thresholdSessionId'
  | 'remainingUses'
  | 'expiresAtMs'
  | 'updatedAtMs'
>;

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

function ecdsaLaneCommon(overrides: EcdsaLaneOverrides): EcdsaLaneCommon {
  const key =
    overrides.key ||
    buildEvmFamilyEcdsaKeyIdentity({
      walletId: WALLET_ID,
      evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
        walletId: WALLET_ID,
        signingRootId: 'root-1',
        signingRootVersion: 'default',
      }),
      ecdsaThresholdKeyId: overrides.ecdsaThresholdKeyId || 'ecdsa-key-1',
      signingRootId: 'root-1',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: overrides.thresholdOwnerAddress || THRESHOLD_OWNER_ADDRESS,
    });
  const publicFacts =
    overrides.publicFacts ||
    buildVerifiedEcdsaPublicFacts({
      keyHandle: `${TEST_ECDSA_KEY_HANDLE}-${String(key.ecdsaThresholdKeyId)}-${String(
        key.signingRootId,
      )}-${String(key.signingRootVersion)}` as EvmFamilyEcdsaKeyHandle,
      publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      participantIds: key.participantIds,
      thresholdOwnerAddress: key.thresholdOwnerAddress,
    });
  return {
    key,
    publicFacts,
    curve: 'ecdsa',
    chainTarget: overrides.chainTarget || EVM_TARGET,
    state: overrides.state || 'ready',
    signingGrantId: overrides.signingGrantId || 'wallet-session-1',
    thresholdSessionId: overrides.thresholdSessionId || 'threshold-session-1',
    remainingUses: overrides.remainingUses ?? 3,
    expiresAtMs: overrides.expiresAtMs ?? 1_900_000_000_000,
    updatedAtMs: overrides.updatedAtMs ?? 1_800_000_000_000,
  };
}

function resolvedPasskeyKey(common: EcdsaLaneCommon, rpId: ReturnType<typeof toRpId>) {
  return buildResolvedEvmFamilyEcdsaKey({
    walletId: common.key.walletId,
    publicFacts: common.publicFacts,
    authBinding: buildPasskeyEcdsaAuthBinding({
      rpId,
      credentialIdB64u: PASSKEY_CREDENTIAL_ID,
    }),
  });
}

function durablePublicReauthAuthority(
  common: EcdsaLaneCommon,
  auth: ConcreteAvailableEcdsaSigningLane['auth'],
): EcdsaReauthAnchorPublicRestore {
  const base = {
    chainTarget: common.chainTarget,
    signingRootId: common.key.signingRootId,
    signingRootVersion: common.key.signingRootVersion,
    evmFamilySigningKeySlotId: common.key.evmFamilySigningKeySlotId,
    keyHandle: common.publicFacts.keyHandle,
    ecdsaThresholdKeyId: common.key.ecdsaThresholdKeyId,
    ethereumAddress: common.key.thresholdOwnerAddress,
    relayerKeyId: 'signing-worker-export-lane',
    thresholdEcdsaPublicKeyB64u: common.publicFacts.publicKeyB64u,
    participantIds: [...common.key.participantIds],
    runtimePolicyScope: {
      orgId: 'org-export-lane',
      projectId: 'project-export-lane',
      envId: 'test',
      signingRootVersion: common.key.signingRootVersion,
    },
    routerAbEcdsaDerivationNormalSigning: runtimeEcdsaRouterAbNormalSigningState({
      key: common.key,
      thresholdSessionId: common.thresholdSessionId,
      thresholdEcdsaPublicKeyB64u: common.publicFacts.publicKeyB64u,
      thresholdOwnerAddress: common.key.thresholdOwnerAddress,
    }),
  };
  switch (auth.kind) {
    case 'passkey':
      return {
        ...base,
        source: 'login',
        rpId: auth.rpId,
        credentialIdB64u: auth.credentialIdB64u,
      };
    case 'email_otp':
      return {
        ...base,
        source: 'email_otp',
        provider: 'google',
        providerSubjectId: auth.providerSubjectId,
        emailHashHex: '11'.repeat(32),
      };
  }
}

function ecdsaLaneAuth(overrides: EcdsaLaneOverrides): ConcreteAvailableEcdsaSigningLane['auth'] {
  switch (overrides.authMethod) {
    case 'email_otp':
      return overrides.auth || emailOtpSigningAuth();
    case 'passkey':
    case undefined:
      return overrides.auth || passkeySigningAuth(toRpId(overrides.authBindingRpId || RP_ID));
  }
}

function ecdsaLane(overrides: EcdsaLaneOverrides): ConcreteAvailableEcdsaSigningLane {
  const common = ecdsaLaneCommon(overrides);
  const auth = ecdsaLaneAuth(overrides);

  switch (overrides.source) {
    case 'durable_sealed_record':
      return auth.kind === 'passkey'
        ? {
            ...common,
            auth,
            resolvedKey: resolvedPasskeyKey(common, auth.rpId),
            source: 'durable_sealed_record',
            publicReauthAuthority: durablePublicReauthAuthority(common, auth),
          }
        : {
            ...common,
            auth,
            source: 'durable_sealed_record',
            publicReauthAuthority: durablePublicReauthAuthority(common, auth),
          };
    case 'evm_family_shared_key':
      return auth.kind === 'passkey'
        ? {
            ...common,
            auth,
            resolvedKey: resolvedPasskeyKey(common, auth.rpId),
            source: 'evm_family_shared_key',
            sourceChainTarget: overrides.sourceChainTarget || EVM_TARGET,
          }
        : {
            ...common,
            auth,
            source: 'evm_family_shared_key',
            sourceChainTarget: overrides.sourceChainTarget || EVM_TARGET,
          };
    case 'runtime_session_record':
    case undefined:
      return auth.kind === 'passkey'
        ? {
            ...common,
            auth,
            resolvedKey: resolvedPasskeyKey(common, auth.rpId),
            source: 'runtime_session_record',
          }
        : {
            ...common,
            auth,
            source: 'runtime_session_record',
          };
  }
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

function depsFor(lanes: ConcreteAvailableEcdsaSigningLane[]): ExportLaneSelectionDeps {
  return {
    readPersistedAvailableSigningLanesForTargets: async () => availableLanes(lanes),
  };
}

function ed25519Lane(
  overrides: Partial<ConcreteAvailableEd25519SigningLane> = {},
): ConcreteAvailableEd25519SigningLane {
  return {
    auth: passkeySigningAuth(),
    curve: 'ed25519',
    chain: 'near',
    walletId: toWalletId(WALLET_ID),
    nearAccountId: NEAR_ACCOUNT.accountId,
    nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
    signerSlot: 1,
    state: 'ready',
    signingGrantId: 'wallet-session-ed25519-export',
    thresholdSessionId: 'threshold-session-ed25519-export',
    remainingUses: 3,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'runtime_session_record',
    ...overrides,
  };
}

function depsForEd25519(lanes: ConcreteAvailableEd25519SigningLane[]): ExportLaneSelectionDeps {
  return {
    readPersistedAvailableSigningLanesForTargets: async () => ({
      walletId: toWalletId(WALLET_ID),
      generation: 1,
      ecdsa: {
        targets: [],
        lanesByTarget: {},
        candidatesByTarget: {},
      },
      lanes: {
        ed25519: {
          near: lanes[0] || { curve: 'ed25519', chain: 'near', state: 'missing' },
        },
      },
      candidates: {
        ed25519: {
          near: lanes,
        },
      },
    }),
  };
}

function depsForTargets(
  candidatesByTarget: Record<string, ConcreteAvailableEcdsaSigningLane[]>,
): ExportLaneSelectionDeps {
  return {
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
    }),
    auth: lane.auth,
    signingGrantId: lane.signingGrantId,
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
      laneIdentity: expect.objectContaining({
        kind: 'exact_signing_lane',
        auth: expect.objectContaining({
          kind: 'passkey',
          credentialIdB64u: PASSKEY_CREDENTIAL_ID,
        }),
        signingGrantId: lane.signingGrantId,
        thresholdSessionId: lane.thresholdSessionId,
      }),
    });
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
      laneIdentity: expect.objectContaining({
        kind: 'exact_signing_lane',
        signingGrantId: lane.signingGrantId,
        thresholdSessionId: lane.thresholdSessionId,
      }),
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
      laneIdentity: expect.objectContaining({
        auth: {
          kind: 'email_otp',
          providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
        },
        signingGrantId: lane.signingGrantId,
        thresholdSessionId: lane.thresholdSessionId,
      }),
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
        laneIdentity: expect.objectContaining({
          signingGrantId: lane.signingGrantId,
          thresholdSessionId: lane.thresholdSessionId,
        }),
      });
    }
  });

  test('rejects deferred material and duplicate lanes', async () => {
    const invalidSets: ConcreteAvailableEd25519SigningLane[][] = [
      [
        ed25519Lane({
          state: 'deferred',
          source: 'durable_sealed_record',
        }),
      ],
      [ed25519Lane(), ed25519Lane()],
    ];

    for (const lanes of invalidSets) {
      await expect(
        resolveExactKeyExportLane(depsForEd25519(lanes), {
          kind: 'ed25519',
          walletSession: walletSessionRefFromSession({
            walletId: WALLET_ID,
            walletSessionUserId: WALLET_ID,
          }),
          nearAccount: NEAR_ACCOUNT,
        }),
      ).rejects.toThrow('exact Yao lane selection failed');
    }
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

    const selected = await resolveEcdsaSessionForExport(depsFor([lane]), {
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
      authMethod: 'email_otp',
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
      signingGrantId: 'wallet-session-2',
      thresholdSessionId: 'threshold-session-2',
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
      signingGrantId: 'wallet-session-requested',
      thresholdSessionId: 'threshold-session-requested',
    });
    const otherLane = ecdsaLane({
      ecdsaThresholdKeyId: 'ecdsa-key-other',
      signingGrantId: 'wallet-session-other',
      thresholdSessionId: 'threshold-session-other',
    });

    const selected = await resolveEcdsaSessionForExport(depsFor([otherLane, requestedLane]), {
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
      resolveEcdsaSessionForExport(depsFor([lane, duplicateLane]), {
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
      resolveEcdsaSessionForExport(depsFor([staleLane, readyDuplicateLane]), {
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
    const selected = await resolveEcdsaSessionForExport(depsFor([lane]), {
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
      resolveEcdsaSessionForExport(depsFor([exhaustedLane, activeDuplicateLane]), {
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
    const selected = await resolveEcdsaSessionForExport(
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

  test('resolves the concrete sealed source target without hydrating signer material', async () => {
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

    const selected = await resolveEcdsaSessionForExport(
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

    expect(selected.session.material.kind).toBe('sealed_worker_material');
  });

  test('uses shared-key target lane when source material is absent from export inventory', async () => {
    const sharedTempoLane = ecdsaLane({
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: EVM_TARGET,
      state: 'deferred',
      signingGrantId: 'wallet-session-shared-only',
      thresholdSessionId: 'threshold-session-shared-only',
    });

    const selected = await resolveEcdsaSessionForExport(
      depsForTargets({
        [thresholdEcdsaChainTargetKey(TEMPO_TARGET)]: [sharedTempoLane],
      }),
      {
        walletId: WALLET_ID,
        signingTarget: TEMPO_TARGET,
        laneIdentity: ecdsaLaneIdentity(sharedTempoLane),
      },
    );

    expect(selected.session.chainTarget).toEqual(EVM_TARGET);
    expect(selected.session.thresholdSessionId).toBe('threshold-session-shared-only');
    expect(selected.session.material.kind).toBe('sealed_worker_material');
  });
});
