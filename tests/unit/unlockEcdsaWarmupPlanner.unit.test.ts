import { expect, test } from '@playwright/test';
import {
  buildSharedKeyTargetCompletion,
  configuredTargetThresholdEcdsaWarmKey,
  parseActiveEcdsaSignerRecordForUnlock,
  planUnlockEcdsaWarmup,
  type ActiveEcdsaSignerRecord,
  type KeyFactsInventoryRequiredEcdsaSignerRecord,
  type WalletUnlockSelection,
} from '@/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner';
import { evmFamilyEcdsaWalletKeyToIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';

const WALLET_ID = toAccountId('alice.testnet');
const RP_ID = 'wallet.example.test';
const OWNER_ADDRESS = `0x${'ab'.repeat(20)}`;
const PUBLIC_KEY_33_B64U = Buffer.from([2, ...Array(32).fill(7)]).toString('base64url');
const RELAYER_PUBLIC_KEY_33_B64U = Buffer.from([3, ...Array(32).fill(9)]).toString('base64url');
const CONTEXT_BINDING_32_B64U = Buffer.from(new Uint8Array(32).fill(6)).toString('base64url');
const STATE_BLOB_B64U = Buffer.from(new Uint8Array(96).fill(8)).toString('base64url');

const EVM_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const satisfies ThresholdEcdsaChainTarget;

const TEMPO_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const satisfies ThresholdEcdsaChainTarget;

const ECDSA_SELECTION = {
  mode: 'ecdsa_only',
  ecdsa: true,
} satisfies WalletUnlockSelection;

const ED25519_SELECTION = {
  mode: 'ed25519_only',
  ed25519: true,
} satisfies WalletUnlockSelection;

function profileSigner(args: {
  chainTarget?: ThresholdEcdsaChainTarget;
  keyHandle?: string;
  sharedKey?: boolean;
  signerId?: string;
  status?: AccountSignerRecord['status'];
}): AccountSignerRecord {
  const chainTarget = args.chainTarget ?? EVM_TARGET;
  const keyHandle = args.keyHandle ?? 'ehss-key-shared';
  return {
    profileId: WALLET_ID,
    chainIdKey: thresholdEcdsaChainTargetKey(chainTarget),
    accountAddress: OWNER_ADDRESS,
    signerId: args.signerId ?? `signer-${thresholdEcdsaChainTargetKey(chainTarget)}`,
    signerSlot: 1,
    signerType: 'threshold',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    status: args.status ?? 'active',
    addedAt: Date.now(),
    updatedAt: Date.now(),
    metadata: {
      keyHandle,
      chainTarget,
      ...(args.sharedKey === false
        ? {}
        : {
            sharedEvmFamilyKey: {
              walletId: WALLET_ID,
              rpId: RP_ID,
              keyScope: 'evm-family',
              ecdsaThresholdKeyId: 'ehss-shared',
              signingRootId: 'project:dev',
              signingRootVersion: 'default',
              participantIds: [1, 2],
              thresholdOwnerAddress: OWNER_ADDRESS,
              thresholdEcdsaPublicKeyB64u: PUBLIC_KEY_33_B64U,
            },
          }),
    },
  };
}

function parseActive(
  signer: AccountSignerRecord,
  configuredTargets: readonly ThresholdEcdsaChainTarget[] = [EVM_TARGET, TEMPO_TARGET],
): ActiveEcdsaSignerRecord {
  const parsed = parseActiveEcdsaSignerRecordForUnlock({
    walletId: WALLET_ID,
    configuredTargets,
    signer,
  });
  if (parsed.kind !== 'active_ecdsa_signer_record') {
    throw new Error(`expected active signer, got ${parsed.kind}`);
  }
  return parsed;
}

function parseKeyFactsInventoryRequired(
  signer: AccountSignerRecord,
): KeyFactsInventoryRequiredEcdsaSignerRecord {
  const parsed = parseActiveEcdsaSignerRecordForUnlock({
    walletId: WALLET_ID,
    configuredTargets: [EVM_TARGET, TEMPO_TARGET],
    signer,
  });
  if (parsed.kind !== 'key_facts_inventory_required') {
    throw new Error(`expected key-facts inventory signer, got ${parsed.kind}`);
  }
  return parsed;
}

function localSessionRecordFor(active: ActiveEcdsaSignerRecord): ThresholdEcdsaSessionRecord {
  return {
    walletId: WALLET_ID,
    authMetadata: { rpId: RP_ID },
    chainTarget: active.chainTarget,
    relayerUrl: 'https://relay.example',
    keyHandle: active.walletKey.keyHandle,
    ecdsaThresholdKeyId: 'ehss-shared',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    relayerKeyId: 'rk-1',
    clientVerifyingShareB64u: 'client-share',
    ecdsaRoleLocalReadyRecord: buildEcdsaRoleLocalReadyRecord({
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: STATE_BLOB_B64U,
      },
      publicFacts: buildEcdsaRoleLocalPublicFacts({
        walletId: WALLET_ID,
        rpId: RP_ID,
        chainTarget: active.chainTarget,
        keyHandle: active.walletKey.keyHandle,
        ecdsaThresholdKeyId: 'ehss-shared',
        signingRootId: 'project:dev',
        signingRootVersion: 'default',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        contextBinding32B64u: CONTEXT_BINDING_32_B64U,
        hssClientSharePublicKey33B64u: PUBLIC_KEY_33_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
        groupPublicKey33B64u: PUBLIC_KEY_33_B64U,
        ethereumAddress: OWNER_ADDRESS,
      }),
      authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: active.walletKey.keyHandle,
        rpId: RP_ID,
      }),
    }),
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    walletSessionJwt: 'jwt',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 2,
    ethereumAddress: OWNER_ADDRESS,
    updatedAtMs: Date.now(),
    source: 'login',
  };
}

test.describe('unlock ECDSA warm-up planner', () => {
  test('skips ECDSA planning for Ed25519-only unlock', () => {
    const result = planUnlockEcdsaWarmup({
      selection: ED25519_SELECTION,
      configuredTargets: [EVM_TARGET],
      activeSignerRecords: [],
      localSessionRecords: [],
    });

    expect(result).toEqual({ kind: 'no_configured_ecdsa_targets' });
  });

  test('returns no configured targets for ECDSA-only unlock without configured chains', () => {
    const result = planUnlockEcdsaWarmup({
      selection: ECDSA_SELECTION,
      configuredTargets: [],
      activeSignerRecords: [],
      localSessionRecords: [],
    });

    expect(result).toEqual({ kind: 'no_configured_ecdsa_targets' });
  });

  test('returns ready from complete local wallet keys without inventory lookup', () => {
    const evm = parseActive(profileSigner({ chainTarget: EVM_TARGET }));
    const tempo = parseActive(profileSigner({ chainTarget: TEMPO_TARGET }));
    const result = planUnlockEcdsaWarmup({
      selection: ECDSA_SELECTION,
      configuredTargets: [EVM_TARGET, TEMPO_TARGET],
      activeSignerRecords: [evm, tempo],
      localSessionRecords: [localSessionRecordFor(evm)],
      allowAuthenticatedKeyFactsInventory: false,
      explicitKeyFactsInventoryMode: false,
    });

    expect(result.kind).toBe('ready');
    if (result.kind !== 'ready') throw new Error('expected ready plan');
    expect(result.readyTargets.map((target) => target.targetKey)).toEqual([
      'evm:eip155:5042002',
      'tempo:42431',
    ]);
    expect(result.readyTargets[0].localSessionRecord?.thresholdSessionId).toBe(
      'threshold-session-1',
    );
    expect(result.readyTargets[1].localSessionRecord).toBeUndefined();
  });

  test('completes configured targets from one shared EVM-family wallet key', () => {
    const evm = parseActive(profileSigner({ chainTarget: EVM_TARGET }));
    const result = buildSharedKeyTargetCompletion({
      context: {
        ecdsaKeys: [
          configuredTargetThresholdEcdsaWarmKey({
            chainTarget: EVM_TARGET,
            keyHandle: evm.walletKey.keyHandle,
            key: evmFamilyEcdsaWalletKeyToIdentity(evm.walletKey),
          }),
        ],
      },
      configuredTargets: [{ chainTarget: EVM_TARGET }, { chainTarget: TEMPO_TARGET }],
    });

    expect(result.kind).toBe('complete_shared_key_targets');
    if (result.kind !== 'complete_shared_key_targets') throw new Error('expected complete targets');
    expect(result.context.ecdsaKeys.map((key) => key.targetKey).sort()).toEqual(
      [thresholdEcdsaChainTargetKey(EVM_TARGET), thresholdEcdsaChainTargetKey(TEMPO_TARGET)].sort(),
    );
  });

  test('keeps key-handle-only active signers in key-facts inventory until explicit inventory auth exists', () => {
    const keyFactsInventoryRequired = parseKeyFactsInventoryRequired(
      profileSigner({ chainTarget: EVM_TARGET, sharedKey: false }),
    );
    const defaultPlan = planUnlockEcdsaWarmup({
      selection: ECDSA_SELECTION,
      configuredTargets: [EVM_TARGET],
      activeSignerRecords: [],
      keyFactsInventoryRequiredRecords: [keyFactsInventoryRequired],
      localSessionRecords: [],
    });
    const explicitInventoryPlan = planUnlockEcdsaWarmup({
      selection: ECDSA_SELECTION,
      configuredTargets: [EVM_TARGET],
      activeSignerRecords: [],
      keyFactsInventoryRequiredRecords: [keyFactsInventoryRequired],
      localSessionRecords: [],
      explicitKeyFactsInventoryMode: true,
      allowAuthenticatedKeyFactsInventory: true,
    });

    expect(defaultPlan).toMatchObject({
      kind: 'key_facts_inventory_required',
      keyFactsInventoryRequiredRecords: [
        { targetKey: 'evm:eip155:5042002', reason: 'missing_key_facts' },
      ],
    });
    expect(explicitInventoryPlan).toMatchObject({
      kind: 'awaiting_authenticated_key_facts_inventory',
      keyTargets: [{ keyHandle: 'ehss-key-shared', chainTarget: EVM_TARGET }],
    });
  });

  test('returns blocked for invalid active signer key handles before planning warm sessions', () => {
    const parsed = parseActiveEcdsaSignerRecordForUnlock({
      walletId: WALLET_ID,
      configuredTargets: [EVM_TARGET],
      signer: profileSigner({
        chainTarget: EVM_TARGET,
        keyHandle: 'invalid:key-handle',
      }),
    });
    expect(parsed).toEqual({
      kind: 'blocked',
      targetKey: 'evm:eip155:5042002',
      reason: 'invalid_key_handle',
      signerId: 'signer-evm:eip155:5042002',
    });
    const result = planUnlockEcdsaWarmup({
      selection: ECDSA_SELECTION,
      configuredTargets: [EVM_TARGET],
      activeSignerRecords: [],
      blockedRecords: parsed.kind === 'blocked' ? [parsed] : [],
      localSessionRecords: [],
    });

    expect(result).toEqual({
      kind: 'blocked',
      blockedRecords: [parsed],
    });
  });

  test('blocks active signers that only carry keyHandle inside key facts', () => {
    const signer = profileSigner({ chainTarget: EVM_TARGET });
    const metadata = signer.metadata as Record<string, unknown>;
    delete metadata.keyHandle;
    metadata.sharedEvmFamilyKey = {
      ...(metadata.sharedEvmFamilyKey as Record<string, unknown>),
      keyHandle: 'ehss-key-shared',
    };

    const parsed = parseActiveEcdsaSignerRecordForUnlock({
      walletId: WALLET_ID,
      configuredTargets: [EVM_TARGET],
      signer,
    });

    expect(parsed).toMatchObject({
      kind: 'blocked',
      targetKey: thresholdEcdsaChainTargetKey(EVM_TARGET),
      reason: 'missing_key_handle',
    });
  });

  test('blocks ambiguous active wallet keys for the same configured target', () => {
    const first = parseActive(
      profileSigner({ chainTarget: EVM_TARGET, keyHandle: 'ehss-key-one' }),
    );
    const second = parseActive(
      profileSigner({ chainTarget: EVM_TARGET, keyHandle: 'ehss-key-two', signerId: 'signer-two' }),
    );
    const result = planUnlockEcdsaWarmup({
      selection: ECDSA_SELECTION,
      configuredTargets: [EVM_TARGET],
      activeSignerRecords: [first, second],
      localSessionRecords: [],
    });

    expect(result).toMatchObject({
      kind: 'blocked',
      blockedRecords: [
        {
          targetKey: 'evm:eip155:5042002',
          reason: 'ambiguous_key_handle',
          signerId: 'signer-two',
        },
      ],
    });
  });
});
