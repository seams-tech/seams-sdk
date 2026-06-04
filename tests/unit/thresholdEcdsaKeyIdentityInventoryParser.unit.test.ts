import { expect, test } from '@playwright/test';
import {
  parseProfileContinuityEcdsaWarmKey,
  parseThresholdEcdsaKeyIdentityTargets,
} from '../../client/src/core/signingEngine/session/passkey/ecdsaKeyFactsInventory';
import { toAccountId } from '../../client/src/core/types/accountIds';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountSignerRecord } from '../../client/src/core/indexedDB/passkeyClientDB.types';

const WALLET_ID = toAccountId('alice.testnet');
const SUBJECT_ID = toWalletId(WALLET_ID);
const RP_ID = 'wallet.example.test';
const OWNER_ADDRESS = `0x${'ab'.repeat(20)}`;
const THRESHOLD_ECDSA_PUBLIC_KEY_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const EVM_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const satisfies ThresholdEcdsaChainTarget;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org_inventory_parser',
  projectId: 'project_inventory_parser',
  envId: 'dev',
  signingRootVersion: 'root_v1',
} as const;

function inventoryRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    keyHandle: 'ehss-key-inventory',
    walletId: WALLET_ID,
    subjectId: SUBJECT_ID,
    rpId: RP_ID,
    ecdsaThresholdKeyId: 'ehss-inventory',
    signingRootId: 'project_inventory_parser:dev',
    signingRootVersion: 'root_v1',
    participantIds: [1, 2],
    thresholdEcdsaPublicKeyB64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
    chainTarget: EVM_TARGET,
    accountAddress: OWNER_ADDRESS,
    ownerAddress: OWNER_ADDRESS,
    thresholdOwnerAddress: OWNER_ADDRESS,
    ...overrides,
  };
}

function profileSigner(metadataOverrides: Record<string, unknown> = {}): AccountSignerRecord {
  return {
    profileId: WALLET_ID,
    chainIdKey: 'evm:eip155:5042002',
    accountAddress: OWNER_ADDRESS,
    signerId: 'signer-evm:eip155:5042002',
    signerSlot: 1,
    signerType: 'threshold',
    status: 'active',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    addedAt: Date.now(),
    updatedAt: Date.now(),
    metadata: {
      keyHandle: 'ehss-key-inventory',
      chainTarget: EVM_TARGET,
      sharedEvmFamilyKey: {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        rpId: RP_ID,
        keyScope: 'evm-family',
        ecdsaThresholdKeyId: 'ehss-inventory',
        signingRootId: 'project_inventory_parser:dev',
        signingRootVersion: 'root_v1',
        participantIds: [1, 2],
        thresholdOwnerAddress: OWNER_ADDRESS,
        thresholdEcdsaPublicKeyB64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
      },
      ...metadataOverrides,
    },
  };
}

test.describe('threshold ECDSA key identity inventory parser', () => {
  test('accepts canonical inventory records and binds runtime policy scope', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      nearAccountId: WALLET_ID,
      rpId: RP_ID,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      records: [inventoryRecord()],
    });

    expect(parsed).toHaveLength(1);
    expect(parsed[0]).toMatchObject({
      accountAddress: OWNER_ADDRESS.toLowerCase(),
      ownerAddress: OWNER_ADDRESS.toLowerCase(),
      walletKey: {
        kind: 'evm_family_ecdsa_wallet_key',
        walletId: WALLET_ID,
        rpId: RP_ID,
        keyHandle: 'ehss-key-inventory',
        chainTarget: EVM_TARGET,
        keyFacts: {
          kind: 'evm_family_ecdsa_key_facts',
          keyScope: 'evm-family',
          ecdsaThresholdKeyId: 'ehss-inventory',
          signingRootId: 'project_inventory_parser:dev',
          signingRootVersion: 'root_v1',
          participantIds: [1, 2],
          thresholdOwnerAddress: OWNER_ADDRESS.toLowerCase(),
          thresholdEcdsaPublicKeyB64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
        },
      },
    });
  });

  test('rejects records that do not bind the expected wallet, rpId, and owner', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      nearAccountId: WALLET_ID,
      rpId: RP_ID,
      records: [
        inventoryRecord({ subjectId: 'wallet_other' }),
        inventoryRecord({ rpId: 'other.example.test' }),
        inventoryRecord({
          ownerAddress: `0x${'cd'.repeat(20)}`,
          thresholdOwnerAddress: OWNER_ADDRESS,
        }),
      ],
    });

    expect(parsed).toEqual([]);
  });

  test('rejects incomplete or target-only legacy inventory records', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      nearAccountId: WALLET_ID,
      rpId: RP_ID,
      records: [
        inventoryRecord({ keyHandle: '' }),
        inventoryRecord({ ecdsaThresholdKeyId: '' }),
        inventoryRecord({ participantIds: [] }),
        inventoryRecord({ thresholdEcdsaPublicKeyB64u: '' }),
        inventoryRecord({ chainTarget: { kind: 'tempo' } }),
        {
          walletId: WALLET_ID,
          rpId: RP_ID,
          chainTarget: EVM_TARGET,
          ownerAddress: OWNER_ADDRESS,
          accountAddress: OWNER_ADDRESS,
        },
      ],
    });

    expect(parsed).toEqual([]);
  });

  test('rejects synthetic legacy ids at the inventory boundary', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      nearAccountId: WALLET_ID,
      rpId: RP_ID,
      records: [
        inventoryRecord({ keyHandle: 'legacy-key-handle:ehss-key-inventory' }),
        inventoryRecord({ ecdsaThresholdKeyId: 'legacy-key-handle:ehss-key-inventory' }),
      ],
    });

    expect(parsed).toEqual([]);
  });

  test('parses active profile continuity ECDSA signer as a wallet key', () => {
    const parsed = parseProfileContinuityEcdsaWarmKey({
      nearAccountId: WALLET_ID,
      configuredTargets: [EVM_TARGET],
      signer: profileSigner(),
    });

    expect(parsed).toMatchObject({
      kind: 'active_wallet_key',
      targetKey: 'evm:eip155:5042002',
      walletKey: {
        kind: 'evm_family_ecdsa_wallet_key',
        walletId: WALLET_ID,
        rpId: RP_ID,
        keyHandle: 'ehss-key-inventory',
        chainTarget: EVM_TARGET,
      },
    });
  });

  test('marks key-handle-only profile continuity ECDSA signer for repair', () => {
    const parsed = parseProfileContinuityEcdsaWarmKey({
      nearAccountId: WALLET_ID,
      configuredTargets: [EVM_TARGET],
      signer: profileSigner({ sharedEvmFamilyKey: undefined }),
    });

    expect(parsed).toEqual({
      kind: 'repair_required',
      chainTarget: EVM_TARGET,
      targetKey: 'evm:eip155:5042002',
      keyHandle: 'ehss-key-inventory',
      reason: 'missing_key_facts',
    });
  });

  test('blocks invalid profile continuity ECDSA signer metadata', () => {
    const configuredTargets = [EVM_TARGET];
    const baseSharedKey = (profileSigner().metadata as Record<string, unknown>)
      .sharedEvmFamilyKey as Record<string, unknown>;
    const missingChainTarget = parseProfileContinuityEcdsaWarmKey({
      nearAccountId: WALLET_ID,
      configuredTargets,
      signer: profileSigner({ chainTarget: undefined }),
    });
    const ambiguousKeyHandle = parseProfileContinuityEcdsaWarmKey({
      nearAccountId: WALLET_ID,
      configuredTargets,
      signer: profileSigner({
        keyHandle: 'ehss-key-one',
        sharedEvmFamilyKey: {
          ...baseSharedKey,
          keyHandle: 'ehss-key-two',
        },
      }),
    });
    const legacyKey = parseProfileContinuityEcdsaWarmKey({
      nearAccountId: WALLET_ID,
      configuredTargets,
      signer: profileSigner({ keyHandle: 'legacy-key-handle:ehss-key-inventory' }),
    });

    expect(missingChainTarget).toEqual({
      kind: 'blocked',
      targetKey: '',
      reason: 'missing_chain_target',
    });
    expect(ambiguousKeyHandle).toEqual({
      kind: 'blocked',
      targetKey: 'evm:eip155:5042002',
      reason: 'ambiguous_key_handle',
    });
    expect(legacyKey).toEqual({
      kind: 'blocked',
      targetKey: 'evm:eip155:5042002',
      reason: 'synthetic_legacy_key_id',
    });
  });
});
