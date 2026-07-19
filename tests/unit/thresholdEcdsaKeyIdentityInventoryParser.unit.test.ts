import { expect, test } from '@playwright/test';
import {
  parseProfileContinuityEcdsaWarmKey,
  parseThresholdEcdsaKeyIdentityTargets,
} from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaKeyFactsInventory';
import {
  toWalletId,
  walletIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AccountSignerRecord } from '../../packages/sdk-web/src/core/indexedDB/passkeyClientDB.types';
import { parseRouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';

const WALLET_ID = toWalletId('alice.testnet');
const SUBJECT_ID = walletIdFromWalletProfile({ walletId: WALLET_ID });
const RP_ID = 'wallet.example.test';
const OWNER_ADDRESS = `0x${'ab'.repeat(20)}`;
const THRESHOLD_ECDSA_PUBLIC_KEY_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const EVM_FAMILY_SIGNING_KEY_SLOT_ID =
  'wallet-key:evm-family:alice.testnet:project_inventory_parser%3Adev:root_v1';
const EVM_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const satisfies ThresholdEcdsaChainTarget;

function publicCapability() {
  const digestB64u = Buffer.alloc(32, 7).toString('base64url');
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: {
      application_binding_digest_b64u: digestB64u,
    },
    public_identity: {
      context_binding_b64u: digestB64u,
      derivation_client_share_public_key33_b64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
      server_public_key33_b64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
      threshold_public_key33_b64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
      ethereum_address20_b64u: Buffer.from(OWNER_ADDRESS.slice(2), 'hex').toString('base64url'),
      client_share_retry_counter: 0,
      server_share_retry_counter: 0,
    },
    signer_set: {
      signer_set_id: 'inventory-signer-set',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'inventory-signer-a',
        key_epoch: 'inventory-epoch',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'inventory-signer-b',
        key_epoch: 'inventory-epoch',
      },
      selected_server: {
        server_id: 'inventory-signing-worker',
        key_epoch: 'inventory-epoch',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
    },
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'inventory-epoch',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'inventory-epoch',
        public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
      },
    },
    router_id: 'inventory-router',
    client_id: WALLET_ID,
    activation_epoch: 'inventory-activation',
    registration_request_digest_b64u: digestB64u,
    proof_transcript_digest_b64u: digestB64u,
  });
}

function inventoryRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    keyHandle: 'ederivation-key-inventory',
    walletId: WALLET_ID,
    subjectId: SUBJECT_ID,
    rpId: RP_ID,
    ecdsaThresholdKeyId: 'ederivation-inventory',
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    signingRootId: 'project_inventory_parser:dev',
    signingRootVersion: 'root_v1',
    participantIds: [1, 2],
    thresholdEcdsaPublicKeyB64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
    chainTarget: EVM_TARGET,
    accountAddress: OWNER_ADDRESS,
    ownerAddress: OWNER_ADDRESS,
    thresholdOwnerAddress: OWNER_ADDRESS,
    publicCapability: publicCapability(),
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
      keyHandle: 'ederivation-key-inventory',
      chainTarget: EVM_TARGET,
      sharedEvmFamilyKey: {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        rpId: RP_ID,
        keyScope: 'evm-family',
        ecdsaThresholdKeyId: 'ederivation-inventory',
        evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
        signingRootId: 'project_inventory_parser:dev',
        signingRootVersion: 'root_v1',
        participantIds: [1, 2],
        thresholdOwnerAddress: OWNER_ADDRESS,
        thresholdEcdsaPublicKeyB64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
      },
      publicCapability: publicCapability(),
      ...metadataOverrides,
    },
  };
}

test.describe('threshold ECDSA key identity inventory parser', () => {
  test('accepts canonical inventory records and binds explicit signing-root facts', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      walletId: WALLET_ID,
      rpId: RP_ID,
      records: [inventoryRecord()],
    });

    expect(parsed).toHaveLength(1);
    expect(parsed[0]).toMatchObject({
      accountAddress: OWNER_ADDRESS.toLowerCase(),
      ownerAddress: OWNER_ADDRESS.toLowerCase(),
      publicCapability: publicCapability(),
      walletKey: {
        kind: 'evm_family_ecdsa_wallet_key',
        walletId: WALLET_ID,
        keyHandle: 'ederivation-key-inventory',
        chainTarget: EVM_TARGET,
        keyFacts: {
          kind: 'evm_family_ecdsa_key_facts',
          keyScope: 'evm-family',
          ecdsaThresholdKeyId: 'ederivation-inventory',
          signingRootId: 'project_inventory_parser:dev',
          signingRootVersion: 'root_v1',
          participantIds: [1, 2],
          thresholdOwnerAddress: OWNER_ADDRESS.toLowerCase(),
          thresholdEcdsaPublicKeyB64u: THRESHOLD_ECDSA_PUBLIC_KEY_B64U,
        },
      },
    });
  });

  test('rejects an inventory capability for another wallet or threshold public key', () => {
    const wrongWalletCapability = structuredClone(publicCapability());
    wrongWalletCapability.client_id = 'other.testnet';
    const wrongPublicKeyCapability = structuredClone(publicCapability());
    wrongPublicKeyCapability.public_identity.threshold_public_key33_b64u = Buffer.from([
      2,
      ...new Uint8Array(32).fill(9),
    ]).toString('base64url');

    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      walletId: WALLET_ID,
      rpId: RP_ID,
      records: [
        inventoryRecord({ publicCapability: wrongWalletCapability }),
        inventoryRecord({ publicCapability: wrongPublicKeyCapability }),
      ],
    });

    expect(parsed).toEqual([]);
  });

  test('rejects records that do not bind the expected wallet, passkey auth scope, and owner', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      walletId: WALLET_ID,
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

  test('rejects incomplete or target-only inventory records', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      walletId: WALLET_ID,
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

  test('rejects invalid key handles at the inventory boundary', () => {
    const parsed = parseThresholdEcdsaKeyIdentityTargets({
      walletId: WALLET_ID,
      rpId: RP_ID,
      records: [
        inventoryRecord({ keyHandle: 'invalid:key-handle' }),
        inventoryRecord({ keyHandle: 'plain-key-handle' }),
      ],
    });

    expect(parsed).toEqual([]);
  });

  test('parses active profile continuity ECDSA signer as a wallet key', () => {
    const parsed = parseProfileContinuityEcdsaWarmKey({
      walletId: WALLET_ID,
      configuredTargets: [EVM_TARGET],
      signer: profileSigner(),
    });

    expect(parsed).toMatchObject({
      kind: 'active_wallet_key',
      targetKey: 'evm:eip155:5042002',
      walletKey: {
        kind: 'evm_family_ecdsa_wallet_key',
        walletId: WALLET_ID,
        keyHandle: 'ederivation-key-inventory',
        chainTarget: EVM_TARGET,
      },
      publicCapability: {
        kind: 'persisted_public_capability',
        value: publicCapability(),
      },
    });
  });

  test('marks key-handle-only profile continuity ECDSA signer as inventory-required', () => {
    const parsed = parseProfileContinuityEcdsaWarmKey({
      walletId: WALLET_ID,
      configuredTargets: [EVM_TARGET],
      signer: profileSigner({ sharedEvmFamilyKey: undefined }),
    });

    expect(parsed).toEqual({
      kind: 'key_facts_inventory_required',
      chainTarget: EVM_TARGET,
      targetKey: 'evm:eip155:5042002',
      keyHandle: 'ederivation-key-inventory',
      reason: 'missing_key_facts',
    });
  });

  test('blocks invalid profile continuity ECDSA signer metadata', () => {
    const configuredTargets = [EVM_TARGET];
    const baseSharedKey = (profileSigner().metadata as Record<string, unknown>)
      .sharedEvmFamilyKey as Record<string, unknown>;
    const missingChainTarget = parseProfileContinuityEcdsaWarmKey({
      walletId: WALLET_ID,
      configuredTargets,
      signer: profileSigner({ chainTarget: undefined }),
    });
    const ambiguousKeyHandle = parseProfileContinuityEcdsaWarmKey({
      walletId: WALLET_ID,
      configuredTargets,
      signer: profileSigner({
        keyHandle: 'ederivation-key-one',
        sharedEvmFamilyKey: {
          ...baseSharedKey,
          keyHandle: 'ederivation-key-two',
        },
      }),
    });
    const invalidKeyHandle = parseProfileContinuityEcdsaWarmKey({
      walletId: WALLET_ID,
      configuredTargets,
      signer: profileSigner({ keyHandle: 'invalid:key-handle' }),
    });

    expect(missingChainTarget).toEqual({
      kind: 'blocked',
      targetKey: '',
      reason: 'missing_chain_target',
    });
    expect(ambiguousKeyHandle).toEqual({
      kind: 'blocked',
      targetKey: 'evm:eip155:5042002',
      reason: 'duplicate_key_handles',
    });
    expect(invalidKeyHandle).toEqual({
      kind: 'blocked',
      targetKey: 'evm:eip155:5042002',
      reason: 'invalid_key_handle',
    });
  });
});
