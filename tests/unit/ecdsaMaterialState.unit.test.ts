import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { buildEcdsaMaterialStateForCandidate } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState';
import type { ThresholdEcdsaChainTarget } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaLaneCandidate } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const EVM_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};

const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const CONTEXT_BINDING_32_B64U = base64UrlEncode(new Uint8Array(32).fill(8));
const STATE_BLOB_B64U = base64UrlEncode(new Uint8Array(64).fill(9));
const OWNER_ADDRESS = `0x${'aa'.repeat(20)}`;

const TEMPO_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 1,
  networkSlug: 'tempo-1',
};

function makeCandidate(): EcdsaLaneCandidate {
  const walletId = toAccountId('alice.testnet');
  return {
    kind: 'lane_candidate',
    walletId,
    key: buildEvmFamilyEcdsaKeyIdentity({
      walletId,
      rpId: 'example.localhost',
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: 'root-1',
      signingRootVersion: 'v1',
      participantIds: [1, 2],
      thresholdOwnerAddress: OWNER_ADDRESS,
    }),
    authMethod: 'passkey',
    curve: 'ecdsa',
    chain: 'evm',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
    walletSigningSessionId: 'wallet-session-1',
    thresholdSessionId: 'threshold-session-1',
    state: 'ready',
    remainingUses: 1,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'runtime_session_record',
    chainTarget: EVM_CHAIN_TARGET,
  };
}

function makeRoleLocalReadyRecord() {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: STATE_BLOB_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toAccountId('alice.testnet'),
      rpId: 'example.localhost',
      chainTarget: EVM_CHAIN_TARGET,
      keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: 'root-1',
      signingRootVersion: 'v1',
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
      hssClientSharePublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: VALID_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      ethereumAddress: OWNER_ADDRESS,
    }),
    authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
      credentialIdB64u: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
      rpId: 'example.localhost',
    }),
  });
}

function makeRecord(
  overrides: Partial<Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>> = {},
): ThresholdEcdsaSessionRecord {
  return {
    walletId: toAccountId('alice.testnet'),
    chainTarget: EVM_CHAIN_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: 'client-verifying-share',
    ecdsaRoleLocalReadyRecord: makeRoleLocalReadyRecord(),
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-session-1',
    thresholdSessionAuthToken: 'threshold-auth-token',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: OWNER_ADDRESS,
    updatedAtMs: 1_800_000_000_000,
    source: 'login',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
    authMetadata: { rpId: 'example.localhost' },
    ...overrides,
  };
}

test.describe('ecdsa material state', () => {
  test('rejects an explicit chainTarget that does not match the candidate', () => {
    expect(() =>
      buildEcdsaMaterialStateForCandidate({
        candidate: makeCandidate(),
        record: undefined,
        authMethod: 'passkey',
        source: 'login',
        chainTarget: TEMPO_CHAIN_TARGET,
        materialChainTarget: TEMPO_CHAIN_TARGET,
      }),
    ).toThrow(
      '[SigningEngine][ecdsa] material-state builder chain target must match candidate chain target',
    );
  });

  test('treats ready-state blob records as ready signer material', () => {
    const state = buildEcdsaMaterialStateForCandidate({
      candidate: makeCandidate(),
      record: makeRecord(),
      authMethod: 'passkey',
      source: 'login',
      chainTarget: EVM_CHAIN_TARGET,
      materialChainTarget: EVM_CHAIN_TARGET,
    });

    expect(state.kind).toBe('ready_to_sign');
    if (state.kind !== 'ready_to_sign') return;
    expect(state.signerSession.clientShare.kind).toBe('role_local_ready_state_blob');
    expect(state.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
  });

  test('ready material carries a signer session', () => {
    const state = buildEcdsaMaterialStateForCandidate({
      candidate: makeCandidate(),
      record: makeRecord(),
      authMethod: 'passkey',
      source: 'login',
      chainTarget: EVM_CHAIN_TARGET,
      materialChainTarget: EVM_CHAIN_TARGET,
    });

    expect(state.kind).toBe('ready_to_sign');
    if (state.kind !== 'ready_to_sign') return;
    expect(state.signerSession.clientShare.kind).toBe('role_local_ready_state_blob');
    expect(state.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
  });
});
