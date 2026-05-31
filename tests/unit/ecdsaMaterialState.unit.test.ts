import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import { buildEcdsaMaterialStateForCandidate } from '../../client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState';
import type { ThresholdEcdsaChainTarget } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaLaneCandidate } from '../../client/src/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../client/src/core/signingEngine/session/persistence/records';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const EVM_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};

const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
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

function makeRecord(
  overrides: Partial<ThresholdEcdsaSessionRecord> = {},
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

  test('distinguishes public identity from ready signer material', () => {
    const state = buildEcdsaMaterialStateForCandidate({
      candidate: makeCandidate(),
      record: makeRecord(),
      authMethod: 'passkey',
      source: 'login',
      chainTarget: EVM_CHAIN_TARGET,
      materialChainTarget: EVM_CHAIN_TARGET,
    });

    expect(state.kind).toBe('reauth_required');
    if (state.kind !== 'reauth_required') return;
    expect(state.reason).toBe('missing_inline_share');
    expect(state.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
  });

  test('ready material carries a signer session', () => {
    const state = buildEcdsaMaterialStateForCandidate({
      candidate: makeCandidate(),
      record: makeRecord({
        clientAdditiveShare32B64u: 'client-share',
      }),
      authMethod: 'passkey',
      source: 'login',
      chainTarget: EVM_CHAIN_TARGET,
      materialChainTarget: EVM_CHAIN_TARGET,
    });

    expect(state.kind).toBe('ready_to_sign');
    if (state.kind !== 'ready_to_sign') return;
    expect(state.signerSession.clientShare.kind).toBe('inline_client_share');
    expect(state.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
  });
});
