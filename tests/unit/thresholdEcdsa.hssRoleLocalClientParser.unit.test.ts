import { expect, test } from '@playwright/test';
import {
  thresholdEcdsaHssRoleLocalBootstrap,
  type ThresholdEcdsaHssRoleLocalBootstrapRequest,
} from '../../client/src/core/rpcClients/relayer/thresholdEcdsa';
import {
  toEcdsaHssThresholdKeyId,
} from '../../client/src/core/signingEngine/session/identity/emailOtpHssIdentity';
import { toWalletId } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';

const BOOTSTRAP_ARGS = {
  formatVersion: 'ecdsa-hss-role-local' as const,
  walletId: toWalletId('wallet-user'),
  rpId: 'wallet.example.test',
  ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ecdsa-threshold-key'),
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  keyScope: 'evm-family' as const,
  relayerKeyId: 'relayer-key',
  clientPublicKey33B64u: 'client-public-key',
  clientShareRetryCounter: 0,
  contextBinding32B64u: 'context-binding',
  requestId: 'request-id',
  sessionId: 'threshold-session',
  walletSigningSessionId: 'wallet-signing-session',
  ttlMs: 60_000,
  remainingUses: 2,
  participantIds: [1, 2],
} satisfies ThresholdEcdsaHssRoleLocalBootstrapRequest;

function bootstrapValue(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: 'wallet-user',
    rpId: 'wallet.example.test',
    ecdsaThresholdKeyId: 'ecdsa-threshold-key',
    relayerKeyId: 'relayer-key',
    contextBinding32B64u: 'context-binding',
    publicIdentity: {
      clientPublicKey33B64u: 'client-public-key',
      relayerPublicKey33B64u: 'relayer-public-key',
      groupPublicKey33B64u: 'group-public-key',
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    publicTranscriptDigest32B64u: 'public-transcript-digest',
    keyHandle: 'key-handle',
    signingRootId: 'project:env',
    signingRootVersion: 'default',
    thresholdEcdsaPublicKeyB64u: 'group-public-key',
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    relayerVerifyingShareB64u: 'relayer-public-key',
    participantIds: [1, 2],
    sessionId: 'threshold-session',
    walletSigningSessionId: 'wallet-signing-session',
    expiresAtMs: Date.now() + 60_000,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    remainingUses: 2,
    ...(overrides || {}),
  };
}

test.describe('threshold ECDSA HSS role-local client parser', () => {
  test('rejects relayer secret fields in non-export bootstrap responses', async () => {
    const originalFetch = globalThis.fetch;
    const forbiddenFields = [
      'clientShare32B64u',
      'relayerShare32B64u',
      'serverExportShare32B64u',
      'relayerRootShare32B64u',
      'relayerBackendInputB64u',
      'mappedPrivateShare32B64u',
      'relayerMappedPrivateShare32B64u',
      'canonicalPrivateKeyHex',
      'privateKeyHex',
    ] as const;
    try {
      for (const field of forbiddenFields) {
        globalThis.fetch = (async () =>
          new Response(
            JSON.stringify({
              ok: true,
              value: bootstrapValue({ [field]: 'secret-material' }),
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          )) as typeof fetch;

        const result = await thresholdEcdsaHssRoleLocalBootstrap(
          'https://relay.example.test',
          BOOTSTRAP_ARGS,
        );

        expect(result, field).toMatchObject({ ok: false });
        expect('value' in result ? result.value : undefined).toBeUndefined();
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
