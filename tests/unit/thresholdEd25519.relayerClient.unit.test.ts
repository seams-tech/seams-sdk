import { expect, test } from '@playwright/test';
import {
  finalizeThresholdEd25519Presign,
  refillThresholdEd25519PresignPool,
  type ThresholdEd25519FinalizeAndDispatchRequestWire,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/thresholdEd25519Presign';
import type { PrepareThresholdEd25519PresignPoolPayload } from '../../packages/sdk-web/src/core/types/signer-worker';

const runtimePolicyScope = {
  orgId: 'org-client',
  projectId: 'project-client',
  envId: 'test',
  signingRootVersion: 'root-v1',
};

function installJsonFetch(
  responseBody: unknown,
  captures: Array<{ url: string; init: RequestInit }>,
) {
  const previous = globalThis.fetch;
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    captures.push({ url: String(url), init: init || {} });
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = previous;
  };
}

test.describe('threshold Ed25519 relayer client', () => {
  test('maps presign pool refill payloads to the relayer route and pool result', async () => {
    const captures: Array<{ url: string; init: RequestInit }> = [];
    const restoreFetch = installJsonFetch(
      {
        ok: true,
        kind: 'threshold_ed25519_presign_refill_response_v1',
        accepted: [
          {
            presignId: 'server-presign-1',
            clientPresignId: 'client-presign-1',
            relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
            relayerVerifyingShareB64u: 'relayer-verifying-share',
            signerPublicKey: 'ed25519:signer',
            nearNetworkId: 'testnet',
            participantIds: [1, 2],
            expiresAtMs: 12345,
          },
        ],
        rejectedClientPresignIds: ['client-presign-2'],
        serverTimeMs: 1000,
      },
      captures,
    );
    try {
      const payload = {
        kind: 'prepare_threshold_ed25519_presign_pool_v1',
        relayUrl: 'https://relay.example.test/',
        sessionKind: 'jwt',
        thresholdSessionAuthToken: 'threshold-session-token',
        thresholdSessionId: 'threshold-session',
        walletSigningSessionId: 'wallet-signing-session',
        relayerKeyId: 'relayer-key',
        nearAccountId: 'alice.testnet',
        nearNetworkId: 'testnet',
        signerPublicKey: 'ed25519:signer',
        participantIds: [1, 2],
        runtimePolicyScope,
        policy: { targetDepth: 2, lowWatermark: 1, maxAcceptedRefillCount: 8, ttlMs: 60_000 },
        requestTag: 'background_presign_pool_refill',
        generation: 7,
        clientPresigns: [
          {
            clientPresignId: 'client-presign-1',
            nonceHandle: 'nonce-handle-1',
            clientVerifyingShareB64u: 'client-verifying-share',
            clientCommitments: { hiding: 'client-hiding', binding: 'client-binding' },
          },
        ],
      } satisfies PrepareThresholdEd25519PresignPoolPayload;

      const result = await refillThresholdEd25519PresignPool(payload);

      expect(captures).toHaveLength(1);
      expect(captures[0].url).toBe('https://relay.example.test/threshold-ed25519/presign/refill');
      expect(captures[0].init.credentials).toBe('omit');
      expect((captures[0].init.headers as Record<string, string>).Authorization).toBe(
        'Bearer threshold-session-token',
      );
      expect(JSON.parse(String(captures[0].init.body))).toMatchObject({
        kind: 'threshold_ed25519_presign_refill_v1',
        expectedSignerPublicKey: 'ed25519:signer',
        clientPresigns: [
          {
            clientPresignId: 'client-presign-1',
            clientVerifyingShareB64u: 'client-verifying-share',
          },
        ],
      });
      expect(result).toMatchObject({
        ok: true,
        generation: 7,
        expiresAtMs: 12345,
        accepted: [
          {
            presignId: 'server-presign-1',
            clientPresignId: 'client-presign-1',
            relayerVerifyingShareB64u: 'relayer-verifying-share',
          },
        ],
        rejectedClientPresignIds: ['client-presign-2'],
      });
    } finally {
      restoreFetch();
    }
  });

  test('uses cookie session auth for finalize-and-dispatch requests', async () => {
    const captures: Array<{ url: string; init: RequestInit }> = [];
    const restoreFetch = installJsonFetch(
      {
        ok: true,
        kind: 'threshold_ed25519_signature_only_result_v1',
        operationId: 'operation-1',
        budgetState: 'consumed',
        remainingSigningUses: 0,
        signatureB64u: 'signature',
        signerPublicKey: 'ed25519:signer',
      },
      captures,
    );
    try {
      const request = {
        kind: 'threshold_ed25519_finalize_signature_only_v1',
        operation: {
          kind: 'threshold_ed25519_signing_operation_v1',
          operationId: 'operation-1',
          operationFingerprint: 'sha256:fingerprint',
          purpose: 'nep413_message',
        },
        requestIntegrityHash: 'sha256:request-integrity',
        presignId: 'server-presign-1',
        relayerKeyId: 'relayer-key',
        nearAccountId: 'alice.testnet',
        nearNetworkId: 'testnet',
        expectedSignerPublicKey: 'ed25519:signer',
        intent: {
          kind: 'nep413_message_v1',
          message: 'hello',
          recipient: 'recipient.testnet',
          nonce: 'nonce',
        },
        clientSignatureShareB64u: 'client-share',
      } satisfies ThresholdEd25519FinalizeAndDispatchRequestWire;

      const result = await finalizeThresholdEd25519Presign({
        relayServerUrl: 'https://relay.example.test',
        auth: { sessionKind: 'cookie', useThresholdSessionCookie: true },
        request,
      });

      expect(captures).toHaveLength(1);
      expect(captures[0].url).toBe(
        'https://relay.example.test/threshold-ed25519/sign/finalize-and-dispatch',
      );
      expect(captures[0].init.credentials).toBe('include');
      expect((captures[0].init.headers as Record<string, string>).Authorization).toBeUndefined();
      expect(JSON.parse(String(captures[0].init.body))).toMatchObject({
        kind: 'threshold_ed25519_finalize_signature_only_v1',
        operation: { purpose: 'nep413_message' },
        requestIntegrityHash: 'sha256:request-integrity',
        clientSignatureShareB64u: 'client-share',
      });
      expect(result).toMatchObject({
        ok: true,
        kind: 'threshold_ed25519_signature_only_result_v1',
        signatureB64u: 'signature',
      });
    } finally {
      restoreFetch();
    }
  });
});
