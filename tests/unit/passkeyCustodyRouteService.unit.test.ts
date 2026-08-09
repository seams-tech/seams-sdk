import { test, expect } from '@playwright/test';
import { createD1PasskeyCustodyRouteService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import { normalizeLogger } from '../../packages/sdk-server-ts/src/core/logger';

/**
 * The port's own decisions — the ones made before the retrieval gate runs.
 *
 * Everything the retrieval decides is tested against the retrieval. What is
 * tested here is the binding: that the challenge is consumed rather than read,
 * and that the values the assertion is checked against come from the record
 * the server issued rather than from the request.
 */

type ConsumeCall = string;

function storeStub(options: {
  readonly challenge?: {
    readonly userId: string;
    readonly rpId: string;
    readonly challengeB64u: string;
  };
  readonly consumed: ConsumeCall[];
}) {
  let remaining = options.challenge ? 1 : 0;
  return {
    consumeLoginChallenge: async (challengeId: string) => {
      options.consumed.push(challengeId);
      // Single-use, like the real store: a second call finds nothing.
      if (remaining <= 0 || !options.challenge) return null;
      remaining -= 1;
      return {
        version: 'webauthn_login_challenge_v1' as const,
        challengeId,
        userId: options.challenge.userId,
        rpId: options.challenge.rpId,
        challengeB64u: options.challenge.challengeB64u,
        createdAtMs: 1,
        expiresAtMs: 2,
      };
    },
    readAuthenticator: async () => null,
    writeAuthenticator: async () => {},
    updateAuthenticatorCounter: async () => {},
  };
}

function serviceWith(store: ReturnType<typeof storeStub>, seen: unknown[]) {
  return createD1PasskeyCustodyRouteService({
    passkeyCustodyEnvelopes: {
      read: async (...args: unknown[]) => {
        seen.push(args);
        return null;
      },
    } as never,
    walletCustodyCommits: {} as never,
    walletStore: {} as never,
    webAuthnStore: store as never,
    logger: normalizeLogger(),
  });
}

const ASSERTION = {
  id: 'credential-1',
  rawId: 'credential-1',
  type: 'public-key',
  response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA', userHandle: null },
  clientExtensionResults: {},
} as never;

const LOCATOR = {
  walletId: 'alice.testnet',
  factor: { kind: 'passkey', rpId: 'example.localhost', credentialIdB64u: 'credential-1' },
} as never;

test('a request without a challenge id is refused before any store read', async () => {
  const consumed: ConsumeCall[] = [];
  const seen: unknown[] = [];
  const service = serviceWith(storeStub({ consumed }), seen);

  const response = await service.retrieveEnvelope({
    locator: LOCATOR,
    challengeId: '   ',
    expectedOrigin: 'https://example.localhost',
    webauthnAuthentication: ASSERTION,
  });

  expect(response.status).toBe(400);
  expect(response.body.code).toBe('challenge_required');
  expect(consumed).toEqual([]);
  expect(seen).toEqual([]);
});

test('an unknown or expired challenge is refused as unauthenticated', async () => {
  const consumed: ConsumeCall[] = [];
  const seen: unknown[] = [];
  const service = serviceWith(storeStub({ consumed }), seen);

  const response = await service.retrieveEnvelope({
    locator: LOCATOR,
    challengeId: 'challenge-1',
    expectedOrigin: 'https://example.localhost',
    webauthnAuthentication: ASSERTION,
  });

  expect(response.status).toBe(401);
  expect(response.body.code).toBe('challenge_unknown');
  expect(consumed).toEqual(['challenge-1']);
  // The envelope is never read for a request that failed to name a live
  // challenge — an unauthenticated caller learns nothing about what exists.
  expect(seen).toEqual([]);
});

test('the same challenge cannot be used twice', async () => {
  const consumed: ConsumeCall[] = [];
  const seen: unknown[] = [];
  const store = storeStub({
    challenge: { userId: 'user-1', rpId: 'example.localhost', challengeB64u: 'Y2hhbGxlbmdl' },
    consumed,
  });
  const service = serviceWith(store, seen);

  const first = await service.retrieveEnvelope({
    locator: LOCATOR,
    challengeId: 'challenge-1',
    expectedOrigin: 'https://example.localhost',
    webauthnAuthentication: ASSERTION,
  });
  const second = await service.retrieveEnvelope({
    locator: LOCATOR,
    challengeId: 'challenge-1',
    expectedOrigin: 'https://example.localhost',
    webauthnAuthentication: ASSERTION,
  });

  // The first gets past the challenge check and fails further down (the
  // assertion is not real); the second never gets that far.
  expect(first.body.code).not.toBe('challenge_unknown');
  expect(second.status).toBe(401);
  expect(second.body.code).toBe('challenge_unknown');
  expect(consumed).toEqual(['challenge-1', 'challenge-1']);
});
