import { expect, test } from '@playwright/test';
import { exchangeSession } from '@/core/rpcClients/near/rpcCalls';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { parseReusableWalletSessionMintId } from '@shared/authorization/capabilityKinds';

type CapturedFetch = {
  url: string;
  init?: RequestInit;
};

const UNSCOPED_SESSION_EXCHANGE = { kind: 'unscoped' } as const;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function ecdsaSessionActivationFixture() {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'carol.testnet',
    chain: 'evm',
    sessionId: 'passkey-exchange-session',
  });
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!binding || binding.materialKind !== 'role_local_worker_handle') {
    throw new Error('expected passkey ECDSA role-local fixture');
  }
  const runtimePolicyScope = bootstrap.session.runtimePolicyScope;
  const walletSessionJwt = bootstrap.session.jwt;
  const normalSigning = bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning;
  if (!runtimePolicyScope || !walletSessionJwt || !normalSigning) {
    throw new Error('expected complete ECDSA Wallet Session fixture');
  }
  const mintId = parseReusableWalletSessionMintId('wallet-session-mint-fixture');
  if (!mintId.ok) throw new Error('expected valid Wallet Session mint fixture');
  return {
    request: parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1({
      kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
      public_capability: binding.publicFacts.publicCapability,
      session_policy: {
        threshold_session_id: bootstrap.session.thresholdSessionId,
        wallet_session_mint_id: mintId.value,
        ttl_ms: 120_000,
        remaining_uses: bootstrap.session.remainingUses,
        runtime_policy_scope: runtimePolicyScope,
      },
    }),
    response: parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1({
      kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
      public_capability: binding.publicFacts.publicCapability,
      session: {
        authorization_session_id: bootstrap.session.authorizationSessionId,
        threshold_session_id: bootstrap.session.thresholdSessionId,
        signing_grant_id: bootstrap.session.signingGrantId,
        wallet_session_id: bootstrap.session.walletSessionId,
        quota_id: bootstrap.session.quotaId,
        expires_at_ms: bootstrap.session.expiresAtMs,
        remaining_uses: bootstrap.session.remainingUses,
        wallet_session_jwt: walletSessionJwt,
      },
      normal_signing: normalSigning,
    }),
  };
}

test.describe('exchangeSession', () => {
  const sampleWebauthnCredential = {
    id: 'cred-id-1',
    rawId: 'cred-raw-1',
    type: 'public-key',
    authenticatorAttachment: undefined,
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature-b64u',
      userHandle: undefined,
      clientExtensionResults: { shouldRedact: true },
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: 'prf-first',
          second: 'prf-second',
        },
      },
    },
  } as const;

  test('exchanges oidc_jwt and returns app session metadata + jwt', async () => {
    const originalFetch = globalThis.fetch;
    const captured: CapturedFetch[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), init });
        return jsonResponse({
          ok: true,
          session: {
            kind: 'app_session_v1',
            userId: 'alice.testnet',
            expiresAt: '2030-01-01T00:00:00.000Z',
          },
          jwt: 'app-jwt-1',
        });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example/',
        '/session/exchange',
        'jwt',
        {
          type: 'oidc_jwt',
          token: 'oidc-token-1',
        },
        UNSCOPED_SESSION_EXCHANGE,
      );

      expect(result.success).toBe(true);
      expect(result.sessionUserId).toBe('alice.testnet');
      expect(result.sessionExpiresAt).toBe('2030-01-01T00:00:00.000Z');
      expect(result.jwt).toBe('app-jwt-1');
      expect(captured).toHaveLength(1);
      expect(captured[0]!.url).toBe('https://relay.example/session/exchange');
      const body = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<string, unknown>;
      expect(body.sessionKind).toBe('jwt');
      expect(body.exchange).toEqual({ type: 'oidc_jwt', token: 'oidc-token-1' });
      expect(captured[0]!.init?.credentials).toBe('omit');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('uses cookie credentials mode and succeeds when jwt is omitted', async () => {
    const originalFetch = globalThis.fetch;
    const captured: CapturedFetch[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), init });
        return jsonResponse({
          ok: true,
          session: { kind: 'app_session_v1', userId: 'bob.testnet' },
        });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        'session/exchange',
        'cookie',
        {
          type: 'oidc_jwt',
          token: 'oidc-token-2',
        },
        UNSCOPED_SESSION_EXCHANGE,
      );

      expect(result.success).toBe(true);
      expect(result.sessionUserId).toBe('bob.testnet');
      expect(result.sessionExpiresAt).toBeUndefined();
      expect(result.jwt).toBeUndefined();
      expect(captured).toHaveLength(1);
      expect(captured[0]!.url).toBe('https://relay.example/session/exchange');
      expect(captured[0]!.init?.credentials).toBe('include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('maps relay error response message', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () =>
        jsonResponse(
          { ok: false, code: 'invalid_claims', message: 'issuer mismatch' },
          401,
        )) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'jwt',
        {
          type: 'oidc_jwt',
          token: 'oidc-token-3',
        },
        UNSCOPED_SESSION_EXCHANGE,
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('issuer mismatch');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('exchanges passkey_assertion and redacts extension outputs', async () => {
    const originalFetch = globalThis.fetch;
    const captured: CapturedFetch[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), init });
        return jsonResponse({
          ok: true,
          session: {
            kind: 'app_session_v1',
            userId: 'carol.testnet',
            expiresAt: '2030-01-01T00:00:00.000Z',
          },
        });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'cookie',
        {
          type: 'passkey_assertion',
          challengeId: 'challenge-passkey-1',
          webauthn_authentication: sampleWebauthnCredential as any,
          expected_origin: 'https://wallet.example',
        },
        {
          kind: 'managed',
          projectEnvironmentId: 'project-env-1',
          publishableKey: 'pk_test_1',
        },
      );

      expect(result.success).toBe(true);
      expect(result.sessionUserId).toBe('carol.testnet');
      expect(captured).toHaveLength(1);
      const body = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<string, unknown>;
      const exchange = (body.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.challengeId).toBe('challenge-passkey-1');
      expect(exchange.expected_origin).toBe('https://wallet.example');
      expect(body.projectEnvironmentId).toBe('project-env-1');
      expect(new Headers(captured[0]!.init?.headers).get('authorization')).toBe('Bearer pk_test_1');
      const credential = (exchange.webauthn_authentication || {}) as Record<string, unknown>;
      expect(credential.clientExtensionResults).toBeNull();
      expect(
        ((credential.response || {}) as Record<string, unknown>).clientExtensionResults,
      ).toBeNull();
      expect(captured[0]!.init?.credentials).toBe('include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('correlates a passkey exchange with its requested first ECDSA Wallet Session', async () => {
    const originalFetch = globalThis.fetch;
    const captured: CapturedFetch[] = [];
    const activation = ecdsaSessionActivationFixture();
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), init });
        return jsonResponse({
          ok: true,
          session: { kind: 'app_session_v1', userId: 'carol.testnet' },
          ecdsaSession: activation.response,
        });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'jwt',
        {
          type: 'passkey_assertion',
          challengeId: 'challenge-passkey-activation-1',
          webauthn_authentication: sampleWebauthnCredential as any,
          ecdsaSessionActivation: activation.request,
        },
        UNSCOPED_SESSION_EXCHANGE,
      );

      expect(result.success).toBe(true);
      if (!result.success) throw new Error(result.error);
      expect(result.ecdsaSession).toEqual(activation.response);
      const body = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<string, unknown>;
      expect((body.exchange as Record<string, unknown>).ecdsa_session_activation).toEqual(
        activation.request,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('fails closed when a requested ECDSA Wallet Session result is absent or malformed', async () => {
    const originalFetch = globalThis.fetch;
    const activation = ecdsaSessionActivationFixture();
    try {
      for (const ecdsaSession of [undefined, { kind: 'wrong_kind' }]) {
        globalThis.fetch = (async () =>
          jsonResponse({
            ok: true,
            session: { kind: 'app_session_v1', userId: 'carol.testnet' },
            ...(ecdsaSession === undefined ? {} : { ecdsaSession }),
          })) as typeof fetch;

        const result = await exchangeSession(
          'https://relay.example',
          '/session/exchange',
          'jwt',
          {
            type: 'passkey_assertion',
            challengeId: 'challenge-passkey-activation-2',
            webauthn_authentication: sampleWebauthnCredential as any,
            ecdsaSessionActivation: activation.request,
          },
          UNSCOPED_SESSION_EXCHANGE,
        );

        expect(result.success).toBe(false);
        expect(result.error).toContain(
          ecdsaSession === undefined
            ? 'omitted the requested ECDSA Wallet Session activation'
            : 'postRegistrationSessionActivated.kind is invalid',
        );
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('fails fast on missing token and does not call fetch', async () => {
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    try {
      globalThis.fetch = (async () => {
        fetchCalls += 1;
        return jsonResponse({ ok: true });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'jwt',
        {
          type: 'oidc_jwt',
          token: '  ',
        },
        UNSCOPED_SESSION_EXCHANGE,
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('Missing exchange token');
      expect(fetchCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('fails fast on missing passkey challengeId and does not call fetch', async () => {
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    try {
      globalThis.fetch = (async () => {
        fetchCalls += 1;
        return jsonResponse({ ok: true });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'jwt',
        {
          type: 'passkey_assertion',
          challengeId: '   ',
          webauthn_authentication: sampleWebauthnCredential as any,
        },
        UNSCOPED_SESSION_EXCHANGE,
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('Missing passkey challengeId');
      expect(fetchCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
