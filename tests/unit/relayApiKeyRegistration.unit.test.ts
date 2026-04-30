import { expect, test } from '@playwright/test';
import { createAccountAndRegisterWithRelayServer } from '@/core/SeamsPasskey/faucets/createAccountRelayServer';
import type { PasskeyManagerContext } from '@/core/SeamsPasskey';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';

function buildSerializedCredential(): WebAuthnRegistrationCredential {
  return {
    id: 'cred_registration_1',
    rawId: 'raw_registration_1',
    type: 'public-key',
    authenticatorAttachment: undefined,
    response: {
      clientDataJSON: 'Y2xpZW50RGF0YQ',
      attestationObject: 'YXR0ZXN0YXRpb24',
      transports: ['internal'],
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: undefined,
          second: undefined,
        },
      },
    },
  };
}

function buildMinimalContext(input: {
  relayUrl: string;
  registrationBootstrapUrl?: string;
  managed?: {
    environmentId: string;
    publishableKey: string;
  };
}): PasskeyManagerContext {
  return {
    configs: {
      network: {
        relayer: {
          url: input.relayUrl,
        },
      },
      registration: input.managed
        ? {
            mode: 'managed',
            environmentId: input.managed.environmentId,
            publishableKey: input.managed.publishableKey,
          }
        : {
            mode: 'backend_proxy',
            bootstrapUrl:
              input.registrationBootstrapUrl ||
              `${String(input.relayUrl).replace(/\/+$/, '')}/registration/bootstrap`,
          },
      webauthn: {
        authenticatorOptions: {},
      },
    },
  } as unknown as PasskeyManagerContext;
}

test.describe('createAccountAndRegisterWithRelayServer registration bootstrap transport', () => {
  test('uses registration bootstrap URL and never injects a browser secret header', async () => {
    const originalFetch = globalThis.fetch;
    let capturedAuthorization = '';
    let capturedUrl = '';
    (globalThis as { fetch: typeof fetch }).fetch = async (input, init) => {
      capturedUrl = String(input);
      capturedAuthorization = String(new Headers(init?.headers).get('authorization') || '');
      return new Response(
        JSON.stringify({
          success: true,
          transactionHash: 'tx_registration_123',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    };

    try {
      const result = await createAccountAndRegisterWithRelayServer(
        buildMinimalContext({
          relayUrl: 'https://relay.example.test',
          registrationBootstrapUrl: 'https://app.example.test/api/registration/bootstrap',
        }),
        'alice.w3a-relayer.testnet',
        buildSerializedCredential(),
        'wallet.example.test',
      );

      expect(result.success).toBe(true);
      expect(capturedUrl).toBe('https://app.example.test/api/registration/bootstrap');
      expect(capturedAuthorization).toBe('');
    } finally {
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    }
  });

  test('returns typed errorCode when bootstrap endpoint rejects secret-key scope', async () => {
    const originalFetch = globalThis.fetch;
    const originalConsoleError = console.error;
    console.error = () => {};
    (globalThis as { fetch: typeof fetch }).fetch = async () =>
      new Response(
        JSON.stringify({
          success: false,
          code: 'secret_key_forbidden_scope',
          error: 'Secret key does not have required scope',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        },
      );

    try {
      const result = await createAccountAndRegisterWithRelayServer(
        buildMinimalContext({
          relayUrl: 'https://relay.example.test',
        }),
        'alice.w3a-relayer.testnet',
        buildSerializedCredential(),
        'wallet.example.test',
      );

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('secret_key_forbidden_scope');
      expect(String(result.error || '')).toContain('required scope');
    } finally {
      console.error = originalConsoleError;
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    }
  });

  test('managed mode requests a bootstrap grant then redeems the bootstrap token with relay', async () => {
    const originalFetch = globalThis.fetch;
    const calls: Array<{
      url: string;
      method: string;
      authorization: string;
      body: Record<string, unknown>;
    }> = [];
    (globalThis as { fetch: typeof fetch }).fetch = async (input, init) => {
      const url = String(input);
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      calls.push({
        url,
        method: String(init?.method || 'GET'),
        authorization: String(new Headers(init?.headers).get('authorization') || ''),
        body,
      });
      if (url === 'https://relay.example.test/v1/registration/bootstrap-grants') {
        return new Response(
          JSON.stringify({
            ok: true,
            grant: {
              token: 'tbt_v1_issued_token',
              expiresAt: '2030-01-01T00:00:00.000Z',
              orgId: 'org_prod',
              projectId: 'proj_prod',
              environmentId: 'env_prod',
              origin: 'https://app.example.test',
              mode: 'free',
            },
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return new Response(
        JSON.stringify({
          success: true,
          transactionHash: 'tx_registration_123',
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    };

    try {
      const result = await createAccountAndRegisterWithRelayServer(
        buildMinimalContext({
          relayUrl: 'https://relay.example.test',
          managed: {
            environmentId: 'env_prod',
            publishableKey: 'pk_publishable',
          },
        }),
        'alice.w3a-relayer.testnet',
        buildSerializedCredential(),
        'wallet.example.test',
      );

      expect(result.success).toBe(true);
      expect(calls).toHaveLength(2);
      expect(calls[0]?.url).toBe('https://relay.example.test/v1/registration/bootstrap-grants');
      expect(calls[0]?.authorization).toBe('Bearer pk_publishable');
      expect(calls[0]?.body.environmentId).toBe('env_prod');
      expect(calls[0]?.body.newAccountId).toBe('alice.w3a-relayer.testnet');
      expect(calls[0]?.body.rpId).toBe('wallet.example.test');
      expect(calls[0]?.body.flow).toBe('registration_v1');
      expect(calls[0]?.body.requestHashSha256).toBeUndefined();
      expect(calls[1]?.url).toBe('https://relay.example.test/registration/bootstrap');
      expect(calls[1]?.authorization).toBe('Bearer tbt_v1_issued_token');
      expect(calls[1]?.body.new_account_id).toBe('alice.w3a-relayer.testnet');
    } finally {
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    }
  });

  test('managed mode returns typed errorCode when broker denies publishable_key origin', async () => {
    const originalFetch = globalThis.fetch;
    const originalConsoleError = console.error;
    console.error = () => {};
    (globalThis as { fetch: typeof fetch }).fetch = async () =>
      new Response(
        JSON.stringify({
          ok: false,
          code: 'publishable_key_origin_blocked',
          message: 'Origin is not allowed for this publishable key',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        },
      );

    try {
      const result = await createAccountAndRegisterWithRelayServer(
        buildMinimalContext({
          relayUrl: 'https://relay.example.test',
          managed: {
            environmentId: 'env_prod',
            publishableKey: 'pk_publishable',
          },
        }),
        'alice.w3a-relayer.testnet',
        buildSerializedCredential(),
        'wallet.example.test',
      );

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('publishable_key_origin_blocked');
      expect(String(result.error || '')).toContain('Origin is not allowed');
    } finally {
      console.error = originalConsoleError;
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    }
  });
});
