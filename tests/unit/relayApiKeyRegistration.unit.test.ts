import { expect, test } from '@playwright/test';
import { createAccountAndRegisterWithRelayServer } from '@/core/TatchiPasskey/faucets/createAccountRelayServer';
import type { PasskeyManagerContext } from '@/core/TatchiPasskey';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';

function buildSerializedCredential(): WebAuthnRegistrationCredential {
  return {
    id: 'cred_registration_1',
    rawId: 'raw_registration_1',
    type: 'public-key',
    response: {
      clientDataJSON: 'Y2xpZW50RGF0YQ',
      attestationObject: 'YXR0ZXN0YXRpb24',
      transports: ['internal'],
    },
    clientExtensionResults: {
      prf: {
        results: {},
      },
    },
  };
}

function buildMinimalContext(input: { relayUrl: string; relayApiKey?: string }): PasskeyManagerContext {
  return {
    configs: {
      network: {
        relayer: {
          url: input.relayUrl,
          apiKey: String(input.relayApiKey || '').trim(),
        },
      },
      webauthn: {
        authenticatorOptions: {},
      },
    },
  } as unknown as PasskeyManagerContext;
}

test.describe('createAccountAndRegisterWithRelayServer relay API key integration', () => {
  test('attaches Authorization header when relayer apiKey config is set', async () => {
    const originalFetch = globalThis.fetch;
    let capturedAuthorization = '';
    (globalThis as { fetch: typeof fetch }).fetch = async (_input, init) => {
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
          relayApiKey: 'tsk_live_abc123',
        }),
        'alice.w3a-relayer.testnet',
        undefined,
        buildSerializedCredential(),
        'wallet.example.test',
      );

      expect(result.success).toBe(true);
      expect(capturedAuthorization).toBe('Bearer tsk_live_abc123');
    } finally {
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    }
  });

  test('returns typed errorCode when relay rejects API key scope', async () => {
    const originalFetch = globalThis.fetch;
    const originalConsoleError = console.error;
    console.error = () => {};
    (globalThis as { fetch: typeof fetch }).fetch = async () =>
      new Response(
        JSON.stringify({
          success: false,
          code: 'api_key_forbidden_scope',
          error: 'API key does not have required scope',
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
          relayApiKey: 'tsk_live_abc123',
        }),
        'alice.w3a-relayer.testnet',
        undefined,
        buildSerializedCredential(),
        'wallet.example.test',
      );

      expect(result.success).toBe(false);
      expect(result.errorCode).toBe('api_key_forbidden_scope');
      expect(String(result.error || '')).toContain('required scope');
    } finally {
      console.error = originalConsoleError;
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    }
  });
});
