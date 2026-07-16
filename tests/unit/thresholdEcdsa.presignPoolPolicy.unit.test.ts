import { expect, test } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import {
  clearAllRouterAbEcdsaDerivationClientPresignatures,
  resolveRouterAbEcdsaDerivationPresignaturePoolPolicy,
  scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool';
import type { RouterAbEcdsaDerivationPresignaturePoolFill } from '@/core/signingEngine/routerAb/ecdsaDerivation/poolFillRoutes';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';

test.describe('Router A/B ECDSA derivation presignature pool policy', () => {
  const ECDSA_THRESHOLD_KEY_ID = parseEcdsaThresholdKeyId('ecdsa-derivation-test-key-1');
  const BACKEND_CLIENT_VERIFYING_SHARE_B64U = parseEcdsaClientVerifyingShareB64u(
    'backend-client-share',
  );
  const WALLET_SESSION_CREDENTIAL = {
    kind: 'jwt' as const,
    walletSessionJwt: 'wallet-session-jwt',
  };

  function routerAbPoolFill(
    ecdsaThresholdKeyId: string = ECDSA_THRESHOLD_KEY_ID,
  ): RouterAbEcdsaDerivationPresignaturePoolFill {
    return {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
      scope: {
        wallet_key_id: 'localhost',
        wallet_id: 'alice.testnet',
        ecdsa_threshold_key_id: ecdsaThresholdKeyId,
        signing_root_id: 'project:dev',
        signing_root_version: 'default',
        context: {
          application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
        },
        public_identity: {
          context_binding_b64u: 'OyVzuOm6z7oD9lROMqtIK1MZuxTy-l6AMUji9knVQ6w',
          derivation_client_share_public_key33_b64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          server_public_key33_b64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          threshold_public_key33_b64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          ethereum_address20_b64u: 'ERERERERERERERERERERERERERE',
          client_share_retry_counter: 0,
          server_share_retry_counter: 1,
        },
        signing_worker: {
          server_id: 'signing-worker-1',
          key_epoch: 'worker-epoch-1',
          recipient_encryption_key:
            'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
        activation_epoch: 'activation-1',
      },
      expiresAtMs: Date.now() + 60_000,
    };
  }

  function clientSigningMaterial() {
    return {
      kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1' as const,
      initClientPresignSession: async () => {
        throw new Error('policy tests must not initialize Router A/B ECDSA derivation presign sessions');
      },
      stepClientPresignSession: async () => {
        throw new Error('policy tests must not step Router A/B ECDSA derivation presign sessions');
      },
      abortClientPresignSession: async () => {
        throw new Error('policy tests must not abort Router A/B ECDSA derivation presign sessions');
      },
      admitClientPresignature: async () => {
        throw new Error('policy tests must not admit Router A/B ECDSA derivation presignatures');
      },
      destroyClientPresignature: async () => {
        throw new Error('policy tests must not destroy Router A/B ECDSA derivation presignatures');
      },
      reserveClientPresignature: async () => {
        throw new Error('policy tests must not reserve Router A/B ECDSA presignatures');
      },
      commitClientPresignature: async () => {
        throw new Error('policy tests must not commit Router A/B ECDSA presignatures');
      },
      computeSignatureShareFromPresignatureHandle: async () => {
        throw new Error('policy tests must not compute Router A/B ECDSA derivation signature shares');
      },
    };
  }

  test.beforeEach(async () => {
    clearAllRouterAbEcdsaDerivationClientPresignatures();
  });

  test('applies sane defaults when no policy is provided', async () => {
    const policy = resolveRouterAbEcdsaDerivationPresignaturePoolPolicy();
    expect(policy.enabled).toBe(true);
    expect(policy.targetDepth).toBe(3);
    expect(policy.lowWatermark).toBe(1);
    expect(policy.maxRefillInFlight).toBe(1);
    expect(policy.refillAttemptTimeoutMs).toBe(30_000);
  });

  test('clamps invalid policy input values', async () => {
    const policy = resolveRouterAbEcdsaDerivationPresignaturePoolPolicy({
      enabled: true,
      targetDepth: -10,
      lowWatermark: 999,
      maxRefillInFlight: 0,
      refillAttemptTimeoutMs: 1,
    });
    expect(policy.targetDepth).toBe(1);
    expect(policy.lowWatermark).toBe(1);
    expect(policy.maxRefillInFlight).toBe(1);
    expect(policy.refillAttemptTimeoutMs).toBe(5_000);
  });

  test('buildConfigsFromEnv rejects invalid Router A/B ECDSA derivation presignature pool config values', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        iframeWallet: { walletOrigin: 'https://wallet.example.test' },
        routerAbEcdsaDerivationPresignaturePool: {
          enabled: false,
          targetDepth: 99,
          lowWatermark: -2,
          maxRefillInFlight: 99,
          refillAttemptTimeoutMs: 999_999,
        },
      }),
    ).toThrow(
      '[configPresets] Invalid config: routerAbEcdsaDerivationPresignaturePool.targetDepth must be in [1, 64]',
    );
  });

  test('accepts larger target depth policy for pooled warm signing', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      iframeWallet: { walletOrigin: 'https://wallet.example.test' },
      routerAbEcdsaDerivationPresignaturePool: {
        enabled: true,
        targetDepth: 12,
        lowWatermark: 4,
      },
    });
    expect(cfg.signing.routerAbEcdsaDerivation.presignaturePool.targetDepth).toBe(12);
    expect(cfg.signing.routerAbEcdsaDerivation.presignaturePool.lowWatermark).toBe(4);
  });

  test('scheduler no-ops cleanly when policy is disabled', async () => {
    const result = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      // The retained low-level refill helper still needs the client public share.
      clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      clientSigningMaterial: clientSigningMaterial(),
      credential: WALLET_SESSION_CREDENTIAL,
      routerAbEcdsaDerivationPoolFill: routerAbPoolFill(),
      workerCtx: {} as any,
      poolPolicy: { enabled: false },
    });
    expect(result.scheduled).toBe(false);
    expect(result.reason).toBe('disabled');
  });

  test('scheduler dedupes by pool key when a refill is already in flight', async () => {
    const first = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      clientSigningMaterial: clientSigningMaterial(),
      credential: WALLET_SESSION_CREDENTIAL,
      routerAbEcdsaDerivationPoolFill: routerAbPoolFill(),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 2 },
    });
    const second = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      clientSigningMaterial: clientSigningMaterial(),
      credential: WALLET_SESSION_CREDENTIAL,
      routerAbEcdsaDerivationPoolFill: routerAbPoolFill(),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 2 },
    });

    expect(first.scheduled).toBe(true);
    expect(second.scheduled).toBe(false);
    expect(second.reason).toBe('in_flight_for_pool_key');
  });

  test('scheduler enforces global in-flight refill limit', async () => {
    const first = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-derivation-test-key-1'),
      clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u('backend-client-share-1'),
      clientSigningMaterial: clientSigningMaterial(),
      credential: WALLET_SESSION_CREDENTIAL,
      routerAbEcdsaDerivationPoolFill: routerAbPoolFill('ecdsa-derivation-test-key-1'),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
    });
    const second = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-derivation-test-key-2'),
      clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u('backend-client-share-2'),
      clientSigningMaterial: clientSigningMaterial(),
      credential: WALLET_SESSION_CREDENTIAL,
      routerAbEcdsaDerivationPoolFill: routerAbPoolFill('ecdsa-derivation-test-key-2'),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
    });

    expect(first.scheduled).toBe(true);
    expect(second.scheduled).toBe(false);
    expect(second.reason).toBe('global_in_flight_limit');
  });

  test('scheduler exits quickly when another runtime holds cross-tab refill authority lock', async () => {
    const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    if (navigatorDescriptor && !navigatorDescriptor.configurable) {
      return;
    }
    const hadNavigator = Object.prototype.hasOwnProperty.call(globalThis, 'navigator');
    const originalNavigator = (globalThis as Record<string, unknown>).navigator;
    try {
      Object.defineProperty(globalThis, 'navigator', {
        configurable: true,
        value: {
          locks: {
            request: async (
              _name: string,
              _opts: { mode?: string; ifAvailable?: boolean },
              callback: (lock: unknown) => Promise<void>,
            ): Promise<void> => {
              await callback(null);
            },
          },
        },
      });

      const first = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        clientSigningMaterial: clientSigningMaterial(),
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaDerivationPoolFill: routerAbPoolFill(),
        workerCtx: {} as any,
        poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
      });
      expect(first.scheduled).toBe(true);

      await new Promise((resolve) => setTimeout(resolve, 0));

      const second = scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        clientSigningMaterial: clientSigningMaterial(),
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaDerivationPoolFill: routerAbPoolFill(),
        workerCtx: {} as any,
        poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
      });
      expect(second.scheduled).toBe(true);
    } finally {
      if (hadNavigator) {
        Object.defineProperty(globalThis, 'navigator', {
          configurable: true,
          value: originalNavigator,
        });
      } else {
        delete (globalThis as Record<string, unknown>).navigator;
      }
    }
  });
});
