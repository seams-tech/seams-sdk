import { expect, test } from '@playwright/test';
import {
  thresholdEcdsaDerivationRoleLocalBootstrap,
  type ThresholdEcdsaDerivationRoleLocalBootstrapRequest,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa';
import type { DerivationClientSharePublicKey33B64u } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  toEcdsaDerivationThresholdKeyId,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';

function toDerivationClientSharePublicKey33B64uForTest(value: string): DerivationClientSharePublicKey33B64u {
  return value as DerivationClientSharePublicKey33B64u;
}

function base64UrlEncodeJsonFixture(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function buildUnsignedJwtFixture(payload: Record<string, unknown>): string {
  return `${base64UrlEncodeJsonFixture({ alg: 'none', typ: 'JWT' })}.${base64UrlEncodeJsonFixture(payload)}.fixture`;
}

const CONTEXT_BINDING_32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const APPLICATION_BINDING_DIGEST_32_B64U = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const EVM_FAMILY_SIGNING_KEY_SLOT_ID = 'wallet-key:evm-family:wallet-user:project%3Aenv:default';
const CLIENT_PUBLIC_KEY_33_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const RELAYER_PUBLIC_KEY_33_B64U = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD';
const GROUP_PUBLIC_KEY_33_B64U = 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
const ETHEREUM_ADDRESS20_B64U = 'ERERERERERERERERERERERERERE';

function buildRouterAbEcdsaDerivationWalletSessionJwtFixture(args: { expiresAtMs: number }): string {
  return buildUnsignedJwtFixture({
    kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    sub: 'wallet-user',
    walletId: 'wallet-user',
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    thresholdSessionId: 'threshold-session',
    signingGrantId: 'signing-grant',
    keyScope: 'evm-family',
    keyHandle: 'key-handle',
    relayerKeyId: 'relayer-key',
    thresholdExpiresAtMs: args.expiresAtMs,
    participantIds: [1, 2],
    routerAbEcdsaDerivationNormalSigning: {
      kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
      scope: {
        wallet_key_id: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
        wallet_id: 'wallet-user',
        ecdsa_threshold_key_id: 'ecdsa-threshold-key',
        signing_root_id: 'project:env',
        signing_root_version: 'default',
        context: {
          application_binding_digest_b64u: APPLICATION_BINDING_DIGEST_32_B64U,
        },
        public_identity: {
          context_binding_b64u: CONTEXT_BINDING_32_B64U,
          derivation_client_share_public_key33_b64u: CLIENT_PUBLIC_KEY_33_B64U,
          server_public_key33_b64u: RELAYER_PUBLIC_KEY_33_B64U,
          threshold_public_key33_b64u: GROUP_PUBLIC_KEY_33_B64U,
          ethereum_address20_b64u: ETHEREUM_ADDRESS20_B64U,
          client_share_retry_counter: 0,
          server_share_retry_counter: 0,
        },
        signing_worker: {
          server_id: 'signing-worker-test',
          key_epoch: 'signing-worker-output-epoch',
          recipient_encryption_key: `x25519:${'33'.repeat(32)}`,
        },
        activation_epoch: 'threshold-session',
      },
    },
  });
}

const BOOTSTRAP_ARGS = {
  formatVersion: 'ecdsa-derivation-role-local' as const,
  walletId: toWalletId('wallet-user'),
  evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
  ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId('ecdsa-threshold-key'),
  signingRootId: 'project:env',
  signingRootVersion: 'default',
  keyScope: 'evm-family' as const,
  relayerKeyId: 'relayer-key',
  derivationClientSharePublicKey33B64u:
    toDerivationClientSharePublicKey33B64uForTest(CLIENT_PUBLIC_KEY_33_B64U),
  clientShareRetryCounter: 0,
  contextBinding32B64u: CONTEXT_BINDING_32_B64U,
  requestId: 'request-id',
  sessionId: 'threshold-session',
  signingGrantId: 'signing-grant',
  ttlMs: 60_000,
  remainingUses: 2,
  participantIds: [1, 2],
} satisfies ThresholdEcdsaDerivationRoleLocalBootstrapRequest;

function bootstrapValue(overrides?: Record<string, unknown>): Record<string, unknown> {
  const expiresAtMs = Date.now() + 60_000;
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: 'wallet-user',
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    ecdsaThresholdKeyId: 'ecdsa-threshold-key',
    relayerKeyId: 'relayer-key',
    applicationBindingDigestB64u: APPLICATION_BINDING_DIGEST_32_B64U,
    contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    publicIdentity: {
      derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
      relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
      groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 0,
    publicTranscriptDigest32B64u: 'public-transcript-digest',
    keyHandle: 'key-handle',
    signingRootId: 'project:env',
    signingRootVersion: 'default',
    thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
    participantIds: [1, 2],
    thresholdSessionId: 'threshold-session',
    signingGrantId: 'signing-grant',
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: 2,
    jwt: buildRouterAbEcdsaDerivationWalletSessionJwtFixture({ expiresAtMs }),
    ...(overrides || {}),
  };
}

test.describe('threshold ECDSA derivation role-local client parser', () => {
  test('sends publishable-key authorization for project-environment passkey bootstrap', async () => {
    const originalFetch = globalThis.fetch;
    let capturedInit: RequestInit | undefined;
    try {
      globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        capturedInit = init;
        return new Response(
          JSON.stringify({
            ok: true,
            value: bootstrapValue(),
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }) as typeof fetch;

      const result = await thresholdEcdsaDerivationRoleLocalBootstrap('https://relay.example.test', {
        ...BOOTSTRAP_ARGS,
        passkeyBootstrapAuthorization: {
          kind: 'passkey_bootstrap',
          rpId: 'wallet.example.test',
          webauthn_authentication: {
            id: 'credential-id',
            rawId: 'credential-id',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
            },
            clientExtensionResults: {
              prf: { results: { first: undefined, second: undefined } },
            },
          },
          projectEnvironmentId: 'env-test',
          projectEnvironmentPublishableKey: 'pk_test_runtime',
        },
      });

      expect(result).toMatchObject({ ok: true });
      expect((capturedInit?.headers as Record<string, string> | undefined)?.Authorization).toBe(
        'Bearer pk_test_runtime',
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

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

        const result = await thresholdEcdsaDerivationRoleLocalBootstrap(
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
