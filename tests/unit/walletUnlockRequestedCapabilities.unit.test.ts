import { expect, test } from '@playwright/test';
import type { RouterApiWalletUnlockService } from '../../packages/sdk-server-ts/src/router/authServicePort';
import {
  handleWalletUnlockVerifyRoute,
  type WalletUnlockEd25519YaoSessionContext,
} from '../../packages/sdk-server-ts/src/router/walletUnlockRouteHandlers';
import {
  EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND,
  EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND,
  parseWalletUnlockRequestedCapabilitiesRequest,
} from '../../packages/sdk-server-ts/src/router/walletUnlockRequestedCapabilitiesValidation';

const BASE_BODY = {
  unlockBackend: 'email_otp',
  walletId: 'requested-capabilities-wallet.testnet',
  orgId: 'requested-capabilities-org',
  challengeId: 'requested-capabilities-challenge',
  unlockProof: { kind: 'test-proof' },
} as const;

function buildUnlockService(): RouterApiWalletUnlockService {
  return {
    createEmailOtpUnlockChallenge: async () => ({
      ok: false,
      code: 'unused',
      message: 'unused in this test',
    }),
    createWebAuthnLoginOptions: async () => ({
      ok: false,
      code: 'unused',
      message: 'unused in this test',
    }),
    markEmailOtpStrongAuthSatisfied: async (input) => ({
      ok: true,
      walletId: String(input.walletId),
    }),
    verifyEmailOtpUnlockProof: async () => ({
      ok: true,
      verified: true,
      userId: 'requested-capabilities-user',
      walletId: BASE_BODY.walletId,
      providerUserId: 'requested-capabilities-provider',
      orgId: BASE_BODY.orgId,
      unlockKeyVersion: 'v1',
    }),
    verifyWebAuthnLogin: async () => ({
      ok: false,
      verified: false,
      code: 'unused',
      message: 'unused in this test',
    }),
  };
}

function buildNoEd25519Context(): WalletUnlockEd25519YaoSessionContext {
  return { kind: 'email_otp_no_ed25519_session' };
}

function buildEd25519Context(
  request: Extract<
    NonNullable<
      Extract<
        ReturnType<typeof parseWalletUnlockRequestedCapabilitiesRequest>,
        { readonly ok: true; readonly request: object }
      >['request']
    >,
    { readonly requestedCapabilities: { readonly kind: 'ed25519_yao' } }
  >,
  onProvision: () => void,
): WalletUnlockEd25519YaoSessionContext {
  return {
    kind: 'email_otp_ed25519_yao',
    request,
    provisionWalletSession: async () => {
      onProvision();
      return { ok: false, code: 'not_configured', message: 'test provisioning failure' };
    },
  };
}

function parseRequest(body: Record<string, unknown>) {
  const parsed = parseWalletUnlockRequestedCapabilitiesRequest(body);
  if (!parsed.ok || !parsed.request) throw new Error('expected an Email OTP request');
  return parsed.request;
}

test.describe('wallet unlock requested capabilities boundary', () => {
  test('accepts none and ed25519_yao, rejects unknown fields and kinds', async () => {
    const none = parseRequest({
      ...BASE_BODY,
      requestedCapabilities: { kind: EMAIL_OTP_NO_REQUESTED_CAPABILITIES_KIND },
    });
    expect(none.requestedCapabilities).toEqual({ kind: 'none' });

    const ed25519 = parseRequest({
      ...BASE_BODY,
      requestedCapabilities: {
        kind: EMAIL_OTP_ED25519_YAO_REQUESTED_CAPABILITIES_KIND,
        signerSlot: 1,
        remainingUses: 3,
      },
    });
    expect(ed25519.requestedCapabilities).toEqual({
      kind: 'ed25519_yao',
      signerSlot: 1,
      remainingUses: 3,
    });

    const unknownField = parseWalletUnlockRequestedCapabilitiesRequest({
      ...BASE_BODY,
      requestedCapabilities: {
        kind: 'none',
        unsupported: true,
      },
    });
    expect(unknownField.ok).toBe(false);

    const unknownKind = parseWalletUnlockRequestedCapabilitiesRequest({
      ...BASE_BODY,
      requestedCapabilities: { kind: 'unknown' },
    });
    expect(unknownKind.ok).toBe(false);
  });

  test('only invokes Ed25519 provisioning for the ed25519_yao request', async () => {
    const service = buildUnlockService();
    const noneResponse = await handleWalletUnlockVerifyRoute({
      body: {
        ...BASE_BODY,
        requestedCapabilities: { kind: 'none' },
      },
      service,
      ed25519YaoSession: buildNoEd25519Context(),
      ecdsaSession: { kind: 'no_ecdsa_session' },
      emitRouterApiWebhook: async () => undefined,
      emitEmailOtpWebhook: async () => undefined,
    });
    expect(noneResponse.status).toBe(200);

    const ed25519Request = parseRequest({
      ...BASE_BODY,
      requestedCapabilities: {
        kind: 'ed25519_yao',
        signerSlot: 1,
        remainingUses: 3,
      },
    });
    let ed25519ProvisionCalls = 0;
    const ed25519Response = await handleWalletUnlockVerifyRoute({
      body: {
        ...BASE_BODY,
        requestedCapabilities: ed25519Request.requestedCapabilities,
      },
      service,
      ed25519YaoSession: buildEd25519Context(ed25519Request, () => {
        ed25519ProvisionCalls += 1;
      }),
      ecdsaSession: { kind: 'no_ecdsa_session' },
      emitRouterApiWebhook: async () => undefined,
      emitEmailOtpWebhook: async () => undefined,
    });
    expect(ed25519Response.status).toBeGreaterThanOrEqual(400);
    expect(ed25519ProvisionCalls).toBe(1);
  });
});
