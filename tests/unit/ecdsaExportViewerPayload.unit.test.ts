import { expect, test } from '@playwright/test';
import {
  requestEmailOtpKeyExportAuthorization,
  requestThresholdEcdsaExportAuthorization,
  showThresholdEcdsaExportViewer,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportConfirmation';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
};

const TEST_WEBAUTHN_CREDENTIAL = {
  id: 'credential-id',
  rawId: 'raw-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: 'first-prf',
        second: undefined,
      },
    },
  },
} satisfies WebAuthnAuthenticationCredential;

test.describe('threshold ECDSA export viewer payload', () => {
  test('includes EVM address in the loading viewer payload', async () => {
    let capturedRequestType = '';
    let capturedPayload: any = null;

    await showThresholdEcdsaExportViewer(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => {
            capturedRequestType = String(request.type);
            capturedPayload = request.payload;
            return { requestId: request.requestId, confirmed: true };
          },
        },
        theme: 'light',
      },
      {
        state: 'loading',
        walletId: 'frost-vermillion-k7p9m2',
        chainTarget: EVM_TARGET,
        publicKeyHex: '0x02abcdef',
        ethereumAddress: '0x1111111111111111111111111111111111111111',
        variant: 'drawer',
        theme: 'light',
        viewerSessionId: 'export-viewer-session-1',
        flowId: 'key-export-flow-1',
      },
    );

    if (!capturedPayload) throw new Error('expected export viewer request to be captured');

    expect(capturedRequestType).toBe('showSecurePrivateKeyUi');
    expect(capturedPayload.subject).toEqual({
      kind: 'evm_wallet',
      walletId: 'frost-vermillion-k7p9m2',
    });
    expect(capturedPayload.loading).toBe(true);
    expect(capturedPayload.keys).toEqual([
      {
        scheme: 'secp256k1',
        label: 'EVM private key',
        publicKey: '0x02abcdef',
        privateKey: '',
        address: '0x1111111111111111111111111111111111111111',
      },
    ]);
  });

  test('accepts server-allocated wallet ids for passkey export authorization', async () => {
    let capturedSummaryAccountId = '';
    let capturedIntentDigest = '';

    const authorization = await requestThresholdEcdsaExportAuthorization(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => {
            capturedSummaryAccountId = String(
              (request.summary as { accountId?: unknown }).accountId || '',
            );
            capturedIntentDigest = String(request.intentDigest || '');
            return {
              requestId: request.requestId,
              confirmed: true,
              credential: TEST_WEBAUTHN_CREDENTIAL,
            };
          },
        },
      },
      {
        walletSessionUserId: 'frost-vermillion-k7p9m2',
        publicKey: '0x02abcdef',
        chainTarget: EVM_TARGET,
        flowId: 'key-export-flow-1',
      },
    );

    expect(authorization.walletSessionUserId).toBe('frost-vermillion-k7p9m2');
    expect(capturedSummaryAccountId).toBe('frost-vermillion-k7p9m2');
    expect(capturedIntentDigest).toContain('frost-vermillion-k7p9m2');
  });

  test('accepts server-allocated wallet ids for Email OTP export authorization', async () => {
    let capturedSummaryAccountId = '';
    let capturedPayloadWalletId = '';
    let capturedChallengeKind = '';

    const authorization = await requestEmailOtpKeyExportAuthorization(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => {
            capturedSummaryAccountId = String(
              (request.summary as { accountId?: unknown }).accountId || '',
            );
            capturedPayloadWalletId = String(
              (request.payload as { signingSubject?: { walletId?: unknown } }).signingSubject
                ?.walletId || '',
            );
            return {
              requestId: request.requestId,
              confirmed: true,
              otpCode: '123456',
              emailOtpChallengeId: 'email-otp-export-1',
            };
          },
        },
        requestExportChallenge: async (request) => {
          capturedChallengeKind = request.kind;
          return { challengeId: 'email-otp-export-1' };
        },
      },
      {
        kind: 'wallet_session_export_auth',
        walletSession: {
          walletId: toWalletId('frost-vermillion-k7p9m2'),
          walletSessionUserId: 'frost-vermillion-k7p9m2',
        },
        chain: 'evm',
        publicKey: '0x02abcdef',
        curve: 'ecdsa',
      },
    );

    expect(authorization.walletSessionUserId).toBe('frost-vermillion-k7p9m2');
    expect(authorization.challengeId).toBe('email-otp-export-1');
    expect(authorization.otpCode).toBe('123456');
    expect(capturedChallengeKind).toBe('wallet_session_challenge');
    expect(capturedSummaryAccountId).toBe('frost-vermillion-k7p9m2');
    expect(capturedPayloadWalletId).toBe('frost-vermillion-k7p9m2');
  });
});
