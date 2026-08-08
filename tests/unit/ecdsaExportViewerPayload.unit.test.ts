import { expect, test } from '@playwright/test';
import {
  requestEmailOtpEd25519KeyExportAuthorization,
  requestEmailOtpKeyExportAuthorization,
  requestThresholdEcdsaExportAuthorization,
  showEd25519ExportViewer,
  showThresholdEcdsaExportViewer,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportConfirmation';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';
import { resolveEmailOtpAuthLane } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  KeyExportEventPhase,
  type KeyExportFlowEvent,
} from '../../packages/sdk-web/src/core/types/sdkSentEvents';

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
  test('renders Ed25519 loading state without private material', async () => {
    let capturedPayload: any = null;

    await showEd25519ExportViewer(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => {
            capturedPayload = request.payload;
            return { requestId: request.requestId, confirmed: true };
          },
        },
      },
      {
        state: 'loading',
        walletId: 'frost-vermillion-k7p9m2',
        nearAccountId: 'frost-vermillion-k7p9m2.testnet',
        publicKey: 'ed25519:public-key',
        variant: 'drawer',
        viewerSessionId: 'ed25519-export-viewer-session-1',
        flowId: 'key-export-flow-1',
      },
    );

    if (!capturedPayload) throw new Error('expected export viewer request to be captured');

    expect(capturedPayload.viewerSessionId).toBe('ed25519-export-viewer-session-1');
    expect(capturedPayload.loading).toBe(true);
    expect(capturedPayload.keys).toEqual([
      {
        scheme: 'ed25519',
        label: 'NEAR Ed25519 private key',
        publicKey: 'ed25519:public-key',
        privateKey: '',
      },
    ]);
  });

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
    expect(capturedPayload.variant).toBe('drawer');
    expect(capturedPayload.keys).toEqual([
      {
        scheme: 'secp256k1',
        label: 'EVM',
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
    const exportEvents: KeyExportFlowEvent[] = [];

    const appSessionJwt = 'app-session-jwt';
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
          return {
            challengeId: 'email-otp-export-1',
            emailHint: 'a***@example.test',
            delivery: {
              kind: 'provider_and_demo_code',
              status: 'sent',
              emailHint: 'a***@example.test',
              otpCode: '654321',
            },
          };
        },
        requestPublicReauthExportChallenge: async () => {
          throw new Error('unexpected public-reauth export challenge');
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
        challengeAuthority: { kind: 'app_session', appSessionJwt },
        flowId: 'key-export-flow-1',
        onEvent: (event) => exportEvents.push(event),
      },
    );

    expect(authorization.walletSessionUserId).toBe('frost-vermillion-k7p9m2');
    expect(authorization.challengeId).toBe('email-otp-export-1');
    expect(authorization.otpCode).toBe('123456');
    expect(capturedChallengeKind).toBe('wallet_capability_export_challenge');
    expect(capturedSummaryAccountId).toBe('frost-vermillion-k7p9m2');
    expect(capturedPayloadWalletId).toBe('frost-vermillion-k7p9m2');
    expect(exportEvents).toEqual([
      expect.objectContaining({
        phase: KeyExportEventPhase.STEP_02_AUTH_EMAIL_OTP_INPUT_REQUIRED,
        status: 'waiting_for_user',
        authMethod: 'email_otp',
        data: {
          emailHint: 'a***@example.test',
          demoOtpCode: '654321',
        },
      }),
    ]);
  });

  test('requests fresh Email OTP export authorization from the current app session', async () => {
    const walletId = toWalletId('frost-vermillion-k7p9m2');

    const authorization = await requestEmailOtpKeyExportAuthorization(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => ({
            requestId: request.requestId,
            confirmed: true,
            otpCode: '123456',
            emailOtpChallengeId: 'email-otp-public-reauth-export-1',
          }),
        },
        requestExportChallenge: async () => {
          return {
            challengeId: 'email-otp-public-reauth-export-1',
            emailHint: 'a***@example.test',
            delivery: {
              kind: 'provider',
              status: 'sent',
              emailHint: 'a***@example.test',
            },
          };
        },
      },
      {
        kind: 'wallet_session_export_auth',
        walletSession: {
          walletId,
          walletSessionUserId: String(walletId),
        },
        chain: 'evm',
        publicKey: '0x02abcdef',
        curve: 'ecdsa',
        challengeAuthority: { kind: 'app_session', appSessionJwt: 'app-session-jwt' },
        flowId: 'key-export-flow-2',
        onEvent: (event) => {
          expect(event.data?.demoOtpCode).toBeNull();
        },
      },
    );

    expect(authorization.challengeId).toBe('email-otp-public-reauth-export-1');
  });

  test('emits the demo Email OTP code on the Ed25519 key-export lane', async () => {
    const walletId = toWalletId('frost-vermillion-k7p9m2');
    const exportEvents: KeyExportFlowEvent[] = [];
    const authLane = resolveEmailOtpAuthLane({
      routeAuth: { kind: 'wallet_session', jwt: 'durable-wallet-session-jwt' },
      thresholdSessionId: 'threshold-session-1',
      curve: 'ed25519',
    });
    if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ed25519') {
      throw new Error('expected Ed25519 signing-session auth lane');
    }

    const authorization = await requestEmailOtpEd25519KeyExportAuthorization(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => ({
            requestId: request.requestId,
            confirmed: true,
            otpCode: '123456',
            emailOtpChallengeId: 'email-otp-ed25519-export-1',
          }),
        },
        requestExportChallenge: async () => ({
          challengeId: 'email-otp-ed25519-export-1',
          emailHint: 'a***@example.test',
          delivery: {
            kind: 'demo_code_response',
            status: 'sent',
            emailHint: 'a***@example.test',
            otpCode: '654321',
          },
        }),
      },
      {
        kind: 'wallet_session_ed25519_export_auth',
        walletSession: {
          walletId,
          walletSessionUserId: String(walletId),
        },
        nearAccountId: 'frost-vermillion-k7p9m2.testnet',
        nearEd25519SigningKeyId: 'ed25519-signing-key-1',
        signerSlot: 1,
        thresholdSessionId: 'threshold-session-1',
        publicKey: 'ed25519:abcdef',
        curve: 'ed25519',
        chain: 'near',
        authLane,
        flowId: 'key-export-flow-ed25519-1',
        onEvent: (event) => exportEvents.push(event),
      },
    );

    expect(authorization.challengeId).toBe('email-otp-ed25519-export-1');
    expect(authorization.otpCode).toBe('123456');
    expect(exportEvents).toEqual([
      expect.objectContaining({
        phase: KeyExportEventPhase.STEP_02_AUTH_EMAIL_OTP_INPUT_REQUIRED,
        status: 'waiting_for_user',
        authMethod: 'email_otp',
        flowId: 'key-export-flow-ed25519-1',
        accountId: String(walletId),
        data: {
          emailHint: 'a***@example.test',
          demoOtpCode: '654321',
        },
      }),
    ]);
  });

  test('withholds the demo code from the Ed25519 lane on provider-only delivery', async () => {
    const walletId = toWalletId('frost-vermillion-k7p9m2');
    const exportEvents: KeyExportFlowEvent[] = [];
    const authLane = resolveEmailOtpAuthLane({
      routeAuth: { kind: 'wallet_session', jwt: 'durable-wallet-session-jwt' },
      thresholdSessionId: 'threshold-session-1',
      curve: 'ed25519',
    });
    if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ed25519') {
      throw new Error('expected Ed25519 signing-session auth lane');
    }

    await requestEmailOtpEd25519KeyExportAuthorization(
      {
        touchConfirm: {
          requestUserConfirmation: async (request) => ({
            requestId: request.requestId,
            confirmed: true,
            otpCode: '123456',
            emailOtpChallengeId: 'email-otp-ed25519-export-2',
          }),
        },
        requestExportChallenge: async () => ({
          challengeId: 'email-otp-ed25519-export-2',
          emailHint: 'a***@example.test',
          delivery: {
            kind: 'provider',
            status: 'sent',
            emailHint: 'a***@example.test',
          },
        }),
      },
      {
        kind: 'wallet_session_ed25519_export_auth',
        walletSession: {
          walletId,
          walletSessionUserId: String(walletId),
        },
        nearAccountId: 'frost-vermillion-k7p9m2.testnet',
        nearEd25519SigningKeyId: 'ed25519-signing-key-1',
        signerSlot: 1,
        thresholdSessionId: 'threshold-session-1',
        publicKey: 'ed25519:abcdef',
        curve: 'ed25519',
        chain: 'near',
        authLane,
        flowId: 'key-export-flow-ed25519-2',
        onEvent: (event) => exportEvents.push(event),
      },
    );

    expect(exportEvents).toHaveLength(1);
    expect(exportEvents[0]?.data?.demoOtpCode).toBeNull();
  });
});
