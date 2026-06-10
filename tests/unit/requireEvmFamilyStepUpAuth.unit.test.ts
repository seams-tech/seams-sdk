import { expect, test } from '@playwright/test';
import { SigningAuthPlanKind } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types';
import {
  requireEvmFamilyStepUpAuth,
  type EvmFamilyThresholdEcdsaStepUp,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth';

test.describe('requireEvmFamilyStepUpAuth', () => {
  test('returns a warm-session branch without prompt wrappers', async () => {
    const thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp = {
      kind: 'required_not_admitted',
      authPlan: {
        kind: 'planned',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.WarmSession,
          method: 'passkey',
          accountId: 'alice.testnet',
          intent: 'transaction_sign',
          curve: 'ecdsa',
          signingRootId: 'root-1',
          sessionId: 'threshold-session-warm',
          expiresAtMs: 1_777_777_777_000,
          remainingUses: 2,
        },
      },
      runtime: {},
    };

    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp,
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: false,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared).toEqual({
      kind: 'warm_session',
      confirmationAuthPayload: {
        signingAuthPlan: thresholdEcdsaStepUp.authPlan.signingAuthPlan,
      },
    });
  });

  test('returns an email-otp branch with the typed challenge prompt', async () => {
    const thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp = {
      kind: 'required_not_admitted',
      authPlan: {
        kind: 'planned',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.EmailOtpReauth,
          method: 'email_otp',
        },
      },
      runtime: {
        emailOtpSigning: {
          prepare: async () => ({ challengeId: 'otp-1', emailHint: 'a***@x.test' }),
          complete: async () => {
            throw new Error('not used in prepare test');
          },
        },
      },
    };

    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp,
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: false,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared.kind).toBe('email_otp');
    if (prepared.kind !== 'email_otp') throw new Error('expected email_otp branch');
    expect(prepared.emailOtpPrompt.challengeId).toBe('otp-1');
    expect(prepared.confirmationAuthPayload.signingAuthPlan.kind).toBe(
      SigningAuthPlanKind.EmailOtpReauth,
    );
  });

  test('returns a passkey branch with the planned reconnect identity', async () => {
    const thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp = {
      kind: 'required_not_admitted',
      authPlan: {
        kind: 'planned',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.PasskeyReauth,
          method: 'passkey',
        },
      },
      runtime: {
        passkeyReconnect: {
          prepare: async () => ({
            webauthnChallenge: {
              kind: 'ecdsa_role_local_bootstrap',
              digest32B64u: 'digest-32',
              requestId: 'request-1',
              thresholdSessionId: 'threshold-session-passkey',
              walletSigningSessionId: 'wallet-session-passkey',
            },
          }),
          reconnect: async () => {
            throw new Error('not used in prepare test');
          },
        },
      },
    };

    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp,
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: true,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared.kind).toBe('passkey');
    if (prepared.kind !== 'passkey') throw new Error('expected passkey branch');
    expect(prepared.plannedPasskeyReconnect).toEqual({
      webauthnChallenge: {
        kind: 'ecdsa_role_local_bootstrap',
        digest32B64u: 'digest-32',
        requestId: 'request-1',
        thresholdSessionId: 'threshold-session-passkey',
        walletSigningSessionId: 'wallet-session-passkey',
      },
    });
  });
});
