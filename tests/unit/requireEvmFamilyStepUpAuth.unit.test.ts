import { expect, test } from '@playwright/test';
import { SigningAuthPlanKind } from '../../packages/wallet/src/core/signingEngine/stepUpConfirmation/types';
import {
  requireEvmFamilyStepUpAuth,
  type EvmFamilyReusableAuthorizationState,
  type EvmFamilyThresholdEcdsaStepUp,
} from '../../packages/wallet/src/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth';
import {
  evmFamilyThresholdEcdsaOperationFixture,
  evmFamilyThresholdEcdsaStepUpRuntimeFixture,
} from './helpers/ecdsaOperationStepUp.fixtures';

// `reusableAuthorization` is what tells the step-up resolver whether the
// material candidate is auth-neutral. With an active reusable Wallet Session
// the confirmation's plan chooses the lane; without one the capability's own
// factor is required, so a warm-session plan cannot be honoured and cannot be
// substituted by a different factor.

const OPERATION = evmFamilyThresholdEcdsaOperationFixture();

function warmSessionStepUp(
  reusableAuthorization: EvmFamilyReusableAuthorizationState,
): EvmFamilyThresholdEcdsaStepUp {
  return {
    kind: 'required',
    authPlan: {
      kind: 'planned',
      signingAuthPlan: {
        kind: SigningAuthPlanKind.WarmSession,
        method: 'passkey',
        accountId: 'alice.testnet',
        intent: 'transaction_sign',
        curve: 'ecdsa',
        thresholdSessionId: 'threshold-session-warm',
        expiresAtMs: 1_777_777_777_000,
        remainingUses: 2,
      },
    },
    operation: OPERATION,
    runtime: evmFamilyThresholdEcdsaStepUpRuntimeFixture({ reusableAuthorization }),
  };
}

test.describe('requireEvmFamilyStepUpAuth', () => {
  test('reuses the warm session when a reusable Wallet Session is active', async () => {
    const thresholdEcdsaStepUp = warmSessionStepUp({ kind: 'active' });

    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp,
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: false,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared.kind).toBe('warm_session');
    expect(prepared.confirmationAuthPayload.signingAuthPlan).toEqual(
      thresholdEcdsaStepUp.kind === 'required'
        ? thresholdEcdsaStepUp.authPlan.signingAuthPlan
        : undefined,
    );
  });

  test('escalates a warm-session plan to passkey step-up when reusable auth is absent', async () => {
    // The plan still says warm session. It cannot be honoured, because there is
    // no reusable Wallet Session to reuse.
    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp: warmSessionStepUp({
        kind: 'absent',
        requiredFactor: 'passkey',
      }),
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: false,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared.kind).toBe('passkey');
  });

  test('escalates to the capability factor, not the plan factor, when reusable auth is absent', async () => {
    // A passkey-preferring plan on Email-OTP-bound material must escalate to
    // Email OTP: step-up is same-method by the capability's factor.
    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp: {
        ...warmSessionStepUp({ kind: 'absent', requiredFactor: 'email_otp' }),
        runtime: evmFamilyThresholdEcdsaStepUpRuntimeFixture({
          reusableAuthorization: { kind: 'absent', requiredFactor: 'email_otp' },
          emailOtpChallenge: { challengeId: 'otp-1', emailHint: 'a***@x.test' },
        }),
      },
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: false,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared.kind).toBe('email_otp');
    if (prepared.kind !== 'email_otp') throw new Error('expected email_otp branch');
    expect(prepared.emailOtpPrompt.challengeId).toBe('otp-1');
  });

  test('returns an email-otp branch with the typed challenge prompt', async () => {
    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp: {
        kind: 'required',
        authPlan: {
          kind: 'planned',
          signingAuthPlan: {
            kind: SigningAuthPlanKind.EmailOtpReauth,
            method: 'email_otp',
          },
        },
        operation: OPERATION,
        runtime: evmFamilyThresholdEcdsaStepUpRuntimeFixture({
          reusableAuthorization: { kind: 'active' },
          emailOtpChallenge: { challengeId: 'otp-2', emailHint: 'a***@x.test' },
        }),
      },
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: false,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared.kind).toBe('email_otp');
    if (prepared.kind !== 'email_otp') throw new Error('expected email_otp branch');
    expect(prepared.emailOtpPrompt.challengeId).toBe('otp-2');
    expect(prepared.confirmationAuthPayload.signingAuthPlan.kind).toBe(
      SigningAuthPlanKind.EmailOtpReauth,
    );
  });

  test('returns a passkey branch for a passkey reauth plan', async () => {
    const prepared = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp: {
        kind: 'required',
        authPlan: {
          kind: 'planned',
          signingAuthPlan: {
            kind: SigningAuthPlanKind.PasskeyReauth,
            method: 'passkey',
          },
        },
        operation: OPERATION,
        runtime: evmFamilyThresholdEcdsaStepUpRuntimeFixture({
          reusableAuthorization: { kind: 'active' },
        }),
      },
      hasThresholdEcdsaRequest: true,
      needsWebAuthn: true,
      requiredSignatureUses: 1,
      explicitAuthErrorLabel: 'EVM',
    });

    expect(prepared.kind).toBe('passkey');
    expect(prepared.confirmationAuthPayload.signingAuthPlan.kind).toBe(
      SigningAuthPlanKind.PasskeyReauth,
    );
  });
});
