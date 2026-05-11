import { expect, test } from '@playwright/test';
import { requireNearStepUpAuth } from '../../client/src/core/signingEngine/flows/signNear/requireNearStepUpAuth';
import {
  buildEd25519EmailOtpSigningLane,
  buildEd25519PasskeySigningLane,
} from '../../client/src/core/signingEngine/session/operationState/lanes';
import { SigningAuthPlanKind } from '../../client/src/core/signingEngine/stepUpConfirmation/types';

test.describe('requireNearStepUpAuth', () => {
  test('returns a warm-session branch without prompt wrappers', async () => {
    const signingAuthPlan = {
      kind: SigningAuthPlanKind.WarmSession,
      method: 'passkey' as const,
      accountId: 'alice.testnet',
      intent: 'transaction_sign' as const,
      sessionId: 'threshold-session-warm',
      expiresAtMs: 1_777_777_777_000,
      remainingUses: 3,
    };
    const signingLane = buildEd25519PasskeySigningLane({
      accountId: 'alice.testnet',
      walletSigningSessionId: 'wallet-session-warm',
      thresholdSessionId: 'threshold-session-warm',
      storageSource: 'login',
    });

    const prepared = await requireNearStepUpAuth({
      signingAuthPlan,
      signingLane,
      usesNeeded: 1,
    });

    expect(prepared).toEqual({
      kind: 'warm_session',
      confirmationAuthPayload: {
        signingAuthPlan,
      },
    });
  });

  test('returns an email-otp branch with the typed challenge prompt', async () => {
    const signingAuthPlan = {
      kind: SigningAuthPlanKind.EmailOtpReauth,
      method: 'email_otp' as const,
    };
    const signingLane = buildEd25519EmailOtpSigningLane({
      accountId: 'alice.testnet',
      walletSigningSessionId: 'wallet-session-email',
      thresholdSessionId: 'threshold-session-email',
    });

    const prepared = await requireNearStepUpAuth({
      signingAuthPlan,
      signingLane,
      usesNeeded: 1,
      emailOtpSigning: {
        prepare: async () => ({ challengeId: 'otp-1', emailHint: 'a***@x.test' }),
        complete: async () => ({ sessionId: 'threshold-session-email' }),
      },
    });

    expect(prepared.kind).toBe('email_otp');
    if (prepared.kind !== 'email_otp') throw new Error('expected email_otp branch');
    expect(prepared.emailOtpPrompt.challengeId).toBe('otp-1');
    expect(prepared.confirmationAuthPayload.signingAuthPlan.kind).toBe(
      SigningAuthPlanKind.EmailOtpReauth,
    );
  });

  test('returns a passkey branch with the planned reconnect identity', async () => {
    const signingAuthPlan = {
      kind: SigningAuthPlanKind.PasskeyReauth,
      method: 'passkey' as const,
    };
    const signingLane = buildEd25519PasskeySigningLane({
      accountId: 'alice.testnet',
      walletSigningSessionId: 'wallet-session-passkey',
      thresholdSessionId: 'threshold-session-passkey',
      storageSource: 'login',
    });

    const prepared = await requireNearStepUpAuth({
      signingAuthPlan,
      signingLane,
      usesNeeded: 2,
      passkeyEd25519Reconnect: {
        prepare: async () => ({
          sessionId: 'threshold-session-passkey',
          walletSigningSessionId: 'wallet-session-passkey',
          sessionPolicyDigest32: 'digest-32',
        }),
        reconnect: async () => ({ sessionId: 'threshold-session-passkey' }),
      },
    });

    expect(prepared.kind).toBe('passkey');
    if (prepared.kind !== 'passkey') throw new Error('expected passkey branch');
    expect(prepared.plannedPasskeyReconnect).toEqual({
      sessionId: 'threshold-session-passkey',
      walletSigningSessionId: 'wallet-session-passkey',
      sessionPolicyDigest32: 'digest-32',
    });
  });
});
