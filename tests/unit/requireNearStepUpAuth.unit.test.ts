import { expect, test } from '@playwright/test';
import { requireNearStepUpAuth } from '../../packages/sdk-web/src/core/signingEngine/flows/signNear/requireNearStepUpAuth';
import {
  buildEd25519EmailOtpSigningLane,
  buildEd25519PasskeySigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { SigningAuthPlanKind } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types';
import { ActionType } from '../../packages/sdk-web/src/core/types/actions';
import { requiredNearTransactionSignatureUses } from '../../packages/sdk-web/src/core/signingEngine/flows/signNear/signatureUses';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { ed25519KeyScopeIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

const WALLET_ID = toWalletId('frost-vermillion-k7p9m2');
const NEAR_ACCOUNT_ID = toAccountId('alice.testnet');
const ED25519_KEY_SCOPE_ID = ed25519KeyScopeIdFromString('scope-frost-vermillion-k7p9m2');

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
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      ed25519KeyScopeId: ED25519_KEY_SCOPE_ID,
      signingGrantId: SigningSessionIds.signingGrant('wallet-session-warm'),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session-warm'),
      storageSource: 'login',
    });

    const prepared = await requireNearStepUpAuth({
      signingAuthPlan,
      signingLane,
      requiredSignatureUses: 1,
    });

    expect(prepared).toEqual({
      kind: 'warm_session',
      confirmationAuthPayload: {
        signingAuthPlan,
      },
    });
  });

  test('uses a one-remaining-use warm session for one multi-action transaction', async () => {
    const requiredSignatureUses = requiredNearTransactionSignatureUses({
      receiverId: 'contract.testnet',
      actions: [
        {
          action_type: ActionType.FunctionCall,
          method_name: 'setGreeting',
          args: '{}',
          gas: '30000000000000',
          deposit: '0',
        },
        {
          action_type: ActionType.Transfer,
          deposit: '1',
        },
      ],
    });
    const signingAuthPlan = {
      kind: SigningAuthPlanKind.WarmSession,
      method: 'passkey' as const,
      accountId: 'alice.testnet',
      intent: 'transaction_sign' as const,
      sessionId: 'threshold-session-warm-one',
      expiresAtMs: 1_777_777_777_000,
      remainingUses: 1,
    };
    const signingLane = buildEd25519PasskeySigningLane({
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      ed25519KeyScopeId: ED25519_KEY_SCOPE_ID,
      signingGrantId: SigningSessionIds.signingGrant('wallet-session-warm-one'),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
        'threshold-session-warm-one',
      ),
      storageSource: 'login',
    });

    const prepared = await requireNearStepUpAuth({
      signingAuthPlan,
      signingLane,
      requiredSignatureUses,
    });

    expect(prepared.kind).toBe('warm_session');
  });

  test('returns an email-otp branch with the typed challenge prompt', async () => {
    const signingAuthPlan = {
      kind: SigningAuthPlanKind.EmailOtpReauth,
      method: 'email_otp' as const,
    };
    const signingLane = buildEd25519EmailOtpSigningLane({
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      ed25519KeyScopeId: ED25519_KEY_SCOPE_ID,
      signingGrantId: SigningSessionIds.signingGrant('wallet-session-email'),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session-email'),
    });
    const preparedUses: number[] = [];

    const prepared = await requireNearStepUpAuth({
      signingAuthPlan,
      signingLane,
      requiredSignatureUses: 1,
      emailOtpSigning: {
        prepare: async ({ requiredSignatureUses }) => {
          preparedUses.push(requiredSignatureUses);
          return { challengeId: 'otp-1', emailHint: 'a***@x.test' };
        },
        complete: async () => ({ sessionId: 'threshold-session-email' }),
      },
    });

    expect(preparedUses).toEqual([1]);
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
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      ed25519KeyScopeId: ED25519_KEY_SCOPE_ID,
      signingGrantId: SigningSessionIds.signingGrant('wallet-session-passkey'),
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session-passkey'),
      storageSource: 'login',
    });
    const preparedUses: number[] = [];

    const prepared = await requireNearStepUpAuth({
      signingAuthPlan,
      signingLane,
      requiredSignatureUses: 1,
      passkeyEd25519Reconnect: {
        prepare: async ({ requiredSignatureUses }) => {
          preparedUses.push(requiredSignatureUses);
          return {
            sessionId: 'threshold-session-passkey',
            signingGrantId: 'wallet-session-passkey',
            sessionPolicyDigest32: 'digest-32',
          };
        },
        reconnect: async () => ({ sessionId: 'threshold-session-passkey' }),
      },
    });

    expect(preparedUses).toEqual([1]);
    expect(prepared.kind).toBe('passkey');
    if (prepared.kind !== 'passkey') throw new Error('expected passkey branch');
    expect(prepared.plannedPasskeyReconnect).toEqual({
      sessionId: 'threshold-session-passkey',
      signingGrantId: 'wallet-session-passkey',
      sessionPolicyDigest32: 'digest-32',
    });
  });
});
