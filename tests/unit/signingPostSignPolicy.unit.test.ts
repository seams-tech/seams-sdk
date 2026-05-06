import { expect, test } from '@playwright/test';
import { SENSITIVE_OPERATION_POLICIES } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  applyEcdsaPostSignPolicy,
  assertEcdsaOperationAllowed,
} from '@/core/signingEngine/session/signingSession/postSignPolicy';
import { toAccountId } from '@/core/types/accountIds';

const NEAR_ACCOUNT_ID = toAccountId('alice.testnet');

function ecdsaRecord(args: {
  thresholdSessionId: string;
  source?: 'email_otp' | 'login';
  retention?: 'session' | 'single_use';
  consumedAtMs?: number;
}): ThresholdEcdsaSessionRecord {
  return {
    nearAccountId: NEAR_ACCOUNT_ID,
    chain: 'evm',
    thresholdSessionId: args.thresholdSessionId,
    source: args.source || 'email_otp',
    emailOtpAuthContext:
      args.source === 'login'
        ? undefined
        : {
            authMethod: 'email_otp',
            policy: 'single_use',
            reason: 'signing',
            retention: args.retention || 'single_use',
            ...(args.consumedAtMs ? { consumedAtMs: args.consumedAtMs } : {}),
          },
  } as ThresholdEcdsaSessionRecord;
}

test.describe('SigningPostSignPolicy', () => {
  test('clears single-use selected Email OTP material and marks the lane consumed', async () => {
    const consumed: Array<{ nearAccountId: string; chain: string }> = [];
    const cleared: Array<{
      recordThresholdSessionId: string;
      thresholdSessionId: string;
    }> = [];

    await applyEcdsaPostSignPolicy({
      nearAccountId: NEAR_ACCOUNT_ID,
      chain: 'evm',
      thresholdSessionId: 'otp-session',
      selectedRecord: ecdsaRecord({ thresholdSessionId: 'otp-session' }),
      markEmailOtpSessionConsumed: (args) => consumed.push(args),
      clearEcdsaEphemeralMaterial: async (args) => {
        cleared.push({
          recordThresholdSessionId: args.record.thresholdSessionId,
          thresholdSessionId: args.thresholdSessionId || '',
        });
      },
    });

    expect(consumed).toEqual([{ nearAccountId: 'alice.testnet', chain: 'evm', uses: 1 }]);
    expect(cleared).toEqual([
      {
        recordThresholdSessionId: 'otp-session',
        thresholdSessionId: 'otp-session',
      },
    ]);
  });

  test('clears stale secondary Email OTP material when the selected lane is passkey', async () => {
    const cleared: Array<{
      recordThresholdSessionId: string;
      thresholdSessionId: string;
    }> = [];

    await applyEcdsaPostSignPolicy({
      nearAccountId: NEAR_ACCOUNT_ID,
      chain: 'tempo',
      selectedRecord: ecdsaRecord({
        thresholdSessionId: 'passkey-session',
        source: 'login',
      }),
      secondaryRecord: ecdsaRecord({ thresholdSessionId: 'otp-session' }),
      clearEcdsaEphemeralMaterial: async (args) => {
        cleared.push({
          recordThresholdSessionId: args.record.thresholdSessionId,
          thresholdSessionId: args.thresholdSessionId || '',
        });
      },
    });

    expect(cleared).toEqual([
      {
        recordThresholdSessionId: 'otp-session',
        thresholdSessionId: 'otp-session',
      },
    ]);
  });

  test('blocks consumed single-use Email OTP sensitive operations', () => {
    expect(() =>
      assertEcdsaOperationAllowed({
        chain: 'evm',
        operationLabel: 'evm signing',
        selectedRecord: ecdsaRecord({
          thresholdSessionId: 'otp-session',
          consumedAtMs: Date.now(),
        }),
      }),
    ).toThrow(/fresh Email OTP/i);
  });

  test('requires passkey when sensitive policy denies Email OTP', () => {
    expect(() =>
      assertEcdsaOperationAllowed({
        chain: 'evm',
        operationLabel: 'evm signing',
        selectedRecord: ecdsaRecord({
          thresholdSessionId: 'otp-session',
          retention: 'session',
        }),
        sensitivePolicy: SENSITIVE_OPERATION_POLICIES.requirePasskey,
      }),
    ).toThrow(/passkey/i);
  });
});
