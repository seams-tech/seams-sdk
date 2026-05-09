import { expect, test } from '@playwright/test';
import { SENSITIVE_OPERATION_POLICIES } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  applyEcdsaPostSignPolicy,
  assertEcdsaOperationAllowed,
  ecdsaPostSignPolicyMaterialFromRecord,
  ecdsaPostSignPolicySessionFromRecord,
} from '@/core/signingEngine/session/operationState/postSignPolicy';
import { toAccountId } from '@/core/types/accountIds';

const NEAR_ACCOUNT_ID = toAccountId('alice.testnet');
const EVM_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};
const TEMPO_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 1,
  networkSlug: 'tempo-mainnet',
};

function ecdsaRecord(args: {
  thresholdSessionId: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  source?: 'email_otp' | 'login';
  retention?: 'session' | 'single_use';
  consumedAtMs?: number;
}): ThresholdEcdsaSessionRecord {
  return {
    nearAccountId: NEAR_ACCOUNT_ID,
    chainTarget: args.chainTarget || EVM_CHAIN_TARGET,
    thresholdSessionId: args.thresholdSessionId,
    source: args.source || 'email_otp',
    emailOtpAuthContext:
      args.source === 'login'
        ? undefined
        : {
            authMethod: 'email_otp',
            policy: 'single_use',
            reason: 'sign',
            retention: args.retention || 'single_use',
            ...(args.consumedAtMs ? { consumedAtMs: args.consumedAtMs } : {}),
          },
  } as ThresholdEcdsaSessionRecord;
}

test.describe('SigningPostSignPolicy', () => {
  test('clears single-use selected Email OTP material and marks the lane consumed', async () => {
    const consumed: Array<{ nearAccountId: string; chainTarget: ThresholdEcdsaChainTarget }> = [];
    const cleared: Array<{
      recordThresholdSessionId: string;
      thresholdSessionId: string;
    }> = [];
    const selectedRecord = ecdsaRecord({ thresholdSessionId: 'otp-session' });

    await applyEcdsaPostSignPolicy({
      source: null,
      thresholdSessionId: 'otp-session',
      selectedMaterial: ecdsaPostSignPolicyMaterialFromRecord({
        record: selectedRecord,
        clearEcdsaEphemeralMaterial: async (args) => {
          cleared.push({
            recordThresholdSessionId: args.record.thresholdSessionId,
            thresholdSessionId: args.thresholdSessionId || '',
          });
        },
      }),
      secondaryMaterial: null,
      markEmailOtpSessionConsumed: (args) => consumed.push(args),
    });

    expect(consumed).toEqual([
      { nearAccountId: 'alice.testnet', chainTarget: EVM_CHAIN_TARGET, uses: 1 },
    ]);
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
    const selectedRecord = ecdsaRecord({
      chainTarget: TEMPO_CHAIN_TARGET,
      thresholdSessionId: 'passkey-session',
      source: 'login',
    });
    const secondaryRecord = ecdsaRecord({
      chainTarget: TEMPO_CHAIN_TARGET,
      thresholdSessionId: 'otp-session',
    });

    await applyEcdsaPostSignPolicy({
      source: null,
      thresholdSessionId: null,
      selectedMaterial: ecdsaPostSignPolicyMaterialFromRecord({
        record: selectedRecord,
        clearEcdsaEphemeralMaterial: async () => {},
      }),
      secondaryMaterial: ecdsaPostSignPolicyMaterialFromRecord({
        record: secondaryRecord,
        clearEcdsaEphemeralMaterial: async (args) => {
          cleared.push({
            recordThresholdSessionId: args.record.thresholdSessionId,
            thresholdSessionId: args.thresholdSessionId || '',
          });
        },
      }),
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
        chainTarget: EVM_CHAIN_TARGET,
        operationLabel: 'evm signing',
        thresholdSessionId: null,
        source: null,
        selectedSession: ecdsaPostSignPolicySessionFromRecord(
          ecdsaRecord({
            thresholdSessionId: 'otp-session',
            consumedAtMs: Date.now(),
          }),
        ),
        secondarySession: null,
      }),
    ).toThrow(/fresh Email OTP/i);
  });

  test('requires passkey when sensitive policy denies Email OTP', () => {
    expect(() =>
      assertEcdsaOperationAllowed({
        chainTarget: EVM_CHAIN_TARGET,
        operationLabel: 'evm signing',
        thresholdSessionId: null,
        source: null,
        selectedSession: ecdsaPostSignPolicySessionFromRecord(
          ecdsaRecord({
            thresholdSessionId: 'otp-session',
            retention: 'session',
          }),
        ),
        secondarySession: null,
        sensitivePolicy: SENSITIVE_OPERATION_POLICIES.requirePasskey,
      }),
    ).toThrow(/passkey/i);
  });
});
