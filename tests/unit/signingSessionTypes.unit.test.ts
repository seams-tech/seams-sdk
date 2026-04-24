import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { buildTempoTransactionSigningLane } from '@/core/signingEngine/session/SigningLaneBuilders';
import { buildWalletSigningSpendPlan } from '@/core/signingEngine/session/SigningBudgetSpendPlan';
import {
  normalizeWalletSigningSpendPlan,
  SigningSessionIds,
} from '@/core/signingEngine/session/signingSessionTypes';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test.describe('signing session shared types', () => {
  test('branded id helpers normalize required session ids', () => {
    expect(SigningSessionIds.walletSigningSession(' wsess-1 ')).toBe('wsess-1');
    expect(SigningSessionIds.thresholdEd25519Session(' tsess-ed25519 ')).toBe('tsess-ed25519');
    expect(SigningSessionIds.thresholdEcdsaSession(' tsess-ecdsa ')).toBe('tsess-ecdsa');
    expect(SigningSessionIds.backingMaterialSession(' backing-session ')).toBe('backing-session');
    expect(SigningSessionIds.emailOtpChallenge(' challenge-1 ')).toBe('challenge-1');
    expect(SigningSessionIds.signingOperation(' op-1 ')).toBe('op-1');
  });

  test('branded id helpers reject empty values at module boundaries', () => {
    expect(() => SigningSessionIds.walletSigningSession('')).toThrow(
      '[SigningSession] walletSigningSessionId is required',
    );
    expect(() => SigningSessionIds.thresholdEcdsaSession('   ')).toThrow(
      '[SigningSession] thresholdEcdsaSessionId is required',
    );
  });

  test('wallet signing spend plan codec rejects mismatched lane bindings', () => {
    const operationId = SigningSessionIds.signingOperation('op-spend-codec');
    const lane = buildTempoTransactionSigningLane({
      accountId: toAccountId('spend-codec.testnet'),
      authMethod: 'email_otp',
      walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-spend-codec'),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tsess-spend-codec'),
      signingRootId: 'proj_codec:dev',
      signingRootVersion: 'default',
    });
    const spend = buildWalletSigningSpendPlan({ operationId, intent: 'transaction_sign' }, lane);

    expect(
      normalizeWalletSigningSpendPlan({
        ...spend,
        thresholdSessionIds: [...spend.thresholdSessionIds, ...spend.thresholdSessionIds],
      }).thresholdSessionIds,
    ).toEqual(['tsess-spend-codec']);
    expect(() =>
      normalizeWalletSigningSpendPlan({
        ...spend,
        walletSigningSessionId: SigningSessionIds.walletSigningSession('wsess-other'),
      }),
    ).toThrow('walletSigningSessionId does not match lane');
    expect(() =>
      normalizeWalletSigningSpendPlan({
        ...spend,
        uses: 2,
      } as any),
    ).toThrow('wallet signing spend uses must be 1');
  });

  test('threshold session readiness module no longer occupies the planner name', () => {
    const oldPath = path.join(
      repoRoot,
      'client/src/core/signingEngine/orchestration/shared/thresholdSigningSessionPlanner.ts',
    );
    const newPath = path.join(
      repoRoot,
      'client/src/core/signingEngine/orchestration/shared/thresholdSigningSessionReadiness.ts',
    );

    expect(fs.existsSync(oldPath)).toBe(false);
    expect(fs.existsSync(newPath)).toBe(true);
  });
});
