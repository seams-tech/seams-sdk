import { expect, test } from '@playwright/test';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';

test.describe('threshold ECDSA registration bootstrap parity gate', () => {
  test('registration-source bootstrap soft-fails startup parity errors', async () => {
    const engine = Object.create(SigningEngine.prototype) as SigningEngine & {
      ensureSealedRefreshStartupParity: () => Promise<void>;
      ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: (args: {
        nearAccountId: string;
        chain?: 'tempo' | 'evm';
        source?: 'login' | 'registration' | 'manual-bootstrap';
      }) => Promise<void>;
    };
    engine.ensureSealedRefreshStartupParity = async () => {
      throw new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502');
    };

    const originalWarn = console.warn;
    const warnings: unknown[][] = [];
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };

    try {
      await expect(
        engine.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
          source: 'registration',
        }),
      ).resolves.toBeUndefined();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(String(warnings[0]?.[0] || '')).toContain(
      'registration bootstrap skipped sealed-refresh startup parity enforcement',
    );
    expect(warnings[0]?.[1]).toMatchObject({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('manual bootstrap still fails on startup parity errors', async () => {
    const engine = Object.create(SigningEngine.prototype) as SigningEngine & {
      ensureSealedRefreshStartupParity: () => Promise<void>;
      ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: (args: {
        nearAccountId: string;
        source?: 'login' | 'registration' | 'manual-bootstrap';
      }) => Promise<void>;
    };
    engine.ensureSealedRefreshStartupParity = async () => {
      throw new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502');
    };

    await expect(
      engine.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
        nearAccountId: 'alice.testnet',
        source: 'manual-bootstrap',
      }),
    ).rejects.toThrow('Well-known endpoint returned HTTP 502');
  });
});
