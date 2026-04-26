import { expect, test } from '@playwright/test';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import { SigningOperationIntent } from '@/core/signingEngine/session/signingSessionTypes';

test.describe('threshold ECDSA registration bootstrap parity gate', () => {
  test('registration-source bootstrap soft-fails startup parity errors', async () => {
    const engine: any = Object.create(SigningEngine.prototype);
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
    const engine: any = Object.create(SigningEngine.prototype);
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

  test('transaction-sign bootstrap soft-fails retryable well-known fetch errors', async () => {
    const engine: any = Object.create(SigningEngine.prototype);
    engine.ensureSealedRefreshStartupParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502'),
        { code: 'sealed_refresh_parity_http_error' },
      );
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
          chain: 'evm',
          source: 'manual-bootstrap',
          operationIntent: SigningOperationIntent.TransactionSign,
        }),
      ).resolves.toBeUndefined();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(String(warnings[0]?.[0] || '')).toContain(
      'transaction bootstrap skipped retryable sealed-refresh capability fetch failure',
    );
    expect(warnings[0]?.[1]).toMatchObject({
      nearAccountId: 'alice.testnet',
      chain: 'evm',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('Email OTP bootstrap soft-fails retryable well-known fetch errors', async () => {
    const engine: any = Object.create(SigningEngine.prototype);
    engine.ensureSealedRefreshStartupParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502'),
        { code: 'sealed_refresh_parity_http_error' },
      );
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
          chain: 'evm',
          source: 'login',
          emailOtpAuthContext: { authMethod: 'email_otp' },
        }),
      ).resolves.toBeUndefined();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(String(warnings[0]?.[0] || '')).toContain(
      'Email OTP bootstrap skipped retryable sealed-refresh capability fetch failure',
    );
    expect(warnings[0]?.[1]).toMatchObject({
      nearAccountId: 'alice.testnet',
      chain: 'evm',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('Email OTP bootstrap still fails closed on parity mismatches', async () => {
    const engine: any = Object.create(SigningEngine.prototype);
    engine.ensureSealedRefreshStartupParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Client/server mismatch for fields: keyVersion'),
        { code: 'sealed_refresh_parity_mismatch' },
      );
    };

    await expect(
      engine.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
        nearAccountId: 'alice.testnet',
        source: 'login',
        emailOtpAuthContext: { authMethod: 'email_otp' },
      }),
    ).rejects.toThrow('Client/server mismatch');
  });

  test('transaction signing soft-fails retryable well-known fetch errors', async () => {
    const engine: any = Object.create(SigningEngine.prototype);
    engine.ensureSealedRefreshStartupParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502'),
        { code: 'sealed_refresh_parity_http_error' },
      );
    };

    const originalWarn = console.warn;
    const warnings: unknown[][] = [];
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };

    try {
      await expect(
        engine.ensureSealedRefreshStartupParityForTransactionSigning({
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
        }),
      ).resolves.toBeUndefined();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(String(warnings[0]?.[0] || '')).toContain(
      'transaction signing skipped retryable sealed-refresh capability fetch failure',
    );
    expect(warnings[0]?.[1]).toMatchObject({
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('transaction signing still fails closed on parity mismatches', async () => {
    const engine: any = Object.create(SigningEngine.prototype);
    engine.ensureSealedRefreshStartupParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Client/server mismatch for fields: keyVersion'),
        { code: 'sealed_refresh_parity_mismatch' },
      );
    };

    await expect(
      engine.ensureSealedRefreshStartupParityForTransactionSigning({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
      }),
    ).rejects.toThrow('Client/server mismatch');
  });
});
