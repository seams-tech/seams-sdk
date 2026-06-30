import { expect, test } from '@playwright/test';
import { SigningOperationIntent } from '@/core/signingEngine/session/operationState/types';
import {
  ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap,
  ensureSealedRefreshStartupParityForTransactionSigning,
} from '@/core/signingEngine/session/warmCapabilities/sealedRefreshParity';

const TEMPO_CHAIN_TARGET = {
  kind: 'tempo' as const,
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};

const EVM_CHAIN_TARGET = {
  kind: 'evm' as const,
  namespace: 'eip155' as const,
  chainId: 11155111,
  networkSlug: 'sepolia',
};

test.describe('threshold ECDSA key-enrollment bootstrap parity gate', () => {
  test('registration-source bootstrap soft-fails startup parity errors', async () => {
    const ensureParity = async () => {
      throw new Error('[sealed-refresh-parity] Well-known endpoint returned HTTP 502');
    };

    const originalWarn = console.warn;
    const warnings: unknown[][] = [];
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };

    try {
      await expect(
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(ensureParity, {
          kind: 'key_enrollment_bootstrap_parity',
          walletId: 'alice.testnet',
          chainTarget: TEMPO_CHAIN_TARGET,
        }),
      ).resolves.toBeUndefined();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(String(warnings[0]?.[0] || '')).toContain(
      'key enrollment bootstrap skipped sealed-refresh startup parity enforcement',
    );
    expect(warnings[0]?.[1]).toMatchObject({
      walletId: 'alice.testnet',
      chainTarget: 'tempo:42431',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('default bootstrap soft-fails retryable well-known fetch errors', async () => {
    const ensureParity = async () => {
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
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(ensureParity, {
          kind: 'default_bootstrap_parity',
          walletId: 'alice.testnet',
          chainTarget: EVM_CHAIN_TARGET,
        }),
      ).resolves.toBeUndefined();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(String(warnings[0]?.[0] || '')).toContain(
      'default bootstrap skipped retryable sealed-refresh capability fetch failure',
    );
    expect(warnings[0]?.[1]).toMatchObject({
      walletId: 'alice.testnet',
      chainTarget: 'evm:eip155:11155111',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('default bootstrap still fails closed on parity mismatches', async () => {
    const ensureParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Client/server mismatch for fields: keyVersion'),
        { code: 'sealed_refresh_parity_mismatch' },
      );
    };

    await expect(
      ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(ensureParity, {
        kind: 'default_bootstrap_parity',
        walletId: 'alice.testnet',
        chainTarget: EVM_CHAIN_TARGET,
      }),
    ).rejects.toThrow('Client/server mismatch');
  });

  test('transaction-sign bootstrap soft-fails retryable well-known fetch errors', async () => {
    const ensureParity = async () => {
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
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(ensureParity, {
          kind: 'transaction_bootstrap_parity',
          walletId: 'alice.testnet',
          chainTarget: EVM_CHAIN_TARGET,
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
      walletId: 'alice.testnet',
      chainTarget: 'evm:eip155:11155111',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('Email OTP bootstrap soft-fails retryable well-known fetch errors', async () => {
    const ensureParity = async () => {
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
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(ensureParity, {
          kind: 'email_otp_bootstrap_parity',
          walletId: 'alice.testnet',
          chainTarget: EVM_CHAIN_TARGET,
          authMethod: 'email_otp',
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
      walletId: 'alice.testnet',
      chainTarget: 'evm:eip155:11155111',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('Email OTP bootstrap still fails closed on parity mismatches', async () => {
    const ensureParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Client/server mismatch for fields: keyVersion'),
        { code: 'sealed_refresh_parity_mismatch' },
      );
    };

    await expect(
      ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(ensureParity, {
        kind: 'email_otp_bootstrap_parity',
        walletId: 'alice.testnet',
        chainTarget: EVM_CHAIN_TARGET,
        authMethod: 'email_otp',
      }),
    ).rejects.toThrow('Client/server mismatch');
  });

  test('transaction signing soft-fails retryable well-known fetch errors', async () => {
    const ensureParity = async () => {
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
        ensureSealedRefreshStartupParityForTransactionSigning(ensureParity, {
          walletId: 'alice.testnet',
          chainTarget: TEMPO_CHAIN_TARGET,
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
      walletId: 'alice.testnet',
      chainTarget: 'tempo:42431',
      error: '[sealed-refresh-parity] Well-known endpoint returned HTTP 502',
    });
  });

  test('transaction signing still fails closed on parity mismatches', async () => {
    const ensureParity = async () => {
      throw Object.assign(
        new Error('[sealed-refresh-parity] Client/server mismatch for fields: keyVersion'),
        { code: 'sealed_refresh_parity_mismatch' },
      );
    };

    await expect(
      ensureSealedRefreshStartupParityForTransactionSigning(ensureParity, {
        walletId: 'alice.testnet',
        chainTarget: EVM_CHAIN_TARGET,
      }),
    ).rejects.toThrow('Client/server mismatch');
  });
});
