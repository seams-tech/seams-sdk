import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../shared/src/utils/encoders';
import { secureRandomIdFragment } from '../../server/src/core/ThresholdService/secureRandomId';

function restoreGlobalCrypto(original: PropertyDescriptor | undefined): void {
  if (original) {
    Object.defineProperty(globalThis, 'crypto', original);
    return;
  }
  delete (globalThis as { crypto?: unknown }).crypto;
}

function setGlobalCrypto(value: unknown): void {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value,
  });
}

test.describe('threshold service secure random ids', () => {
  test('uses 32 bytes from getRandomValues even when randomUUID exists', () => {
    const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const expected = new Uint8Array(32);
    setGlobalCrypto({
      randomUUID: () => {
        throw new Error('randomUUID must not be used for threshold capability IDs');
      },
      getRandomValues: (bytes: Uint8Array) => {
        expect(bytes).toHaveLength(32);
        for (let i = 0; i < bytes.length; i += 1) {
          bytes[i] = i + 1;
          expected[i] = i + 1;
        }
        return bytes;
      },
    });

    try {
      expect(secureRandomIdFragment()).toBe(base64UrlEncode(expected));
    } finally {
      restoreGlobalCrypto(originalCrypto);
    }
  });

  test('uses getRandomValues without Math.random', () => {
    const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const originalMathRandom = Math.random;
    const expected = new Uint8Array(32);
    setGlobalCrypto({
      getRandomValues: (bytes: Uint8Array) => {
        expect(bytes).toHaveLength(32);
        for (let i = 0; i < bytes.length; i += 1) {
          bytes[i] = i + 1;
          expected[i] = i + 1;
        }
        return bytes;
      },
    });
    Object.defineProperty(Math, 'random', {
      configurable: true,
      value: () => {
        throw new Error('Math.random must not be used for threshold session IDs');
      },
    });

    try {
      expect(secureRandomIdFragment()).toBe(base64UrlEncode(expected));
    } finally {
      Object.defineProperty(Math, 'random', {
        configurable: true,
        value: originalMathRandom,
      });
      restoreGlobalCrypto(originalCrypto);
    }
  });

  test('fails closed when WebCrypto randomness is unavailable', () => {
    const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    setGlobalCrypto({});

    try {
      expect(() => secureRandomIdFragment()).toThrow(
        'WebCrypto getRandomValues is required for threshold session IDs',
      );
    } finally {
      restoreGlobalCrypto(originalCrypto);
    }
  });
});
