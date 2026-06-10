import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import {
  secureRandomBase36,
  secureRandomBase64Url,
  secureRandomId,
} from '../../packages/shared-ts/src/utils/secureRandomId';

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

test.describe('shared secure random id helpers', () => {
  test('encodes the requested number of getRandomValues bytes', () => {
    const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const expected = new Uint8Array([1, 2, 3, 4]);
    setGlobalCrypto({
      getRandomValues: (bytes: Uint8Array) => {
        expect(bytes).toHaveLength(4);
        bytes.set(expected);
        return bytes;
      },
    });

    try {
      expect(secureRandomBase64Url(4, 'test IDs')).toBe(base64UrlEncode(expected));
      expect(secureRandomId('test', 4, 'test IDs')).toBe(`test-${base64UrlEncode(expected)}`);
    } finally {
      restoreGlobalCrypto(originalCrypto);
    }
  });

  test('fails closed without WebCrypto randomness', () => {
    const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    setGlobalCrypto({});

    try {
      expect(() => secureRandomBase64Url(4, 'test IDs')).toThrow(
        'WebCrypto getRandomValues is required for test IDs',
      );
    } finally {
      restoreGlobalCrypto(originalCrypto);
    }
  });

  test('generates base36 identifiers without Math.random', () => {
    const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    const originalMathRandom = Math.random;
    setGlobalCrypto({
      getRandomValues: (bytes: Uint8Array) => {
        for (let index = 0; index < bytes.length; index += 1) {
          bytes[index] = index + 10;
        }
        return bytes;
      },
    });
    Object.defineProperty(Math, 'random', {
      configurable: true,
      value: () => {
        throw new Error('Math.random must not be used');
      },
    });

    try {
      expect(secureRandomBase36(8, 'base36 test IDs')).toMatch(/^[0-9a-z]{8}$/);
    } finally {
      Object.defineProperty(Math, 'random', {
        configurable: true,
        value: originalMathRandom,
      });
      restoreGlobalCrypto(originalCrypto);
    }
  });
});
