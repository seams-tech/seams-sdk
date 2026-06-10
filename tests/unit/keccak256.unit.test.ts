import { test, expect } from '@playwright/test';
import { keccak256Bytes } from '../../packages/shared-ts/src/utils/keccak';

function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hex(value: Uint8Array): string {
  return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function selector(signature: string): string {
  return hex(keccak256Bytes(utf8Bytes(signature)).slice(0, 4));
}

test.describe('keccak256Bytes', () => {
  test('matches canonical keccak-256 vectors', () => {
    expect(hex(keccak256Bytes(new Uint8Array()))).toBe(
      '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
    );
    expect(hex(keccak256Bytes(utf8Bytes('abc')))).toBe(
      '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
    );
    expect(hex(keccak256Bytes(utf8Bytes('The quick brown fox jumps over the lazy dog')))).toBe(
      '0x4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15',
    );
  });

  test('derives known EVM function selectors', () => {
    expect(selector('transfer(address,uint256)')).toBe('0xa9059cbb');
    expect(selector('approve(address,uint256)')).toBe('0x095ea7b3');
    expect(selector('balanceOf(address)')).toBe('0x70a08231');
  });
});
