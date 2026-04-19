import { expect, test } from '@playwright/test';
import {
  normalizePositiveInteger,
  requireTrimmedString,
  toOptionalTrimmedNonEmptyString,
} from '@shared/utils/validation';

test.describe('shared validation helpers', () => {
  test('requires trimmed non-empty strings with stable error text', () => {
    expect(requireTrimmedString('  value  ', 'field')).toBe('value');
    expect(() => requireTrimmedString('   ', 'field')).toThrow('field is required');
    expect(() =>
      requireTrimmedString(undefined, 'field', 'must be a non-empty string'),
    ).toThrow('field must be a non-empty string');
  });

  test('normalizes optional non-empty strings without accepting non-strings', () => {
    expect(toOptionalTrimmedNonEmptyString('  value  ')).toBe('value');
    expect(toOptionalTrimmedNonEmptyString('   ')).toBeUndefined();
    expect(toOptionalTrimmedNonEmptyString(123)).toBeUndefined();
  });

  test('normalizes positive integers and rejects invalid values', () => {
    expect(normalizePositiveInteger('42.9')).toBe(42);
    expect(normalizePositiveInteger(1)).toBe(1);
    expect(normalizePositiveInteger(0)).toBeNull();
    expect(normalizePositiveInteger(-1)).toBeNull();
    expect(normalizePositiveInteger(Number.POSITIVE_INFINITY)).toBeNull();
  });
});
