import { expect, test } from '@playwright/test';
import { parsePostgresRow } from '../../packages/sdk-server-ts/src/storage/postgres';

test.describe('postgres read helpers', () => {
  test('returns typed missing, malformed, and current row results', () => {
    expect(
      parsePostgresRow({
        row: undefined,
        parser: () => ({ ok: true }),
      }),
    ).toEqual({ kind: 'missing' });

    expect(
      parsePostgresRow({
        row: 123,
        parser: () => ({ ok: true }),
      }),
    ).toEqual({ kind: 'malformed' });

    expect(
      parsePostgresRow({
        row: { value: '' },
        parser: () => null,
      }),
    ).toEqual({ kind: 'malformed' });

    expect(
      parsePostgresRow({
        row: { value: 'current' },
        parser: (row) => {
          const value = String(row.value || '').trim();
          return value ? { value } : null;
        },
      }),
    ).toEqual({
      kind: 'current',
      value: {
        value: 'current',
      },
    });
  });
});
