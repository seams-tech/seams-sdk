import { expect, test } from '@playwright/test';
import { prepareWalletRecoveryWithCodeV1 } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryAttempt';
import { deriveWalletRecoveryKeyIdFromBytes } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodes';

/**
 * Reserving a recovery code, end to end against a store stub.
 *
 * Three properties, each of which fails silently if it regresses:
 *
 * - a spent code receives the terminal consumed result;
 * - the reservation is written before the payload is returned;
 * - the write is version-guarded, so two concurrent attempts cannot both
 *   commit and quietly restore each other's spent code.
 */

const WALLET_ID = 'alice.testnet';
const B64U_32 = 'A'.repeat(43);
const CODE = new Uint8Array(20).fill(7);
const OTHER_CODE = new Uint8Array(20).fill(9);

async function recoverySet(lifecycleState: 'active' | 'reserved' | 'consumed' = 'active') {
  const recoveryKeyId = await deriveWalletRecoveryKeyIdFromBytes({
    codeBytes: CODE,
    walletId: WALLET_ID,
  });
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: WALLET_ID,
    manifestKekWraps: [
      {
        recoveryKeyId,
        nonceB64u: 'B'.repeat(16),
        wrappedManifestKekB64u: 'C'.repeat(64),
        aadHashB64u: B64U_32,
        lifecycle:
          lifecycleState === 'active'
            ? { state: 'active' }
            : lifecycleState === 'reserved'
              ? {
                  state: 'reserved',
                  issuedAtMs: 1,
                  reservationId: 'prior-recovery',
                  reservedAtMs: 1_000,
                  reservationExpiresAtMs: 60_000,
                }
              : {
                  state: 'consumed',
                  issuedAtMs: 1,
                  reservationId: 'prior-recovery',
                  consumedAtMs: 1_000,
                },
      },
    ],
    entries: [
      {
        custodySecretKind: 'wallet_custody_seed_v1',
        nonceB64u: 'D'.repeat(16),
        wrappedCustodySecretB64u: 'E'.repeat(64),
        aadHashB64u: B64U_32,
      },
    ],
    issuedAtMs: 1,
    updatedAtMs: 1,
  };
}

async function expectedRecoveryKeyId() {
  return await deriveWalletRecoveryKeyIdFromBytes({
    codeBytes: CODE,
    walletId: WALLET_ID,
  });
}

function storeStub(record: unknown, options: { writes: unknown[]; conflict?: boolean }) {
  return {
    readRecoveryEnvelopeSet: async () => (record ? { record, storeVersion: '4' } : null),
    writeRecoveryEnvelopeSet: async (input: unknown) => {
      options.writes.push(input);
      return options.conflict ? { kind: 'conflict' } : { kind: 'stored', storeVersion: '5' };
    },
  } as never;
}

test('a valid code returns the wrapped payload and records only a reservation', async () => {
  const writes: unknown[] = [];
  const result = await prepareWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet(), { writes }),
    walletId: WALLET_ID as never,
    expectedRecoveryKeyId: await expectedRecoveryKeyId(),
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1' as never,
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });

  expect(result.kind).toBe('prepared');
  expect(writes).toHaveLength(1);
  expect((writes[0] as { expectedStoreVersion: string }).expectedStoreVersion).toBe('4');
  const written = writes[0] as {
    record: { manifestKekWraps: readonly [{ lifecycle: { state: string } }] };
  };
  expect(written.record.manifestKekWraps[0].lifecycle.state).toBe('reserved');
});

test('a spent code is distinguished from an unknown code', async () => {
  const unknown = await prepareWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet(), { writes: [] }),
    walletId: WALLET_ID as never,
    expectedRecoveryKeyId: await expectedRecoveryKeyId(),
    recoveryCodeBytes: OTHER_CODE,
    reservationId: 'reservation-1' as never,
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });
  const spent = await prepareWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet('consumed'), { writes: [] }),
    walletId: WALLET_ID as never,
    expectedRecoveryKeyId: await expectedRecoveryKeyId(),
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1' as never,
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });

  expect(unknown).toEqual({ kind: 'refused', reason: 'that recovery code cannot be used' });
  expect(spent).toEqual({ kind: 'consumed' });
});

test('a code held by another recovery is reported as already used', async () => {
  const held = await prepareWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet('reserved'), { writes: [] }),
    walletId: WALLET_ID as never,
    expectedRecoveryKeyId: await expectedRecoveryKeyId(),
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-2' as never,
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });

  expect(held).toEqual({ kind: 'reserved' });
});

test('a wallet with no recovery set answers like a wrong code', async () => {
  const missing = await prepareWalletRecoveryWithCodeV1({
    store: storeStub(null, { writes: [] }),
    walletId: WALLET_ID as never,
    expectedRecoveryKeyId: await expectedRecoveryKeyId(),
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1' as never,
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });
  expect(missing.kind).toBe('refused');
});

test('a losing concurrent attempt is a conflict, never a silent success', async () => {
  const writes: unknown[] = [];
  const result = await prepareWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet(), { writes, conflict: true }),
    walletId: WALLET_ID as never,
    expectedRecoveryKeyId: await expectedRecoveryKeyId(),
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1' as never,
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });
  // No payload: the caller must not hold a recovery payload for a spend that
  // did not land.
  expect(result.kind).toBe('conflict');
});
