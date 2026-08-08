import { expect, test } from '@playwright/test';
import { attemptWalletRecoveryWithCodeV1 } from '../../packages/sdk-server-ts/src/router/domains/passkeyCustody/walletRecoveryAttempt';
import { deriveWalletRecoveryKeyIdFromBytes } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodes';

/**
 * Spending a recovery code, end to end against a store stub.
 *
 * Three properties, each of which fails silently if it regresses:
 *
 * - a spent code and an unknown code answer identically, so the route is not
 *   an oracle for how many of a user's ten codes remain;
 * - the spend is written *before* the payload is returned, so a failed write
 *   cannot leave a handed-out code still spendable;
 * - the write is version-guarded, so two concurrent attempts cannot both
 *   commit and quietly restore each other's spent code.
 */

const WALLET_ID = 'alice.testnet';
const B64U_32 = 'A'.repeat(43);
const CODE = new Uint8Array(20).fill(7);
const OTHER_CODE = new Uint8Array(20).fill(9);

async function recoverySet(lifecycleState: 'active' | 'consumed' = 'active') {
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
            : { state: 'consumed', consumedAtMs: 1_000 },
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

function storeStub(record: unknown, options: { writes: unknown[]; conflict?: boolean }) {
  return {
    readRecoveryEnvelopeSet: async () => (record ? { record, storeVersion: '4' } : null),
    writeRecoveryEnvelopeSet: async (input: unknown) => {
      options.writes.push(input);
      return options.conflict ? { kind: 'conflict' } : { kind: 'stored', storeVersion: '5' };
    },
  } as never;
}

test('a valid code returns the wrapped payload and records the spend first', async () => {
  const writes: unknown[] = [];
  const result = await attemptWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet(), { writes }),
    walletId: WALLET_ID as never,
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1',
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });

  expect(result.kind).toBe('committed');
  // The spend was written, and with the version the read observed.
  expect(writes).toHaveLength(1);
  expect((writes[0] as { expectedStoreVersion: string }).expectedStoreVersion).toBe('4');
});

test('an unknown code and a spent code are indistinguishable', async () => {
  const unknown = await attemptWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet(), { writes: [] }),
    walletId: WALLET_ID as never,
    recoveryCodeBytes: OTHER_CODE,
    reservationId: 'reservation-1',
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });
  const spent = await attemptWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet('consumed'), { writes: [] }),
    walletId: WALLET_ID as never,
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1',
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });

  // Byte-identical: anything else counts how many codes remain.
  expect(unknown).toEqual(spent);
});

test('a wallet with no recovery set answers like a wrong code', async () => {
  const missing = await attemptWalletRecoveryWithCodeV1({
    store: storeStub(null, { writes: [] }),
    walletId: WALLET_ID as never,
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1',
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });
  expect(missing.kind).toBe('refused');
});

test('a losing concurrent attempt is a conflict, never a silent success', async () => {
  const writes: unknown[] = [];
  const result = await attemptWalletRecoveryWithCodeV1({
    store: storeStub(await recoverySet(), { writes, conflict: true }),
    walletId: WALLET_ID as never,
    recoveryCodeBytes: CODE,
    reservationId: 'reservation-1',
    nowMs: 2_000,
    reservationTtlMs: 60_000,
  });
  // No payload: the caller must not hold a recovery payload for a spend that
  // did not land.
  expect(result.kind).toBe('conflict');
});
