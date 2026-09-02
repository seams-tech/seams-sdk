import { expect, test } from '@playwright/test';
import { rotateWalletRecoveryCodesV1 } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryRotation';
import {
  rawManifestKekWrap,
  rawWalletRecoveryEnvelopeSet,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * Rotating a wallet's recovery codes.
 *
 * Three failures here are silent, which is why each gets a test: entries that
 * move (recovery quietly stops working), a timestamp that does not advance
 * (the user stays marked as having saved codes that no longer work), and a
 * set that reaches the store with the wrong number of wraps (a wallet with
 * nine codes looks fine until someone counts).
 *
 * Built from the shared factories, which run the real boundary parser — an
 * inline literal here silently drifted from the lifecycle shape and made the
 * rotation look broken when the fixture was.
 */

const WALLET_ID = 'alice.testnet';
const DIGEST_PREFIX = 'A'.repeat(42);

/** Fresh wraps, distinct from the stored set's, as a real rotation produces. */
function rotatedWraps(count: number) {
  return Array.from({ length: count }, (_, index) =>
    rawManifestKekWrap({
      recoveryKeyId: `wallet-rkid-v1-${DIGEST_PREFIX}${'KLMNOPQRST'[index] ?? 'Z'}`,
    }),
  ) as never;
}

function replacement(count = 10) {
  const wraps = rotatedWraps(count) as Array<Record<string, unknown>>;
  return {
    walletId: WALLET_ID,
    manifestKekWraps: wraps.map((wrap) => ({
      recoveryKeyId: wrap.recoveryKeyId,
      nonceB64u: String(wrap.nonceB64u),
      ciphertextB64u: String(wrap.wrappedManifestKekB64u),
      aadHashB64u: String(wrap.aadHashB64u),
    })),
    entry: {
      nonceB64u: 'AQIDBAUGBwgJCgsM',
      wrappedCustodySecretB64u: 'BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2',
      aadHashB64u: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA',
    },
  };
}

function recoveryCodeLocators(count = 10) {
  return (replacement(count).manifestKekWraps as Array<{ recoveryKeyId: string }>).map(
    (wrap, index) => ({
      locatorB64u: `${String.fromCharCode(65 + index)}${'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA'.slice(
        1,
      )}`,
      walletId: WALLET_ID as never,
      recoveryKeyId: wrap.recoveryKeyId as never,
    }),
  );
}

function storeStub(options: {
  readonly writes: unknown[];
  readonly conflict?: boolean;
  readonly missing?: boolean;
}) {
  const record = rawWalletRecoveryEnvelopeSet({ issuedAtMs: 1_000, updatedAtMs: 1_000 });
  return {
    record,
    store: {
      readRecoveryEnvelopeSet: async () => (options.missing ? null : { record, storeVersion: '4' }),
      replaceRecoveryEnvelopeSetAndPreserveBackupAcknowledgement: async (input: unknown) => {
        options.writes.push(input);
        return options.conflict ? { kind: 'conflict' } : { kind: 'stored', storeVersion: '5' };
      },
    } as never,
  };
}

test('a rotation replaces the wraps and leaves the entries alone', async () => {
  const writes: unknown[] = [];
  const { record, store } = storeStub({ writes });
  const result = await rotateWalletRecoveryCodesV1({
    store,
    walletId: WALLET_ID as never,
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    expectedStoreVersion: '4',
    nowMs: 9_000,
  });

  expect(result.kind).toBe('rotated');
  const written = (writes[0] as { record: { entries: unknown[]; issuedAtMs: number } }).record;
  // The seed wraps are unchanged by a rotation. Rebuilding them would need the
  // seed the server does not have; dropping them would destroy recovery while
  // appearing to refresh it.
  expect(written.entries).toEqual(record.entries);
  expect(written.issuedAtMs).toBe(9_000);
});

test('a rotation that does not advance the clock is refused', async () => {
  const writes: unknown[] = [];
  const result = await rotateWalletRecoveryCodesV1({
    store: storeStub({ writes }).store,
    walletId: WALLET_ID as never,
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    expectedStoreVersion: '4',
    nowMs: 1_000,
  });

  // Otherwise the backup acknowledgement still covers the old issuance and the
  // user is never asked to save the codes that now work.
  expect(result.kind).toBe('rejected');
  expect(writes).toEqual([]);
});

test('a set with the wrong number of wraps never reaches the store', async () => {
  const writes: unknown[] = [];
  const result = await rotateWalletRecoveryCodesV1({
    store: storeStub({ writes }).store,
    walletId: WALLET_ID as never,
    replacement: replacement(9),
    recoveryCodeLocators: recoveryCodeLocators(9),
    expectedStoreVersion: '4',
    nowMs: 9_000,
  });

  expect(result.kind).toBe('rejected');
  // A wallet with nine codes looks fine until someone counts.
  expect(writes).toEqual([]);
});

test('the write is guarded against the version the read saw', async () => {
  const writes: unknown[] = [];
  await rotateWalletRecoveryCodesV1({
    store: storeStub({ writes }).store,
    walletId: WALLET_ID as never,
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    expectedStoreVersion: '4',
    nowMs: 9_000,
  });
  // A rotation and a spend both rewrite the wrap list; without this one could
  // land on the other and resurrect a consumed code.
  expect((writes[0] as { expectedRecoverySetVersion: string }).expectedRecoverySetVersion).toBe(
    '4',
  );
});

test('a losing rotation is a conflict, not a silent no-op', async () => {
  const result = await rotateWalletRecoveryCodesV1({
    store: storeStub({ writes: [], conflict: true }).store,
    walletId: WALLET_ID as never,
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    expectedStoreVersion: '4',
    nowMs: 9_000,
  });
  // Reporting success would tell the user their old codes are dead when a
  // spend landed in between and they are not.
  expect(result.kind).toBe('conflict');
});

test('a wallet with no recovery set cannot rotate', async () => {
  const result = await rotateWalletRecoveryCodesV1({
    store: storeStub({ writes: [], missing: true }).store,
    walletId: WALLET_ID as never,
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    expectedStoreVersion: '4',
    nowMs: 9_000,
  });
  expect(result.kind).toBe('no_recovery_set');
});
