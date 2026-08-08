import { expect, test } from '@playwright/test';
import { admitWalletRecoveryCredentialPromotion } from '../../packages/shared-ts/src/wallet-recovery/credentialPromotion';

/**
 * Promoting a replacement credential is all-or-nothing across the wallet.
 *
 * A mixed wallet recovers NEAR and EVM-family keys in one operation. Promoting
 * after only some verified leaves a wallet the owner believes is recovered
 * while part of it answers to a credential they no longer hold — and the gap
 * surfaces only the first time the missing key set is used.
 */

const NEAR = 'near_ed25519_v1';
const EVM = 'evm_family_ecdsa_v1';

test('a mixed wallet promotes only when every key set verified', () => {
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: [NEAR, EVM],
    outcomes: [
      { keySet: NEAR, kind: 'verified' },
      { keySet: EVM, kind: 'verified' },
    ],
  });

  expect(admission.kind).toBe('admitted');
  expect(admission.kind === 'admitted' && [...admission.verifiedKeySets].sort()).toEqual(
    [EVM, NEAR].sort(),
  );
});

test('a partial recovery never promotes, and names what is outstanding', () => {
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: [NEAR, EVM],
    outcomes: [
      { keySet: NEAR, kind: 'verified' },
      { keySet: EVM, kind: 'failed', reason: 'the relayer never activated' },
    ],
  });

  expect(admission.kind).toBe('refused');
  expect(admission.kind === 'refused' && admission.outstandingKeySets).toEqual([EVM]);
});

test('a key set with no outcome at all is outstanding', () => {
  // Silence is not success: a key set nothing reported on was not recovered.
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: [NEAR, EVM],
    outcomes: [{ keySet: NEAR, kind: 'verified' }],
  });

  expect(admission.kind).toBe('refused');
  expect(admission.kind === 'refused' && admission.outstandingKeySets).toEqual([EVM]);
});

test('a single-key-set wallet recovers when its one key set verifies', () => {
  // The manifest is the list of what must be reproduced, so a wallet with one
  // key set is fully recovered by one verification.
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: [NEAR],
    outcomes: [{ keySet: NEAR, kind: 'verified' }],
  });
  expect(admission.kind).toBe('admitted');
});

test('conflicting outcomes for one key set are treated as failure', () => {
  /* Two reports mean the caller cannot say which run produced the material.
     Promoting on the optimistic one is the mistake this gate exists for. */
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: [NEAR],
    outcomes: [
      { keySet: NEAR, kind: 'verified' },
      { keySet: NEAR, kind: 'failed', reason: 'public key continuity mismatch' },
    ],
  });

  expect(admission.kind).toBe('refused');
  expect(admission.kind === 'refused' && admission.outstandingKeySets).toEqual([NEAR]);
});

test('an empty manifest is refused rather than trivially satisfied', () => {
  // No required key sets means the caller did not load a manifest, not that
  // there is nothing to check — promoting here would promote on no proof.
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: [],
    outcomes: [{ keySet: NEAR, kind: 'verified' }],
  });

  expect(admission.kind).toBe('refused');
  expect(admission.kind === 'refused' && admission.reason).toContain('must name the key sets');
});

test('outcomes for key sets the wallet does not have cannot satisfy it', () => {
  const admission = admitWalletRecoveryCredentialPromotion({
    requiredKeySets: [NEAR],
    outcomes: [{ keySet: EVM, kind: 'verified' }],
  });

  expect(admission.kind).toBe('refused');
  expect(admission.kind === 'refused' && admission.outstandingKeySets).toEqual([NEAR]);
});
