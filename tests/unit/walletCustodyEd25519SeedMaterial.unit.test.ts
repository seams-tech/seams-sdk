import { expect, test } from '@playwright/test';
import {
  buildWalletCustodyEd25519MaterialRecordV1,
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
} from '../../packages/wallet/src/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';

/**
 * The wallet's Ed25519 continuity cache, as stored.
 *
 * One record per wallet rather than one per factor. The two rows this replaces
 * existed only because two factors wrapped them, and the record's binding is
 * where that shows: it names the key set and no credential.
 */

const TARGET = {
  profileId: 'profile-1',
  chainIdKey: 'near:testnet',
  accountAddress: 'alice.testnet',
} as const;

const SEALED = {
  ciphertextB64u: base64UrlEncode(new Uint8Array(89).fill(9)),
  nonceB64u: base64UrlEncode(new Uint8Array(12).fill(3)),
} as const;

function binding(
  overrides: Partial<WalletCustodyEd25519MaterialBindingV1> = {},
): WalletCustodyEd25519MaterialBindingV1 {
  return {
    kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    applicationBindingDigestB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
    registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(2)),
    participantIds: [1, 2],
    stateEpoch: '1',
    walletId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    signerSlot: 1,
    signingWorkerId: 'signing-worker-1',
    signingWorkerVerifyingShareB64u: base64UrlEncode(new Uint8Array(32).fill(4)),
    ...overrides,
  };
}

test('the record stores the ceremony ciphertext verbatim under its own algorithm', () => {
  /* The algorithm names the seed domain so a reader cannot mistake this row
     for one of the per-factor records and try a factor secret on it. */
  const record = buildWalletCustodyEd25519MaterialRecordV1({
    target: TARGET,
    binding: binding(),
    sealed: SEALED,
  });

  expect(record.keyKind).toBe(WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND);
  expect(record.payloadEnvelope.alg).toContain('wallet-custody-seed');
  expect(record.payloadEnvelope.ciphertext).toBe(SEALED.ciphertextB64u);
  expect(record.payloadEnvelope.nonce).toBe(SEALED.nonceB64u);
  expect(record.signerId).toBe('near-ed25519-key-1');
  expect(record.publicKey.startsWith('ed25519:')).toBe(true);
});

test('the binding names the key set and no credential', () => {
  /* The absence is the point. Naming the credential that happened to run the
     ceremony would reintroduce the coupling the seed-sealed cache removes,
     and a wallet unlocking under a later-enrolled factor would not match. */
  const record = buildWalletCustodyEd25519MaterialRecordV1({
    target: TARGET,
    binding: binding(),
    sealed: SEALED,
  });
  const stored = (record.payload as { binding: Record<string, unknown> }).binding;

  expect(Object.keys(stored)).not.toContain('rpId');
  expect(Object.keys(stored)).not.toContain('credentialIdB64u');
  // What a reader needs to rebuild the ceremony's seal binding.
  expect(stored.applicationBindingDigestB64u).toBeTruthy();
  expect(stored.registeredPublicKeyB64u).toBeTruthy();
  expect(stored.participantIds).toEqual([1, 2]);
  expect(stored.stateEpoch).toBe('1');
});

test('a binding missing any identity field is refused', () => {
  /* A row that stores but cannot be used is worse than one never written: the
     wallet looks cached and fails at signing time. */
  for (const field of [
    'walletId',
    'nearAccountId',
    'nearEd25519SigningKeyId',
    'signingWorkerId',
    'applicationBindingDigestB64u',
    'signingWorkerVerifyingShareB64u',
    'stateEpoch',
  ] as const) {
    expect(() =>
      buildWalletCustodyEd25519MaterialRecordV1({
        target: TARGET,
        binding: binding({ [field]: '  ' } as Partial<WalletCustodyEd25519MaterialBindingV1>),
        sealed: SEALED,
      }),
    ).toThrow(new RegExp(field));
  }
});

test('a registered public key of the wrong width is refused', () => {
  expect(() =>
    buildWalletCustodyEd25519MaterialRecordV1({
      target: TARGET,
      binding: binding({ registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(31)) }),
      sealed: SEALED,
    }),
  ).toThrow(/32-byte registered public key/);
});

test('a record with no ciphertext or nonce is refused', () => {
  // The ceremony is the only thing that can produce these; an empty one means
  // the run did not seal, and storing it would cache nothing openable.
  for (const sealed of [
    { ciphertextB64u: '', nonceB64u: SEALED.nonceB64u },
    { ciphertextB64u: SEALED.ciphertextB64u, nonceB64u: '' },
  ]) {
    expect(() =>
      buildWalletCustodyEd25519MaterialRecordV1({ target: TARGET, binding: binding(), sealed }),
    ).toThrow(/sealed ciphertext and nonce/);
  }
});

test('exactly two participants are required', () => {
  expect(() =>
    buildWalletCustodyEd25519MaterialRecordV1({
      target: TARGET,
      binding: binding({ participantIds: [1] as unknown as readonly [number, number] }),
      sealed: SEALED,
    }),
  ).toThrow(/exactly two participants/);
});
