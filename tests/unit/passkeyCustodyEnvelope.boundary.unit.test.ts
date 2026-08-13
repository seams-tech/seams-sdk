import { expect, test } from '@playwright/test';
import {
  buildPasskeyCustodyKekDerivationContext,
  parsePasskeyCustodyEnvelopeRecord,
  parsePasskeyCustodySecretBinding,
} from '@shared/passkey-custody';
import { parseWalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import type { WalletId } from '@shared/utils/domainIds';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  DIGEST_B64U,
  EVM_LANE_ID,
  EVM_WALLET_KEY_ID,
  NONCE_12_B64U,
  OTHER_WALLET_ID,
  RECOVERY_KEY_ID,
  SECP256K1_PUBLIC_KEY_B64U,
  THRESHOLD_ECDSA_SESSION_ID,
  WALLET_ID,
  rawEcdsaLaneHolderShareBinding,
  rawEd25519LaneHolderShareBinding,
  rawEmailOtpFactor,
  rawManifestKekWrap,
  rawManifestKekWrapSet,
  rawPasskeyCustodyEnvelope,
  rawPasskeyFactor,
  rawWalletCustodySeedBinding,
  rawWalletRecoveryEnvelopeEntry,
  rawWalletRecoveryEnvelopeSet,
} from './helpers/passkeyCustodyEnvelope.fixtures';

test('every custody-secret branch parses into its exact kind', () => {
  expect(parsePasskeyCustodySecretBinding(rawWalletCustodySeedBinding())).toMatchObject({
    kind: 'wallet_custody_seed_v1',
    derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
  });
  expect(parsePasskeyCustodySecretBinding(rawEd25519LaneHolderShareBinding())).toMatchObject({
    kind: 'ed25519_lane_holder_share_v1',
  });
  expect(parsePasskeyCustodySecretBinding(rawEcdsaLaneHolderShareBinding())).toMatchObject({
    kind: 'ecdsa_lane_holder_share_v1',
    thresholdSessionId: THRESHOLD_ECDSA_SESSION_ID,
  });
});

test('the wallet seed is wallet-scoped and rejects lane identity', () => {
  // Owner custody covers every key; a lane on the seed would imply otherwise.
  expect(() =>
    parsePasskeyCustodySecretBinding(rawWalletCustodySeedBinding({ laneId: EVM_LANE_ID })),
  ).toThrow(/laneId is not part of/);
  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawWalletCustodySeedBinding({ derivationScheme: 'wallet_seed_chained_v0' }),
    ),
  ).toThrow(/derivationScheme must be wallet_seed_parallel_hkdf_sha256_v1/);
});

test('the retired per-curve owner root kinds no longer parse', () => {
  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawWalletCustodySeedBinding({ kind: 'ed25519_yao_client_root_v1' }),
    ),
  ).toThrow(/must be a known passkey custody secret kind/);
});

test('cross-branch fields are rejected instead of dropped', () => {
  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawEcdsaLaneHolderShareBinding({ keyManifestDigestB64u: DIGEST_B64U }),
    ),
  ).toThrow(/keyManifestDigestB64u is not part of/);

  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawEcdsaLaneHolderShareBinding({ clientRootPublicKey33B64u: SECP256K1_PUBLIC_KEY_B64U }),
    ),
  ).toThrow(/clientRootPublicKey33B64u is not part of/);

  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawEd25519LaneHolderShareBinding({ thresholdSessionId: THRESHOLD_ECDSA_SESSION_ID }),
    ),
  ).toThrow(/thresholdSessionId is not part of/);
});

test('an ECDSA holder share without its threshold session fails', () => {
  const { thresholdSessionId: _omitted, ...withoutSession } = rawEcdsaLaneHolderShareBinding();
  expect(() => parsePasskeyCustodySecretBinding(withoutSession)).toThrow(/thresholdSessionId/);
});

test('plaintext custody material is reported as a leak, not a schema mismatch', () => {
  const leakingFields = [
    { passkeyPrfFirstB64u: 'prf' },
    { passkeyKekB64u: 'kek' },
    { clientRootB64u: 'root' },
    { holderShareB64u: 'share' },
    { recoveryCodePlaintext: 'AAAA-BBBB' },
    { root_seed_b64u: 'seed' },
  ];
  for (const field of leakingFields) {
    expect(() => parsePasskeyCustodySecretBinding(rawWalletCustodySeedBinding(field))).toThrow(
      /must never carry plaintext custody material/,
    );
  }
});

test('public identities must decode to their curve', () => {
  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawEd25519LaneHolderShareBinding({ registeredPublicKeyB64u: SECP256K1_PUBLIC_KEY_B64U }),
    ),
  ).toThrow(/32-byte Ed25519 public key/);

  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawWalletCustodySeedBinding({ clientRootPublicKey33B64u: DIGEST_B64U }),
    ),
  ).toThrow(/clientRootPublicKey33B64u is not part of/);
});

test('an envelope parses and yields a branch-specific KEK context', () => {
  const envelope = parsePasskeyCustodyEnvelopeRecord(rawPasskeyCustodyEnvelope());
  expect(envelope.lifecycle).toEqual({ state: 'active', activatedAtMs: 1_000 });

  expect(buildPasskeyCustodyKekDerivationContext(envelope)).toEqual({
    kind: 'wallet_custody_kek_derivation_context_v2',
    walletId: envelope.walletId,
    envelopeId: envelope.envelopeId,
    factor: envelope.factor,
    purpose: 'wallet_custody_seed_v1',
    kekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
  });

  const ecdsaEnvelope = parsePasskeyCustodyEnvelopeRecord(
    rawPasskeyCustodyEnvelope({ binding: rawEcdsaLaneHolderShareBinding() }),
  );
  expect(buildPasskeyCustodyKekDerivationContext(ecdsaEnvelope).purpose).toBe(
    'ecdsa_lane_holder_share_v1',
  );

  // The same seed under an Email OTP factor derives a different KEK context,
  // so interchangeable factors never share a key-encryption key.
  const otpEnvelope = parsePasskeyCustodyEnvelopeRecord(
    rawPasskeyCustodyEnvelope({ factor: rawEmailOtpFactor() }),
  );
  const otpContext = buildPasskeyCustodyKekDerivationContext(otpEnvelope);
  expect(otpContext.kekVersion).toBe('email_otp_factor_kek_hkdf_sha256_v1');
  expect(otpContext.factor).not.toEqual(envelope.factor);
  expect(otpContext.purpose).toBe('wallet_custody_seed_v1');
});

test('factor identity is branch-specific and cannot be mixed', () => {
  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ factor: rawEmailOtpFactor({ credentialIdB64u: 'Y3JlZA' }) }),
    ),
  ).toThrow(/credentialIdB64u is not part of/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ factor: rawPasskeyFactor({ enrollmentId: 'enrollment-1' }) }),
    ),
  ).toThrow(/enrollmentId is not part of/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({
        factor: rawPasskeyFactor({ kekVersion: 'email_otp_factor_kek_hkdf_sha256_v1' }),
      }),
    ),
  ).toThrow(/kekVersion must be passkey_prf_kek_hkdf_sha256_v1/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(rawPasskeyCustodyEnvelope({ factor: { kind: 'sms' } })),
  ).toThrow(/kind must be passkey or email_otp/);
});

test('envelopes reject authorization identity and unknown versions', () => {
  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ authorizationGrantRef: 'grant-1' }),
    ),
  ).toThrow(/authorizationGrantRef is not part of/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ mpcMaterialActivationRef: 'activation-1' }),
    ),
  ).toThrow(/mpcMaterialActivationRef is not part of/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ envelopeVersion: 'passkey_custody_envelope_v1' }),
    ),
  ).toThrow(/envelopeVersion must be wallet_custody_envelope_v2/);
});

test('envelope lifecycle states cannot overlap', () => {
  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({
        lifecycle: { state: 'active', activatedAtMs: 1_000, revokedAtMs: 2_000 },
      }),
    ),
  ).toThrow(/cannot be active and carry a retired or revoked timestamp/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({
        lifecycle: { state: 'revoked', activatedAtMs: 2_000, revokedAtMs: 1_000 },
      }),
    ),
  ).toThrow(/revokedAtMs cannot precede activation/);
});

test('a browser cache row must carry an exact revision and digests', () => {
  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(rawPasskeyCustodyEnvelope({ envelopeRevision: 0 })),
  ).toThrow(/envelopeRevision must be a positive integer revision/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ ciphertextDigestB64u: 'not-a-digest' }),
    ),
  ).toThrow(/ciphertextDigestB64u/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(rawPasskeyCustodyEnvelope({ nonceB64u: DIGEST_B64U })),
  ).toThrow(/12-byte ChaCha20Poly1305 nonce/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ sealedCustodySecretB64u: NONCE_12_B64U }),
    ),
  ).toThrow(/sealed ciphertext with an authentication tag/);
});

test('a recovery envelope set carries exactly the owner seed', () => {
  const expectedWalletId = WALLET_ID as WalletId;

  const parsed = parseWalletRecoveryEnvelopeSetRecord(rawWalletRecoveryEnvelopeSet(), {
    expectedWalletId,
  });
  expect(parsed.entries).toHaveLength(1);
  expect(parsed.entries[0].custodySecretKind).toBe('wallet_custody_seed_v1');

  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({ walletId: OTHER_WALLET_ID }),
      { expectedWalletId },
    ),
  ).toThrow(/outside the authenticated wallet/);

  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(rawWalletRecoveryEnvelopeSet({ entries: [] }), {
      expectedWalletId,
    }),
  ).toThrow(/must cover at least one wallet key/);

  // Two entries means rival seeds claim the same wallet.
  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        entries: [rawWalletRecoveryEnvelopeEntry(), rawWalletRecoveryEnvelopeEntry()],
      }),
      { expectedWalletId },
    ),
  ).toThrow(/exactly one wallet_custody_seed_v1 entry, found 2/);
});

test('lane holder shares are not recoverable', () => {
  // A linked device's share is sealed under that device's own factor, so it
  // survives owner recovery untouched. Accepting one here would instead let an
  // owner recovery code reconstruct that device's material.
  for (const kind of ['ed25519_lane_holder_share_v1', 'ecdsa_lane_holder_share_v1'] as const) {
    expect(() =>
      parseWalletRecoveryEnvelopeSetRecord(
        rawWalletRecoveryEnvelopeSet({ entries: [rawWalletRecoveryEnvelopeEntry(kind)] }),
        { expectedWalletId: WALLET_ID as WalletId },
      ),
    ).toThrow(/reprovisioned, not recovered/);
  }
});

test('a recovery entry cannot carry plaintext custody material', () => {
  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        entries: [
          rawWalletRecoveryEnvelopeEntry('wallet_custody_seed_v1', {
            custodySecretPlaintextB64u: CIPHERTEXT_B64U,
          }),
        ],
      }),
      { expectedWalletId: WALLET_ID as WalletId },
    ),
  ).toThrow(/must never carry plaintext custody material/);

  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        entries: [
          rawWalletRecoveryEnvelopeEntry('wallet_custody_seed_v1', {
            custodySecretKind: 'holder_share_v1',
          }),
        ],
      }),
      { expectedWalletId: WALLET_ID as WalletId },
    ),
  ).toThrow(/must be wallet_custody_seed_v1/);
});

test('a recovery set requires openable manifest-KEK wraps with unique code ids', () => {
  const expectedWalletId = WALLET_ID as WalletId;

  /* Exactly ten, not one-to-ten. Establishment issues ten and the durable
     invariant keeps ten — a consumed or revoked code keeps its wrap and
     changes its lifecycle state. So a short set is one that lost rows, and
     accepting it would let a wallet look recoverable while holding fewer
     codes than its owner wrote down. */
  for (const count of [0, 1, 9, 11]) {
    expect(() =>
      parseWalletRecoveryEnvelopeSetRecord(
        rawWalletRecoveryEnvelopeSet({
          manifestKekWraps: Array.from({ length: count }, (_, index) =>
            rawManifestKekWrap({
              recoveryKeyId: `${RECOVERY_KEY_ID.slice(0, -2)}${String(10 + index)}`,
            }),
          ),
        }),
        { expectedWalletId },
      ),
    ).toThrow(/must carry exactly 10 recovery-code wraps/);
  }

  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        manifestKekWraps: Array.from({ length: 10 }, () => rawManifestKekWrap()),
      }),
      { expectedWalletId },
    ),
  ).toThrow(/duplicate recoveryKeyId/);

  // A full set with one poisoned wrap, so the plaintext check is what rejects
  // it rather than the count check standing in front.
  const poisoned = rawManifestKekWrapSet();
  poisoned[3] = { ...poisoned[3], manifestKekPlaintextB64u: 'kek' };
  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({ manifestKekWraps: poisoned }),
      { expectedWalletId },
    ),
  ).toThrow(/must never carry plaintext custody material/);
});

test('a consumed code wrap keeps the set parseable for the remaining codes', () => {
  /* A consumed code keeps its row and changes its lifecycle state — that is
     precisely why the set is exactly ten rather than "up to ten". Dropping the
     row would shrink the set and make a used code indistinguishable from one
     that was never issued. */
  const expectedWalletId = WALLET_ID as WalletId;
  const wraps = rawManifestKekWrapSet();
  wraps[0] = {
    ...wraps[0],
    lifecycle: {
      state: 'consumed',
      issuedAtMs: 1_000,
      reservationId: 'recovery-operation-1',
      consumedAtMs: 2_000,
    },
  };

  const parsed = parseWalletRecoveryEnvelopeSetRecord(
    rawWalletRecoveryEnvelopeSet({ manifestKekWraps: wraps }),
    { expectedWalletId },
  );
  expect(parsed.manifestKekWraps).toHaveLength(10);
  expect(parsed.manifestKekWraps[0].lifecycle.state).toBe('consumed');
  expect(parsed.manifestKekWraps[1].lifecycle.state).toBe('active');
});
