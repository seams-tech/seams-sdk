import { expect, test } from '@playwright/test';
import {
  buildPasskeyCustodyKekDerivationContext,
  parsePasskeyCustodyEnvelopeRecord,
  parsePasskeyCustodySecretBinding,
} from '@shared/passkey-custody';
import { parseWalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletKeyId } from '@shared/signing-lanes';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  DIGEST_B64U,
  ED25519_WALLET_KEY_ID,
  EVM_FAMILY_SIGNING_KEY_SLOT_ID,
  EVM_LANE_ID,
  EVM_WALLET_KEY_ID,
  NONCE_12_B64U,
  OTHER_WALLET_ID,
  SECP256K1_PUBLIC_KEY_B64U,
  THRESHOLD_ECDSA_SESSION_ID,
  WALLET_ID,
  rawEcdsaClientRootShareBinding,
  rawEcdsaLaneHolderShareBinding,
  rawEd25519LaneHolderShareBinding,
  rawEd25519YaoClientRootBinding,
  rawPasskeyCustodyEnvelope,
  rawWalletRecoveryEnvelopeEntry,
  rawWalletRecoveryEnvelopeSet,
} from './helpers/passkeyCustodyEnvelope.fixtures';

test('every custody-secret branch parses into its exact kind', () => {
  expect(parsePasskeyCustodySecretBinding(rawEd25519YaoClientRootBinding())).toMatchObject({
    kind: 'ed25519_yao_client_root_v1',
    keyCreationSignerSlot: 1,
    stableContextDigestB64u: DIGEST_B64U,
  });
  expect(parsePasskeyCustodySecretBinding(rawEd25519LaneHolderShareBinding())).toMatchObject({
    kind: 'ed25519_lane_holder_share_v1',
  });
  expect(parsePasskeyCustodySecretBinding(rawEcdsaClientRootShareBinding())).toMatchObject({
    kind: 'ecdsa_client_root_share_v1',
    clientRootPublicKey33B64u: SECP256K1_PUBLIC_KEY_B64U,
  });
  expect(parsePasskeyCustodySecretBinding(rawEcdsaLaneHolderShareBinding())).toMatchObject({
    kind: 'ecdsa_lane_holder_share_v1',
    thresholdSessionId: THRESHOLD_ECDSA_SESSION_ID,
  });
});

test('cross-curve fields are rejected instead of dropped', () => {
  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawEd25519YaoClientRootBinding({
        evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
      }),
    ),
  ).toThrow(/evmFamilySigningKeySlotId is not part of/);

  expect(() =>
    parsePasskeyCustodySecretBinding(rawEcdsaLaneHolderShareBinding({ keyCreationSignerSlot: 1 })),
  ).toThrow(/keyCreationSignerSlot is not part of/);

  expect(() =>
    parsePasskeyCustodySecretBinding(
      rawEcdsaLaneHolderShareBinding({ clientRootPublicKey33B64u: SECP256K1_PUBLIC_KEY_B64U }),
    ),
  ).toThrow(/clientRootPublicKey33B64u is not part of/);
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
    expect(() => parsePasskeyCustodySecretBinding(rawEd25519YaoClientRootBinding(field))).toThrow(
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
      rawEcdsaClientRootShareBinding({ clientRootPublicKey33B64u: DIGEST_B64U }),
    ),
  ).toThrow(/33-byte compressed secp256k1 point/);
});

test('an envelope parses and yields a branch-specific KEK context', () => {
  const envelope = parsePasskeyCustodyEnvelopeRecord(rawPasskeyCustodyEnvelope());
  expect(envelope.lifecycle).toEqual({ state: 'active', activatedAtMs: 1_000 });

  expect(buildPasskeyCustodyKekDerivationContext(envelope)).toEqual({
    kind: 'passkey_custody_kek_derivation_context_v1',
    walletId: envelope.walletId,
    envelopeId: envelope.envelopeId,
    rpId: envelope.rpId,
    credentialIdB64u: envelope.credentialIdB64u,
    purpose: 'ed25519_yao_client_root_v1',
    passkeyKekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
  });

  const ecdsaEnvelope = parsePasskeyCustodyEnvelopeRecord(
    rawPasskeyCustodyEnvelope({ binding: rawEcdsaLaneHolderShareBinding() }),
  );
  expect(buildPasskeyCustodyKekDerivationContext(ecdsaEnvelope).purpose).toBe(
    'ecdsa_lane_holder_share_v1',
  );
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
      rawPasskeyCustodyEnvelope({ passkeyKekVersion: 'passkey_prf_kek_v0' }),
    ),
  ).toThrow(/passkeyKekVersion must be passkey_prf_kek_hkdf_sha256_v1/);
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
  ).toThrow(/12-byte or 24-byte AEAD nonce/);

  expect(() =>
    parsePasskeyCustodyEnvelopeRecord(
      rawPasskeyCustodyEnvelope({ sealedCustodySecretB64u: NONCE_12_B64U }),
    ),
  ).toThrow(/sealed ciphertext with an authentication tag/);
});

test('a recovery envelope set is wallet-scoped and covers the exact key manifest', () => {
  const expectedWalletId = WALLET_ID as WalletId;
  const requiredWalletKeyIds = [ED25519_WALLET_KEY_ID, EVM_WALLET_KEY_ID] as WalletKeyId[];

  const parsed = parseWalletRecoveryEnvelopeSetRecord(rawWalletRecoveryEnvelopeSet(), {
    expectedWalletId,
    requiredWalletKeyIds,
  });
  expect(parsed.entries.map((entry) => entry.custodySecretKind)).toEqual([
    'ed25519_yao_client_root_v1',
    'ecdsa_client_root_share_v1',
  ]);

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

  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        entries: [rawWalletRecoveryEnvelopeEntry('ed25519_yao_client_root_v1')],
      }),
      { expectedWalletId, requiredWalletKeyIds },
    ),
  ).toThrow(new RegExp(`omits required walletKeyId ${EVM_WALLET_KEY_ID}`));
});

test('a recovery envelope set rejects duplicate wallet keys and lanes', () => {
  const expectedWalletId = WALLET_ID as WalletId;

  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        entries: [
          rawWalletRecoveryEnvelopeEntry('ed25519_yao_client_root_v1'),
          rawWalletRecoveryEnvelopeEntry('ed25519_lane_holder_share_v1'),
        ],
      }),
      { expectedWalletId },
    ),
  ).toThrow(/duplicate walletKeyId/);

  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        entries: [
          rawWalletRecoveryEnvelopeEntry('ed25519_yao_client_root_v1'),
          rawWalletRecoveryEnvelopeEntry('ecdsa_client_root_share_v1', {
            walletKeyId: EVM_WALLET_KEY_ID,
            laneId: EVM_LANE_ID,
          }),
          rawWalletRecoveryEnvelopeEntry('ecdsa_lane_holder_share_v1', {
            walletKeyId: `${EVM_WALLET_KEY_ID}:2`,
            laneId: EVM_LANE_ID,
          }),
        ],
      }),
      { expectedWalletId },
    ),
  ).toThrow(/duplicate laneId/);
});

test('a recovery entry cannot carry plaintext custody material', () => {
  expect(() =>
    parseWalletRecoveryEnvelopeSetRecord(
      rawWalletRecoveryEnvelopeSet({
        entries: [
          rawWalletRecoveryEnvelopeEntry('ed25519_yao_client_root_v1', {
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
          rawWalletRecoveryEnvelopeEntry('ed25519_yao_client_root_v1', {
            aadHashB64u: ALT_DIGEST_B64U,
            custodySecretKind: 'holder_share_v1',
          }),
        ],
      }),
      { expectedWalletId: WALLET_ID as WalletId },
    ),
  ).toThrow(/must be a known passkey custody secret kind/);
});
