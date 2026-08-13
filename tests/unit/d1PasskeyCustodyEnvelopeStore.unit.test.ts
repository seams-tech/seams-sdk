import { expect, test } from '@playwright/test';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  CREDENTIAL_ID_B64U,
  DIGEST_B64U,
  ENVELOPE_ID,
  OTHER_WALLET_ID,
  RP_ID,
  WALLET_ID,
  passkeyCustodyEnvelope,
  rawEcdsaLaneHolderShareBinding,
  rawEmailOtpFactor,
} from './helpers/passkeyCustodyEnvelope.fixtures';

const TEST_SCOPE = {
  namespace: 'passkey-custody-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const LOCATOR = {
  walletId: WALLET_ID as WalletId,
  factor: {
    kind: 'passkey',
    rpId: RP_ID as WebAuthnRpId,
    credentialIdB64u: CREDENTIAL_ID_B64U as WebAuthnCredentialIdB64u,
  },
  envelopeId: ENVELOPE_ID as PasskeyEnvelopeId,
} as const;

async function withStore(
  run: (store: CloudflareD1PasskeyCustodyEnvelopeStore, database: D1DatabaseLike) => Promise<void>,
): Promise<void> {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const store = new CloudflareD1PasskeyCustodyEnvelopeStore({ database, scope: TEST_SCOPE });
    await run(store, database);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
}

test('an active envelope round-trips through the opaque store', async () => {
  await withStore(async (store) => {
    const envelope = passkeyCustodyEnvelope();
    const created = await store.createEnvelope(envelope);
    expect(created.kind).toBe('stored');

    const lookup = await store.lookupEnvelope(LOCATOR);
    expect(lookup.kind).toBe('active');
    if (lookup.kind !== 'active') return;
    expect(lookup.envelope.sealedCustodySecretB64u).toBe(CIPHERTEXT_B64U);
    expect(lookup.envelope.envelopeRevision).toBe(1);
    // The store returns ciphertext and public binding only; it holds no key
    // material and cannot report plaintext.
    expect(Object.keys(lookup.envelope)).not.toContain('custodySecret');
  });
});

test('factor lookup selects one active envelope and rejects duplicate active wraps', async () => {
  await withStore(async (store) => {
    expect((await store.createEnvelope(passkeyCustodyEnvelope())).kind).toBe('stored');
    const factor = LOCATOR.factor;
    const selected = await store.lookupEnvelopeForFactor({ walletId: LOCATOR.walletId, factor });
    expect(selected).toMatchObject({
      kind: 'active',
      envelope: { envelopeId: ENVELOPE_ID },
    });

    expect(
      (
        await store.createEnvelope(
          passkeyCustodyEnvelope({ envelopeId: 'passkey-envelope-duplicate' }),
        )
      ).kind,
    ).toBe('stored');
    expect(await store.lookupEnvelopeForFactor({ walletId: LOCATOR.walletId, factor })).toEqual({
      kind: 'conflict',
    });
  });
});

test('a missing envelope and a foreign wallet both read as missing', async () => {
  await withStore(async (store) => {
    expect((await store.lookupEnvelope(LOCATOR)).kind).toBe('missing');

    await store.createEnvelope(passkeyCustodyEnvelope());
    const foreignWallet = await store.lookupEnvelope({
      ...LOCATOR,
      walletId: OTHER_WALLET_ID as WalletId,
    });
    expect(foreignWallet.kind).toBe('missing');

    const foreignCredential = await store.lookupEnvelope({
      ...LOCATOR,
      factor: {
        kind: 'passkey',
        rpId: RP_ID as WebAuthnRpId,
        credentialIdB64u: 'Y3JlZGVudGlhbC05' as WebAuthnCredentialIdB64u,
      },
    });
    expect(foreignCredential.kind).toBe('missing');

    // The RP ID is part of factor identity: the same credential id under a
    // different relying party is a different factor.
    const foreignRp = await store.lookupEnvelope({
      ...LOCATOR,
      factor: {
        kind: 'passkey',
        rpId: 'evil.example' as WebAuthnRpId,
        credentialIdB64u: CREDENTIAL_ID_B64U as WebAuthnCredentialIdB64u,
      },
    });
    expect(foreignRp.kind).toBe('missing');

    // An Email OTP address never resolves a passkey-sealed envelope.
    const foreignFactor = await store.lookupEnvelope({
      ...LOCATOR,
      factor: {
        kind: 'email_otp',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
      },
    });
    expect(foreignFactor.kind).toBe('missing');
  });
});

test('creation requires revision 1 and rejects a duplicate locator', async () => {
  await withStore(async (store) => {
    const atRevisionTwo = await store.createEnvelope(
      passkeyCustodyEnvelope({ envelopeRevision: 2 }),
    );
    expect(atRevisionTwo).toEqual({ kind: 'revision_conflict', expectedRevision: 1 });

    expect((await store.createEnvelope(passkeyCustodyEnvelope())).kind).toBe('stored');
    expect((await store.createEnvelope(passkeyCustodyEnvelope())).kind).toBe('version_mismatch');
  });
});

test('a rewrap must advance the revision by exactly one', async () => {
  await withStore(async (store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());

    const skipped = await store.rewrapEnvelope(passkeyCustodyEnvelope({ envelopeRevision: 3 }));
    expect(skipped).toEqual({ kind: 'revision_conflict', expectedRevision: 2 });

    const replayed = await store.rewrapEnvelope(passkeyCustodyEnvelope({ envelopeRevision: 1 }));
    expect(replayed).toEqual({ kind: 'revision_conflict', expectedRevision: 2 });

    const advanced = await store.rewrapEnvelope(
      passkeyCustodyEnvelope({ envelopeRevision: 2, updatedAtMs: 3_000 }),
    );
    expect(advanced).toEqual({
      kind: 'stored',
      storeVersion: '2',
      envelopeRevision: 2,
    });

    const lookup = await store.lookupEnvelope(LOCATOR);
    expect(lookup.kind === 'active' && lookup.envelope.envelopeRevision).toBe(2);
  });
});

test('rewrapping an absent envelope reports not_found rather than creating one', async () => {
  await withStore(async (store) => {
    const result = await store.rewrapEnvelope(passkeyCustodyEnvelope({ envelopeRevision: 2 }));
    expect(result).toEqual({ kind: 'not_found' });
    expect((await store.lookupEnvelope(LOCATOR)).kind).toBe('missing');
  });
});

test('retirement and revocation are reported explicitly, never as missing', async () => {
  await withStore(async (store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());

    expect((await store.retireEnvelope({ locator: LOCATOR, retiredAtMs: 5_000 })).kind).toBe(
      'stored',
    );
    const retired = await store.lookupEnvelope(LOCATOR);
    expect(retired).toEqual({
      kind: 'retired',
      envelopeId: ENVELOPE_ID,
      retiredAtMs: 5_000,
    });

    expect((await store.revokeEnvelope({ locator: LOCATOR, revokedAtMs: 6_000 })).kind).toBe(
      'stored',
    );
    const revoked = await store.lookupEnvelope(LOCATOR);
    expect(revoked).toEqual({
      kind: 'revoked',
      envelopeId: ENVELOPE_ID,
      revokedAtMs: 6_000,
    });
  });
});

test('a lifecycle transition preserves the envelope revision', async () => {
  await withStore(async (store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());
    await store.rewrapEnvelope(passkeyCustodyEnvelope({ envelopeRevision: 2 }));

    const retired = await store.retireEnvelope({ locator: LOCATOR, retiredAtMs: 5_000 });
    // The ciphertext did not change, so the sealed AAD must stay valid.
    expect(retired).toMatchObject({ kind: 'stored', envelopeRevision: 2 });
  });
});

test('revocation is terminal for both rewrap and further transitions', async () => {
  await withStore(async (store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());
    await store.revokeEnvelope({ locator: LOCATOR, revokedAtMs: 6_000 });

    expect(await store.rewrapEnvelope(passkeyCustodyEnvelope({ envelopeRevision: 2 }))).toEqual({
      kind: 'terminal_lifecycle',
      state: 'revoked',
    });
    expect(await store.revokeEnvelope({ locator: LOCATOR, revokedAtMs: 7_000 })).toEqual({
      kind: 'terminal_lifecycle',
      state: 'revoked',
    });
    // A revoked row is retained as a credential tombstone, not deleted.
    expect((await store.lookupEnvelope(LOCATOR)).kind).toBe('revoked');
  });
});

test('retirement only applies to an active envelope', async () => {
  await withStore(async (store) => {
    expect(await store.retireEnvelope({ locator: LOCATOR, retiredAtMs: 5_000 })).toEqual({
      kind: 'not_found',
    });

    await store.createEnvelope(passkeyCustodyEnvelope());
    await store.retireEnvelope({ locator: LOCATOR, retiredAtMs: 5_000 });
    expect((await store.retireEnvelope({ locator: LOCATOR, retiredAtMs: 5_500 })).kind).toBe(
      'version_mismatch',
    );
  });
});

test('a stored ciphertext that disagrees with its digest fails the lookup', async () => {
  await withStore(async (store) => {
    await store.createEnvelope(passkeyCustodyEnvelope({ ciphertextDigestB64u: DIGEST_B64U }));
    const lookup = await store.lookupEnvelope(LOCATOR);
    expect(lookup.kind).toBe('digest_mismatch');
    if (lookup.kind !== 'digest_mismatch') return;
    expect(lookup.storedCiphertextDigestB64u).toBe(DIGEST_B64U);
    expect(lookup.actualCiphertextDigestB64u).not.toBe(DIGEST_B64U);
  });
});

test('a browser cache is usable only at the exact revision and digest', async () => {
  await withStore(async (store) => {
    const envelope = passkeyCustodyEnvelope();
    await store.createEnvelope(envelope);

    const valid = await store.validateCachedEnvelope({
      locator: LOCATOR,
      cachedRevision: 1,
      cachedCiphertextDigestB64u: String(envelope.ciphertextDigestB64u),
    });
    expect(valid.kind).toBe('cache_valid');

    const staleRevision = await store.validateCachedEnvelope({
      locator: LOCATOR,
      cachedRevision: 0,
      cachedCiphertextDigestB64u: String(envelope.ciphertextDigestB64u),
    });
    expect(staleRevision).toMatchObject({ kind: 'cache_stale', serverRevision: 1 });

    const staleDigest = await store.validateCachedEnvelope({
      locator: LOCATOR,
      cachedRevision: 1,
      cachedCiphertextDigestB64u: ALT_DIGEST_B64U,
    });
    expect(staleDigest.kind).toBe('cache_stale');
  });
});

test('a revoked envelope makes every cache entry unusable', async () => {
  await withStore(async (store) => {
    const envelope = passkeyCustodyEnvelope();
    await store.createEnvelope(envelope);
    await store.revokeEnvelope({ locator: LOCATOR, revokedAtMs: 6_000 });

    const validation = await store.validateCachedEnvelope({
      locator: LOCATOR,
      cachedRevision: 1,
      cachedCiphertextDigestB64u: String(envelope.ciphertextDigestB64u),
    });
    expect(validation).toMatchObject({
      kind: 'cache_unusable',
      lookup: { kind: 'revoked' },
    });
  });
});

test('interchangeable factors seal the same seed under separate envelopes', async () => {
  await withStore(async (store) => {
    // The point of the factor union: one wallet custody seed, two independent
    // unwrap paths, each with its own envelope and its own revocation.
    const passkeyEnvelope = passkeyCustodyEnvelope();
    const otpEnvelope = passkeyCustodyEnvelope({
      envelopeId: 'wallet-custody-envelope-2',
      factor: rawEmailOtpFactor(),
    });
    expect((await store.createEnvelope(passkeyEnvelope)).kind).toBe('stored');
    expect((await store.createEnvelope(otpEnvelope)).kind).toBe('stored');

    const otpLocator = {
      walletId: WALLET_ID as WalletId,
      factor: {
        kind: 'email_otp',
        enrollmentId: 'enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
      },
      envelopeId: 'wallet-custody-envelope-2' as PasskeyEnvelopeId,
    } as const;

    const viaPasskey = await store.lookupEnvelope(LOCATOR);
    const viaOtp = await store.lookupEnvelope(otpLocator);
    expect(viaPasskey.kind).toBe('active');
    expect(viaOtp.kind).toBe('active');
    // Same sealed seed, different factor envelopes.
    expect(viaPasskey.kind === 'active' && viaPasskey.envelope.binding.kind).toBe(
      'wallet_custody_seed_v1',
    );
    expect(viaOtp.kind === 'active' && viaOtp.envelope.binding.kind).toBe('wallet_custody_seed_v1');

    // Revoking one factor leaves the other able to open the same seed.
    await store.revokeEnvelope({ locator: LOCATOR, revokedAtMs: 6_000 });
    expect((await store.lookupEnvelope(LOCATOR)).kind).toBe('revoked');
    expect((await store.lookupEnvelope(otpLocator)).kind).toBe('active');
  });
});

test('lane holder-share envelopes coexist with the owner seed', async () => {
  await withStore(async (store) => {
    const seedEnvelope = passkeyCustodyEnvelope();
    const laneEnvelope = passkeyCustodyEnvelope({
      envelopeId: 'wallet-custody-envelope-3',
      factor: {
        kind: 'passkey',
        rpId: RP_ID,
        credentialIdB64u: 'Y3JlZGVudGlhbC0y',
        kekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
      },
      binding: rawEcdsaLaneHolderShareBinding(),
    });
    expect((await store.createEnvelope(seedEnvelope)).kind).toBe('stored');
    expect((await store.createEnvelope(laneEnvelope)).kind).toBe('stored');

    const laneLookup = await store.lookupEnvelope({
      walletId: WALLET_ID as WalletId,
      factor: {
        kind: 'passkey',
        rpId: RP_ID as WebAuthnRpId,
        credentialIdB64u: 'Y3JlZGVudGlhbC0y' as WebAuthnCredentialIdB64u,
      },
      envelopeId: 'wallet-custody-envelope-3' as PasskeyEnvelopeId,
    });
    expect(laneLookup.kind === 'active' && laneLookup.envelope.binding.kind).toBe(
      'ecdsa_lane_holder_share_v1',
    );
  });
});

test('locators whose ids contain delimiters cannot collide', async () => {
  await withStore(async (store) => {
    // With a ':'-joined key these two locators would map to the same row:
    // {enrollment "e", envelope "x:y"} vs {enrollment "e:x", envelope "y"}.
    // The identity re-check kept reads safe, but the second create would
    // conflict with the first. JSON-encoded keys keep them distinct.
    const first = passkeyCustodyEnvelope({
      envelopeId: 'x:y',
      factor: rawEmailOtpFactor({ enrollmentId: 'e' }),
    });
    const second = passkeyCustodyEnvelope({
      envelopeId: 'y',
      factor: rawEmailOtpFactor({ enrollmentId: 'e:x' }),
    });
    expect((await store.createEnvelope(first)).kind).toBe('stored');
    expect((await store.createEnvelope(second)).kind).toBe('stored');

    const firstLookup = await store.lookupEnvelope({
      walletId: WALLET_ID as WalletId,
      factor: { kind: 'email_otp', enrollmentId: 'e', enrollmentSealKeyVersion: 'seal-v1' },
      envelopeId: 'x:y' as PasskeyEnvelopeId,
    });
    const secondLookup = await store.lookupEnvelope({
      walletId: WALLET_ID as WalletId,
      factor: { kind: 'email_otp', enrollmentId: 'e:x', enrollmentSealKeyVersion: 'seal-v1' },
      envelopeId: 'y' as PasskeyEnvelopeId,
    });
    expect(firstLookup.kind).toBe('active');
    expect(secondLookup.kind).toBe('active');
    expect(firstLookup.kind === 'active' && String(firstLookup.envelope.envelopeId)).toBe('x:y');
    expect(secondLookup.kind === 'active' && String(secondLookup.envelope.envelopeId)).toBe('y');
  });
});
