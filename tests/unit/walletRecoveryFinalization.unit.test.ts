import { expect, test } from '@playwright/test';
import { parseRecoveryCodeReservationId } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeReservation';
import { resolveCommittedRecoveryReplayV1 } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryFinalization';

const WALLET_ID = 'alice.testnet';
const RESERVATION_ID = parseRecoveryCodeReservationId('recovery-operation-1');

function envelope(input: {
  readonly envelopeId: string;
  readonly credentialIdB64u: string;
  readonly state: 'active' | 'retired';
}) {
  return {
    kind: 'wallet_custody_envelope_v2',
    envelopeId: input.envelopeId,
    walletId: WALLET_ID,
    binding: { kind: 'wallet_custody_seed_v1' },
    factor: {
      kind: 'passkey',
      rpId: 'example.localhost',
      credentialIdB64u: input.credentialIdB64u,
    },
    envelopeVersion: 'v2',
    envelopeRevision: 1,
    nonceB64u: 'B'.repeat(16),
    sealedCustodySecretB64u: 'C'.repeat(64),
    ciphertextDigestB64u: 'A'.repeat(43),
    aadHashB64u: 'A'.repeat(43),
    lifecycle:
      input.state === 'active'
        ? { state: 'active', activatedAtMs: 1 }
        : { state: 'retired', activatedAtMs: 1, retiredAtMs: 5 },
    createdAtMs: 1,
    updatedAtMs: 5,
  } as never;
}

function consumedRecoverySet() {
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: WALLET_ID,
    manifestKekWraps: [
      {
        recoveryKeyId: `wallet-rkid-v1-${'A'.repeat(43)}`,
        nonceB64u: 'B'.repeat(16),
        wrappedManifestKekB64u: 'C'.repeat(64),
        aadHashB64u: 'A'.repeat(43),
        lifecycle: {
          state: 'consumed',
          issuedAtMs: 1,
          reservationId: RESERVATION_ID,
          consumedAtMs: 5,
        },
      },
    ],
    entries: [],
    issuedAtMs: 1,
    updatedAtMs: 5,
  } as never;
}

function replayStores(input: { readonly sourceState: 'active' | 'retired' }) {
  const replacement = envelope({
    envelopeId: 'replacement-1',
    credentialIdB64u: 'replacement-credential',
    state: 'active',
  });
  const source = envelope({
    envelopeId: 'source-1',
    credentialIdB64u: 'source-credential',
    state: input.sourceState,
  });
  const activeMethod = {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    walletId: WALLET_ID,
    rpId: 'example.localhost',
    credentialIdB64u: 'replacement-credential',
    credentialPublicKeyB64u: 'replacement-public-key',
    counter: 0,
    createdAtMs: 1,
    updatedAtMs: 5,
  } as never;
  const revokedMethod = {
    ...activeMethod,
    status: 'revoked',
    credentialIdB64u: 'source-credential',
  } as never;
  return {
    replacement,
    envelopeStore: {
      lookupEnvelope: async () => ({ kind: 'active', envelope: replacement, storeVersion: 'v2' }),
      listWalletEnvelopes: async () => [replacement, source],
    },
    walletCustodyCommits: {
      readRecoveryEnvelopeSet: async () => ({ record: consumedRecoverySet(), storeVersion: 'v1' }),
      listWalletAuthMethods: async () => [activeMethod, revokedMethod],
      hasActiveWalletSessionsForAuthMethod: async () => false,
    },
    webAuthnStore: {
      readAuthenticator: async () => ({ credentialIdB64u: 'replacement-credential' }),
      readBindingByCredential: async () => ({
        userId: WALLET_ID,
        rpId: 'example.localhost',
        credentialIdB64u: 'replacement-credential',
      }),
    },
  };
}

test('a missing challenge is rejected until every promotion state is present', async () => {
  const stores = replayStores({ sourceState: 'active' });
  const result = await resolveCommittedRecoveryReplayV1({
    ...stores,
    walletId: WALLET_ID,
    reservationId: RESERVATION_ID,
    replacementId: 'replacement-1',
    replacementEnvelope: stores.replacement,
  } as never);

  expect(result).toEqual({
    kind: 'conflict',
    reason: 'the recovery commit is incomplete; retry finalization or contact support',
  });
});

test('strict replay returns the committed promotion without retire failure state', async () => {
  const stores = replayStores({ sourceState: 'retired' });
  const result = await resolveCommittedRecoveryReplayV1({
    ...stores,
    walletId: WALLET_ID,
    reservationId: RESERVATION_ID,
    replacementId: 'replacement-1',
    replacementEnvelope: stores.replacement,
  } as never);

  expect(result).toEqual({ kind: 'promoted', storeVersion: 'v2' });
});
