import { expect, test } from '@playwright/test';
import { parseRecoveryCodeReservationId } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeReservation';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { resolveCommittedRecoveryReplayV1 } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryFinalization';
import {
  buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture,
  passkeyCustodyEnvelope,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import { PASSKEY_PRF_KEK_VERSION_V1 } from '../../packages/shared-ts/src/passkey-custody';

const WALLET_ID = 'alice.testnet';
const RESERVATION_ID = parseRecoveryCodeReservationId('recovery-operation-1');
const WALLET = parseWalletId(WALLET_ID);
const RP_ID = parseWebAuthnRpId('example.localhost');
const AUTHORITY_ID = parseWalletAuthorityId('wallet-authority:recovery-test');

if (!WALLET.ok || !RP_ID.ok || !AUTHORITY_ID.ok) {
  throw new Error('recovery replay test ids are invalid');
}

function passkeyMethod(input: {
  readonly walletAuthMethodId: string;
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly status: 'active' | 'revoked';
}) {
  const walletAuthMethodId = parseWalletAuthMethodId(input.walletAuthMethodId);
  const credentialIdB64u = parseWebAuthnCredentialIdB64u(input.credentialIdB64u);
  if (!walletAuthMethodId.ok || !credentialIdB64u.ok) {
    throw new Error('recovery replay test auth-method ids are invalid');
  }
  return buildWalletAuthMethodRecordV2(
    input.status === 'active'
      ? {
          version: 'wallet_auth_method_v2',
          walletAuthMethodId: walletAuthMethodId.value,
          walletId: WALLET.value,
          walletAuthorityId: AUTHORITY_ID.value,
          kind: 'passkey',
          status: 'active',
          rpId: RP_ID.value,
          credentialIdB64u: credentialIdB64u.value,
          credentialPublicKeyB64u: input.credentialPublicKeyB64u,
          counter: 0,
          createdAtMs: 1,
          updatedAtMs: 5,
          activatedAtMs: 1,
        }
      : {
          version: 'wallet_auth_method_v2',
          walletAuthMethodId: walletAuthMethodId.value,
          walletId: WALLET.value,
          walletAuthorityId: AUTHORITY_ID.value,
          kind: 'passkey',
          status: 'revoked',
          rpId: RP_ID.value,
          credentialIdB64u: credentialIdB64u.value,
          credentialPublicKeyB64u: input.credentialPublicKeyB64u,
          counter: 0,
          createdAtMs: 1,
          updatedAtMs: 5,
          activatedAtMs: 1,
          revokedAtMs: 5,
        },
  );
}

function activeEmailOtpMethod() {
  const walletAuthMethodId = parseWalletAuthMethodId('wallet-auth-method:email-sibling');
  if (!walletAuthMethodId.ok) throw new Error('recovery replay email method id is invalid');
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId: WALLET.value,
    walletAuthorityId: AUTHORITY_ID.value,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: 'a'.repeat(64),
    registrationAuthorityId: 'email-authority:recovery-test',
    createdAtMs: 1,
    updatedAtMs: 1,
    activatedAtMs: 1,
  });
}

function envelope(input: {
  readonly envelopeId: string;
  readonly credentialIdB64u: string;
  readonly walletAuthMethodId: string;
  readonly state: 'active' | 'retired';
}) {
  return passkeyCustodyEnvelope({
    envelopeId: input.envelopeId,
    walletId: WALLET_ID,
    ownership: {
      kind: 'method_bound',
      walletAuthMethodId: input.walletAuthMethodId,
    },
    factor: {
      kind: 'passkey',
      rpId: 'example.localhost',
      credentialIdB64u: input.credentialIdB64u,
      kekVersion: PASSKEY_PRF_KEK_VERSION_V1,
    },
    lifecycle:
      input.state === 'active'
        ? { state: 'active', activatedAtMs: 1 }
        : { state: 'retired', activatedAtMs: 1, retiredAtMs: 5 },
    createdAtMs: 1,
    updatedAtMs: 5,
  });
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
    walletAuthMethodId: 'wallet-auth-method:replacement',
    state: 'active',
  });
  const source = envelope({
    envelopeId: 'source-1',
    credentialIdB64u: 'source-credential',
    walletAuthMethodId: 'wallet-auth-method:source',
    state: input.sourceState,
  });
  const emailSiblingEnvelope = buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture({
    walletId: WALLET_ID,
    envelopeId: 'email-sibling-envelope',
    enrollmentId: 'email-sibling-enrollment',
    enrollmentSealKeyVersion: 'email-sibling-seal-v1',
    walletAuthMethodId: 'wallet-auth-method:email-sibling',
  });
  const activeMethod = passkeyMethod({
    walletAuthMethodId: 'wallet-auth-method:replacement',
    credentialIdB64u: 'replacement-credential',
    credentialPublicKeyB64u: 'replacement-public-key',
    status: 'active',
  });
  const revokedMethod = passkeyMethod({
    walletAuthMethodId: 'wallet-auth-method:source',
    credentialIdB64u: 'source-credential',
    credentialPublicKeyB64u: 'source-public-key',
    status: 'revoked',
  });
  const emailSibling = activeEmailOtpMethod();
  return {
    replacement,
    envelopeStore: {
      lookupEnvelope: async () => ({ kind: 'active', envelope: replacement, storeVersion: 'v2' }),
      listWalletEnvelopes: async () => [replacement, source, emailSiblingEnvelope],
    },
    walletCustodyCommits: {
      readRecoveryEnvelopeSet: async () => ({ record: consumedRecoverySet(), storeVersion: 'v1' }),
      listWalletAuthMethods: async () => [activeMethod, emailSibling, revokedMethod],
      readPasskeyWalletAuthMethod: async () => activeMethod,
      hasActiveWalletSessionsForAuthMethod: async () => false,
    },
    webAuthnStore: {
      readAuthenticator: async () => ({
        credentialIdB64u: 'replacement-credential',
        credentialPublicKeyB64u: 'replacement-public-key',
        counter: 0,
      }),
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

  expect(result).toEqual({
    kind: 'promoted',
    storeVersion: 'v2',
    credential: {
      credentialIdB64u: 'replacement-credential',
      credentialPublicKeyB64u: 'replacement-public-key',
      counter: 0,
    },
    walletAuthMethodId: 'wallet-auth-method:replacement',
    walletAuthorityId: 'wallet-authority:recovery-test',
  });
});
