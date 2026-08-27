import { expect, test } from '@playwright/test';
import {
  parseWalletAuthorityBindingDigest,
  parseWalletAuthorityId,
  parseWalletId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  selectWalletRecoveryContinuityAnchor,
  type WalletRecoveryAuthoritySelection,
} from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import {
  activeRecoveryEmailOtpMethodFixture,
  activeRecoveryPasskeyMethodFixture,
} from './helpers/walletRecovery.fixtures';
import {
  buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture,
  buildActiveMethodBoundPasskeyCustodyEnvelopeFixture,
} from './helpers/passkeyCustodyEnvelope.fixtures';

const WALLET_ID = parseWalletId('alice.testnet');
const AUTHORITY_DIGEST = parseWalletAuthorityBindingDigest('A'.repeat(43));

if (!WALLET_ID.ok || !AUTHORITY_DIGEST.ok) {
  throw new Error('recovery continuity selection fixture identities are invalid');
}

function authoritySelection(input: {
  readonly authorityId: string;
  readonly provenanceKind: WalletRecoveryAuthoritySelection['provenanceKind'];
}): WalletRecoveryAuthoritySelection {
  const authorityId = parseWalletAuthorityId(input.authorityId);
  if (!authorityId.ok) throw new Error('recovery continuity authority fixture is invalid');
  return {
    walletId: WALLET_ID.value,
    authorityId: authorityId.value,
    authorityDigestB64u: AUTHORITY_DIGEST.value,
    state: 'active',
    provenanceKind: input.provenanceKind,
  };
}

test('selects an exact active envelope independently of the target RP', () => {
  const emailMethod = activeRecoveryEmailOtpMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:email-registration',
    createdAtMs: 200,
  });
  const passkeyMethod = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:passkey-linked',
    credentialIdB64u: 'linked-credential',
    rpId: 'old.example.localhost',
    createdAtMs: 100,
  });
  const selected = selectWalletRecoveryContinuityAnchor({
    walletId: WALLET_ID.value,
    targetFamily: 'passkey',
    methods: [emailMethod, passkeyMethod],
    envelopes: [
      buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture({
        walletId: 'alice.testnet',
        envelopeId: 'passkey-envelope:email',
        enrollmentId: 'email-enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        walletAuthMethodId: 'wallet-auth-method:email-registration',
      }),
      buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
        walletId: 'alice.testnet',
        envelopeId: 'passkey-envelope:passkey',
        rpId: 'old.example.localhost',
        credentialIdB64u: 'linked-credential',
        walletAuthMethodId: 'wallet-auth-method:passkey-linked',
      }),
    ],
    authorities: [
      authoritySelection({
        authorityId: 'wallet-authority:recovery-email-sibling',
        provenanceKind: 'wallet_registration',
      }),
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'device_link',
      }),
    ],
  });

  expect(selected?.method.walletAuthMethodId).toBe('wallet-auth-method:email-registration');
  expect(selected?.envelope.factor.kind).toBe('email_otp');
});

test('prefers a target-family method after provenance ranking', () => {
  const emailMethod = activeRecoveryEmailOtpMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:email-linked',
    createdAtMs: 1,
  });
  const passkeyMethod = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:passkey-linked',
    credentialIdB64u: 'linked-credential',
    rpId: 'old.example.localhost',
    createdAtMs: 2,
  });
  const selected = selectWalletRecoveryContinuityAnchor({
    walletId: WALLET_ID.value,
    targetFamily: 'passkey',
    methods: [emailMethod, passkeyMethod],
    envelopes: [
      buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture({
        walletId: 'alice.testnet',
        envelopeId: 'passkey-envelope:email',
        enrollmentId: 'email-enrollment-1',
        enrollmentSealKeyVersion: 'seal-v1',
        walletAuthMethodId: 'wallet-auth-method:email-linked',
      }),
      buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
        walletId: 'alice.testnet',
        envelopeId: 'passkey-envelope:passkey',
        rpId: 'old.example.localhost',
        credentialIdB64u: 'linked-credential',
        walletAuthMethodId: 'wallet-auth-method:passkey-linked',
      }),
    ],
    authorities: [
      authoritySelection({
        authorityId: 'wallet-authority:recovery-email-sibling',
        provenanceKind: 'device_link',
      }),
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'device_link',
      }),
    ],
  });

  expect(selected?.method.walletAuthMethodId).toBe('wallet-auth-method:passkey-linked');
});

test('uses method id as the deterministic tie-breaker', () => {
  const earlierId = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:a',
    credentialIdB64u: 'credential-a',
    rpId: 'old.example.localhost',
    createdAtMs: 10,
  });
  const laterId = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:b',
    credentialIdB64u: 'credential-b',
    rpId: 'old.example.localhost',
    createdAtMs: 10,
  });
  const envelopeFor = (credentialIdB64u: string, walletAuthMethodId: string, envelopeId: string) =>
    buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
      walletId: 'alice.testnet',
      envelopeId,
      rpId: 'old.example.localhost',
      credentialIdB64u,
      walletAuthMethodId,
    });
  const selected = selectWalletRecoveryContinuityAnchor({
    walletId: WALLET_ID.value,
    targetFamily: 'passkey',
    methods: [laterId, earlierId],
    envelopes: [
      envelopeFor('credential-b', 'wallet-auth-method:b', 'passkey-envelope:b'),
      envelopeFor('credential-a', 'wallet-auth-method:a', 'passkey-envelope:a'),
    ],
    authorities: [
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'wallet_registration',
      }),
    ],
  });

  expect(selected?.method.walletAuthMethodId).toBe('wallet-auth-method:a');
});

test('ignores methods without one exact active method-bound custody envelope', () => {
  const method = activeRecoveryPasskeyMethodFixture({
    walletAuthMethodId: 'wallet-auth-method:source',
    credentialIdB64u: 'source-credential',
    rpId: 'old.example.localhost',
    createdAtMs: 1,
  });
  const selected = selectWalletRecoveryContinuityAnchor({
    walletId: WALLET_ID.value,
    targetFamily: 'passkey',
    methods: [method],
    envelopes: [
      buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
        walletId: 'alice.testnet',
        envelopeId: 'passkey-envelope:wrong-owner',
        rpId: 'old.example.localhost',
        credentialIdB64u: 'source-credential',
        walletAuthMethodId: 'wallet-auth-method:other',
      }),
    ],
    authorities: [
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'wallet_registration',
      }),
    ],
  });

  expect(selected).toBeUndefined();
});
