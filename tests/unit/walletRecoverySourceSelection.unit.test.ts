import { expect, test } from '@playwright/test';
import {
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
import {
  buildLinkedDeviceManagementAuthorityFixture,
  fullOwnerPermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';

const WALLET_ID = parseWalletId('alice.testnet');

if (!WALLET_ID.ok) {
  throw new Error('recovery continuity selection fixture identities are invalid');
}

async function authoritySelection(input: {
  readonly authorityId: string;
  readonly provenanceKind: WalletRecoveryAuthoritySelection['provenance']['kind'];
}): Promise<WalletRecoveryAuthoritySelection> {
  const authorityId = parseWalletAuthorityId(input.authorityId);
  if (!authorityId.ok) throw new Error('recovery continuity authority fixture is invalid');
  const label = input.authorityId.replace(/[^a-zA-Z0-9_-]/g, '-');
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label,
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: input.provenanceKind,
    identity: {
      walletId: 'alice.testnet',
      authorityId: String(authorityId.value),
      walletAuthMethodId: `wallet-auth-method:${label}`,
      rpId: 'old.example.localhost',
    },
  });
  return fixture.authority;
}

test('selects an exact active envelope independently of the target RP', async () => {
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
    authorities: await Promise.all([
      authoritySelection({
        authorityId: 'wallet-authority:recovery-email-sibling',
        provenanceKind: 'wallet_registration',
      }),
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'device_link',
      }),
    ]),
  });

  expect(selected?.method.walletAuthMethodId).toBe('wallet-auth-method:email-registration');
  expect(selected?.envelope.factor.kind).toBe('email_otp');
});

test('prefers a target-family method after provenance ranking', async () => {
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
    authorities: await Promise.all([
      authoritySelection({
        authorityId: 'wallet-authority:recovery-email-sibling',
        provenanceKind: 'device_link',
      }),
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'device_link',
      }),
    ]),
  });

  expect(selected?.method.walletAuthMethodId).toBe('wallet-auth-method:passkey-linked');
});

test('uses method id as the deterministic tie-breaker', async () => {
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
    authorities: await Promise.all([
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'wallet_registration',
      }),
    ]),
  });

  expect(selected?.method.walletAuthMethodId).toBe('wallet-auth-method:a');
});

test('ignores methods without one exact active method-bound custody envelope', async () => {
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
    authorities: await Promise.all([
      authoritySelection({
        authorityId: 'wallet-authority:recovery-source',
        provenanceKind: 'wallet_registration',
      }),
    ]),
  });

  expect(selected).toBeUndefined();
});
