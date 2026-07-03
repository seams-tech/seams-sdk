import type {
  VerifiedEcdsaWalletSessionAuth,
  VerifiedEd25519WalletSessionAuth,
  VerifiedWalletSessionAuth,
} from './verifiedWalletSessionAuth';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

const passkeyAuthority = buildPasskeyWalletAuthAuthority({
  walletId: 'wallet-ed25519',
  rpId: 'example.localhost',
  credentialIdB64u: 'credential-id',
});

const ecdsaAuth = {
  kind: 'wallet_session',
  curve: 'ecdsa',
  thresholdSessionId: 'threshold-session-ecdsa',
  signingGrantId: 'signing-grant-ecdsa',
  userId: 'wallet-ecdsa',
  evmFamilySigningKeySlotId: 'wallet-key-example-localhost',
  relayerKeyId: 'ecdsa-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  keyHandle: 'ehss-key-1',
} satisfies VerifiedEcdsaWalletSessionAuth;

const ed25519Auth = {
  kind: 'wallet_session',
  curve: 'ed25519',
  thresholdSessionId: 'threshold-session-ed25519',
  signingGrantId: 'signing-grant-ed25519',
  userId: 'wallet-ed25519',
  authority: passkeyAuthority,
  relayerKeyId: 'ed25519-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  ed25519RelayerKeyId: 'ed25519-relayer',
} satisfies VerifiedEd25519WalletSessionAuth;

function requireVerifiedWalletSessionAuth(auth: VerifiedWalletSessionAuth): VerifiedWalletSessionAuth {
  return auth;
}

void requireVerifiedWalletSessionAuth(ecdsaAuth);
void requireVerifiedWalletSessionAuth(ed25519Auth);

// @ts-expect-error Core wallet-session auth consumers require a verified object.
requireVerifiedWalletSessionAuth('threshold-session-id');

const invalidMissingSigningGrant = {
  kind: 'wallet_session',
  curve: 'ecdsa',
  thresholdSessionId: 'threshold-session-ecdsa',
  userId: 'wallet-ecdsa',
  evmFamilySigningKeySlotId: 'wallet-key-example-localhost',
  relayerKeyId: 'ecdsa-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  keyHandle: 'ehss-key-1',
  // @ts-expect-error signingGrantId is required on verified Wallet Session auth.
} satisfies VerifiedEcdsaWalletSessionAuth;
void invalidMissingSigningGrant;

const invalidEcdsaWithEd25519OnlyField = {
  kind: 'wallet_session',
  curve: 'ecdsa',
  thresholdSessionId: 'threshold-session-ecdsa',
  signingGrantId: 'signing-grant-ecdsa',
  userId: 'wallet-ecdsa',
  evmFamilySigningKeySlotId: 'wallet-key-example-localhost',
  relayerKeyId: 'ecdsa-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  keyHandle: 'ehss-key-1',
  // @ts-expect-error ECDSA auth must not carry Ed25519-only relayer identity.
  ed25519RelayerKeyId: 'ed25519-relayer',
} satisfies VerifiedEcdsaWalletSessionAuth;
void invalidEcdsaWithEd25519OnlyField;

const invalidEd25519WithEcdsaOnlyField = {
  kind: 'wallet_session',
  curve: 'ed25519',
  thresholdSessionId: 'threshold-session-ed25519',
  signingGrantId: 'signing-grant-ed25519',
  userId: 'wallet-ed25519',
  authority: passkeyAuthority,
  relayerKeyId: 'ed25519-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  ed25519RelayerKeyId: 'ed25519-relayer',
  // @ts-expect-error Ed25519 auth must not carry ECDSA key handles.
  keyHandle: 'ehss-key-1',
} satisfies VerifiedEd25519WalletSessionAuth;
void invalidEd25519WithEcdsaOnlyField;

const invalidEd25519WithAuthorityScope = {
  kind: 'wallet_session',
  curve: 'ed25519',
  thresholdSessionId: 'threshold-session-ed25519',
  signingGrantId: 'signing-grant-ed25519',
  userId: 'wallet-ed25519',
  authority: passkeyAuthority,
  relayerKeyId: 'ed25519-relayer',
  participantIds: [1, 2] as const,
  expiresAtMs: Date.now() + 60_000,
  ed25519RelayerKeyId: 'ed25519-relayer',
  // @ts-expect-error Verified Ed25519 auth carries WalletAuthAuthority, not authorityScope.
  authorityScope: { kind: 'passkey_rp', rpId: 'example.localhost' },
} satisfies VerifiedEd25519WalletSessionAuth;
void invalidEd25519WithAuthorityScope;

export {};
