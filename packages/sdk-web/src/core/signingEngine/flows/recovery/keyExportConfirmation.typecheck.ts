import type {
  EmailOtpNearAccountExportAuthorizationDeps,
  EmailOtpWalletSessionExportAuthorizationDeps,
} from './keyExportConfirmation';
import { requestEmailOtpKeyExportAuthorization } from './keyExportConfirmation';
import type { AccountId } from '@/core/types/accountIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

declare const nearAccountId: AccountId;
declare const walletId: WalletId;
declare const walletDeps: EmailOtpWalletSessionExportAuthorizationDeps;
declare const nearDeps: EmailOtpNearAccountExportAuthorizationDeps;
declare const ecdsaAuthLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
declare const ed25519AuthLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;

void requestEmailOtpKeyExportAuthorization(walletDeps, {
  kind: 'wallet_session_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
  challengeAuthority: { kind: 'fresh_login' },
});

void requestEmailOtpKeyExportAuthorization(walletDeps, {
  kind: 'wallet_session_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
  challengeAuthority: { kind: 'signing_session', authLane: ecdsaAuthLane },
});

void requestEmailOtpKeyExportAuthorization(nearDeps, {
  kind: 'near_account_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  nearAccountId,
  chain: 'near',
  publicKey: 'ed25519:public-key',
  curve: 'ed25519',
  challengeAuthority: { kind: 'signing_session', authLane: ed25519AuthLane },
});

void requestEmailOtpKeyExportAuthorization(
  // @ts-expect-error wallet-session export deps do not serve near-account export requests.
  walletDeps,
  {
    kind: 'near_account_export_auth',
    walletSession: {
      walletId,
      walletSessionUserId: 'user-1',
    },
    nearAccountId,
    chain: 'near',
    publicKey: 'ed25519:public-key',
    curve: 'ed25519',
    challengeAuthority: { kind: 'signing_session', authLane: ed25519AuthLane },
  },
);

void requestEmailOtpKeyExportAuthorization(
  // @ts-expect-error near-account export deps do not serve wallet-session export requests.
  nearDeps,
  {
    kind: 'wallet_session_export_auth',
    walletSession: {
      walletId,
      walletSessionUserId: 'user-1',
    },
    chain: 'evm',
    publicKey: '02'.padEnd(66, '1'),
    curve: 'ecdsa',
    challengeAuthority: { kind: 'fresh_login' },
  },
);

// @ts-expect-error committed wallet-session ECDSA export requires ECDSA signing-session authority.
void requestEmailOtpKeyExportAuthorization(walletDeps, {
  kind: 'wallet_session_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
  challengeAuthority: { kind: 'signing_session', authLane: ed25519AuthLane },
});

// @ts-expect-error NEAR Email OTP export cannot use a fresh app-session challenge.
void requestEmailOtpKeyExportAuthorization(nearDeps, {
  kind: 'near_account_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  nearAccountId,
  chain: 'near',
  publicKey: 'ed25519:public-key',
  curve: 'ed25519',
  challengeAuthority: { kind: 'fresh_login' },
});

// @ts-expect-error export authorization no longer accepts loose routeAuth beside challengeAuthority.
void requestEmailOtpKeyExportAuthorization(walletDeps, {
  kind: 'wallet_session_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
  challengeAuthority: { kind: 'fresh_login' },
  routeAuth: { kind: 'app_session', jwt: 'app-session-jwt' },
});

export {};
