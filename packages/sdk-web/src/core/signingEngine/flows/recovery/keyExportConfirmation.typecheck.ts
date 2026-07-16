import type { EmailOtpEcdsaExportAuthorizationDeps } from './keyExportConfirmation';
import { requestEmailOtpKeyExportAuthorization } from './keyExportConfirmation';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

declare const walletId: WalletId;
declare const walletDeps: EmailOtpEcdsaExportAuthorizationDeps;
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
  challengeAuthority: {
    // @ts-expect-error ECDSA export requires exact signing-session authority.
    kind: 'fresh_login',
  },
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
  challengeAuthority: { kind: 'public_reauth' },
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

void requestEmailOtpKeyExportAuthorization(walletDeps, {
  kind: 'wallet_session_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
  challengeAuthority: {
    kind: 'signing_session',
    // @ts-expect-error committed wallet-session ECDSA export requires ECDSA signing-session authority.
    authLane: ed25519AuthLane,
  },
});

export {};
