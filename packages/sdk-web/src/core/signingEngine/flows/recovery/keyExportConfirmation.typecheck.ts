import type { EmailOtpWalletSessionExportAuthorizationDeps } from './keyExportConfirmation';
import { requestEmailOtpKeyExportAuthorization } from './keyExportConfirmation';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

declare const walletId: WalletId;
declare const walletDeps: EmailOtpWalletSessionExportAuthorizationDeps;
declare const ecdsaAuthLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
const appSessionJwt = 'app-session-jwt';

void requestEmailOtpKeyExportAuthorization(walletDeps, {
  kind: 'wallet_session_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
  flowId: 'key-export-flow-1',
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
  flowId: 'key-export-flow-2',
  // @ts-expect-error ECDSA export challenge authority must be the exact signing session.
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
  flowId: 'key-export-flow-3',
  challengeAuthority: { kind: 'app_session', appSessionJwt },
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
  flowId: 'key-export-flow-4',
  challengeAuthority: {
    // @ts-expect-error ECDSA export challenge cannot use a signing-session lane.
    kind: 'signing_session',
    authLane: ecdsaAuthLane,
  },
});

export {};
