import type {
  EmailOtpNearAccountExportAuthorizationDeps,
  EmailOtpWalletSessionExportAuthorizationDeps,
} from './keyExportConfirmation';
import { requestEmailOtpKeyExportAuthorization } from './keyExportConfirmation';
import type { AccountId } from '@/core/types/accountIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

declare const nearAccountId: AccountId;
declare const walletId: WalletId;
declare const walletDeps: EmailOtpWalletSessionExportAuthorizationDeps;
declare const nearDeps: EmailOtpNearAccountExportAuthorizationDeps;

void requestEmailOtpKeyExportAuthorization(walletDeps, {
  kind: 'wallet_session_export_auth',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
  publicKey: '02'.padEnd(66, '1'),
  curve: 'ecdsa',
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
  },
);

export {};
