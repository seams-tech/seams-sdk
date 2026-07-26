import type { WalletIframeExactSessionState } from './exactSessionState';
import { parseSigningGrantId, parseWalletId } from '@shared/utils/domainIds';

const walletId = parseWalletId('wallet-id');
const walletSessionId = parseSigningGrantId('wallet-session-id');
if (!walletId.ok || !walletSessionId.ok) throw new Error('Type fixture IDs must be valid');

const activeSession = {
  kind: 'active_session',
  status: 'active',
  walletId: walletId.value,
  walletSessionId: walletSessionId.value,
  authMethod: 'passkey',
  expiresAtMs: 1,
} satisfies WalletIframeExactSessionState;
void activeSession;

const materialStateInReusableLifecycle: WalletIframeExactSessionState = {
  kind: 'active_session',
  // @ts-expect-error reusable Wallet Session state does not encode material restorability
  status: 'active_restorable',
  walletId: walletId.value,
  walletSessionId: walletSessionId.value,
  authMethod: 'passkey',
  expiresAtMs: 1,
};
void materialStateInReusableLifecycle;
