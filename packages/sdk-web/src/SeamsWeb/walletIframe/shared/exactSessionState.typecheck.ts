import type { WalletIframeExactSessionState } from './exactSessionState';
import { parseWalletId } from '@shared/utils/domainIds';
import {
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';

const walletId = parseWalletId('wallet-id');
const walletSessionId = parseWalletSessionId('wallet-session-id');
const authorizationId = parseWalletSessionAuthorizationId('wallet-session-authorization-id');
const linkedAuthorizationId = parseLinkedDeviceWalletSessionAuthorizationId(
  'linked-device-wallet-session-authorization-id',
);
if (!walletId.ok || !walletSessionId.ok || !authorizationId.ok || !linkedAuthorizationId.ok) {
  throw new Error('Type fixture IDs must be valid');
}

const activeSession = {
  kind: 'active_session',
  status: 'active',
  walletId: walletId.value,
  authorizationId: authorizationId.value,
  walletSessionId: walletSessionId.value,
  authMethod: 'passkey',
  expiresAtMs: 1,
} satisfies WalletIframeExactSessionState;
void activeSession;

const linkedActiveSession = {
  kind: 'active_session',
  status: 'active',
  walletId: walletId.value,
  authorizationId: linkedAuthorizationId.value,
  walletSessionId: walletSessionId.value,
  authMethod: 'linked_device',
  expiresAtMs: 1,
} satisfies WalletIframeExactSessionState;
void linkedActiveSession;

const invalidLinkedAuthorization = {
  kind: 'active_session',
  status: 'active',
  walletId: walletId.value,
  // @ts-expect-error linked-device identity rejects owner authorization IDs
  authorizationId: authorizationId.value,
  walletSessionId: walletSessionId.value,
  authMethod: 'linked_device',
  expiresAtMs: 1,
} satisfies WalletIframeExactSessionState;
void invalidLinkedAuthorization;

const missingSession = {
  kind: 'wallet_unlocked_without_signing_session',
  walletId: walletId.value,
  reason: 'not_found',
  authorizationId: authorizationId.value,
  walletSessionId: walletSessionId.value,
  authMethod: 'passkey',
} satisfies WalletIframeExactSessionState;
void missingSession;

// @ts-expect-error missing authorization state must retain exact identity
const missingSessionWithoutIdentity: WalletIframeExactSessionState = {
  kind: 'wallet_unlocked_without_signing_session',
  walletId: walletId.value,
  reason: 'not_found',
  walletSessionId: walletSessionId.value,
  authMethod: 'passkey',
};
void missingSessionWithoutIdentity;

const materialStateInReusableLifecycle: WalletIframeExactSessionState = {
  kind: 'active_session',
  // @ts-expect-error reusable Wallet Session state does not encode material restorability
  status: 'active_restorable',
  walletId: walletId.value,
  authorizationId: authorizationId.value,
  walletSessionId: walletSessionId.value,
  authMethod: 'passkey',
  expiresAtMs: 1,
};
void materialStateInReusableLifecycle;
