import {
  buildHostedAuthMenuExternalAuthResolution,
  buildHostedAuthMenuOpenRequest,
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  hostedAuthMenuSessionIdFromBoundary,
  buildHostedAuthMenuCancelPayload,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuOutcome,
} from './messages';
import { walletIframeRequestIdFromBoundary } from '@/core/types/walletIframeIdentity';
import { parseWalletId } from '@shared/utils/domainIds';

const sessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-session-1');
const externalRequestId = hostedAuthMenuExternalAuthRequestIdFromBoundary('external-1');
const requestId = walletIframeRequestIdFromBoundary('request-1');
const walletId = parseWalletId('wallet-1');
if (!sessionId || !externalRequestId || !walletId.ok) {
  throw new Error('Auth-menu identity fixture is invalid');
}

const openRequest = buildHostedAuthMenuOpenRequest({ authMenuSessionId: sessionId });
void openRequest;

const externalRequest: HostedAuthMenuExternalAuthRequest = {
  kind: 'hosted_auth_menu_external_auth_request_v1',
  authMenuSessionId: sessionId,
  externalAuthRequestId: externalRequestId,
  provider: 'google',
  mode: 'login',
};
void externalRequest;

const externalResolution = buildHostedAuthMenuExternalAuthResolution({
  authMenuSessionId: sessionId,
  externalAuthRequestId: externalRequestId,
  requestId,
  evidence: { kind: 'cancelled', reason: 'user_cancelled' },
});
void externalResolution;

const cancellation = buildHostedAuthMenuCancelPayload({
  authMenuSessionId: sessionId,
  requestId,
  reason: 'component_unmounted',
});
void cancellation;

// @ts-expect-error Auth-menu control payloads require the original PM_OPEN request identity.
buildHostedAuthMenuCancelPayload({
  authMenuSessionId: sessionId,
  reason: 'component_unmounted',
});

const authenticatedOutcome: HostedAuthMenuOutcome = {
  kind: 'authenticated',
  authMenuSessionId: sessionId,
  walletId: walletId.value,
  method: 'passkey',
};
void authenticatedOutcome;

const unbrandedSessionOutcome: HostedAuthMenuOutcome = {
  kind: 'cancelled',
  // @ts-expect-error Auth-menu identities cannot cross the boundary as plain strings.
  authMenuSessionId: 'auth-menu-session-1',
  reason: 'component_unmounted',
};
void unbrandedSessionOutcome;

const callbackBearingExternalRequest: HostedAuthMenuExternalAuthRequest = {
  ...externalRequest,
  // @ts-expect-error Executable provider handlers do not cross the MessagePort boundary.
  onResolve: () => undefined,
};
void callbackBearingExternalRequest;
