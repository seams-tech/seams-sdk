import {
  buildHostedAuthMenuOpenRequest,
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  hostedAuthMenuSessionIdFromBoundary,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuExternalAuthResolutionInput,
  type HostedAuthMenuOutcome,
  type SeamsWeb,
} from './index';

declare const seams: SeamsWeb;

const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-bridge-session');
const externalAuthRequestId = hostedAuthMenuExternalAuthRequestIdFromBoundary(
  'auth-menu-bridge-external-request',
);
if (!authMenuSessionId || !externalAuthRequestId) {
  throw new Error('Hosted auth-menu bridge fixture identity is invalid');
}

const request = buildHostedAuthMenuOpenRequest({ authMenuSessionId });
const outcome: Promise<HostedAuthMenuOutcome> = seams.openHostedAuthMenu(request);
void outcome;

const unsubscribe = seams.onHostedAuthMenuExternalAuthRequest(
  (externalRequest: HostedAuthMenuExternalAuthRequest) => {
    const resolution: HostedAuthMenuExternalAuthResolutionInput = {
      kind: 'hosted_auth_menu_external_auth_resolution_v1',
      authMenuSessionId: externalRequest.authMenuSessionId,
      externalAuthRequestId: externalRequest.externalAuthRequestId,
      evidence: { kind: 'cancelled', reason: 'user_cancelled' },
    };
    void seams.resolveHostedAuthMenuExternalAuth(resolution);
  },
);
void unsubscribe;

void seams.cancelHostedAuthMenu({ authMenuSessionId });

void seams.resolveHostedAuthMenuExternalAuth({
  kind: 'hosted_auth_menu_external_auth_resolution_v1',
  authMenuSessionId,
  externalAuthRequestId,
  // @ts-expect-error The app bridge cannot provide the wallet-owned PM_OPEN request identity.
  requestId: 'wallet-owned-request-id',
  evidence: { kind: 'cancelled', reason: 'user_cancelled' },
});
