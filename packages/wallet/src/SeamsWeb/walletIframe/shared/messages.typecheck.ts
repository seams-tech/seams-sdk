import {
  buildHostedAuthMenuExternalAuthResolution,
  buildHostedAuthMenuOpenRequest,
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  hostedAuthMenuSessionIdFromBoundary,
  parseWalletIframeSurfaceMeasurement,
  buildHostedAuthMenuCancelPayload,
  buildPMRedeemHostedWalletSeamsSessionPayload,
  type PMRedeemHostedWalletSeamsSessionPayload,
  type HostedAuthMenuExternalAuthRequest,
  type HostedAuthMenuOutcome,
  type WalletIframeSurfaceMeasurement,
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

const measurement: WalletIframeSurfaceMeasurement = {
  kind: 'measured_v1',
  requestId,
  sequence: 1,
  widthCssPx: 320,
  heightCssPx: 240,
};
void measurement;
if (!parseWalletIframeSurfaceMeasurement(measurement)) {
  throw new Error('Measurement fixture is invalid');
}

const authMeasurement: WalletIframeSurfaceMeasurement = {
  kind: 'measured_auth_menu_v1',
  requestId,
  authMenuSessionId: sessionId,
  sequence: 1,
  widthCssPx: 320,
  heightCssPx: 240,
};
void authMeasurement;

// @ts-expect-error Generic measurements cannot carry an auth-menu session identity.
const genericMeasurementWithSession: WalletIframeSurfaceMeasurement = {
  kind: 'measured_v1',
  requestId,
  authMenuSessionId: sessionId,
  sequence: 1,
  widthCssPx: 320,
  heightCssPx: 240,
};
void genericMeasurementWithSession;

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

const hostedRedemption = buildPMRedeemHostedWalletSeamsSessionPayload({
  exchangeCode: 'exchange-code',
  nonce: 'exchange-nonce',
  appOrigin: 'https://app.example.test',
  walletOrigin: 'https://wallet.example.test',
  relayUrl: 'https://relay.example.test',
});
const exactHostedRedemption: PMRedeemHostedWalletSeamsSessionPayload = hostedRedemption;
void exactHostedRedemption;

buildPMRedeemHostedWalletSeamsSessionPayload({
  exchangeCode: 'exchange-code',
  nonce: 'exchange-nonce',
  appOrigin: 'https://app.example.test',
  walletOrigin: 'https://wallet.example.test',
  relayUrl: 'https://relay.example.test',
  // @ts-expect-error Hosted V2 redemption is curve-free.
  curve: 'ecdsa',
});

const unbrandedHostedRedemption: PMRedeemHostedWalletSeamsSessionPayload = {
  // @ts-expect-error Exchange codes enter through the hosted redemption builder/parser.
  exchangeCode: 'exchange-code',
  // @ts-expect-error Exchange nonces enter through the hosted redemption builder/parser.
  nonce: 'exchange-nonce',
  appOrigin: 'https://app.example.test',
  walletOrigin: 'https://wallet.example.test',
  relayUrl: 'https://relay.example.test',
};
void unbrandedHostedRedemption;
