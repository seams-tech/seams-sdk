import type {
  AuthIdentityMutationRequest,
  AuthLinkIdentityRequest,
  AuthProviderActionRoute,
  AuthUnlinkIdentityRequest,
  PasskeyLoginOptionsRequest,
} from './authRequestValidation';
import type { PrepareEmailRecoveryRequest } from './emailRecoveryRequestValidation';

const passkeyOptions: PasskeyLoginOptionsRequest = {
  user_id: 'wallet-1',
  rp_id: 'example.localhost',
};
void passkeyOptions;

const passkeyOptionsWithLegacyNames: PasskeyLoginOptionsRequest = {
  user_id: 'wallet-1',
  rp_id: 'example.localhost',
  // @ts-expect-error Auth options boundary uses ttl_ms, not ttlMs.
  ttlMs: 60_000,
};
void passkeyOptionsWithLegacyNames;

const emailRecoveryPrepare: PrepareEmailRecoveryRequest = {
  account_id: 'wallet-1',
  request_id: 'request-1',
  rp_id: 'example.localhost',
  webauthn_registration: {},
  threshold_ecdsa_prepare: {},
  expected_origin: 'https://example.localhost',
};
void emailRecoveryPrepare;

const emailRecoveryPrepareWithLegacyRequestId: PrepareEmailRecoveryRequest = {
  account_id: 'wallet-1',
  request_id: 'request-1',
  rp_id: 'example.localhost',
  webauthn_registration: {},
  threshold_ecdsa_prepare: {},
  expected_origin: 'https://example.localhost',
  // @ts-expect-error Email recovery prepare uses request_id at the route boundary.
  requestId: 'request-1',
};
void emailRecoveryPrepareWithLegacyRequestId;

const authLink: AuthLinkIdentityRequest = {
  provider: 'google',
  idToken: 'token',
  stepUp: {
    challengeId: 'challenge',
    webauthn_authentication: {},
    expected_origin: 'https://example.localhost',
  },
};
void authLink;

const authUnlink: AuthUnlinkIdentityRequest = {
  subject: 'google:subject',
  session_kind: 'jwt',
  stepUp: {
    challengeId: 'challenge',
    webauthn_authentication: {},
    expected_origin: 'https://example.localhost',
  },
};
void authUnlink;

const authUnlinkWithLegacySessionKind: AuthUnlinkIdentityRequest = {
  subject: 'google:subject',
  session_kind: 'jwt',
  stepUp: {
    challengeId: 'challenge',
    webauthn_authentication: {},
    expected_origin: 'https://example.localhost',
  },
  // @ts-expect-error Auth unlink route uses session_kind at the boundary.
  sessionKind: 'jwt',
};
void authUnlinkWithLegacySessionKind;

function assertNeverAuthProviderAction(route: never): never {
  throw new Error(String((route as { kind?: unknown })?.kind || 'unknown'));
}

declare const providerRoute: AuthProviderActionRoute;

switch (providerRoute.kind) {
  case 'passkey_options':
  case 'passkey_verify':
  case 'google_options':
  case 'google_verify':
    break;
  default:
    assertNeverAuthProviderAction(providerRoute);
}

function assertNeverAuthIdentityMutation(route: never): never {
  throw new Error(String((route as { kind?: unknown })?.kind || 'unknown'));
}

declare const identityMutation: AuthIdentityMutationRequest;

switch (identityMutation.kind) {
  case 'link':
  case 'unlink':
    break;
  default:
    assertNeverAuthIdentityMutation(identityMutation);
}

export {};
