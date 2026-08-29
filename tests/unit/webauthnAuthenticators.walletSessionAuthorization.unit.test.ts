import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import { handleWebAuthnAuthenticators } from '../../packages/wallet-server/src/router/transport/fetch/routes/webauthnAuthenticators';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

type AuthenticatorListInput = {
  readonly userId: string;
  readonly rpId?: string;
};

class WebAuthnAuthenticatorsRouteHarness {
  readonly listInputs: AuthenticatorListInput[] = [];
  legacyReads = 0;

  constructor(
    readonly exactAdmission: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {}

  async readExactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    return this.exactAdmission;
  }

  async resolveLegacySession(): Promise<null> {
    this.legacyReads += 1;
    return null;
  }

  async listAuthenticators(input: AuthenticatorListInput) {
    this.listInputs.push(input);
    return { ok: true as const, authenticators: [] };
  }

  service() {
    return {
      authorizationSessions: {
        tenantId: 'tenant:webauthn-authenticators',
        readWalletSessionAuthorizationV2ByOperationCredential: this.readExactAdmission.bind(this),
        resolveOpaqueWalletSessionToken: this.resolveLegacySession.bind(this),
      },
      webAuthn: {
        listWebAuthnAuthenticatorsForUser: this.listAuthenticators.bind(this),
      },
    };
  }
}

function routeContext(
  request: Request,
  harness: WebAuthnAuthenticatorsRouteHarness,
): FetchRouterApiContext {
  const url = new URL(request.url);
  return {
    request,
    url,
    pathname: url.pathname,
    method: request.method,
    runtime: { kind: 'inline' },
    service: harness.service(),
    opts: {},
    logger: {},
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
}

async function exactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const exact = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'webauthn-authenticator-list',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs: Date.now() + 60_000,
  });
  return {
    authorization: exact.issuedSession,
    authority: exact.authority,
    authMethod: exact.authMethod,
    retiredAtMs: null,
  };
}

async function invokeRoute(harness: WebAuthnAuthenticatorsRouteHarness): Promise<Response> {
  const request = new Request(
    'https://relay.example.test/webauthn/authenticators?rpId=wallet.example.test',
    { headers: { authorization: 'Bearer wallet-session-operation-credential' } },
  );
  const response = await handleWebAuthnAuthenticators(routeContext(request, harness));
  if (!response) throw new Error('WebAuthn authenticators route did not match');
  return response;
}

test('WebAuthn inventory admits the exact operation credential without probing legacy sessions', async () => {
  const admission = await exactAdmission();
  const harness = new WebAuthnAuthenticatorsRouteHarness(admission);

  const response = await invokeRoute(harness);

  expect(response.status).toBe(200);
  expect(harness.listInputs).toEqual([
    {
      userId: String(admission.authorization.session.walletId),
      rpId: 'wallet.example.test',
    },
  ]);
  expect(harness.legacyReads).toBe(0);
});

test('WebAuthn inventory rejects a missing exact session without probing legacy sessions', async () => {
  const harness = new WebAuthnAuthenticatorsRouteHarness(null);

  const response = await invokeRoute(harness);

  expect(response.status).toBe(401);
  expect(harness.listInputs).toEqual([]);
  expect(harness.legacyReads).toBe(0);
});
