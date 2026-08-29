import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import { handleAuth } from '../../packages/wallet-server/src/router/transport/fetch/routes/auth';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

type ExactMethodId =
  RouterApiWalletSessionAuthorizationV2AdmissionContext['authMethod']['walletAuthMethodId'];
type ExactAuthorityId =
  RouterApiWalletSessionAuthorizationV2AdmissionContext['authority']['authorityId'];

type StepUpIdentity = {
  readonly walletId: string;
  readonly walletAuthMethodId: ExactMethodId;
  readonly walletAuthorityId: ExactAuthorityId;
};

class AuthIdentityRouteHarness {
  readonly listedUserIds: string[] = [];
  readonly unlinked: Array<{ readonly userId: string; readonly subject: string }> = [];
  readonly strongAuthWalletIds: string[] = [];

  constructor(
    readonly exactAdmission: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
    readonly stepUpIdentity: StepUpIdentity | null,
  ) {}

  async readExactAdmission(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    return this.exactAdmission;
  }

  async listIdentities(input: { readonly userId: string }) {
    this.listedUserIds.push(input.userId);
    return { ok: true as const, subjects: ['passkey:test'] };
  }

  async verifyStepUp() {
    if (!this.stepUpIdentity) {
      return { ok: false as const, code: 'invalid_step_up', message: 'Step-up unavailable' };
    }
    return {
      ok: true as const,
      verified: true as const,
      userId: this.stepUpIdentity.walletId,
      rpId: 'wallet.example.test',
      credentialIdB64u: 'credential:auth-identity-step-up',
      walletAuthMethodId: this.stepUpIdentity.walletAuthMethodId,
      walletAuthorityId: this.stepUpIdentity.walletAuthorityId,
      ed25519: { kind: 'absent' as const },
    };
  }

  async markStrongAuth(input: { readonly walletId: string }) {
    this.strongAuthWalletIds.push(input.walletId);
    return { ok: true as const, walletId: input.walletId };
  }

  async unlinkIdentity(input: { readonly userId: string; readonly subject: string }) {
    this.unlinked.push(input);
    return { ok: true as const };
  }

  service() {
    return {
      authorizationSessions: {
        tenantId: 'tenant:auth-identity',
        readWalletSessionAuthorizationV2ByOperationCredential: this.readExactAdmission.bind(this),
      },
      webAuthn: {
        verifyWebAuthnLogin: this.verifyStepUp.bind(this),
      },
      emailOtp: {
        markEmailOtpStrongAuthSatisfied: this.markStrongAuth.bind(this),
      },
      identity: {
        listIdentities: this.listIdentities.bind(this),
        unlinkIdentity: this.unlinkIdentity.bind(this),
      },
    };
  }
}

function routeContext(request: Request, harness: AuthIdentityRouteHarness): FetchRouterApiContext {
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

async function exactAdmission(
  label: string,
  identity?: {
    readonly walletId: string;
    readonly authorityId: string;
    readonly walletAuthMethodId: string;
    readonly rpId: string;
  },
): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const exact = await buildLinkedDeviceManagementAuthorityFixture({
    label,
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs: Date.now() + 60_000,
    ...(identity ? { identity } : {}),
  });
  return {
    authorization: exact.issuedSession,
    authority: exact.authority,
    authMethod: exact.authMethod,
    retiredAtMs: null,
  };
}

function stepUpIdentity(
  admission: RouterApiWalletSessionAuthorizationV2AdmissionContext,
): StepUpIdentity {
  return {
    walletId: String(admission.authorization.session.walletId),
    walletAuthMethodId: admission.authMethod.walletAuthMethodId,
    walletAuthorityId: admission.authority.authorityId,
  };
}

async function invokeAuthRoute(
  request: Request,
  harness: AuthIdentityRouteHarness,
): Promise<Response> {
  const response = await handleAuth(routeContext(request, harness));
  if (!response) throw new Error('Auth identity route did not match');
  return response;
}

function identityListRequest(): Request {
  return new Request('https://relay.example.test/auth/identities', {
    headers: { authorization: 'Bearer wallet-session-operation-credential' },
  });
}

function unlinkRequest(): Request {
  return new Request('https://relay.example.test/auth/unlink', {
    method: 'POST',
    headers: {
      authorization: 'Bearer wallet-session-operation-credential',
      'content-type': 'application/json',
      origin: 'https://wallet.example.test',
    },
    body: JSON.stringify({
      subject: 'google:auth-identity@example.test',
      step_up_challenge_id: 'challenge:auth-identity-step-up',
      webauthn_authentication: { id: 'credential:auth-identity-step-up' },
    }),
  });
}

test('identity inventory derives the wallet from one exact operation credential', async () => {
  const admission = await exactAdmission('auth-identity-list');
  const harness = new AuthIdentityRouteHarness(admission, null);

  const response = await invokeAuthRoute(identityListRequest(), harness);

  expect(response.status).toBe(200);
  expect(harness.listedUserIds).toEqual([String(admission.authorization.session.walletId)]);
});

test('identity mutation accepts a fresh proof from the exact session method and authority', async () => {
  const admission = await exactAdmission('auth-identity-unlink');
  const harness = new AuthIdentityRouteHarness(admission, stepUpIdentity(admission));

  const response = await invokeAuthRoute(unlinkRequest(), harness);
  const walletId = String(admission.authorization.session.walletId);

  expect(response.status).toBe(200);
  expect(harness.strongAuthWalletIds).toEqual([walletId]);
  expect(harness.unlinked).toEqual([
    { userId: walletId, subject: 'google:auth-identity@example.test' },
  ]);
});

test('identity mutation rejects a sibling same-wallet method before side effects', async () => {
  const admission = await exactAdmission('auth-identity-source');
  const walletId = String(admission.authorization.session.walletId);
  const sibling = await exactAdmission('auth-identity-sibling', {
    walletId,
    authorityId: 'authority:auth-identity-sibling',
    walletAuthMethodId: 'wallet-auth-method:auth-identity-sibling',
    rpId: 'wallet.example.test',
  });
  const harness = new AuthIdentityRouteHarness(admission, stepUpIdentity(sibling));

  const response = await invokeAuthRoute(unlinkRequest(), harness);

  expect(response.status).toBe(403);
  expect(harness.strongAuthWalletIds).toEqual([]);
  expect(harness.unlinked).toEqual([]);
});

test('identity inventory rejects a missing exact session without probing legacy sessions', async () => {
  const harness = new AuthIdentityRouteHarness(null, null);

  const response = await invokeAuthRoute(identityListRequest(), harness);

  expect(response.status).toBe(401);
  expect(harness.listedUserIds).toEqual([]);
});
