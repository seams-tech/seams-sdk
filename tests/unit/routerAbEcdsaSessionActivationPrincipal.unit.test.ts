import { expect, test } from '@playwright/test';
import type { FetchRouterApiContext } from '../../packages/sdk-server-ts/src/router/transport/fetch/fetchRouter.types';
import { handleStrictEcdsaSessionActivation } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/thresholdEcdsa';
import { handleReusableWalletSessionStatus } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/sessions';
import { buildActiveAuthorizationSession } from '../../packages/sdk-server-ts/src/authorization/domain';
import { parsePrincipalId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import { buildReusableAuthorizationCoreFixture } from './helpers/authorizationCore.fixtures';
import { buildRouterAbEcdsaWalletSessionClaimsFixture } from './helpers/routerAbEcdsaWalletSessionClaims.fixtures';

const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'project-a',
  envId: 'env-a',
  signingRootVersion: 'root-v1',
} as const;

async function activationFixture() {
  const reusable = await buildReusableAuthorizationCoreFixture();
  const providerPrincipal = parsePrincipalId('google-subject-1');
  if (!providerPrincipal.ok) throw new Error(providerPrincipal.error.message);
  const authorizationSession = buildActiveAuthorizationSession({
    tenantId: reusable.session.tenantId,
    principalId: providerPrincipal.value,
    sessionId: reusable.session.sessionId,
    authSource: reusable.session.authSource,
    deviceId: reusable.session.deviceId,
    audience: reusable.session.audience,
    appSessionVersion: reusable.session.appSessionVersion,
    assurance: reusable.session.assurance,
    createdAtMs: reusable.session.createdAtMs,
    lifecycle: reusable.session.lifecycle,
  });
  const walletId = reusable.reusableWalletSession.walletId;
  const signer = createWalletEcdsaSignerRecord({ walletId, now: Date.now() });
  const capability = signer.walletKey.publicCapability;
  const normalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_id: signer.walletKey.walletId,
      ecdsa_threshold_key_id: signer.walletKey.ecdsaThresholdKeyId,
      signing_root_id: signer.walletKey.signingRootId,
      signing_root_version: signer.walletKey.signingRootVersion,
      context: capability.context,
      public_identity: capability.public_identity,
      material_activation: capability.material_activation,
      signing_worker: capability.signer_set.selected_server,
      activation_epoch: capability.activation_epoch,
    },
  });
  if (!normalSigning) throw new Error('ECDSA normal-signing fixture is invalid');
  const request = parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1({
    kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
    public_capability: capability,
    session_policy: {
      threshold_session_id: 'threshold-otp-activation',
      wallet_session_mint_id: 'wallet-session-mint-activation',
      ttl_ms: 60_000,
      remaining_uses: 3,
      runtime_policy_scope: RUNTIME_POLICY_SCOPE,
    },
  });
  const claims = buildRouterAbEcdsaWalletSessionClaimsFixture({
    walletId: String(walletId),
    keyHandle: signer.walletKey.keyHandle,
    relayerKeyId: signer.walletKey.relayerKeyId,
    participantIds: signer.walletKey.participantIds,
    thresholdExpiresAtMs: Date.now() + 60_000,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    normalSigningScope: normalSigning.scope,
    authorizationSessionId: String(authorizationSession.sessionId),
    authorizationId: String(reusable.reusableWalletSession.authorizationId),
    walletSessionId: String(reusable.reusableWalletSession.walletSessionId),
    quotaId: String(reusable.reusableWalletSession.quotaId),
    thresholdSessionId: request.session_policy.threshold_session_id,
  });
  claims.exp = Math.ceil((Date.now() + 60_000) / 1000);
  const statusInputs: Array<{ readonly principalId: string }> = [];
  const ctx = {
    request: new Request('https://relay.example/router-ab/ecdsa-derivation/session/activate', {
      method: 'POST',
      headers: { authorization: 'Bearer ecdsa-wallet-session' },
      body: JSON.stringify(request),
    }),
    opts: {
      session: {
        async parse() {
          return { ok: true as const, claims };
        },
        async signJwt() {
          return 'fresh-ecdsa-wallet-session-jwt';
        },
      },
    },
    service: {
      authorizationSessions: {
        tenantId: authorizationSession.tenantId,
        async readActiveSession() {
          return authorizationSession;
        },
        async readReusableWalletSessionStatus(input: {
          readonly principalId: { toString(): string };
        }) {
          statusInputs.push({ principalId: String(input.principalId) });
          return {
            kind: 'active' as const,
            tenantId: authorizationSession.tenantId,
            principalId: input.principalId,
            walletSessionId: reusable.reusableWalletSession.walletSessionId,
            quotaId: reusable.reusableWalletSession.quotaId,
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
          };
        },
      },
      walletRegistration: {
        async activateEcdsaPostRegistrationSession() {
          return {
            ok: true as const,
            walletKey: signer.walletKey,
            session: {
              thresholdSessionId: request.session_policy.threshold_session_id,
              expiresAtMs: Date.now() + request.session_policy.ttl_ms,
              remainingUses: request.session_policy.remaining_uses,
            },
            normalSigning,
          };
        },
      },
    },
  } as unknown as FetchRouterApiContext;
  return { ctx, request, claims, authorizationSession, walletId, statusInputs };
}

test('additional ECDSA activation uses the Email OTP authorization principal for quota lookup', async () => {
  const fixture = await activationFixture();
  const response = await handleStrictEcdsaSessionActivation({
    ctx: fixture.ctx,
    body: fixture.request,
    source: 'additional_wallet_target',
  });

  expect(response.status).toBe(200);
  expect(fixture.statusInputs).toEqual([
    { principalId: String(fixture.authorizationSession.principalId) },
  ]);
  const body = (await response.json()) as { session: { wallet_session_jwt: string } };
  expect(body.session.wallet_session_jwt).toBe('fresh-ecdsa-wallet-session-jwt');
  expect(String(fixture.authorizationSession.principalId)).not.toBe(String(fixture.walletId));
});

test('ECDSA Wallet Session status uses the authorization-session principal', async () => {
  const fixture = await activationFixture();
  const statusInputs: Array<{ readonly principalId: string }> = [];
  const context = {
    ...fixture.ctx,
    method: 'POST',
    pathname: '/wallet/session/status',
    request: new Request('https://relay.example/wallet/session/status', {
      method: 'POST',
      headers: { authorization: 'Bearer ecdsa-wallet-session' },
      body: JSON.stringify({
        walletSessionId: String(fixture.claims.walletSessionId),
        quotaId: String(fixture.claims.quotaId),
      }),
    }),
    service: {
      ...fixture.ctx.service,
      authorizationSessions: {
        ...fixture.ctx.service.authorizationSessions,
        async readReusableWalletSessionStatus(input: {
          readonly principalId: { toString(): string };
        }) {
          statusInputs.push({ principalId: String(input.principalId) });
          return {
            kind: 'active' as const,
            tenantId: fixture.authorizationSession.tenantId,
            principalId: input.principalId,
            walletSessionId: fixture.claims.walletSessionId,
            quotaId: fixture.claims.quotaId,
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
          };
        },
      },
    },
  } as unknown as FetchRouterApiContext;

  const response = await handleReusableWalletSessionStatus(context);

  expect(response?.status).toBe(200);
  expect(statusInputs).toEqual([{ principalId: String(fixture.authorizationSession.principalId) }]);
  expect(String(fixture.authorizationSession.principalId)).not.toBe(String(fixture.walletId));
});

test('additional ECDSA activation rejects a different wallet capability', async () => {
  const fixture = await activationFixture();
  const otherWalletId = parseWalletId('wallet-authorization-other');
  if (!otherWalletId.ok) throw new Error(otherWalletId.error.message);
  const body = (await fixture.ctx.request.clone().json()) as {
    public_capability: Record<string, unknown>;
  };
  body.public_capability.client_id = String(otherWalletId.value);

  const response = await handleStrictEcdsaSessionActivation({
    ctx: fixture.ctx,
    body,
    source: 'additional_wallet_target',
  });

  expect(response.status).toBe(403);
  expect(fixture.statusInputs).toEqual([]);
});
