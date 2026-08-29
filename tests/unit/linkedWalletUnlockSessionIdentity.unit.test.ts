import { expect, test } from '@playwright/test';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  type DirectV2IssueResult,
  type IssuedWalletSessionAuthorizationV2,
} from '../../packages/wallet-server/src/authorization/domain';
import { buildVerifiedOwnerProof } from '../../packages/wallet-server/src/authorization/factorEvidence';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../packages/wallet-server/src/core/ThresholdService/validation';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../../packages/wallet-server/src/core/registrationContracts';
import {
  handleWalletUnlockVerifyRoute,
  walletUnlockAlreadyCommittedRouteResponse,
  type WalletUnlockCapabilityContext,
} from '../../packages/wallet-server/src/router/domains/walletUnlock/walletUnlockRouteHandlers';
import {
  parseWalletUnlockIssuanceRejectionCode,
  type RouterApiWalletUnlockService,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import {
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
  WALLET_SESSION_CLIENT_CAPABILITY_V1,
} from '@shared/authorization/capabilityKinds';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function buildLinkedWalletSession(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceUnlockRuntimeFixture>>,
): IssuedWalletSessionAuthorizationV2 {
  const tenantId = required(parseTenantId('tenant:linked-runtime'));
  const principalId = required(parsePrincipalId('principal:linked-runtime'));
  const mintId = required(parseWalletSessionMintId('wallet-mint:linked-runtime'));
  const session = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId: fixture.walletId,
    authorityId: fixture.authority.authorityId,
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    authorityDigestB64u: fixture.authority.authorityDigestB64u,
    authorityRevocationEpoch: fixture.authority.revocationEpoch,
    mintId,
    authorizationId: fixture.ed25519Session.authorizationId,
    walletSessionId: fixture.ed25519Session.walletSessionId,
    quotaId: fixture.ed25519Session.quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(fixture.authority),
    createdAtMs: 300,
    expiresAtMs: fixture.ed25519Session.expiresAtMs,
  });
  return {
    session,
    quota: buildActiveWalletSessionQuota({
      tenantId,
      principalId,
      walletSessionId: session.walletSessionId,
      quotaId: session.quotaId,
      remainingUses: fixture.ed25519Session.remainingUses,
      expiresAtMs: session.expiresAtMs,
    }),
  };
}

function buildAlreadyCommittedUnlockResult(
  session: IssuedWalletSessionAuthorizationV2,
): Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }> {
  return {
    kind: 'already_committed',
    walletId: session.session.walletId,
    authorityId: session.session.authorityId,
    walletAuthMethodId: session.session.walletAuthMethodId,
    mintId: session.session.mintId,
    authorizationId: session.session.authorizationId,
    walletSessionId: session.session.walletSessionId,
    quotaId: session.session.quotaId,
    next: 'unlock_exact_method',
  };
}

function buildCapability(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceUnlockRuntimeFixture>>,
): RouterAbEd25519YaoActiveCapabilityDescriptorV1 {
  const activation = fixture.authority.signerActivations.ed25519;
  if (!activation) throw new Error('linked runtime fixture is missing Ed25519 activation');
  const runtimePolicyScope = fixture.ed25519Session.runtimePolicyScope;
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation: routerAbMpcMaterialActivationRefToWire(activation.materialActivation),
    activeCapabilityBinding: [1],
    registeredPublicKey: [2],
    nearAccountId: fixture.ed25519Session.nearAccountId,
    applicationBinding: {
      wallet_id: String(fixture.walletId),
      near_ed25519_signing_key_id: fixture.ed25519Session.nearEd25519SigningKeyId,
      signing_root_id: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
      key_creation_signer_slot: 1,
    },
    runtimePolicyScope,
    participantIds: fixture.ed25519Session.participantIds,
    lifecycle: {
      lifecycleId: 'lifecycle:linked-runtime',
      rootShareEpoch: runtimePolicyScope.signingRootVersion,
      accountId: String(fixture.walletId),
      thresholdSessionId: fixture.ed25519Session.thresholdSessionId,
      signerSetId: 'signer-set:linked-runtime',
      signingWorkerId: fixture.ed25519Session.relayerKeyId,
    },
    stateEpoch: 1,
    registrationContinuity: {
      kind: 'recovery',
      activationTranscript: [3],
    },
  };
}

function buildEd25519Session(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceUnlockRuntimeFixture>>,
  authority: Parameters<typeof thresholdEd25519AuthorityScopeFromWalletAuthAuthority>[0],
): WalletRegistrationEd25519YaoBootstrapSession {
  const runtimePolicyScope = fixture.ed25519Session.runtimePolicyScope;
  return {
    sessionKind: 'reused_wallet_session_v2',
    walletId: fixture.walletId,
    nearAccountId: fixture.ed25519Session.nearAccountId,
    nearEd25519SigningKeyId: fixture.ed25519Session.nearEd25519SigningKeyId,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
    thresholdSessionId: String(fixture.ed25519Session.thresholdSessionId),
    authorizationId: fixture.ed25519Session.authorizationId,
    walletSessionId: fixture.ed25519Session.walletSessionId,
    quotaId: fixture.ed25519Session.quotaId,
    expiresAtMs: fixture.ed25519Session.expiresAtMs,
    participantIds: fixture.ed25519Session.participantIds,
    remainingUses: fixture.ed25519Session.remainingUses,
    signingRootId: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
    signingRootVersion: runtimePolicyScope.signingRootVersion,
    runtimePolicyScope,
    routerAbNormalSigning: fixture.ed25519Session.routerAbNormalSigning,
  };
}

test('linked Passkey Ed25519 unlock reuses the issued V2 Wallet Session identity', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const linkedWalletSession = buildLinkedWalletSession(fixture);
  let sessionResolution: Awaited<
    ReturnType<RouterApiWalletUnlockService['issueWalletSessionForPasskeyUnlock']>
  > = {
    kind: 'active_authority',
    walletSession: linkedWalletSession,
    operationCredential: fixture.operationCredential,
  };
  const provisioningRequests: Parameters<
    Extract<
      WalletUnlockCapabilityContext,
      { readonly kind: 'passkey_unlock' }
    >['provisionWalletSession']
  >[0][] = [];
  const service: RouterApiWalletUnlockService = {
    createEmailOtpUnlockChallenge: async () => {
      throw new Error('Email OTP is outside this Passkey test');
    },
    createWebAuthnLoginOptions: async () => {
      throw new Error('challenge creation is outside this test');
    },
    markEmailOtpStrongAuthSatisfied: async ({ walletId }) => ({
      ok: true,
      walletId: String(walletId),
    }),
    verifyEmailOtpUnlockProof: async () => {
      throw new Error('Email OTP is outside this Passkey test');
    },
    verifyWebAuthnLogin: async () => ({
      ok: true,
      verified: true,
      userId: String(fixture.walletId),
      rpId: String(fixture.authMethod.rpId),
      credentialIdB64u: String(fixture.authMethod.credentialIdB64u),
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      walletAuthorityId: fixture.authMethod.walletAuthorityId,
      ed25519: {
        kind: 'active',
        nearAccountId: fixture.ed25519Session.nearAccountId,
        nearEd25519SigningKeyId: fixture.ed25519Session.nearEd25519SigningKeyId,
        signerSlot: 1,
        publicKey: 'ed25519:linked-runtime',
        relayerKeyId: fixture.ed25519Session.relayerKeyId,
        participantIds: fixture.ed25519Session.participantIds,
      },
    }),
    resolveEmailOtpAuthorityForUnlock: async () => {
      throw new Error('Email OTP is outside this Passkey test');
    },
    issueWalletSessionForPasskeyUnlock: async () => sessionResolution,
    issueWalletSessionForEmailOtpUnlock: async () => {
      throw new Error('Email OTP is outside this Passkey test');
    },
  };
  const capabilityContext: Extract<
    WalletUnlockCapabilityContext,
    { readonly kind: 'passkey_unlock' }
  > = {
    kind: 'passkey_unlock',
    provisionWalletSession: async (request) => {
      provisioningRequests.push(request);
      return {
        ok: true,
        session: buildEd25519Session(fixture, request.authority),
        capability: buildCapability(fixture),
      };
    },
  };

  const routeDependencies = {
    origin: 'https://wallet.example.test',
    service,
    resolveEmailOtpCustody: async () => {
      throw new Error('Email OTP is outside this Passkey test');
    },
    resolvePasskeyCustody: async () => {
      throw new Error('linked Passkey authority does not load wallet-registration custody');
    },
    emitRouterApiWebhook: async () => {},
    emitEmailOtpWebhook: async () => {},
    capabilityContext,
    ecdsaSession: { kind: 'no_ecdsa_session' as const },
    tenantId: required(parseTenantId('tenant:linked-runtime')),
    buildVerifiedOwnerProof,
    resolveEmailOtpAuthority: async () => {
      throw new Error('Email OTP is outside this Passkey test');
    },
  } satisfies Omit<Parameters<typeof handleWalletUnlockVerifyRoute>[0], 'body'>;

  const missingCapabilityResponse = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:linked-runtime',
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'requested', remainingUses: 7 },
    },
  });
  expect(missingCapabilityResponse).toEqual({
    status: 400,
    body: {
      ok: false,
      code: 'invalid_body',
      message: 'walletSessionClientCapability is required',
    },
  });

  const invalidCapabilityResponse = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:linked-runtime',
      walletSessionClientCapability: 'direct_exact_response_future_record_tolerant_v2',
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'requested', remainingUses: 7 },
    },
  });
  expect(invalidCapabilityResponse).toEqual({
    status: 400,
    body: {
      ok: false,
      code: 'invalid_body',
      message: 'walletSessionClientCapability must be direct_exact_response_future_record_tolerant',
    },
  });

  const response = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:linked-runtime',
      walletSessionClientCapability: WALLET_SESSION_CLIENT_CAPABILITY_V1,
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'requested', remainingUses: 7 },
    },
  });

  expect(response.status).toBe(200);
  expect(provisioningRequests).toHaveLength(1);
  const request = provisioningRequests[0];
  if (!request) throw new Error('Ed25519 provisioning request was not captured');
  expect(request.walletSessionIdentity).toEqual({
    kind: 'reuse_wallet_session_v2',
    authorizationId: linkedWalletSession.session.authorizationId,
    walletSessionId: linkedWalletSession.session.walletSessionId,
    quotaId: linkedWalletSession.session.quotaId,
    expiresAtMs: linkedWalletSession.session.expiresAtMs,
    remainingUses: linkedWalletSession.quota.remainingUses,
  });
  expect(response.body.ed25519Session).toMatchObject({
    sessionKind: 'reused_wallet_session_v2',
    authorizationId: linkedWalletSession.session.authorizationId,
    walletSessionId: linkedWalletSession.session.walletSessionId,
    quotaId: linkedWalletSession.session.quotaId,
  });
  /* The reused branch never carries a second credential: the unlock response
     already delivered the one that admits this exact Wallet Session. */
  expect(response.body.ed25519Session).not.toHaveProperty('operationCredential');
  expect(response.body.ed25519Session).not.toHaveProperty('walletSessionToken');
  expect(response.body.operationCredential).toEqual(fixture.operationCredential);

  sessionResolution = {
    kind: 'already_committed',
    authorityProvenanceKind: 'device_link',
    committed: buildAlreadyCommittedUnlockResult(linkedWalletSession),
  };
  const replay = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:linked-runtime',
      walletSessionClientCapability: WALLET_SESSION_CLIENT_CAPABILITY_V1,
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'requested', remainingUses: 7 },
    },
  });

  expect(replay).toMatchObject({
    status: 409,
    body: {
      ok: false,
      unlocked: false,
      code: 'already_committed',
      kind: 'already_committed',
      next: 'unlock_exact_method',
      walletSessionId: linkedWalletSession.session.walletSessionId,
      quotaId: linkedWalletSession.session.quotaId,
    },
  });
  expect(replay.body.operationCredential).toBeUndefined();
  expect(provisioningRequests).toHaveLength(1);

  sessionResolution = {
    kind: 'rejected',
    code: 'invalid_body',
    message: 'verified Email OTP authority identity is required',
  };
  const invalidBodyRejection = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:linked-runtime',
      walletSessionClientCapability: WALLET_SESSION_CLIENT_CAPABILITY_V1,
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'requested', remainingUses: 7 },
    },
  });
  expect(invalidBodyRejection).toEqual({
    status: 403,
    body: {
      ok: false,
      code: 'invalid_body',
      message: 'verified Email OTP authority identity is required',
    },
  });
});

test('wallet unlock issuance preserves invalid_body rejection codes', () => {
  expect(parseWalletUnlockIssuanceRejectionCode('invalid_body')).toBe('invalid_body');
});

test('Email OTP already-committed unlock response is credential-free and retryable', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const committed = buildAlreadyCommittedUnlockResult(buildLinkedWalletSession(fixture));
  const response = walletUnlockAlreadyCommittedRouteResponse({
    unlockBackend: 'email_otp',
    committed,
  });

  expect(response).toMatchObject({
    status: 409,
    body: {
      ok: false,
      unlocked: false,
      unlockBackend: 'email_otp',
      code: 'already_committed',
      kind: 'already_committed',
      next: 'unlock_exact_method',
      walletId: committed.walletId,
      authorityId: committed.authorityId,
      walletAuthMethodId: committed.walletAuthMethodId,
      mintId: committed.mintId,
      authorizationId: committed.authorizationId,
      walletSessionId: committed.walletSessionId,
      quotaId: committed.quotaId,
    },
  });
  expect(response.body.operationCredential).toBeUndefined();
  expect(response.body.walletSession).toBeUndefined();
});
