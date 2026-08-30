import { expect, test } from '@playwright/test';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  projectActiveWalletSession,
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
  type WalletUnlockEcdsaAuthorization,
  type WalletUnlockEcdsaSessionContext,
} from '../../packages/wallet-server/src/router/domains/walletUnlock/walletUnlockRouteHandlers';
import {
  parseWalletUnlockIssuanceRejectionCode,
  type RouterApiWalletUnlockService,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import {
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import { createEcdsaSessionActivationFixture } from './helpers/ecdsaBootstrap.fixtures';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildLinkedDeviceUnlockRuntimeFixture,
  buildWalletRecoveryAuthorityFixture,
} from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture,
  buildActiveMethodBoundPasskeyCustodyEnvelopeFixture,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildEmailOtpEcdsaWalletSessionFixture } from './helpers/linkedDeviceManagement.fixtures';

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
  sessionKind: WalletRegistrationEd25519YaoBootstrapSession['sessionKind'],
): WalletRegistrationEd25519YaoBootstrapSession {
  const runtimePolicyScope = fixture.ed25519Session.runtimePolicyScope;
  const identity = {
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
  if (sessionKind === 'issued_exact_wallet_session') {
    return { ...identity, sessionKind, operationCredential: fixture.operationCredential };
  }
  return { ...identity, sessionKind };
}

type PasskeyCustodyResolution = Awaited<
  ReturnType<Parameters<typeof handleWalletUnlockVerifyRoute>[0]['resolvePasskeyCustody']>
>;

function buildFoundingPasskeyCustodyResolution(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceUnlockRuntimeFixture>>,
): PasskeyCustodyResolution {
  const capability = buildCapability(fixture);
  return {
    custody: {
      kind: 'active',
      envelope: buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
        walletId: String(fixture.walletId),
        envelopeId: 'passkey-envelope-1',
        rpId: String(fixture.authMethod.rpId),
        credentialIdB64u: String(fixture.authMethod.credentialIdB64u),
        walletAuthMethodId: String(fixture.authMethod.walletAuthMethodId),
      }),
      storeVersion: 'founding-runtime-v1',
      keyManifest: {
        version: 'wallet_custody_unlock_key_manifest_v1',
        walletId: fixture.walletId,
        entries: [
          {
            kind: 'near_ed25519',
            keySetId: 'near_ed25519:linked-runtime',
            signerId: 'signer:linked-runtime',
            nearAccountId: fixture.ed25519Session.nearAccountId,
            nearEd25519SigningKeyId: fixture.ed25519Session.nearEd25519SigningKeyId,
            signerSlot: 1,
            registeredPublicKeyB64u: 'founding-runtime-public-key',
            recordedKeyManifestDigestB64u: 'founding-runtime-manifest-digest',
            activeCapabilityBinding: [...capability.activeCapabilityBinding],
          },
        ],
      },
    },
    capability,
  };
}

test('linked Passkey Ed25519 unlock reuses the issued V2 Wallet Session identity', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const linkedWalletSession = buildLinkedWalletSession(fixture);
  let sessionResolution: Awaited<
    ReturnType<RouterApiWalletUnlockService['issueWalletSessionForPasskeyUnlock']>
  > = {
    kind: 'active_authority',
    authorityProvenanceKind: 'device_link',
    walletSession: linkedWalletSession,
    operationCredential: fixture.operationCredential,
  };
  let authorityResolution: Awaited<
    ReturnType<RouterApiWalletUnlockService['resolveActivePasskeyAuthorityForUnlock']>
  > = {
    kind: 'active_authority',
    authority: fixture.authority,
    authMethod: fixture.authMethod,
  };
  let sessionIssueCount = 0;
  const provisioningRequests: Parameters<
    Extract<
      WalletUnlockCapabilityContext,
      { readonly kind: 'passkey_unlock' }
    >['provisionWalletSession']
  >[0][] = [];
  const foundingPasskeyCustody = buildFoundingPasskeyCustodyResolution(fixture);
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
    resolveActivePasskeyAuthorityForUnlock: async () => authorityResolution,
    resolveEmailOtpAuthorityForUnlock: async () => {
      throw new Error('Email OTP is outside this Passkey test');
    },
    issueWalletSessionForPasskeyUnlock: async () => {
      sessionIssueCount += 1;
      return sessionResolution;
    },
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
        session: buildEd25519Session(
          fixture,
          request.authority,
          request.walletSessionIdentity.kind === 'new_wallet_session'
            ? 'issued_exact_wallet_session'
            : 'already_committed_exact_wallet_session',
        ),
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
    resolvePasskeyCustody: async () => foundingPasskeyCustody,
    emitRouterApiWebhook: async () => {},
    emitEmailOtpWebhook: async () => {},
    capabilityContext,
    ecdsaSession: { kind: 'no_ecdsa_session' as const },
    tenantId: required(parseTenantId('tenant:linked-runtime')),
    buildVerifiedOwnerProof,
  } satisfies Omit<Parameters<typeof handleWalletUnlockVerifyRoute>[0], 'body'>;

  const response = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:linked-runtime',
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
    sessionKind: 'already_committed_exact_wallet_session',
    authorizationId: linkedWalletSession.session.authorizationId,
    walletSessionId: linkedWalletSession.session.walletSessionId,
    quotaId: linkedWalletSession.session.quotaId,
  });
  /* The reused branch never carries a second credential: the unlock response
     already delivered the one that admits this exact Wallet Session. */
  expect(response.body.ed25519Session).not.toHaveProperty('operationCredential');
  expect(response.body.ed25519Session).not.toHaveProperty('walletSessionToken');
  expect(response.body.operationCredential).toEqual(fixture.operationCredential);

  const deviceLinkEcdsaActivationFixture = createEcdsaSessionActivationFixture({
    walletId: String(fixture.walletId),
    chain: 'tempo',
    sessionId: 'linked-device-ecdsa-policy',
  });
  const deviceLinkEcdsaSession: WalletUnlockEcdsaSessionContext = {
    kind: 'provision_first_ecdsa_session',
    walletId: String(fixture.walletId),
    policy: parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1({
      kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
      key_handle: 'ecdsa-key:linked-device-ecdsa-policy',
      session_policy: deviceLinkEcdsaActivationFixture.request.session_policy,
    }),
    provisionWalletSession: async () => {
      throw new Error('device-link ECDSA issuance must be rejected before provisioning');
    },
  };
  const deviceLinkEcdsaRejection = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    ecdsaSession: deviceLinkEcdsaSession,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:linked-device-ecdsa-policy',
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'not_requested' },
    },
  });

  expect(deviceLinkEcdsaRejection).toEqual({
    status: 400,
    body: {
      ok: false,
      code: 'invalid_body',
      message: 'ecdsaSessionPolicy is not supported for device-linked wallet unlock',
    },
  });
  expect(sessionIssueCount).toBe(1);

  sessionResolution = { kind: 'wallet_registration' };
  const foundingRegistration = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:founding-runtime',
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'requested', remainingUses: 7 },
    },
  });

  expect(foundingRegistration.status).toBe(200);
  expect(foundingRegistration.body.ed25519Session).toMatchObject({
    sessionKind: 'issued_exact_wallet_session',
    operationCredential: fixture.operationCredential,
  });
  expect(provisioningRequests).toHaveLength(2);
  const foundingRequest = provisioningRequests[1];
  if (!foundingRequest) throw new Error('founding Ed25519 provisioning request was not captured');
  expect(foundingRequest.walletSessionIdentity).toEqual({ kind: 'new_wallet_session' });

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
  expect(provisioningRequests).toHaveLength(2);

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

  const issueCountBeforeEcdsaRecovery = sessionIssueCount;
  authorityResolution = {
    kind: 'active_authority',
    authority: await buildWalletRecoveryAuthorityFixture(fixture),
    authMethod: fixture.authMethod,
  };
  const ecdsaAuthorizationRequests: WalletUnlockEcdsaAuthorization[] = [];
  const ecdsaActivationFixture = createEcdsaSessionActivationFixture({
    walletId: String(fixture.walletId),
    chain: 'tempo',
    sessionId: 'passkey-recovery-ecdsa-only',
  });
  const ecdsaRecoverySession: WalletUnlockEcdsaSessionContext = {
    kind: 'provision_first_ecdsa_session',
    walletId: String(fixture.walletId),
    policy: parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1({
      kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
      key_handle: 'ecdsa-key:passkey-recovery-ecdsa-only',
      session_policy: ecdsaActivationFixture.request.session_policy,
    }),
    provisionWalletSession: async (authorization) => {
      ecdsaAuthorizationRequests.push(authorization);
      return {
        ok: false,
        status: 409,
        code: 'direct_ecdsa_attempted',
        message: 'direct ECDSA issuance reached',
      };
    },
  };
  const ecdsaOnlyRecovery = await handleWalletUnlockVerifyRoute({
    ...routeDependencies,
    ecdsaSession: ecdsaRecoverySession,
    body: {
      unlockBackend: 'passkey',
      challengeId: 'challenge:passkey-recovery-ecdsa-only',
      webauthn_authentication: {},
      ed25519SessionRequest: { kind: 'not_requested' },
    },
  });

  expect(ecdsaOnlyRecovery.status).toBe(409);
  expect(sessionIssueCount).toBe(issueCountBeforeEcdsaRecovery);
  expect(ecdsaAuthorizationRequests).toHaveLength(1);
  expect(ecdsaAuthorizationRequests[0]).toEqual({
    kind: 'verified_wallet_unlock',
    proof: expect.any(Object),
  });
});

test('wallet unlock issuance preserves invalid_body rejection codes', () => {
  expect(parseWalletUnlockIssuanceRejectionCode('invalid_body')).toBe('invalid_body');
});

test('founding Email OTP wallet_session unlock returns its sole direct Wallet Session', async () => {
  const passkeyFixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const emailFixture = await buildEmailOtpEcdsaWalletSessionFixture({
    label: 'founding-email-unlock',
    walletId: String(passkeyFixture.walletId),
    providerUserId: 'founding-email-unlock@example.test',
    expiresAtMs: Date.now() + 60_000,
  });
  const orgId = 'org:founding-email-unlock';
  const challengeId = 'challenge:founding-email-unlock';
  const enrollmentId = 'email-enrollment:founding-email-unlock';
  const enrollmentSealKeyVersion = 'seal-v1';
  const foundingCustody = buildFoundingPasskeyCustodyResolution(passkeyFixture).custody;
  if (foundingCustody.kind !== 'active') {
    throw new Error('founding Email OTP unlock fixture requires active custody');
  }
  const emailOtpEnvelope = buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture({
    walletId: String(emailFixture.authority.walletId),
    envelopeId: 'email-unlock-envelope',
    enrollmentId,
    enrollmentSealKeyVersion,
    walletAuthMethodId: String(emailFixture.authMethod.walletAuthMethodId),
  });
  const emailOtpCustody = {
    kind: 'active' as const,
    envelope: emailOtpEnvelope,
    storeVersion: foundingCustody.storeVersion,
    keyManifest: foundingCustody.keyManifest,
  };
  let directSessionIssueCount = 0;
  let ed25519ProvisionCount = 0;
  const service: RouterApiWalletUnlockService = {
    createEmailOtpUnlockChallenge: async () => {
      throw new Error('challenge creation is outside this test');
    },
    createWebAuthnLoginOptions: async () => {
      throw new Error('WebAuthn is outside this Email OTP test');
    },
    markEmailOtpStrongAuthSatisfied: async ({ walletId }) => ({
      ok: true,
      walletId: String(walletId),
    }),
    verifyEmailOtpUnlockProof: async () => ({
      ok: true,
      verified: true,
      userId: String(emailFixture.authority.walletId),
      walletId: String(emailFixture.authority.walletId),
      providerUserId: String(emailFixture.exactFactorAuthority.factor.providerUserId),
      orgId,
      enrollmentId,
      enrollmentSealKeyVersion,
      unlockKeyVersion: 'unlock-key-v1',
    }),
    verifyWebAuthnLogin: async () => {
      throw new Error('WebAuthn is outside this Email OTP test');
    },
    resolveActivePasskeyAuthorityForUnlock: async () => {
      throw new Error('Passkey is outside this Email OTP test');
    },
    resolveEmailOtpAuthorityForUnlock: async () => ({
      kind: 'active_authority' as const,
      authority: emailFixture.authority,
      walletAuthAuthority: emailFixture.exactFactorAuthority,
      authMethod: emailFixture.authMethod,
    }),
    issueWalletSessionForPasskeyUnlock: async () => {
      throw new Error('Passkey is outside this Email OTP test');
    },
    issueWalletSessionForEmailOtpUnlock: async ({ requestedCapabilities }) => {
      expect(requestedCapabilities).toEqual({ kind: 'wallet_session' });
      directSessionIssueCount += 1;
      return {
        kind: 'active_authority' as const,
        authorityProvenanceKind: 'wallet_registration' as const,
        walletSession: emailFixture.issuedSession,
        operationCredential: emailFixture.operationCredential,
      };
    },
  };
  const capabilityContext: Extract<WalletUnlockCapabilityContext, { readonly kind: 'email_otp' }> =
    {
      kind: 'email_otp',
      request: {
        walletId: String(emailFixture.authority.walletId),
        orgId,
        challengeId,
        requestedCapabilities: { kind: 'wallet_session' },
      },
      provisionWalletSession: async () => {
        ed25519ProvisionCount += 1;
        throw new Error('founding wallet_session unlock must not provision Ed25519');
      },
    };
  const response = await handleWalletUnlockVerifyRoute({
    origin: 'https://wallet.example.test',
    service,
    resolveEmailOtpCustody: async () => emailOtpCustody,
    resolvePasskeyCustody: async () => {
      throw new Error('Passkey is outside this Email OTP test');
    },
    emitRouterApiWebhook: async () => {},
    emitEmailOtpWebhook: async () => {},
    capabilityContext,
    ecdsaSession: { kind: 'no_ecdsa_session' },
    tenantId: required(parseTenantId('tenant:founding-email-unlock')),
    buildVerifiedOwnerProof,
    body: {
      unlockBackend: 'email_otp',
      walletId: String(emailFixture.authority.walletId),
      orgId,
      walletAuthMethodId: String(emailFixture.authMethod.walletAuthMethodId),
      challengeId,
      unlockProof: { publicKey: 'public-key', signature: 'signature' },
      requestedCapabilities: { kind: 'wallet_session' },
    },
  });

  expect(response.status).toBe(200);
  expect(response.body.walletSession).toEqual(
    projectActiveWalletSession(emailFixture.issuedSession),
  );
  expect(response.body.operationCredential).toEqual(emailFixture.operationCredential);
  expect(directSessionIssueCount).toBe(1);
  expect(ed25519ProvisionCount).toBe(0);
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
