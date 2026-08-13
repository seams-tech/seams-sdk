import { expect, test } from '@playwright/test';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
} from '@server/core/ThresholdService/validation';
import {
  buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap,
  signRouterAbEcdsaDerivationWalletSessionJwt,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../packages/sdk-server-ts/src/router/auth/commonRouterUtils';
import {
  validateRouterAbEd25519NormalSigningRequestScope,
  authorizeRouterAbEd25519NormalSigningRoute,
  validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest,
  validateRouterAbEcdsaDerivationNormalSigningPrepareRequest,
  authorizeRouterAbEcdsaDerivationNormalSigningRoute,
} from '../../packages/sdk-server-ts/src/router/domains/signingOperations/routerAbPrivateSigningWorker';
import {
  buildVerifiedEcdsaWalletSessionAuth,
  buildVerifiedEd25519WalletSessionAuth,
} from '../../packages/sdk-server-ts/src/router/auth/verifiedWalletSessionAuth';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/framework/routerApi';
import type { EcdsaDerivationServerBootstrapResponse } from '@server/core/types';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  type RouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
import type {
  DerivationClientSharePublicKey33B64u,
  EcdsaDerivationRelayerPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseRootShareEpoch } from '@shared/utils/domainIds';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { buildRouterAbEcdsaWalletSessionClaimsFixture } from './helpers/routerAbEcdsaWalletSessionClaims.fixtures';
import { buildRouterAbEd25519WalletSessionClaimsFixture } from './helpers/routerAbEd25519WalletSessionClaims.fixtures';

const passkeyAuthority = buildPasskeyWalletAuthAuthority({
  walletId: 'alice.testnet',
  rpId: 'example.localhost',
  credentialIdB64u: 'credential-id',
});
const evmFamilySigningKeySlotId = 'wallet-key:evm-family:alice.testnet:signing-root:default';

function fixtureRootShareEpoch(value: string) {
  const parsed = parseRootShareEpoch(value);
  if (!parsed.ok) throw new Error(`invalid fixture root-share epoch: ${value}`);
  return parsed.value;
}

function b64u(bytes: number[]): string {
  return base64UrlEncode(Uint8Array.from(bytes));
}

const runtimePolicyScope = {
  orgId: 'org',
  projectId: 'proj',
  envId: 'dev',
  signingRootVersion: 'default',
};

const routerAbNormalSigning = {
  kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  signingWorkerId: 'signing-worker-a',
};

const routerAbEd25519MaterialActivation = {
  kind: 'mpc_material_activation_ref' as const,
  activation_id: 'activation-ed25519-1',
  capability: 'capability:ed25519:alice.testnet',
  material_owner: 'alice.testnet',
  key_binding: 'key-binding:ed25519:alice.testnet',
  lifecycle_binding: 'lifecycle:ed25519:alice.testnet',
  signing_worker: 'signing-worker-a',
};

const routerAbEcdsaMaterialActivation = {
  kind: 'mpc_material_activation_ref' as const,
  activation_id: 'activation-ecdsa-1',
  capability: 'capability:ecdsa:alice.testnet',
  material_owner: 'alice.testnet',
  key_binding: 'ederivation-key-test',
  lifecycle_binding: 'lifecycle:ecdsa:alice.testnet',
  signing_worker: 'signing-worker-1',
};

const routerAbOperationDigests = {
  lane_digest_b64u: b64u(Array.from({ length: 32 }, () => 1)),
  intent_digest_b64u: b64u(Array.from({ length: 32 }, () => 1)),
  display_digest_b64u: b64u(Array.from({ length: 32 }, () => 3)),
};

function routerAbEd25519Claims(input: { readonly thresholdExpiresAtMs?: number } = {}) {
  return buildRouterAbEd25519WalletSessionClaimsFixture({
    walletId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'alice.testnet',
    thresholdSessionId: 'threshold-session-1',
    walletSessionId: 'wallet-session-1',
    quotaId: 'wallet-quota-1',
    relayerKeyId: 'relayer-key-1',
    participantIds: [1, 2],
    thresholdExpiresAtMs: input.thresholdExpiresAtMs ?? Date.now() + 60 * 60 * 1000,
    runtimePolicyScope,
    normalSigning: routerAbNormalSigning,
    authority: passkeyAuthority,
  });
}

function routerAbEcdsaIssuerBinding(overrides: Record<string, unknown> = {}) {
  return {
    stableKeyContext: {
      walletId: 'alice.testnet',
      evmFamilySigningKeySlotId,
      keyScope: 'evm-family',
      ecdsaThresholdKeyId: 'ederivation-key-id',
      signingRootId: 'signing-root',
      signingRootVersion: 'default',
      applicationBindingDigestB64u: b64u(Array.from({ length: 32 }, () => 7)),
      contextBinding32B64u: b64u(Array.from({ length: 32 }, (_, index) => index + 1)),
    },
    publicIdentity: {
      derivationClientSharePublicKey33B64u: b64u([
        0x02,
        ...Array.from({ length: 32 }, () => 1),
      ]) as DerivationClientSharePublicKey33B64u,
      relayerPublicKey33B64u: b64u([
        0x03,
        ...Array.from({ length: 32 }, () => 2),
      ]) as EcdsaDerivationRelayerPublicKey33B64u,
      groupPublicKey33B64u: b64u([0x02, ...Array.from({ length: 32 }, () => 3)]),
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    signingWorkerId: 'signing-worker-1',
    activationEpoch: fixtureRootShareEpoch('activation-epoch-1'),
    ...overrides,
  };
}

function routerAbEcdsaClaims() {
  const normalSigning = buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap({
    bootstrap: routerAbEcdsaBootstrap(),
    activationEpoch: fixtureRootShareEpoch('activation-epoch-1'),
    routerAbPublicKeyset,
    signingWorkerId: 'signing-worker-1',
    materialActivation: routerAbEcdsaMaterialActivation,
  });
  if (!normalSigning.ok) throw new Error(normalSigning.message);
  return buildRouterAbEcdsaWalletSessionClaimsFixture({
    walletId: 'alice.testnet',
    keyHandle: 'ederivation-key-test',
    relayerKeyId: 'relayer-key-1',
    participantIds: [1, 2],
    thresholdExpiresAtMs: Date.now() + 60 * 60 * 1000,
    runtimePolicyScope,
    normalSigningScope: normalSigning.state.scope,
    walletSessionId: 'wallet-session-1',
    authorizationSessionId: 'authorization-session-1',
    quotaId: 'wallet-quota-1',
    thresholdSessionId: 'threshold-session-1',
  });
}

const routerAbPublicKeyset = {
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: `x25519:${'11'.repeat(32)}`,
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: `x25519:${'22'.repeat(32)}`,
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: { role: 'signer_a', verifying_key_hex: 'aa'.repeat(32) },
    deriver_b: { role: 'signer_b', verifying_key_hex: 'bb'.repeat(32) },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'signing-worker-output-epoch',
    public_key: `x25519:${'33'.repeat(32)}`,
  },
} satisfies RouterAbPublicKeysetV2;

function routerAbEcdsaBootstrap(): Omit<
  EcdsaDerivationServerBootstrapResponse,
  'routerAbEcdsaDerivationNormalSigning'
> {
  const issuer = routerAbEcdsaIssuerBinding();
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: 'alice.testnet',
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: issuer.stableKeyContext.ecdsaThresholdKeyId,
    relayerKeyId: 'ecdsa-relayer-key-1',
    applicationBindingDigestB64u: issuer.stableKeyContext.applicationBindingDigestB64u,
    contextBinding32B64u: issuer.stableKeyContext.contextBinding32B64u,
    publicIdentity: issuer.publicIdentity,
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 0,
    publicTranscriptDigest32B64u: b64u(Array.from({ length: 32 }, () => 4)),
    keyHandle: 'ederivation-key-test',
    signingRootId: issuer.stableKeyContext.signingRootId,
    signingRootVersion: issuer.stableKeyContext.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: issuer.publicIdentity.groupPublicKey33B64u,
    ethereumAddress: issuer.publicIdentity.ethereumAddress,
    relayerVerifyingShareB64u: issuer.publicIdentity.relayerPublicKey33B64u,
    participantIds: [1, 2],
    thresholdSessionId: 'threshold-ecdsa-session',
    activationEpoch: fixtureRootShareEpoch('activation-epoch-1'),
    expiresAtMs: Date.now() + 60_000,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    remainingUses: 3,
  };
}

test.describe('Router A/B Wallet Session token claims', () => {
  test('preserves Google Email OTP registration attempt claims on app sessions', () => {
    const claims = {
      kind: 'app_session_v1',
      sub: 'google:117142622123955425762',
      appSessionVersion: 'app-v1',
      walletId: 'brisk-shore.testnet',
      googleEmailOtpRegistrationAttemptId: 'attempt-google-register',
      googleEmailOtpResolutionMode: 'register_started',
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'proj',
        envId: 'dev',
        signingRootVersion: 'default',
      },
    };

    expect(parseAppSessionClaims(claims)).toMatchObject({
      sub: 'google:117142622123955425762',
      walletId: 'brisk-shore.testnet',
      googleEmailOtpRegistrationAttemptId: 'attempt-google-register',
      googleEmailOtpResolutionMode: 'register_started',
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'proj',
        envId: 'dev',
        signingRootVersion: 'default',
      },
    });
    expect(
      parseAppSessionClaims({
        ...claims,
        googleEmailOtpResolutionMode: 'invalid',
      }),
    ).toBeNull();
    expect(
      parseAppSessionClaims({
        ...claims,
        googleEmailOtpResolutionMode: undefined,
        googleEmailOtpRegistrationAttemptId: undefined,
      }),
    ).toMatchObject({
      sub: 'google:117142622123955425762',
      walletId: 'brisk-shore.testnet',
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'proj',
        envId: 'dev',
        signingRootVersion: 'default',
      },
    });
    expect(parseAppSessionClaims({ ...claims, googleEmailOtpResolutionMode: '' })).toBeNull();
  });

  test('parses an exact wallet authority reference on passkey app sessions', async () => {
    const authorityRef = await walletAuthAuthorityRef({ authority: passkeyAuthority });
    const claims = {
      kind: 'app_session_v1',
      sub: String(passkeyAuthority.walletId),
      appSessionVersion: 'app-v1',
      walletAuthAuthorityRef: authorityRef,
      runtimePolicyScope: {
        orgId: 'org',
        projectId: 'proj',
        envId: 'dev',
        signingRootVersion: 'default',
      },
    };

    expect(parseAppSessionClaims(claims)?.walletAuthAuthorityRef).toEqual(authorityRef);
    expect(
      parseAppSessionClaims({
        ...claims,
        walletAuthAuthorityRef: { ...authorityRef, unexpected: true },
      }),
    ).toBeNull();
  });

  test('parses an exact wallet authority reference on Email OTP app sessions', async () => {
    const authority = buildEmailOtpWalletAuthAuthority({
      walletId: 'brisk-shore.testnet',
      provider: 'google',
      providerUserId: 'google:117142622123955425762',
      emailHashHex: 'a'.repeat(64),
    });
    const authorityRef = await walletAuthAuthorityRef({ authority });
    const claims = {
      kind: 'app_session_v1',
      sub: 'google:117142622123955425762',
      appSessionVersion: 'app-v1',
      tenantId: 'org',
      seamsSessionId: 'ses_registration_wrc_test',
      walletId: 'brisk-shore.testnet',
      walletAuthAuthorityRef: authorityRef,
      runtimePolicyScope,
    };

    expect(parseAppSessionClaims(claims)?.walletAuthAuthorityRef).toEqual(authorityRef);
    expect(
      parseAppSessionClaims({
        ...claims,
        walletAuthAuthorityRef: { ...authorityRef, unexpected: true },
      }),
    ).toBeNull();
  });

  test('Router A/B Wallet Session parsers require complete curve-specific state', () => {
    const validEd25519Claims = routerAbEd25519Claims();
    expect(
      parseRouterAbEd25519WalletSessionClaims({
        ...validEd25519Claims,
        routerAbNormalSigning: undefined,
      }),
    ).toBeNull();
    expect(parseRouterAbEd25519WalletSessionClaims(routerAbEd25519Claims())?.walletId).toBe(
      'alice.testnet',
    );
    const validEcdsaClaims = routerAbEcdsaClaims();
    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims({
        ...validEcdsaClaims,
        routerAbEcdsaDerivationNormalSigning: undefined,
      }),
    ).toBeNull();
    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims({
        ...validEcdsaClaims,
        routerAbEcdsaDerivationNormalSigning: undefined,
        routerAbEcdsaDerivationIssuerBinding: routerAbEcdsaIssuerBinding(),
      }),
    ).toBeNull();
    expect(parseRouterAbEcdsaDerivationWalletSessionClaims(routerAbEcdsaClaims())?.keyHandle).toBe(
      'ederivation-key-test',
    );
    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims({
        ...validEcdsaClaims,
        sid: 'authorization-session-mismatch',
      }),
    ).toBeNull();
    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims({
        ...routerAbEcdsaClaims(),
        evmFamilySigningKeySlotId,
      }),
    ).toBeNull();
  });

  test('verified Wallet Session auth preserves authorization and threshold identities separately', () => {
    const claims = parseRouterAbEd25519WalletSessionClaims(routerAbEd25519Claims());
    if (!claims) throw new Error('expected Router A/B Ed25519 Wallet Session claims');

    expect(buildVerifiedEd25519WalletSessionAuth(claims)).toMatchObject({
      thresholdSessionId: 'threshold-session-1',
      walletSessionId: 'wallet-session-1',
      quotaId: 'wallet-quota-1',
    });
  });

  test('Router A/B route validators reject missing Wallet Session bearer auth', async () => {
    const missingBearerSession: SessionAdapter = {
      signJwt: async () => 'unused',
      verifyJwt: async () => ({ valid: false as const }),
      parse: async (headers) => {
        expect(headers.authorization || headers.Authorization).toBeUndefined();
        return { ok: false, reason: 'missing' as const };
      },
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };

    await expect(
      validateRouterAbEd25519WalletSessionTokenInputs({
        body: {},
        headers: {},
        session: missingBearerSession,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'wallet_session_missing',
      message: 'Wallet Session is missing',
    });
    await expect(
      validateRouterAbEcdsaDerivationWalletSessionInputs({
        body: {},
        headers: {},
        session: missingBearerSession,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'wallet_session_missing',
      message: 'Wallet Session is missing',
    });
  });

  test('strict Router A/B JWT wrappers require curve-specific signing bindings', async () => {
    const signedPayloads: Record<string, unknown>[] = [];
    const session: SessionAdapter = {
      signJwt: async (sub, extra = {}) => {
        signedPayloads.push({ sub, ...extra });
        return `signed-${signedPayloads.length}`;
      },
      verifyJwt: async () => ({ valid: false as const }),
      parse: async () => ({ ok: false, reason: 'missing' as const }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };
    const ecdsaWalletAuthAuthorityRef = await walletAuthAuthorityRef({
      authority: passkeyAuthority,
    });
    const ecdsaAuthSource = {
      kind: 'passkey' as const,
      credentialIdB64u: passkeyAuthority.factor.credentialIdB64u,
    };
    await expect(
      signRouterAbEd25519WalletSessionJwt({
        session,
        userId: 'alice.testnet',
        authority: passkeyAuthority,
        relayerKeyId: 'relayer-key-1',
        sessionInfo: {
          sessionKind: 'jwt',
          authorizationKind: 'owner_wallet_session',
          walletId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'alice.testnet',
          authorizationId: 'authorization-grant-ed25519',
          walletSessionId: 'wallet-session-ed25519',
          quotaId: 'wallet-quota-ed25519',
          thresholdSessionId: 'threshold-ed25519-session',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          runtimePolicyScope,
          routerAbNormalSigning,
        },
        requireJwtErrorMessage: 'jwt required',
        invalidPayloadErrorMessage: 'invalid ed25519 payload',
      }),
    ).resolves.toMatchObject({ ok: true });

    await expect(
      signRouterAbEd25519WalletSessionJwt({
        session,
        userId: 'alice.testnet',
        authority: passkeyAuthority,
        relayerKeyId: 'relayer-key-1',
        sessionInfo: {
          sessionKind: 'jwt',
          authorizationKind: 'owner_wallet_session',
          walletId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'alice.testnet',
          authorizationId: 'authorization-grant-ed25519',
          walletSessionId: 'wallet-session-ed25519',
          quotaId: 'wallet-quota-ed25519',
          thresholdSessionId: 'threshold-ed25519-session',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          runtimePolicyScope,
          routerAbNormalSigning: undefined,
        },
        requireJwtErrorMessage: 'jwt required',
        invalidPayloadErrorMessage: 'invalid ed25519 payload',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'internal' });

    const ecdsaBootstrap = routerAbEcdsaBootstrap();
    const ecdsaNormalSigning = buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap({
      bootstrap: ecdsaBootstrap,
      activationEpoch: fixtureRootShareEpoch('activation-epoch-1'),
      routerAbPublicKeyset,
      signingWorkerId: 'signing-worker-1',
      materialActivation: routerAbEcdsaMaterialActivation,
    });
    expect(ecdsaNormalSigning).toMatchObject({ ok: true });
    if (!ecdsaNormalSigning.ok) throw new Error(ecdsaNormalSigning.message);

    await expect(
      signRouterAbEcdsaDerivationWalletSessionJwt({
        session,
        walletAuthAuthorityRef: ecdsaWalletAuthAuthorityRef,
        authSource: ecdsaAuthSource,
        userId: 'alice.testnet',
        relayerKeyId: ecdsaBootstrap.relayerKeyId,
        sessionInfo: {
          sessionKind: 'jwt',
          authorizationKind: 'owner_wallet_session',
          authorizationSessionId: 'authorization-session-1',
          authorizationId: 'authorization-grant-ecdsa',
          walletSessionId: 'wallet-session-1',
          quotaId: 'wallet-quota-1',
          thresholdSessionId: ecdsaBootstrap.thresholdSessionId,
          expiresAtMs: ecdsaBootstrap.expiresAtMs,
          participantIds: ecdsaBootstrap.participantIds,
          runtimePolicyScope,
          keyHandle: ecdsaBootstrap.keyHandle,
          ...routerAbEcdsaIssuerBinding(),
          activationEpoch: fixtureRootShareEpoch('activation-epoch-1'),
          routerAbEcdsaDerivationNormalSigning: ecdsaNormalSigning.state,
        },
        requireJwtErrorMessage: 'jwt required',
        invalidPayloadErrorMessage: 'invalid ecdsa payload',
      }),
    ).resolves.toMatchObject({ ok: true });
    expect(
      parseRouterAbEd25519WalletSessionClaims(signedPayloads[0])?.routerAbNormalSigning,
    ).toEqual(routerAbNormalSigning);
    const signedEcdsaClaims = parseRouterAbEcdsaDerivationWalletSessionClaims(signedPayloads[1]);
    expect(signedEcdsaClaims?.routerAbEcdsaDerivationNormalSigning).toEqual(
      ecdsaNormalSigning.state,
    );
    if (!signedEcdsaClaims?.routerAbEcdsaDerivationNormalSigning) {
      throw new Error('expected Router A/B ECDSA derivation normal-signing claims');
    }
    const signedEcdsaWalletSessionAuth = buildVerifiedEcdsaWalletSessionAuth(signedEcdsaClaims);
    const prepareRequest = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
      scope: ecdsaNormalSigning.state.scope,
      requestId: 'router-ab-ecdsa-sign-test',
      operationId: 'router-ab-ecdsa-operation-test',
      operationDigests: routerAbOperationDigests,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: 'wallet-session-1',
      },
      materialActivation: routerAbEcdsaMaterialActivation,
      clientPresignatureId: 'client-presignature-test',
      expiresAtMs: ecdsaBootstrap.expiresAtMs,
      signingDigest32: new Uint8Array(32).fill(1),
      clientRerandomizationCommitment32: new Uint8Array(32).fill(0x31),
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningPrepareRequest({
        claims: signedEcdsaClaims,
        walletSessionAuth: signedEcdsaWalletSessionAuth,
        body: prepareRequest,
      }),
    ).toMatchObject({
      ok: true,
      thresholdSessionId: signedEcdsaClaims.thresholdSessionId,
      requestId: prepareRequest.request_id,
      expiresAtMs: prepareRequest.expires_at_ms,
    });

    await expect(
      signRouterAbEcdsaDerivationWalletSessionJwt({
        session,
        walletAuthAuthorityRef: ecdsaWalletAuthAuthorityRef,
        authSource: ecdsaAuthSource,
        userId: 'alice.testnet',
        relayerKeyId: 'ecdsa-relayer-key-1',
        sessionInfo: {
          sessionKind: 'jwt',
          authorizationKind: 'owner_wallet_session',
          authorizationSessionId: 'authorization-session-1',
          authorizationId: 'authorization-grant-ecdsa',
          walletSessionId: 'wallet-session-1',
          quotaId: 'wallet-quota-1',
          thresholdSessionId: 'threshold-ecdsa-session',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          runtimePolicyScope,
          keyHandle: 'ederivation-key-test',
          stableKeyContext: undefined,
          publicIdentity: undefined,
          activationEpoch: '',
          signingWorkerId: 'signing-worker-1',
          routerAbEcdsaDerivationNormalSigning: undefined,
        },
        requireJwtErrorMessage: 'jwt required',
        invalidPayloadErrorMessage: 'invalid ecdsa payload',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'internal' });
    expect(signedPayloads).toHaveLength(2);

    const issuerBindingOnlySessionInfo = {
      ...routerAbEcdsaIssuerBinding(),
      routerAbEcdsaDerivationIssuerBinding: routerAbEcdsaIssuerBinding(),
      sessionKind: 'jwt' as const,
      authorizationKind: 'owner_wallet_session' as const,
      authorizationSessionId: 'authorization-session-1',
      authorizationId: 'authorization-grant-ecdsa',
      walletSessionId: 'wallet-session-1',
      quotaId: 'wallet-quota-1',
      thresholdSessionId: ecdsaBootstrap.thresholdSessionId,
      expiresAtMs: ecdsaBootstrap.expiresAtMs,
      participantIds: ecdsaBootstrap.participantIds,
      runtimePolicyScope,
      keyHandle: ecdsaBootstrap.keyHandle,
      routerAbEcdsaDerivationNormalSigning: undefined,
    };
    await expect(
      signRouterAbEcdsaDerivationWalletSessionJwt({
        session,
        walletAuthAuthorityRef: ecdsaWalletAuthAuthorityRef,
        authSource: ecdsaAuthSource,
        userId: 'alice.testnet',
        relayerKeyId: ecdsaBootstrap.relayerKeyId,
        sessionInfo: issuerBindingOnlySessionInfo,
        requireJwtErrorMessage: 'jwt required',
        invalidPayloadErrorMessage: 'invalid ecdsa payload',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'internal' });
    expect(signedPayloads).toHaveLength(2);
  });

  test('Router A/B Ed25519 private validators reject scope drift and expired requests', () => {
    const claims = parseRouterAbEd25519WalletSessionClaims(
      routerAbEd25519Claims({ thresholdExpiresAtMs: Date.now() + 60 * 60 * 1000 }),
    );
    expect(claims?.routerAbNormalSigning).toBeTruthy();
    if (!claims) throw new Error('expected Router A/B Ed25519 Wallet Session claims');
    const walletSessionAuth = buildVerifiedEd25519WalletSessionAuth(claims);

    const validBody = {
      scope: {
        request_id: 'router-ab-ed25519-private-validator-prepare',
        account_id: claims.walletId,
        authorization: {
          kind: 'reusable_wallet_session',
          wallet_session_id: claims.walletSessionId,
        },
        material_activation: routerAbEd25519MaterialActivation,
        signing_worker_id: claims.routerAbNormalSigning.signingWorkerId,
      },
      expires_at_ms: claims.thresholdExpiresAtMs,
    };
    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: validBody,
      }),
    ).toMatchObject({
      ok: true,
      thresholdSessionId: claims.thresholdSessionId,
      requestId: validBody.scope.request_id,
      expiresAtMs: validBody.expires_at_ms,
    });

    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: {
          ...validBody,
          scope: { ...validBody.scope, account_id: 'mallory.testnet' },
        },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: {
          ...validBody,
          scope: {
            ...validBody.scope,
            authorization: {
              ...validBody.scope.authorization,
              wallet_session_id: 'substituted-wallet-session',
            },
          },
        },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: {
          ...validBody,
          scope: {
            ...validBody.scope,
            signing_worker_id: 'signing-worker-b',
            material_activation: {
              ...routerAbEd25519MaterialActivation,
              signing_worker: 'signing-worker-b',
            },
          },
        },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: {
          ...validBody,
          expires_at_ms: claims.thresholdExpiresAtMs + 1,
        },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: {
          ...validBody,
          expires_at_ms: 1,
        },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 408,
        body: {
          code: 'expired_request',
          message: 'Router A/B Ed25519 normal-signing request is expired',
        },
      },
    });
  });

  test('Router A/B Ed25519 normal signing rejects substituted active material before admission', async () => {
    const claims = parseRouterAbEd25519WalletSessionClaims(
      routerAbEd25519Claims({ thresholdExpiresAtMs: Date.now() + 60 * 60 * 1000 }),
    );
    if (!claims) throw new Error('expected Router A/B Ed25519 Wallet Session claims');
    const session: SessionAdapter = {
      signJwt: async () => 'unused',
      verifyJwt: async () => ({ valid: false as const }),
      parse: async () => ({ ok: true as const, claims }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };
    let admissions = 0;
    const admissionAdapter = {
      async evaluate() {
        admissions += 1;
        return { ok: true as const };
      },
      async evaluatePolicy() {
        admissions += 1;
        return { ok: true as const };
      },
    };
    const resolveEd25519MaterialActivation = async (input: {
      readonly walletId: string;
      readonly materialActivation: typeof routerAbEd25519MaterialActivation;
    }) =>
      input.walletId === claims.walletId &&
      input.materialActivation.activation_id === routerAbEd25519MaterialActivation.activation_id &&
      input.materialActivation.capability === routerAbEd25519MaterialActivation.capability &&
      input.materialActivation.key_binding === routerAbEd25519MaterialActivation.key_binding &&
      input.materialActivation.lifecycle_binding ===
        routerAbEd25519MaterialActivation.lifecycle_binding
        ? {
            ok: true as const,
            materialActivation: routerAbEd25519MaterialActivation,
            nearAccountId: claims.nearAccountId,
            signerSlot: 1,
            signingWorkerId: claims.routerAbNormalSigning.signingWorkerId,
            participantIds: [1, 2] as const,
          }
        : {
            ok: false as const,
            code: 'not_found' as const,
            message: 'Ed25519 material activation is not active for this wallet',
          };
    const baseBody = {
      sessionKind: 'jwt',
      scope: {
        request_id: 'router-ab-ed25519-material-substitution',
        account_id: claims.walletId,
        authorization: {
          kind: 'reusable_wallet_session' as const,
          wallet_session_id: claims.walletSessionId,
        },
        material_activation: routerAbEd25519MaterialActivation,
        signing_worker_id: claims.routerAbNormalSigning.signingWorkerId,
      },
      expires_at_ms: claims.thresholdExpiresAtMs,
    };
    const substitutions = [
      { activation_id: 'activation-ed25519-substituted' },
      { capability: 'capability:ed25519:substituted' },
      { material_owner: 'mallory.testnet' },
      { key_binding: 'key-binding:ed25519:substituted' },
      { lifecycle_binding: 'lifecycle:ed25519:substituted' },
      { signing_worker: 'signing-worker-substituted' },
    ] as const;
    for (const substitution of substitutions) {
      const substitutedMaterial = {
        ...baseBody.scope.material_activation,
        ...substitution,
      };
      const substitutedScope = {
        ...baseBody.scope,
        material_activation: substitutedMaterial,
        ...('signing_worker' in substitution
          ? { signing_worker_id: substitution.signing_worker }
          : {}),
      };
      const result = await authorizeRouterAbEd25519NormalSigningRoute({
        body: {
          ...baseBody,
          scope: substitutedScope,
        },
        rawBody: baseBody,
        headers: {},
        session,
        authorizedOperations: null,
        authorizationSessions: null,
        admissionAdapter,
        resolveEd25519MaterialActivation,
        phase: 'prepare',
      });
      expect(result).toMatchObject({
        ok: false,
        result: {
          status: 403,
          body: { code: 'wallet_session_scope_mismatch' },
        },
      });
    }
    expect(admissions).toBe(0);
  });

  test('Router A/B ECDSA derivation private validators reject canonical scope drift and expired requests', () => {
    const claims = parseRouterAbEcdsaDerivationWalletSessionClaims(routerAbEcdsaClaims());
    expect(claims?.routerAbEcdsaDerivationNormalSigning).toBeTruthy();
    if (!claims?.routerAbEcdsaDerivationNormalSigning) {
      throw new Error('expected Router A/B ECDSA derivation normal-signing claims');
    }
    const walletSessionAuth = buildVerifiedEcdsaWalletSessionAuth(claims);
    const scope = claims.routerAbEcdsaDerivationNormalSigning.scope;
    const prepareRequest = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
      scope,
      requestId: 'router-ab-ecdsa-private-validator-prepare',
      operationId: 'router-ab-ecdsa-private-validator-operation',
      operationDigests: routerAbOperationDigests,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: claims.walletSessionId,
      },
      materialActivation: routerAbEcdsaMaterialActivation,
      clientPresignatureId: 'client-presignature-private-validator',
      expiresAtMs: claims.thresholdExpiresAtMs,
      signingDigest32: new Uint8Array(32).fill(1),
      clientRerandomizationCommitment32: new Uint8Array(32).fill(0x31),
    });
    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: prepareRequest.request_id,
      operationId: 'router-ab-ecdsa-private-validator-operation',
      operationDigests: routerAbOperationDigests,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: claims.walletSessionId,
      },
      materialActivation: routerAbEcdsaMaterialActivation,
      expiresAtMs: prepareRequest.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(1),
      serverPresignatureId: prepareRequest.client_presignature_id,
      clientSignatureShare32: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
      clientRerandomizationContribution32: new Uint8Array(32).fill(0x41),
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningPrepareRequest({
        claims,
        walletSessionAuth,
        body: prepareRequest,
      }),
    ).toMatchObject({
      ok: true,
      thresholdSessionId: claims.thresholdSessionId,
      requestId: prepareRequest.request_id,
      expiresAtMs: prepareRequest.expires_at_ms,
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest({
        claims,
        walletSessionAuth,
        body: finalizeRequest,
      }),
    ).toMatchObject({
      ok: true,
      thresholdSessionId: claims.thresholdSessionId,
      requestId: finalizeRequest.request_id,
      expiresAtMs: finalizeRequest.expires_at_ms,
    });

    const hostileMaterialActivations = [
      { ...routerAbEcdsaMaterialActivation, activation_id: 'activation-ecdsa-hostile' },
      { ...routerAbEcdsaMaterialActivation, capability: 'capability:ecdsa:hostile' },
      { ...routerAbEcdsaMaterialActivation, material_owner: 'hostile.testnet' },
      { ...routerAbEcdsaMaterialActivation, key_binding: 'hostile-key-binding' },
      { ...routerAbEcdsaMaterialActivation, lifecycle_binding: 'hostile-lifecycle-binding' },
      { ...routerAbEcdsaMaterialActivation, signing_worker: 'signing-worker-hostile' },
    ];
    for (const materialActivation of hostileMaterialActivations) {
      expect(
        validateRouterAbEcdsaDerivationNormalSigningPrepareRequest({
          claims,
          walletSessionAuth,
          body: { ...prepareRequest, material_activation: materialActivation },
        }),
      ).toMatchObject({
        ok: false,
        error: {
          status: 403,
          body: {
            code: 'wallet_session_scope_mismatch',
          },
        },
      });
    }

    const driftedScope = {
      ...scope,
      activation_epoch: 'different-activation-epoch',
    };
    expect(
      validateRouterAbEcdsaDerivationNormalSigningPrepareRequest({
        claims,
        walletSessionAuth,
        body: { ...prepareRequest, scope: driftedScope },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest({
        claims,
        walletSessionAuth,
        body: { ...finalizeRequest, scope: driftedScope },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningPrepareRequest({
        claims,
        walletSessionAuth,
        body: { ...prepareRequest, expires_at_ms: claims.thresholdExpiresAtMs + 1 },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest({
        claims,
        walletSessionAuth,
        body: { ...finalizeRequest, expires_at_ms: claims.thresholdExpiresAtMs + 1 },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'wallet_session_scope_mismatch',
          message: 'Wallet Session scope does not match the request',
        },
      },
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningPrepareRequest({
        claims,
        walletSessionAuth,
        body: { ...prepareRequest, expires_at_ms: 1 },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 408,
        body: {
          code: 'expired_request',
          message: 'Router A/B ECDSA derivation normal-signing request is expired',
        },
      },
    });
    expect(
      validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest({
        claims,
        walletSessionAuth,
        body: { ...finalizeRequest, expires_at_ms: 1 },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 408,
        body: {
          code: 'expired_request',
          message: 'Router A/B ECDSA derivation normal-signing request is expired',
        },
      },
    });
  });

  test('reusable ECDSA prepare and finalize reject superseded material before admission', async () => {
    const claims = parseRouterAbEcdsaDerivationWalletSessionClaims(routerAbEcdsaClaims());
    if (!claims?.routerAbEcdsaDerivationNormalSigning) {
      throw new Error('expected Router A/B ECDSA derivation normal-signing claims');
    }
    const scope = claims.routerAbEcdsaDerivationNormalSigning.scope;
    const prepareRequest = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
      scope,
      requestId: 'router-ab-ecdsa-superseded-prepare',
      operationId: 'router-ab-ecdsa-superseded-operation',
      operationDigests: routerAbOperationDigests,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: claims.walletSessionId,
      },
      materialActivation: routerAbEcdsaMaterialActivation,
      clientPresignatureId: 'client-presignature-superseded',
      expiresAtMs: claims.thresholdExpiresAtMs,
      signingDigest32: new Uint8Array(32).fill(1),
      clientRerandomizationCommitment32: new Uint8Array(32).fill(0x31),
    });
    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: prepareRequest.request_id,
      operationId: 'router-ab-ecdsa-superseded-operation',
      operationDigests: routerAbOperationDigests,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: claims.walletSessionId,
      },
      materialActivation: routerAbEcdsaMaterialActivation,
      expiresAtMs: claims.thresholdExpiresAtMs,
      signingDigest32: new Uint8Array(32).fill(1),
      serverPresignatureId: prepareRequest.client_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(0x51),
      clientRerandomizationContribution32: new Uint8Array(32).fill(0x41),
    });
    const session: SessionAdapter = {
      signJwt: async () => 'unused',
      verifyJwt: async () => ({ valid: false as const }),
      parse: async () => ({ ok: true as const, claims }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };
    let materialLookups = 0;
    let admissions = 0;
    const resolveEcdsaMaterialActivation = async () => {
      materialLookups += 1;
      return {
        ok: false as const,
        code: 'not_found' as const,
        message: 'ECDSA material activation is not active for this wallet',
      };
    };
    const admissionAdapter = {
      async evaluatePolicy() {
        admissions += 1;
        return { ok: true as const };
      },
      async evaluate() {
        admissions += 1;
        return { ok: true as const };
      },
    };

    for (const [phase, body] of [
      ['prepare', prepareRequest],
      ['finalize', finalizeRequest],
    ] as const) {
      await expect(
        authorizeRouterAbEcdsaDerivationNormalSigningRoute({
          body,
          rawBody: body,
          headers: {},
          session,
          authorizedOperations: null,
          authorizationSessions: null,
          admissionAdapter,
          resolveEcdsaMaterialActivation,
          phase,
        }),
      ).resolves.toMatchObject({
        ok: false,
        result: {
          status: 403,
          body: {
            code: 'wallet_session_scope_mismatch',
          },
        },
      });
    }

    expect(materialLookups).toBe(2);
    expect(admissions).toBe(0);
  });
});
