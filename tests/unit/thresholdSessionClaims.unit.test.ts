import { expect, test } from '@playwright/test';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaHssWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  parseThresholdEcdsaSessionClaims,
  parseThresholdEd25519SessionClaims,
} from '@server/core/ThresholdService/validation';
import {
  buildRouterAbEcdsaHssNormalSigningStateForBootstrap,
  signRouterAbEcdsaHssWalletSessionJwt,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEcdsaHssWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../packages/sdk-server-ts/src/router/commonRouterUtils';
import {
  validateRouterAbEd25519NormalSigningRequestScope,
  validateRouterAbEcdsaHssNormalSigningFinalizeRequest,
  validateRouterAbEcdsaHssNormalSigningPrepareRequest,
} from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import {
  buildVerifiedEcdsaWalletSessionAuth,
  buildVerifiedEd25519WalletSessionAuth,
} from '../../packages/sdk-server-ts/src/router/verifiedWalletSessionAuth';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/relay';
import type { EcdsaHssServerBootstrapResponse } from '@server/core/types';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  buildRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1,
  buildRouterAbEcdsaHssEvmDigestSigningRequestV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  type RouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

function baseClaims(kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v2') {
  const claims = {
    kind,
    sub: 'alice.testnet',
    walletId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'alice.testnet',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    relayerKeyId: 'relayer-key-1',
    rpId: 'example.localhost',
    thresholdExpiresAtMs: Date.now() + 60 * 60 * 1000,
    participantIds: [1, 2],
  };
  if (kind !== 'threshold_ecdsa_session_v2') return claims;
  return {
    ...claims,
    walletKeyId: 'wallet-key-alice',
    keyScope: 'evm-family',
    keyHandle: 'ehss-key-test',
  };
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

function routerAbEd25519Claims(overrides: Record<string, unknown> = {}) {
  return {
    ...baseClaims('threshold_ed25519_session_v1'),
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    runtimePolicyScope,
    routerAbNormalSigning,
    ...overrides,
  };
}

function routerAbEcdsaIssuerBinding(overrides: Record<string, unknown> = {}) {
  return {
    stableKeyContext: {
      walletId: 'alice.testnet',
      walletKeyId: 'wallet-key-alice',
      keyScope: 'evm-family',
      ecdsaThresholdKeyId: 'ehss-key-id',
      signingRootId: 'signing-root',
      signingRootVersion: 'default',
      applicationBindingDigestB64u: b64u(Array.from({ length: 32 }, () => 7)),
      contextBinding32B64u: b64u(Array.from({ length: 32 }, (_, index) => index + 1)),
    },
    publicIdentity: {
      hssClientSharePublicKey33B64u: b64u([
        0x02,
        ...Array.from({ length: 32 }, () => 1),
      ]) as EcdsaHssClientSharePublicKey33B64u,
      relayerPublicKey33B64u: b64u([
        0x03,
        ...Array.from({ length: 32 }, () => 2),
      ]) as EcdsaRelayerHssPublicKey33B64u,
      groupPublicKey33B64u: b64u([0x02, ...Array.from({ length: 32 }, () => 3)]),
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    signingWorkerId: 'signing-worker-1',
    activationEpoch: 'activation-epoch-1',
    ...overrides,
  };
}

function routerAbEcdsaClaims(overrides: Record<string, unknown> = {}) {
  const normalSigning = buildRouterAbEcdsaHssNormalSigningStateForBootstrap({
    bootstrap: routerAbEcdsaBootstrap(),
    routerAbPublicKeyset,
    signingWorkerId: 'signing-worker-1',
  });
  if (!normalSigning.ok) throw new Error(normalSigning.message);
  return {
    ...baseClaims('threshold_ecdsa_session_v2'),
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    routerAbEcdsaHssNormalSigning: normalSigning.state,
    ...overrides,
  };
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

function routerAbEcdsaBootstrap(): EcdsaHssServerBootstrapResponse {
  const issuer = routerAbEcdsaIssuerBinding();
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: 'alice.testnet',
    walletKeyId: 'wallet-key-alice',
    ecdsaThresholdKeyId: issuer.stableKeyContext.ecdsaThresholdKeyId,
    relayerKeyId: 'ecdsa-relayer-key-1',
    applicationBindingDigestB64u: issuer.stableKeyContext.applicationBindingDigestB64u,
    contextBinding32B64u: issuer.stableKeyContext.contextBinding32B64u,
    publicIdentity: issuer.publicIdentity,
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 0,
    publicTranscriptDigest32B64u: b64u(Array.from({ length: 32 }, () => 4)),
    keyHandle: 'ehss-key-test',
    signingRootId: issuer.stableKeyContext.signingRootId,
    signingRootVersion: issuer.stableKeyContext.signingRootVersion,
    thresholdEcdsaPublicKeyB64u: issuer.publicIdentity.groupPublicKey33B64u,
    ethereumAddress: issuer.publicIdentity.ethereumAddress,
    relayerVerifyingShareB64u: issuer.publicIdentity.relayerPublicKey33B64u,
    participantIds: [1, 2],
    thresholdSessionId: 'threshold-ecdsa-session',
    signingGrantId: 'signing-grant-ecdsa',
    expiresAtMs: Date.now() + 60_000,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    remainingUses: 3,
  };
}

test.describe('threshold session auth token claims', () => {
  test('requires explicit walletId on threshold-ed25519 session tokens', () => {
    const claims = baseClaims('threshold_ed25519_session_v1');

    expect(parseThresholdEd25519SessionClaims(claims)?.walletId).toBe('alice.testnet');
    expect(parseThresholdEd25519SessionClaims({ ...claims, walletId: undefined })).toBeNull();
  });

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

  test('requires explicit walletId on threshold-ecdsa session tokens', () => {
    const claims = baseClaims('threshold_ecdsa_session_v2');

    expect(parseThresholdEcdsaSessionClaims(claims)?.walletId).toBe('alice.testnet');
    expect(parseThresholdEcdsaSessionClaims({ ...claims, walletId: undefined })).toBeNull();
  });

  test('requires explicit signingGrantId on threshold session tokens', () => {
    expect(
      parseThresholdEd25519SessionClaims({
        ...baseClaims('threshold_ed25519_session_v1'),
        signingGrantId: undefined,
      }),
    ).toBeNull();
    expect(
      parseThresholdEcdsaSessionClaims({
        ...baseClaims('threshold_ecdsa_session_v2'),
        signingGrantId: undefined,
      }),
    ).toBeNull();
  });

  test('rejects threshold-session tokens where JWT sub and walletId disagree', () => {
    expect(
      parseThresholdEd25519SessionClaims({
        ...baseClaims('threshold_ed25519_session_v1'),
        walletId: 'bob.testnet',
      }),
    ).toBeNull();
    expect(
      parseThresholdEcdsaSessionClaims({
        ...baseClaims('threshold_ecdsa_session_v2'),
        walletId: 'bob.testnet',
      }),
    ).toBeNull();
  });

  test('threshold-ecdsa session tokens require EVM-family key identity claims', () => {
    const claims = baseClaims('threshold_ecdsa_session_v2');

    expect(parseThresholdEcdsaSessionClaims(claims)?.walletId).toBe('alice.testnet');
    expect(parseThresholdEcdsaSessionClaims(claims)?.keyHandle).toBe('ehss-key-test');
    expect(parseThresholdEcdsaSessionClaims(claims)?.keyScope).toBe('evm-family');
    expect(parseThresholdEcdsaSessionClaims({ ...claims, keyScope: undefined })).toBeNull();
    expect(parseThresholdEcdsaSessionClaims({ ...claims, keyHandle: undefined })).toBeNull();
    expect(
      parseThresholdEcdsaSessionClaims({
        ...claims,
        keyScope: 'tempo',
      }),
    ).toBeNull();
  });

  test('Router A/B Wallet Session parsers reject legacy threshold-session kinds', () => {
    expect(
      parseRouterAbEd25519WalletSessionClaims(baseClaims('threshold_ed25519_session_v1')),
    ).toBeNull();
    expect(
      parseRouterAbEcdsaHssWalletSessionClaims(baseClaims('threshold_ecdsa_session_v2')),
    ).toBeNull();

    expect(
      parseRouterAbEd25519WalletSessionClaims({
        ...baseClaims('threshold_ed25519_session_v1'),
        kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      }),
    ).toBeNull();
    expect(parseRouterAbEd25519WalletSessionClaims(routerAbEd25519Claims())?.walletId).toBe(
      'alice.testnet',
    );
    expect(
      parseRouterAbEcdsaHssWalletSessionClaims({
        ...baseClaims('threshold_ecdsa_session_v2'),
        kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
      }),
    ).toBeNull();
    expect(
      parseRouterAbEcdsaHssWalletSessionClaims({
        ...baseClaims('threshold_ecdsa_session_v2'),
        kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
        routerAbEcdsaHssIssuerBinding: routerAbEcdsaIssuerBinding(),
      }),
    ).toBeNull();
    expect(parseRouterAbEcdsaHssWalletSessionClaims(routerAbEcdsaClaims())?.keyHandle).toBe(
      'ehss-key-test',
    );
  });

  test('Router A/B route validators reject legacy threshold-session JWT claims', async () => {
    const ed25519Session: SessionAdapter = {
      signJwt: async () => 'unused',
      parse: async () => ({ ok: true, claims: baseClaims('threshold_ed25519_session_v1') }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };
    const ecdsaSession: SessionAdapter = {
      signJwt: async () => 'unused',
      parse: async () => ({ ok: true, claims: baseClaims('threshold_ecdsa_session_v2') }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };

    await expect(
      validateRouterAbEd25519WalletSessionTokenInputs({
        body: {},
        headers: { authorization: 'Bearer old-ed25519' },
        session: ed25519Session,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'unauthorized' });
    await expect(
      validateRouterAbEcdsaHssWalletSessionInputs({
        body: {},
        headers: { authorization: 'Bearer old-ecdsa' },
        session: ecdsaSession,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'unauthorized' });
  });

  test('Router A/B route validators reject missing Wallet Session bearer auth', async () => {
    const missingBearerSession: SessionAdapter = {
      signJwt: async () => 'unused',
      parse: async (headers) => {
        expect(headers.authorization || headers.Authorization).toBeUndefined();
        return { ok: false };
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
      code: 'unauthorized',
      message: 'Missing or invalid Wallet Session JWT',
    });
    await expect(
      validateRouterAbEcdsaHssWalletSessionInputs({
        body: {},
        headers: {},
        session: missingBearerSession,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid Wallet Session token',
    });
  });

  test('strict Router A/B JWT wrappers require curve-specific signing bindings', async () => {
    const signedPayloads: Record<string, unknown>[] = [];
    const session: SessionAdapter = {
      signJwt: async (sub, extra = {}) => {
        signedPayloads.push({ sub, ...extra });
        return `signed-${signedPayloads.length}`;
      },
      parse: async () => ({ ok: false }),
      buildSetCookie: (token) => `session=${token}`,
      buildClearCookie: () => 'session=',
      refresh: async () => ({ ok: false }),
    };
    await expect(
      signRouterAbEd25519WalletSessionJwt({
        session,
        userId: 'alice.testnet',
        rpId: 'example.localhost',
        relayerKeyId: 'relayer-key-1',
        sessionInfo: {
          sessionKind: 'jwt',
          walletId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'alice.testnet',
          thresholdSessionId: 'threshold-ed25519-session',
          signingGrantId: 'signing-grant-ed25519',
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
        rpId: 'example.localhost',
        relayerKeyId: 'relayer-key-1',
        sessionInfo: {
          sessionKind: 'jwt',
          walletId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          nearEd25519SigningKeyId: 'alice.testnet',
          thresholdSessionId: 'threshold-ed25519-session',
          signingGrantId: 'signing-grant-ed25519',
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
    const ecdsaNormalSigning = buildRouterAbEcdsaHssNormalSigningStateForBootstrap({
      bootstrap: ecdsaBootstrap,
      routerAbPublicKeyset,
      signingWorkerId: 'signing-worker-1',
    });
    expect(ecdsaNormalSigning).toMatchObject({ ok: true });
    if (!ecdsaNormalSigning.ok) throw new Error(ecdsaNormalSigning.message);

    await expect(
      signRouterAbEcdsaHssWalletSessionJwt({
        session,
        userId: 'alice.testnet',
        walletKeyId: ecdsaBootstrap.walletKeyId,
        relayerKeyId: ecdsaBootstrap.relayerKeyId,
        sessionInfo: {
          sessionKind: 'jwt',
          thresholdSessionId: ecdsaBootstrap.thresholdSessionId,
          signingGrantId: ecdsaBootstrap.signingGrantId,
          expiresAtMs: ecdsaBootstrap.expiresAtMs,
          participantIds: ecdsaBootstrap.participantIds,
          runtimePolicyScope,
          keyHandle: ecdsaBootstrap.keyHandle,
          ...routerAbEcdsaIssuerBinding(),
          activationEpoch: ecdsaBootstrap.thresholdSessionId,
          routerAbEcdsaHssNormalSigning: ecdsaNormalSigning.state,
        },
        requireJwtErrorMessage: 'jwt required',
        invalidPayloadErrorMessage: 'invalid ecdsa payload',
      }),
    ).resolves.toMatchObject({ ok: true });
    expect(
      parseRouterAbEd25519WalletSessionClaims(signedPayloads[0])?.routerAbNormalSigning,
    ).toEqual(routerAbNormalSigning);
    const signedEcdsaClaims = parseRouterAbEcdsaHssWalletSessionClaims(signedPayloads[1]);
    expect(signedEcdsaClaims?.routerAbEcdsaHssNormalSigning).toEqual(ecdsaNormalSigning.state);
    if (!signedEcdsaClaims?.routerAbEcdsaHssNormalSigning) {
      throw new Error('expected Router A/B ECDSA-HSS normal-signing claims');
    }
    const signedEcdsaWalletSessionAuth = buildVerifiedEcdsaWalletSessionAuth(signedEcdsaClaims);
    const prepareRequest = buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
      scope: ecdsaNormalSigning.state.scope,
      requestId: 'router-ab-ecdsa-sign-test',
      clientPresignatureId: 'client-presignature-test',
      expiresAtMs: ecdsaBootstrap.expiresAtMs,
      signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index),
    });
    expect(
      validateRouterAbEcdsaHssNormalSigningPrepareRequest({
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
      signRouterAbEcdsaHssWalletSessionJwt({
        session,
        userId: 'alice.testnet',
        walletKeyId: 'wallet-key-alice-testnet',
        relayerKeyId: 'ecdsa-relayer-key-1',
        sessionInfo: {
          sessionKind: 'jwt',
          thresholdSessionId: 'threshold-ecdsa-session',
          signingGrantId: 'signing-grant-ecdsa',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          runtimePolicyScope,
          keyHandle: 'ehss-key-test',
          stableKeyContext: undefined,
          publicIdentity: undefined,
          activationEpoch: '',
          signingWorkerId: 'signing-worker-1',
          routerAbEcdsaHssNormalSigning: undefined,
        },
        requireJwtErrorMessage: 'jwt required',
        invalidPayloadErrorMessage: 'invalid ecdsa payload',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'internal' });
    expect(signedPayloads).toHaveLength(2);

    const issuerBindingOnlySessionInfo = {
      ...routerAbEcdsaIssuerBinding(),
      routerAbEcdsaHssIssuerBinding: routerAbEcdsaIssuerBinding(),
      sessionKind: 'jwt' as const,
      thresholdSessionId: ecdsaBootstrap.thresholdSessionId,
      signingGrantId: ecdsaBootstrap.signingGrantId,
      expiresAtMs: ecdsaBootstrap.expiresAtMs,
      participantIds: ecdsaBootstrap.participantIds,
      runtimePolicyScope,
      keyHandle: ecdsaBootstrap.keyHandle,
      routerAbEcdsaHssNormalSigning: undefined,
    };
    await expect(
      signRouterAbEcdsaHssWalletSessionJwt({
        session,
        userId: 'alice.testnet',
        walletKeyId: ecdsaBootstrap.walletKeyId,
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
        session_id: claims.thresholdSessionId,
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
          code: 'forbidden',
          message: 'Router A/B Ed25519 normal-signing scope does not match Wallet Session claims',
        },
      },
    });
    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: {
          ...validBody,
          scope: { ...validBody.scope, session_id: 'other-threshold-session' },
        },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'forbidden',
          message: 'Router A/B Ed25519 normal-signing scope does not match Wallet Session claims',
        },
      },
    });
    expect(
      validateRouterAbEd25519NormalSigningRequestScope({
        claims,
        walletSessionAuth,
        body: {
          ...validBody,
          scope: { ...validBody.scope, signing_worker_id: 'signing-worker-b' },
        },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'forbidden',
          message: 'Router A/B Ed25519 normal-signing worker does not match Wallet Session claims',
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
          code: 'forbidden',
          message: 'Router A/B Ed25519 normal-signing expiry exceeds Wallet Session expiry',
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

  test('Router A/B ECDSA-HSS private validators reject canonical scope drift and expired requests', () => {
    const claims = parseRouterAbEcdsaHssWalletSessionClaims(routerAbEcdsaClaims());
    expect(claims?.routerAbEcdsaHssNormalSigning).toBeTruthy();
    if (!claims?.routerAbEcdsaHssNormalSigning) {
      throw new Error('expected Router A/B ECDSA-HSS normal-signing claims');
    }
    const walletSessionAuth = buildVerifiedEcdsaWalletSessionAuth(claims);
    const scope = claims.routerAbEcdsaHssNormalSigning.scope;
    const prepareRequest = buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
      scope,
      requestId: 'router-ab-ecdsa-private-validator-prepare',
      clientPresignatureId: 'client-presignature-private-validator',
      expiresAtMs: claims.thresholdExpiresAtMs,
      signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    });
    const finalizeRequest = buildRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1({
      scope,
      requestId: prepareRequest.request_id,
      budgetReservationId: 'router-ab-ecdsa-private-validator-budget-reservation',
      budgetOperationId: 'router-ab-ecdsa-private-validator-budget-operation',
      expiresAtMs: prepareRequest.expires_at_ms,
      signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
      serverPresignatureId: prepareRequest.client_presignature_id,
      clientSignatureShare32: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
    });
    expect(
      validateRouterAbEcdsaHssNormalSigningPrepareRequest({
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
      validateRouterAbEcdsaHssNormalSigningFinalizeRequest({
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

    const driftedScope = {
      ...scope,
      activation_epoch: 'different-activation-epoch',
    };
    expect(
      validateRouterAbEcdsaHssNormalSigningPrepareRequest({
        claims,
        walletSessionAuth,
        body: { ...prepareRequest, scope: driftedScope },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'forbidden',
          message: 'Router A/B ECDSA-HSS normal-signing scope does not match Wallet Session claims',
        },
      },
    });
    expect(
      validateRouterAbEcdsaHssNormalSigningFinalizeRequest({
        claims,
        walletSessionAuth,
        body: { ...finalizeRequest, scope: driftedScope },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'forbidden',
          message: 'Router A/B ECDSA-HSS normal-signing scope does not match Wallet Session claims',
        },
      },
    });
    expect(
      validateRouterAbEcdsaHssNormalSigningPrepareRequest({
        claims,
        walletSessionAuth,
        body: { ...prepareRequest, expires_at_ms: claims.thresholdExpiresAtMs + 1 },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'forbidden',
          message: 'Router A/B ECDSA-HSS normal-signing expiry exceeds Wallet Session expiry',
        },
      },
    });
    expect(
      validateRouterAbEcdsaHssNormalSigningFinalizeRequest({
        claims,
        walletSessionAuth,
        body: { ...finalizeRequest, expires_at_ms: claims.thresholdExpiresAtMs + 1 },
      }),
    ).toMatchObject({
      ok: false,
      error: {
        status: 403,
        body: {
          code: 'forbidden',
          message: 'Router A/B ECDSA-HSS normal-signing expiry exceeds Wallet Session expiry',
        },
      },
    });
    expect(
      validateRouterAbEcdsaHssNormalSigningPrepareRequest({
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
          message: 'Router A/B ECDSA-HSS normal-signing request is expired',
        },
      },
    });
    expect(
      validateRouterAbEcdsaHssNormalSigningFinalizeRequest({
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
          message: 'Router A/B ECDSA-HSS normal-signing request is expired',
        },
      },
    });
  });
});
