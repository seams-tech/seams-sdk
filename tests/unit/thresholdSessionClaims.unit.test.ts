import { expect, test } from '@playwright/test';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
} from '@server/core/ThresholdService/validation';
import {
  buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap,
  signRouterAbEcdsaDerivationWalletSessionJwt,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../packages/sdk-server-ts/src/router/commonRouterUtils';
import {
  validateRouterAbEd25519NormalSigningRequestScope,
  validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest,
  validateRouterAbEcdsaDerivationNormalSigningPrepareRequest,
} from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import {
  buildVerifiedEcdsaWalletSessionAuth,
  buildVerifiedEd25519WalletSessionAuth,
} from '../../packages/sdk-server-ts/src/router/verifiedWalletSessionAuth';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/routerApi';
import type { EcdsaDerivationServerBootstrapResponse } from '@server/core/types';
import {
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1,
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  type RouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
import type {
  DerivationClientSharePublicKey33B64u,
  EcdsaRelayerDerivationPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

const passkeyAuthority = buildPasskeyWalletAuthAuthority({
  walletId: 'alice.testnet',
  rpId: 'example.localhost',
  credentialIdB64u: 'credential-id',
});
const evmFamilySigningKeySlotId =
  'wallet-key:evm-family:alice.testnet:signing-root:default';

function baseEd25519Claims() {
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: 'alice.testnet',
    walletId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'alice.testnet',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    relayerKeyId: 'relayer-key-1',
    thresholdExpiresAtMs: Date.now() + 60 * 60 * 1000,
    participantIds: [1, 2],
    authority: passkeyAuthority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(passkeyAuthority),
  };
}

function baseEcdsaClaims() {
  return {
    kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    sub: 'alice.testnet',
    walletId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'alice.testnet',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    relayerKeyId: 'relayer-key-1',
    thresholdExpiresAtMs: Date.now() + 60 * 60 * 1000,
    participantIds: [1, 2],
    evmFamilySigningKeySlotId,
    keyScope: 'evm-family',
    keyHandle: 'ederivation-key-test',
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
    ...baseEd25519Claims(),
    runtimePolicyScope,
    routerAbNormalSigning,
    ...overrides,
  };
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
      ]) as EcdsaRelayerDerivationPublicKey33B64u,
      groupPublicKey33B64u: b64u([0x02, ...Array.from({ length: 32 }, () => 3)]),
      ethereumAddress: '0x1111111111111111111111111111111111111111',
    },
    signingWorkerId: 'signing-worker-1',
    activationEpoch: 'activation-epoch-1',
    ...overrides,
  };
}

function routerAbEcdsaClaims(overrides: Record<string, unknown> = {}) {
  const normalSigning = buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap({
    bootstrap: routerAbEcdsaBootstrap(),
    activationEpoch: 'activation-epoch-1',
    routerAbPublicKeyset,
    signingWorkerId: 'signing-worker-1',
  });
  if (!normalSigning.ok) throw new Error(normalSigning.message);
  return {
    ...baseEcdsaClaims(),
    routerAbEcdsaDerivationNormalSigning: normalSigning.state,
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

function routerAbEcdsaBootstrap(): EcdsaDerivationServerBootstrapResponse {
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
    signingGrantId: 'signing-grant-ecdsa',
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

  test('Router A/B Wallet Session parsers require complete curve-specific state', () => {
    expect(parseRouterAbEd25519WalletSessionClaims(baseEd25519Claims())).toBeNull();
    expect(parseRouterAbEd25519WalletSessionClaims(routerAbEd25519Claims())?.walletId).toBe(
      'alice.testnet',
    );
    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims(baseEcdsaClaims()),
    ).toBeNull();
    expect(
      parseRouterAbEcdsaDerivationWalletSessionClaims({
        ...baseEcdsaClaims(),
        routerAbEcdsaDerivationIssuerBinding: routerAbEcdsaIssuerBinding(),
      }),
    ).toBeNull();
    expect(parseRouterAbEcdsaDerivationWalletSessionClaims(routerAbEcdsaClaims())?.keyHandle).toBe(
      'ederivation-key-test',
    );
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
      validateRouterAbEcdsaDerivationWalletSessionInputs({
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
        authority: passkeyAuthority,
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
        authority: passkeyAuthority,
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
    const ecdsaNormalSigning = buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap({
      bootstrap: ecdsaBootstrap,
      activationEpoch: 'activation-epoch-1',
      routerAbPublicKeyset,
      signingWorkerId: 'signing-worker-1',
    });
    expect(ecdsaNormalSigning).toMatchObject({ ok: true });
    if (!ecdsaNormalSigning.ok) throw new Error(ecdsaNormalSigning.message);

    await expect(
      signRouterAbEcdsaDerivationWalletSessionJwt({
        session,
        userId: 'alice.testnet',
        evmFamilySigningKeySlotId: ecdsaBootstrap.evmFamilySigningKeySlotId,
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
          activationEpoch: 'activation-epoch-1',
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
    expect(signedEcdsaClaims?.routerAbEcdsaDerivationNormalSigning).toEqual(ecdsaNormalSigning.state);
    if (!signedEcdsaClaims?.routerAbEcdsaDerivationNormalSigning) {
      throw new Error('expected Router A/B ECDSA derivation normal-signing claims');
    }
    const signedEcdsaWalletSessionAuth = buildVerifiedEcdsaWalletSessionAuth(signedEcdsaClaims);
    const prepareRequest = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
      scope: ecdsaNormalSigning.state.scope,
      requestId: 'router-ab-ecdsa-sign-test',
      clientPresignatureId: 'client-presignature-test',
      expiresAtMs: ecdsaBootstrap.expiresAtMs,
      signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index),
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
        userId: 'alice.testnet',
        evmFamilySigningKeySlotId: 'wallet-key-alice-testnet',
        relayerKeyId: 'ecdsa-relayer-key-1',
        sessionInfo: {
          sessionKind: 'jwt',
          thresholdSessionId: 'threshold-ecdsa-session',
          signingGrantId: 'signing-grant-ecdsa',
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
      thresholdSessionId: ecdsaBootstrap.thresholdSessionId,
      signingGrantId: ecdsaBootstrap.signingGrantId,
      expiresAtMs: ecdsaBootstrap.expiresAtMs,
      participantIds: ecdsaBootstrap.participantIds,
      runtimePolicyScope,
      keyHandle: ecdsaBootstrap.keyHandle,
      routerAbEcdsaDerivationNormalSigning: undefined,
    };
    await expect(
      signRouterAbEcdsaDerivationWalletSessionJwt({
        session,
        userId: 'alice.testnet',
        evmFamilySigningKeySlotId: ecdsaBootstrap.evmFamilySigningKeySlotId,
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
      clientPresignatureId: 'client-presignature-private-validator',
      expiresAtMs: claims.thresholdExpiresAtMs,
      signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
      clientRerandomizationCommitment32: new Uint8Array(32).fill(0x31),
    });
    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1({
      scope,
      requestId: prepareRequest.request_id,
      budgetReservationId: 'router-ab-ecdsa-private-validator-budget-reservation',
      budgetOperationId: 'router-ab-ecdsa-private-validator-budget-operation',
      expiresAtMs: prepareRequest.expires_at_ms,
      signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
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
          code: 'forbidden',
          message: 'Router A/B ECDSA derivation normal-signing scope does not match Wallet Session claims',
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
          code: 'forbidden',
          message: 'Router A/B ECDSA derivation normal-signing scope does not match Wallet Session claims',
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
          code: 'forbidden',
          message: 'Router A/B ECDSA derivation normal-signing expiry exceeds Wallet Session expiry',
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
          code: 'forbidden',
          message: 'Router A/B ECDSA derivation normal-signing expiry exceeds Wallet Session expiry',
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
});
