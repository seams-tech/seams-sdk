import { expect, test } from '@playwright/test';
import { createWalletStore } from '../../packages/wallet-server/src/core/WalletStore';
import { normalizeLogger } from '../../packages/wallet-server/src/core/logger';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import { handleThresholdEcdsa } from '../../packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa';
import { buildVerifiedWalletOperationFactorEvidenceSet } from '../../packages/wallet-server/src/authorization/factorEvidence';
import { buildAuthorizedOperation } from '../../packages/wallet-server/src/authorization/domain';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseRouterAbMpcMaterialActivationRef,
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { buildPasskeyWalletSessionIssuanceFixture } from './helpers/authorizationCore.fixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';
import { buildRouterAbEcdsaWalletSessionClaimsFixture } from './helpers/routerAbEcdsaWalletSessionClaims.fixtures';

type MaterialActivationField = keyof RouterAbMpcMaterialActivationRefWire;

const MATERIAL_ACTIVATION_FIELDS: readonly MaterialActivationField[] = [
  'kind',
  'activation_id',
  'capability',
  'material_owner',
  'key_binding',
  'lifecycle_binding',
  'signing_worker',
];

function fixtureWalletId() {
  const parsed = parseWalletId('wallet-material-activation-store');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function corruptMaterialActivation(
  activation: RouterAbMpcMaterialActivationRefWire,
  field: MaterialActivationField,
): RouterAbMpcMaterialActivationRefWire {
  return parseRouterAbMpcMaterialActivationRef({
    ...activation,
    [field]: field === 'kind' ? 'mpc_material_activation_ref' : `mismatched-${field}`,
  });
}

function normalSigningScopeWithMaterialActivation(
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
  materialActivation: RouterAbMpcMaterialActivationRefWire,
): RouterAbEcdsaDerivationNormalSigningScopeV1 {
  return {
    wallet_id: scope.wallet_id,
    ecdsa_threshold_key_id: scope.ecdsa_threshold_key_id,
    signing_root_id: scope.signing_root_id,
    signing_root_version: scope.signing_root_version,
    context: scope.context,
    public_identity: scope.public_identity,
    material_activation: materialActivation,
    signing_worker: scope.signing_worker,
    activation_epoch: scope.activation_epoch,
  };
}

type RouteSideEffects = {
  proofVerifications: number;
  otpConsumptions: number;
  evidenceWrites: number;
  admissions: number;
  claims: number;
  audits: number;
  quotaWrites: number;
  runtimeCalls: number;
};

function emptyRouteSideEffects(): RouteSideEffects {
  return {
    proofVerifications: 0,
    otpConsumptions: 0,
    evidenceWrites: 0,
    admissions: 0,
    claims: 0,
    audits: 0,
    quotaWrites: 0,
    runtimeCalls: 0,
  };
}

function digest(seed: number): string {
  return parseDigestB64u(Buffer.from(new Uint8Array(32).fill(seed)).toString('base64url'));
}

async function stepUpRouteFixture(input: {
  signer: ReturnType<typeof createWalletEcdsaSignerRecord>;
  requestedActivation: RouterAbMpcMaterialActivationRefWire;
  sideEffects: RouteSideEffects;
  materialResolutionQueue?: readonly RouterAbMpcMaterialActivationRefWire[];
}): Promise<FetchRouterApiContext> {
  const nowMs = Date.now();
  const walletId = String(input.signer.walletId);
  const sessionFixture = await buildPasskeyWalletSessionIssuanceFixture({
    tenantId: 'tenant-material-activation',
    principalId: 'principal-material-activation',
    walletId,
    credentialIdB64u: 'credential-material-activation',
    rpId: 'app.example.test',
    origin: 'https://app.example.test',
    expiresAtMs: nowMs + 50_000,
  });
  const capability = input.signer.walletKey.publicCapability;
  const materialResolutionQueue = [...(input.materialResolutionQueue ?? [])];
  const requestBody = {
    kind: 'router_ab_ecdsa_operation_step_up_v1',
    operation: {
      wallet_id: walletId,
      operation_kind: 'evm.sign_transaction',
      operation_id: 'operation-material-activation',
      operation_digests: {
        lane_digest_b64u: digest(1),
        intent_digest_b64u: digest(2),
        display_digest_b64u: digest(3),
      },
      material_activation: input.requestedActivation,
      normal_signing_scope: {
        wallet_id: walletId,
        ecdsa_threshold_key_id: input.signer.walletKey.ecdsaThresholdKeyId,
        signing_root_id: input.signer.walletKey.signingRootId,
        signing_root_version: input.signer.walletKey.signingRootVersion,
        context: capability.context,
        public_identity: capability.public_identity,
        material_activation: capability.material_activation,
        signing_worker: capability.signer_set.selected_server,
        activation_epoch: capability.activation_epoch,
      },
      signing_worker_id: input.requestedActivation.signing_worker,
      key_handle: input.signer.walletKey.keyHandle,
      relayer_key_id: input.signer.walletKey.relayerKeyId,
      participant_ids: input.signer.walletKey.participantIds,
      expires_at_ms: nowMs + 40_000,
    },
    proof: {
      kind: 'passkey',
      authority: sessionFixture.authority,
      webauthn_authentication: {
        id: 'credential-material-activation',
        rawId: 'credential-material-activation',
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: 'client-data',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: null,
        },
        clientExtensionResults: null,
      },
    },
  };
  const request = new Request(
    `https://app.example.test${ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH}`,
    {
      method: 'POST',
      headers: {
        authorization: 'Bearer opaque-wallet-session',
        'content-type': 'application/json',
        origin: 'https://app.example.test',
      },
      body: JSON.stringify(requestBody),
    },
  );
  const runtimePolicyScope = {
      orgId: 'tenant-material-activation',
      projectId: 'project-material-activation',
      envId: 'env-material-activation',
      signingRootVersion: input.signer.walletKey.signingRootVersion,
  };
  const rawClaims = buildRouterAbEcdsaWalletSessionClaimsFixture({
    walletId,
    keyHandle: input.signer.walletKey.keyHandle,
    relayerKeyId: input.signer.walletKey.relayerKeyId,
    participantIds: input.signer.walletKey.participantIds,
    thresholdExpiresAtMs: nowMs + 50_000,
    runtimePolicyScope,
    normalSigningScope: requestBody.operation.normal_signing_scope,
    authorizationId: 'authorization-material-activation',
    authorizationSessionId: 'wallet-session-material-activation',
    walletSessionId: 'wallet-session-material-activation',
    quotaId: 'quota-material-activation',
    walletAuthAuthorityRef: sessionFixture.authorityRef,
    authSource: {
      kind: 'passkey',
      credentialIdB64u: sessionFixture.authority.factor.credentialIdB64u,
    },
  });
  return {
    request,
    url: new URL(request.url),
    pathname: ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH,
    method: 'POST',
    logger: normalizeLogger(),
    service: {
      walletRegistration: {
        async resolveEcdsaMaterialActivation({ materialActivation }) {
          const queued = materialResolutionQueue.shift();
          if (queued) {
            return {
              ok: true,
              materialActivation: queued,
              keyHandle: input.signer.walletKey.keyHandle,
              relayerKeyId: input.signer.walletKey.relayerKeyId,
              participantIds: input.signer.walletKey.participantIds,
            };
          }
          return sameRouterAbMpcMaterialActivationRef(
            capability.material_activation,
            materialActivation,
          )
            ? {
                ok: true,
                materialActivation: capability.material_activation,
                keyHandle: input.signer.walletKey.keyHandle,
                relayerKeyId: input.signer.walletKey.relayerKeyId,
                participantIds: input.signer.walletKey.participantIds,
              }
            : {
                ok: false,
                code: 'not_found',
                message: 'ECDSA material activation is not active for this wallet',
              };
        },
      },
      walletAuthMethods: {
        async verifyActivePasskeyAuthority() {
          return { ok: true as const };
        },
      },
      authorizationSessions: {
        tenantId: sessionFixture.session.tenantId,
        async resolveOpaqueWalletSessionToken() {
          return {
            kind: 'resolved_opaque_wallet_session_token' as const,
            curve: 'ecdsa' as const,
            binding: rawClaims,
            authorization: {
              tenantId: sessionFixture.session.tenantId,
              principalId: sessionFixture.session.principalId,
              walletId: input.signer.walletId,
              authorityDigest: sessionFixture.authorityRef.authorityDigest,
              authorizationId: 'authorization-material-activation',
              walletSessionId: 'wallet-session-material-activation',
              quotaId: 'quota-material-activation',
              expiresAtMs: nowMs + 50_000,
            },
            quota: {
              kind: 'active_wallet_session_quota' as const,
              tenantId: sessionFixture.session.tenantId,
              principalId: sessionFixture.session.principalId,
              walletSessionId: 'wallet-session-material-activation',
              quotaId: 'quota-material-activation',
              lifecycle: 'active' as const,
              remainingUses: 3,
              expiresAtMs: nowMs + 50_000,
            },
          };
        },
      },
      authorizedOperations: {
        tenantId: sessionFixture.session.tenantId,
        async recordVerifiedWalletOperationFactorEvidenceSet(evidenceInput) {
          input.sideEffects.evidenceWrites += 1;
          return buildVerifiedWalletOperationFactorEvidenceSet(evidenceInput);
        },
        async readAuthorizedOperation() {
          return null;
        },
        /* Refactor 90's single atomic admission: material validation and the
           claim are one step, so a material the wallet no longer names is
           refused here rather than after a separate grant write. */
        async admitAuthorizedOperation({ operation, material }) {
          if (
            !material ||
            material.walletId !== input.signer.walletId ||
            !sameRouterAbMpcMaterialActivationRef(
              material.materialActivation,
              capability.material_activation,
            )
          ) {
            return { kind: 'material_mismatch' as const };
          }
          input.sideEffects.admissions += 1;
          return {
            kind: 'claimed' as const,
            operation: await buildAuthorizedOperation(operation),
          };
        },
        async completeAuthorizedOperation() {
          throw new Error('an admitted step-up operation must not complete on this route');
        },
      },
      webAuthn: {
        async verifyWebAuthnAuthenticationLite() {
          input.sideEffects.proofVerifications += 1;
          return { success: true, verified: true };
        },
      },
      emailOtp: {
        async consumeEmailOtpGrant() {
          input.sideEffects.otpConsumptions += 1;
          throw new Error('OTP consumption is not expected for a Passkey proof');
        },
      },
      thresholdRuntime: {
        getRouterAbEcdsaPresignRuntime() {
          return {
            async initializePoolFill() {
              input.sideEffects.runtimeCalls += 1;
              throw new Error('pool fill must not initialize before canonical material');
            },
            async advancePoolFill() {
              input.sideEffects.runtimeCalls += 1;
              throw new Error('pool fill must not advance before canonical material');
            },
          };
        },
      },
    },
    opts: {
      session: {
        async parse() {
          return { ok: true, claims: rawClaims };
        },
      },
    },
    mePath: '/me',
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
}

test('wallet store resolves ECDSA signers only by the exact material activation ref', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const store = createWalletStore({ logger: normalizeLogger(), isNode: true });
  await store.putSigner(signer);

  await expect(
    store.getEcdsaSignerByMaterialActivation({
      walletId,
      materialActivation: signer.walletKey.publicCapability.material_activation,
    }),
  ).resolves.toEqual(signer);

  for (const field of MATERIAL_ACTIVATION_FIELDS) {
    if (field === 'kind') continue;
    await expect(
      store.getEcdsaSignerByMaterialActivation({
        walletId,
        materialActivation: corruptMaterialActivation(
          signer.walletKey.publicCapability.material_activation,
          field,
        ),
      }),
      `mutating ${field} must fail closed`,
    ).resolves.toBeNull();
  }
});

test('operation step-up rejects every hostile material-ref mutation before side effects', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  for (const field of MATERIAL_ACTIVATION_FIELDS) {
    if (field === 'kind') continue;
    const sideEffects = emptyRouteSideEffects();
    const response = await handleThresholdEcdsa(
      await stepUpRouteFixture({
        signer,
        requestedActivation: corruptMaterialActivation(
          signer.walletKey.publicCapability.material_activation,
          field,
        ),
        sideEffects,
      }),
    );
    expect(response?.status, `${field} mutation must fail closed`).toBe(403);
    expect(sideEffects).toEqual(emptyRouteSideEffects());
  }
});

test('operation step-up rejects a key handle outside the canonical signer', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const sideEffects = emptyRouteSideEffects();
  const ctx = await stepUpRouteFixture({
    signer,
    requestedActivation: signer.walletKey.publicCapability.material_activation,
    sideEffects,
  });
  const body = (await ctx.request.json()) as {
    operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  };
  ctx.request = new Request(ctx.request.url, {
    method: 'POST',
      headers: {
        authorization: 'Bearer opaque-wallet-session',
        'content-type': 'application/json',
        origin: 'https://app.example.test',
      },
    body: JSON.stringify({
      ...body,
      operation: { ...body.operation, key_handle: 'hostile-key-handle' },
    }),
  });

  const response = await handleThresholdEcdsa(ctx);
  expect(response?.status).toBe(403);
  expect(sideEffects).toEqual(emptyRouteSideEffects());
});

test('operation step-up rejects hostile signer runtime facts before side effects', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  for (const operationOverride of [
    { signing_worker_id: 'hostile-signing-worker' },
    { relayer_key_id: 'hostile-relayer-key' },
    { participant_ids: [2, 3] as const },
  ]) {
    const sideEffects = emptyRouteSideEffects();
    const ctx = await stepUpRouteFixture({
      signer,
      requestedActivation: signer.walletKey.publicCapability.material_activation,
      sideEffects,
    });
    const body = (await ctx.request.json()) as {
      operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
    };
    ctx.request = new Request(ctx.request.url, {
      method: 'POST',
      headers: {
        authorization: 'Bearer opaque-wallet-session',
        'content-type': 'application/json',
        origin: 'https://app.example.test',
      },
      body: JSON.stringify({
        ...body,
        operation: { ...body.operation, ...operationOverride },
      }),
    });

    const response = await handleThresholdEcdsa(ctx);
    expect(response?.status).toBe(403);
    expect(sideEffects).toEqual(emptyRouteSideEffects());
  }
});

test('operation step-up admits one authorized operation for the exact canonical material ref', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const sideEffects = emptyRouteSideEffects();
  const response = await handleThresholdEcdsa(
    await stepUpRouteFixture({
      signer,
      requestedActivation: signer.walletKey.publicCapability.material_activation,
      sideEffects,
    }),
  );

  expect(response?.status).toBe(200);
  expect(sideEffects.proofVerifications).toBe(1);
  expect(sideEffects.evidenceWrites).toBe(1);
  expect(sideEffects.admissions).toBe(1);
  expect(sideEffects.otpConsumptions).toBe(0);
  expect(sideEffects.claims).toBe(0);
  expect(sideEffects.audits).toBe(0);
  expect(sideEffects.quotaWrites).toBe(0);
});

test('operation step-up rejects a material replacement before proof, evidence, or admission', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const canonicalActivation = signer.walletKey.publicCapability.material_activation;
  const replacementActivation = corruptMaterialActivation(canonicalActivation, 'activation_id');
  const sideEffects = emptyRouteSideEffects();
  const response = await handleThresholdEcdsa(
    await stepUpRouteFixture({
      signer,
      requestedActivation: canonicalActivation,
      materialResolutionQueue: [canonicalActivation, replacementActivation],
      sideEffects,
    }),
  );

  expect(response?.status).toBe(403);
  expect(sideEffects.proofVerifications).toBe(0);
  expect(sideEffects.otpConsumptions).toBe(0);
  expect(sideEffects.evidenceWrites).toBe(0);
  expect(sideEffects.admissions).toBe(0);
  expect(sideEffects.claims).toBe(0);
  expect(sideEffects.audits).toBe(0);
  expect(sideEffects.quotaWrites).toBe(0);
  expect(sideEffects.runtimeCalls).toBe(0);
});

test('operation step-up prepare and finalize reject superseded material before claims', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const canonicalActivation = signer.walletKey.publicCapability.material_activation;
  const supersededActivation = corruptMaterialActivation(canonicalActivation, 'activation_id');
  const capability = signer.walletKey.publicCapability;
  const nowMs = Date.now();
  const scope = {
    wallet_id: String(walletId),
    ecdsa_threshold_key_id: signer.walletKey.ecdsaThresholdKeyId,
    signing_root_id: signer.walletKey.signingRootId,
    signing_root_version: signer.walletKey.signingRootVersion,
    context: capability.context,
    public_identity: capability.public_identity,
    material_activation: supersededActivation,
    signing_worker: capability.signer_set.selected_server,
    activation_epoch: capability.activation_epoch,
  };
  const authorization = {
    kind: 'operation_step_up' as const,
  };
  const prepare = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope,
    requestId: 'operation-step-up-superseded-prepare',
    operationId: 'operation-step-up-superseded-operation',
    operationDigests: {
      lane_digest_b64u: digest(4),
      intent_digest_b64u: digest(5),
      display_digest_b64u: digest(6),
    },
    authorization,
    materialActivation: supersededActivation,
    clientPresignatureId: 'client-presignature-superseded',
    expiresAtMs: nowMs + 40_000,
    signingDigest32: new Uint8Array(32).fill(5),
    clientRerandomizationCommitment32: new Uint8Array(32).fill(0x31),
  });
  const finalize = buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1({
    scope,
    requestId: prepare.request_id,
    operationId: 'operation-step-up-superseded-operation',
    operationDigests: prepare.operation_digests,
    authorization,
    materialActivation: supersededActivation,
    expiresAtMs: prepare.expires_at_ms,
    signingDigest32: new Uint8Array(32).fill(5),
    serverPresignatureId: prepare.client_presignature_id,
    clientSignatureShare32: new Uint8Array(32).fill(0x51),
    clientRerandomizationContribution32: new Uint8Array(32).fill(0x41),
  });

  for (const [pathname, body] of [
    [ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH, prepare],
    [ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH, finalize],
  ] as const) {
    const sideEffects = emptyRouteSideEffects();
    const ctx = await stepUpRouteFixture({
      signer,
      requestedActivation: supersededActivation,
      sideEffects,
    });
    ctx.request = new Request(`https://app.example.test${pathname}`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer opaque-wallet-session',
        'content-type': 'application/json',
        origin: 'https://app.example.test',
      },
      body: JSON.stringify(body),
    });
    ctx.url = new URL(ctx.request.url);
    ctx.pathname = pathname;
    ctx.opts.routerAbNormalSigningAdmission = {
      async evaluatePolicy() {
        sideEffects.audits += 1;
        return { ok: true };
      },
      async evaluate() {
        sideEffects.audits += 1;
        return { ok: true };
      },
    };

    const response = await handleThresholdEcdsa(ctx);
    expect(response?.status).toBe(403);
    expect(sideEffects).toEqual(emptyRouteSideEffects());
  }
});

test('operation step-up rejects material replaced during policy evaluation', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const canonicalActivation = signer.walletKey.publicCapability.material_activation;
  const replacementActivation = corruptMaterialActivation(canonicalActivation, 'activation_id');
  const capability = signer.walletKey.publicCapability;
  const request = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope: {
      wallet_id: String(walletId),
      ecdsa_threshold_key_id: signer.walletKey.ecdsaThresholdKeyId,
      signing_root_id: signer.walletKey.signingRootId,
      signing_root_version: signer.walletKey.signingRootVersion,
      context: capability.context,
      public_identity: capability.public_identity,
      material_activation: canonicalActivation,
      signing_worker: capability.signer_set.selected_server,
      activation_epoch: capability.activation_epoch,
    },
    requestId: 'operation-step-up-policy-race-prepare',
    operationId: 'operation-step-up-policy-race-operation',
    operationDigests: {
      lane_digest_b64u: digest(7),
      intent_digest_b64u: digest(7),
      display_digest_b64u: digest(9),
    },
    authorization: {
      kind: 'operation_step_up',
    },
    materialActivation: canonicalActivation,
    clientPresignatureId: 'client-presignature-policy-race',
    expiresAtMs: Date.now() + 40_000,
    signingDigest32: new Uint8Array(32).fill(7),
    clientRerandomizationCommitment32: new Uint8Array(32).fill(0x37),
  });
  const sideEffects = emptyRouteSideEffects();
  const ctx = await stepUpRouteFixture({
    signer,
    requestedActivation: canonicalActivation,
    materialResolutionQueue: [canonicalActivation, replacementActivation],
    sideEffects,
  });
  ctx.request = new Request(
    `https://app.example.test${ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH}`,
    {
      method: 'POST',
      headers: {
        authorization: 'Bearer opaque-wallet-session',
        'content-type': 'application/json',
        origin: 'https://app.example.test',
      },
      body: JSON.stringify(request),
    },
  );
  ctx.url = new URL(ctx.request.url);
  ctx.pathname = ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH;
  ctx.opts.routerAbNormalSigningAdmission = {
    async evaluatePolicy() {
      return { ok: true };
    },
    async evaluate() {
      throw new Error('ECDSA must never reserve legacy admission quota');
    },
  };

  const response = await handleThresholdEcdsa(ctx);
  expect(response?.status).toBe(403);
  expect(sideEffects).toEqual(emptyRouteSideEffects());
});

test('pool-fill rejects hostile material refs before claims or runtime calls', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const canonicalActivation = signer.walletKey.publicCapability.material_activation;
  const supersededActivation = corruptMaterialActivation(canonicalActivation, 'activation_id');
  const mismatchedPoolActivation = corruptMaterialActivation(
    canonicalActivation,
    'lifecycle_binding',
  );

  for (const testCase of [
    {
      name: 'operation-step-up init pool scope',
      authorizationKind: 'operation_step_up' as const,
      pathname: ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
      operationActivation: canonicalActivation,
      poolActivation: mismatchedPoolActivation,
      claimsActivation: canonicalActivation,
    },
    {
      name: 'operation-step-up step operation',
      authorizationKind: 'operation_step_up' as const,
      pathname: ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
      operationActivation: supersededActivation,
      poolActivation: canonicalActivation,
      claimsActivation: canonicalActivation,
    },
    {
      name: 'reusable init pool scope',
      authorizationKind: 'reusable_wallet_session' as const,
      pathname: ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
      operationActivation: canonicalActivation,
      poolActivation: mismatchedPoolActivation,
      claimsActivation: canonicalActivation,
    },
    {
      name: 'reusable step signed claims',
      authorizationKind: 'reusable_wallet_session' as const,
      pathname: ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
      operationActivation: canonicalActivation,
      poolActivation: canonicalActivation,
      claimsActivation: supersededActivation,
    },
  ]) {
    const sideEffects = emptyRouteSideEffects();
    const ctx = await stepUpRouteFixture({
      signer,
      requestedActivation: testCase.operationActivation,
      sideEffects,
    });
    const grantBody = (await ctx.request.clone().json()) as {
      operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
    };
    const operation = grantBody.operation;
    const reusableScope = normalSigningScopeWithMaterialActivation(
      operation.normal_signing_scope,
      testCase.claimsActivation,
    );
    const authorization =
      testCase.authorizationKind === 'operation_step_up'
        ? { kind: 'operation_step_up' as const }
        : { kind: 'reusable_wallet_session' as const, wallet_session_id: 'wallet-session-pool' };
    const body =
      testCase.pathname === ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH
        ? {
            sessionKind: 'jwt',
            count: 1,
            poolFill: {
              kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
              scope: normalSigningScopeWithMaterialActivation(
                operation.normal_signing_scope,
                testCase.poolActivation,
              ),
              expiresAtMs: Date.now() + 40_000,
            },
            authorization,
            ...(testCase.authorizationKind === 'operation_step_up' ? { operation } : {}),
          }
        : {
            sessionKind: 'jwt',
            presignSessionId: 'presign-session-hostile',
            stage: 'triples',
            authorization,
            ...(testCase.authorizationKind === 'operation_step_up' ? { operation } : {}),
          };
    if (testCase.authorizationKind === 'reusable_wallet_session') {
      const claims = buildRouterAbEcdsaWalletSessionClaimsFixture({
        walletId: String(walletId),
        keyHandle: signer.walletKey.keyHandle,
        relayerKeyId: signer.walletKey.relayerKeyId,
        participantIds: signer.walletKey.participantIds,
        thresholdExpiresAtMs: Date.now() + 50_000,
        runtimePolicyScope: {
          orgId: 'tenant-material-activation',
          projectId: 'project-material-activation',
          envId: 'env-material-activation',
          signingRootVersion: signer.walletKey.signingRootVersion,
        },
        normalSigningScope: reusableScope,
        authorizationSessionId: 'authorization-session-pool',
        walletSessionId: 'wallet-session-pool',
        quotaId: 'wallet-quota-pool',
        thresholdSessionId: 'threshold-session-pool',
      });
      ctx.opts.session = {
        async parse() {
          return { ok: true, claims };
        },
      };
    }
    ctx.request = new Request(`https://app.example.test${testCase.pathname}`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer opaque-wallet-session',
        'content-type': 'application/json',
        origin: 'https://app.example.test',
      },
      body: JSON.stringify(body),
    });
    ctx.url = new URL(ctx.request.url);
    ctx.pathname = testCase.pathname;

    const response = await handleThresholdEcdsa(ctx);
    expect(response?.status, testCase.name).toBe(403);
    expect(sideEffects, testCase.name).toEqual(emptyRouteSideEffects());
  }
});

test('operation step-up pool fill rejects a material replacement before claim or runtime calls', async () => {
  const walletId = fixtureWalletId();
  const signer = createWalletEcdsaSignerRecord({ walletId, now: 1_900_000_000_000 });
  const canonicalActivation = signer.walletKey.publicCapability.material_activation;
  const replacementActivation = corruptMaterialActivation(canonicalActivation, 'activation_id');
  const sideEffects = emptyRouteSideEffects();
  const ctx = await stepUpRouteFixture({
    signer,
    requestedActivation: canonicalActivation,
    materialResolutionQueue: [canonicalActivation, replacementActivation],
    sideEffects,
  });
  const grantBody = (await ctx.request.clone().json()) as {
    operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  };
  const operation = grantBody.operation;
  const body = {
    sessionKind: 'jwt',
    count: 1,
    poolFill: {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
      scope: operation.normal_signing_scope,
      expiresAtMs: Date.now() + 40_000,
    },
    authorization: {
      kind: 'operation_step_up' as const,
    },
    operation,
  };
  ctx.request = new Request(
    `https://app.example.test${ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH}`,
    {
      method: 'POST',
      headers: {
        authorization: 'Bearer opaque-wallet-session',
        'content-type': 'application/json',
        origin: 'https://app.example.test',
      },
      body: JSON.stringify(body),
    },
  );
  ctx.url = new URL(ctx.request.url);
  ctx.pathname = ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH;

  const response = await handleThresholdEcdsa(ctx);
  expect(response?.status).toBe(403);
  expect(sideEffects).toEqual(emptyRouteSideEffects());
});
