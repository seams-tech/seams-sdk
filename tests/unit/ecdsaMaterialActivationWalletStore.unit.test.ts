import { expect, test } from '@playwright/test';
import { createWalletStore } from '../../packages/sdk-server-ts/src/core/WalletStore';
import { normalizeLogger } from '../../packages/sdk-server-ts/src/core/logger';
import type { CloudflareRouterApiContext } from '../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter';
import { handleThresholdEcdsa } from '../../packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa';
import { buildVerifiedFactorEvidenceSet } from '../../packages/sdk-server-ts/src/authorization/factorEvidence';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseRouterAbMpcMaterialActivationRef,
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_GRANT_PATH } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { buildPasskeyAuthorizationSessionFixture } from './helpers/authorizationCore.fixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';

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

type RouteSideEffects = {
  proofVerifications: number;
  otpConsumptions: number;
  evidenceWrites: number;
  grantWrites: number;
  claims: number;
  audits: number;
  quotaWrites: number;
};

function emptyRouteSideEffects(): RouteSideEffects {
  return {
    proofVerifications: 0,
    otpConsumptions: 0,
    evidenceWrites: 0,
    grantWrites: 0,
    claims: 0,
    audits: 0,
    quotaWrites: 0,
  };
}

function digest(seed: number): string {
  return parseDigestB64u(Buffer.from(new Uint8Array(32).fill(seed)).toString('base64url'));
}

async function stepUpRouteFixture(input: {
  signer: ReturnType<typeof createWalletEcdsaSignerRecord>;
  requestedActivation: RouterAbMpcMaterialActivationRefWire;
  sideEffects: RouteSideEffects;
}): Promise<CloudflareRouterApiContext> {
  const nowMs = Date.now();
  const walletId = String(input.signer.walletId);
  const sessionFixture = await buildPasskeyAuthorizationSessionFixture({
    tenantId: 'tenant-material-activation',
    principalId: 'principal-material-activation',
    sessionId: 'session-material-activation',
    deviceId: 'device-material-activation',
    walletId,
    credentialIdB64u: 'credential-material-activation',
    rpId: 'app.example.test',
    origin: 'https://app.example.test',
    expiresAtMs: nowMs + 50_000,
  });
  const capability = input.signer.walletKey.publicCapability;
  const requestBody = {
    kind: 'router_ab_ecdsa_operation_step_up_grant_v1',
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
    `https://app.example.test${ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_GRANT_PATH}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.test' },
      body: JSON.stringify(requestBody),
    },
  );
  const rawClaims = {
    kind: 'app_session_v1',
    sub: 'principal-material-activation',
    appSessionVersion: 'app-session-version-1',
    seamsSessionId: 'session-material-activation',
    walletId,
    walletAuthAuthorityRef: sessionFixture.authorityRef,
    runtimePolicyScope: {
      orgId: 'tenant-material-activation',
      projectId: 'project-material-activation',
      envId: 'env-material-activation',
      signingRootVersion: input.signer.walletKey.signingRootVersion,
    },
    tenantId: 'tenant-material-activation',
    exp: Math.floor((nowMs + 50_000) / 1_000),
  };
  return {
    request,
    url: new URL(request.url),
    pathname: ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_GRANT_PATH,
    method: 'POST',
    logger: normalizeLogger(),
    service: {
      walletRegistration: {
        async resolveEcdsaMaterialActivation({ materialActivation }) {
          return sameRouterAbMpcMaterialActivationRef(
            capability.material_activation,
            materialActivation,
          )
            ? { ok: true, materialActivation: capability.material_activation }
            : {
                ok: false,
                code: 'not_found',
                message: 'ECDSA material activation is not active for this wallet',
              };
        },
      },
      authorizationSessions: {
        tenantId: sessionFixture.session.tenantId,
        async readActiveSession() {
          return sessionFixture.session;
        },
      },
      authorizationClaims: {
        tenantId: sessionFixture.session.tenantId,
        async recordVerifiedFactorEvidenceSet(evidenceInput) {
          input.sideEffects.evidenceWrites += 1;
          return buildVerifiedFactorEvidenceSet(evidenceInput);
        },
        async issueGrant() {
          input.sideEffects.grantWrites += 1;
        },
        async claimOperationStepUpFromGrant() {
          input.sideEffects.claims += 1;
          throw new Error('claim must not run while issuing a step-up grant');
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
  } as unknown as CloudflareRouterApiContext;
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

test('operation step-up issues one grant for the exact canonical material ref', async () => {
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
  expect(sideEffects.grantWrites).toBe(1);
  expect(sideEffects.otpConsumptions).toBe(0);
  expect(sideEffects.claims).toBe(0);
  expect(sideEffects.audits).toBe(0);
  expect(sideEffects.quotaWrites).toBe(0);
});
