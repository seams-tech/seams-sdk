import { expect, test } from '@playwright/test';
import { activateStrictEcdsaPostRegistrationSession } from '@/core/signingEngine/threshold/ecdsa/postRegistrationSessionActivation';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
  type EcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  EcdsaDerivationClientCustomResponseType,
  type EcdsaDerivationClientCustomRequest,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { parseSigningGrantId, parseThresholdEcdsaSessionId } from '@shared/utils/domainIds';
import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

type ActivationFetchState = {
  events: string[];
  requestBody: Record<string, unknown> | null;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  thresholdSessionId: string;
  signingGrantId: string;
};

let activationFetchState: ActivationFetchState | null = null;
let activationRoleLocalMaterial: EcdsaRoleLocalWorkerHandle | null = null;

function requireParsedId<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw new Error('test domain id is invalid');
  return result.value;
}

function appSessionJwt(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ kind: 'app_session_v1', sub: 'activation-test' }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}

async function activationFetchMock(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const state = activationFetchState;
  if (!state) throw new Error('activation fetch state is missing');
  state.events.push('server_activation');
  expect(String(input)).toContain('/router-ab/ecdsa-derivation/session/activate');
  state.requestBody = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
  return new Response(
    JSON.stringify({
      kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
      public_capability: state.publicCapability,
      session: {
        threshold_session_id: state.thresholdSessionId,
        signing_grant_id: state.signingGrantId,
        expires_at_ms: Date.now() + 120_000,
        remaining_uses: 5,
        wallet_session_jwt: 'wallet.session.fixture',
      },
      normal_signing: state.normalSigning,
    }),
    {
      status: 200,
      headers: { 'content-type': 'application/json' },
    },
  );
}

async function activationWorkerRequest(
  request: EcdsaDerivationClientCustomRequest,
): Promise<never> {
  const state = activationFetchState;
  const roleLocalMaterial = activationRoleLocalMaterial;
  if (!state || !roleLocalMaterial) {
    throw new Error('activation worker state is missing');
  }
  state.events.push('rehydrate');
  return {
    type: EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess,
    payload: {
      kind: 'ecdsa_role_local_signing_material_rehydrated_v1',
      roleLocalMaterial,
    },
  } as never;
}

const workerCtx: WorkerOperationContext = {
  requestWorkerOperation: activationWorkerRequest,
};

test('existing-account activation rehydrates registered material without recovery', async () => {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'existing-activation.testnet',
    chain: 'evm',
  });
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (backendBinding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('expected role-local activation fixture');
  }
  const publicFacts: EcdsaRoleLocalPublicFacts =
    backendBinding.ecdsaRoleLocalReadyRecord.publicFacts;
  const publicCapability = publicFacts.publicCapability;
  const normalSigning = bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning;
  if (!normalSigning) throw new Error('expected normal-signing activation fixture');
  const roleLocalMaterial: EcdsaRoleLocalWorkerHandle = {
    kind: 'ecdsa_role_local_worker_handle_v1',
    materialHandle: parseEcdsaRoleLocalMaterialHandle(
      'router-ab-ecdsa-registration:existing-activation',
    ),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(publicFacts.contextBinding32B64u),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(
      'router-ab-ecdsa-registration:existing-activation',
    ),
  };
  const thresholdSessionId = requireParsedId(
    parseThresholdEcdsaSessionId('threshold-ecdsa-existing-activation'),
  );
  const signingGrantId = requireParsedId(parseSigningGrantId('signing-grant-existing-activation'));
  const events: string[] = [];
  activationRoleLocalMaterial = roleLocalMaterial;
  activationFetchState = {
    events,
    requestBody: null,
    publicCapability,
    normalSigning,
    thresholdSessionId,
    signingGrantId,
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = activationFetchMock;

  try {
    const activated = await activateStrictEcdsaPostRegistrationSession({
      relayerUrl: 'https://relay.example',
      routeAuth: { kind: 'app_session', jwt: appSessionJwt() },
      workerCtx,
      publicCapability,
      roleLocalMaterial,
      roleLocalPublicFacts: publicFacts,
      walletId: String(publicFacts.walletId),
      thresholdSessionId,
      signingGrantId,
      ttlMs: 120_000,
      remainingUses: 5,
      runtimePolicyScope: {
        orgId: 'org-test',
        projectId: 'sr-test',
        envId: 'dev',
        signingRootVersion: 'default',
      },
    });

    expect(events).toEqual(['rehydrate', 'server_activation']);
    expect(activated.roleLocalActivation.roleLocalMaterial).toEqual(roleLocalMaterial);
    expect(activationFetchState.requestBody).toEqual({
      kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
      public_capability: publicCapability,
      session_policy: {
        threshold_session_id: thresholdSessionId,
        signing_grant_id: signingGrantId,
        ttl_ms: 120_000,
        remaining_uses: 5,
        runtime_policy_scope: {
          orgId: 'org-test',
          projectId: 'sr-test',
          envId: 'dev',
          signingRootVersion: 'default',
        },
      },
    });
    expect(activationFetchState.requestBody).not.toHaveProperty('recovery_binding');
    expect(activationFetchState.requestBody).not.toHaveProperty('refresh_binding');
    expect(activationFetchState.requestBody).not.toHaveProperty('verified_client_facts');
  } finally {
    globalThis.fetch = originalFetch;
    activationFetchState = null;
    activationRoleLocalMaterial = null;
  }
});
