import { expect, test } from '@playwright/test';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { parseTenantId } from '@shared/authorization/capabilityKinds';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  type RouterAbEd25519YaoExportAdmissionReceiptV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportAuthorizationIdentityV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  InMemoryRouterAbEd25519YaoExportService,
  RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter,
  type RouterAbEd25519YaoExportAuthorizationAdapter,
  type RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult,
  type RouterAbEd25519YaoExportBackend,
  type RouterAbEd25519YaoExportBackendResult,
  type RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/export/routerAbEd25519YaoExport';
import {
  handleRouterAbEd25519YaoExportRequestScopedCloudflareV1,
  type RouterAbEd25519YaoExportRequestScopedCloudflareInputV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/export/routerAbEd25519YaoExportRequestScopedCloudflare';
import {
  createRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationStateV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import { partitionRouterAbEd25519YaoProductRegistrationStateV1 } from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitioning';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import type {
  RouterAbEd25519YaoActiveCapabilityDescriptorV1,
  RouterAbEd25519YaoActiveCapabilityLookupResultV1,
  RouterAbEd25519YaoActiveCapabilityResolverV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type {
  RouterApiAuthorizedOperationService,
  RouterApiEmailOtpRouteService,
  RouterApiWalletAuthMethodService,
  RouterApiWalletRegistrationService,
  RouterApiWebAuthnService,
} from '../../packages/wallet-server/src/router/framework/authServicePort';

const WALLET_ID = 'linked-export-wallet.testnet';
const ROUTER_ORIGIN = 'https://router.example.test';
const PARTICIPANT_IDS: readonly [number, number] = [11, 29];
const RUNTIME_POLICY_ORG_ID = 'org-linked-export';
const RUNTIME_POLICY_PROJECT_ID = 'project-linked-export';
const RUNTIME_POLICY_ENV_ID = 'test';
type ExportAuthorizationResult = Awaited<
  ReturnType<RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter['authorize']>
>;

function bytes(seed: number): number[] {
  return new Array<number>(32).fill(seed);
}

function materialActivation(label: string): RouterAbMpcMaterialActivationRefWire {
  return {
    kind: 'mpc_material_activation_ref',
    activation_id: `linked-export-${label}-activation`,
    capability: 'linked-export-capability',
    material_owner: WALLET_ID,
    key_binding: `linked-export-${label}-key`,
    lifecycle_binding: `linked-export-${label}-lifecycle`,
    signing_worker: `linked-export-${label}-worker`,
  };
}

function runtimePolicyScope(label: string) {
  return {
    orgId: RUNTIME_POLICY_ORG_ID,
    projectId: RUNTIME_POLICY_PROJECT_ID,
    envId: RUNTIME_POLICY_ENV_ID,
    signingRootVersion: `linked-export-${label}-root-epoch`,
  } as const;
}

function runtimePolicyScopeForIdentity(identity: RouterAbEd25519YaoExportAuthorizationIdentityV1) {
  return {
    orgId: RUNTIME_POLICY_ORG_ID,
    projectId: RUNTIME_POLICY_PROJECT_ID,
    envId: RUNTIME_POLICY_ENV_ID,
    signingRootVersion: identity.scope.root_share_epoch,
  } as const;
}

async function exportIdentityFixture(
  label: string,
  material: RouterAbMpcMaterialActivationRefWire,
  stateEpoch: number,
): Promise<RouterAbEd25519YaoExportAuthorizationIdentityV1> {
  const scope = runtimePolicyScope(label);
  return {
    scope: {
      lifecycle_id: `linked-export-${label}-lifecycle`,
      root_share_epoch: `linked-export-${label}-root-epoch`,
      account_id: WALLET_ID,
      threshold_session_id: `linked-export-${label}-threshold-session`,
      signer_set_id: `linked-export-${label}-signer-set`,
      signing_worker_id: `linked-export-${label}-worker`,
      material_activation: material,
    },
    application_binding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: 'linked-export-near-key',
      signing_root_id: 'linked-export-signing-root',
      key_creation_signer_slot: 1,
    },
    participant_ids: PARTICIPANT_IDS,
    registered_public_key: bytes(7),
    state_epoch: stateEpoch,
    runtime_policy_binding: await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(scope),
  };
}

function expiredAuthorization(): RouterAbEd25519YaoExportAdmissionRequestV1['authorization'] {
  return {
    confirmation_digest: bytes(1),
    authorization_digest: bytes(2),
    nonce: bytes(3),
    issued_at_ms: 1,
    expires_at_ms: 2,
  };
}

function admissionRequest(
  identity: RouterAbEd25519YaoExportAuthorizationIdentityV1,
): RouterAbEd25519YaoExportAdmissionRequestV1 {
  return {
    ...identity,
    authorization: expiredAuthorization(),
  };
}

function admissionAuthorization() {
  return {
    kind: 'email_otp_factor' as const,
    providerSubjectId: 'google:linked-export-owner',
    challengeId: 'linked-export-challenge',
    otpCode: '123456',
  };
}

function admissionEnvelope(protocol: RouterAbEd25519YaoExportAdmissionRequestV1) {
  return {
    protocol,
    authorization: admissionAuthorization(),
  };
}

async function requestScopedAuthorizationFingerprint(
  identity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        authorizationIdentity: identity,
        authorization: admissionAuthorization(),
      }),
    ),
  );
}

function bytesToHex(value: readonly number[]): string {
  return value.map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function serverAuthorizationIdentity(
  identity: RouterAbEd25519YaoExportAuthorizationIdentityV1,
): RouterAbEd25519YaoExportServerAuthorizationIdentityV1 {
  const parsed = parseThresholdEd25519SessionId(identity.scope.threshold_session_id);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return { thresholdSessionId: parsed.value };
}

function exportAdmissionReceipt(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
): RouterAbEd25519YaoExportAdmissionReceiptV1 {
  return {
    binding: {
      ceremony: {
        lifecycle: {
          lifecycle_id: request.scope.lifecycle_id,
          work_kind: 'key_export',
          primitive_request_kind: 'export',
          root_share_epoch: request.scope.root_share_epoch,
          account_id: request.scope.account_id,
          session_id: request.scope.threshold_session_id,
          signer_set_id: request.scope.signer_set_id,
          selected_server_id: request.scope.signing_worker_id,
        },
        operation: 'export',
        session_id: bytes(10),
        stable_key_context_binding: bytes(11),
        material_activation: request.scope.material_activation,
      },
      registered_public_key: request.registered_public_key,
      state_epoch: request.state_epoch,
      runtime_policy_binding: request.runtime_policy_binding,
      authorization_digest: request.authorization.authorization_digest,
    },
    keyset: {
      deriver_a_input_public_key: bytes(12),
      deriver_b_input_public_key: bytes(13),
      signing_worker_recipient_public_key: bytes(14),
    },
  };
}

function activeCapabilityFixture(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
): RouterAbEd25519YaoActiveCapabilityDescriptorV1 {
  const parsed = parseThresholdEd25519SessionId(request.scope.threshold_session_id);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation: request.scope.material_activation,
    activeCapabilityBinding: bytes(15),
    registeredPublicKey: request.registered_public_key,
    nearAccountId: WALLET_ID,
    applicationBinding: request.application_binding,
    runtimePolicyScope: {
      orgId: RUNTIME_POLICY_ORG_ID,
      projectId: RUNTIME_POLICY_PROJECT_ID,
      envId: RUNTIME_POLICY_ENV_ID,
      signingRootVersion: request.scope.root_share_epoch,
    },
    participantIds: request.participant_ids,
    lifecycle: {
      lifecycleId: request.scope.lifecycle_id,
      rootShareEpoch: request.scope.root_share_epoch,
      accountId: request.scope.account_id,
      thresholdSessionId: parsed.value,
      signerSetId: request.scope.signer_set_id,
      signingWorkerId: request.scope.signing_worker_id,
    },
    stateEpoch: request.state_epoch,
    registrationContinuity: {
      kind: 'recovery',
      activationTranscript: bytes(16),
    },
  };
}

function unavailableDependency(): never {
  throw new Error('export authorization dependency should not run before identity admission');
}

async function unavailableAsyncDependency(): Promise<never> {
  return unavailableDependency();
}

class TargetMaterialActivationResolver {
  constructor(private readonly targetIdentity: RouterAbEd25519YaoExportAuthorizationIdentityV1) {}

  async resolveEd25519MaterialActivation(
    input: Parameters<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>[0],
  ): ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']> {
    return {
      ok: true,
      materialActivation: input.materialActivation,
      nearAccountId: 'linked-export-wallet.testnet',
      signerSlot: 1,
      signingWorkerId: this.targetIdentity.scope.signing_worker_id,
      participantIds: this.targetIdentity.participant_ids,
      runtimePolicyScope: runtimePolicyScopeForIdentity(this.targetIdentity),
      exportIdentity: this.targetIdentity,
    };
  }
}

function exportAuthorizationAdapter(
  targetIdentity: RouterAbEd25519YaoExportAuthorizationIdentityV1,
): RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter {
  const tenantId = parseTenantId('org-linked-export');
  if (!tenantId.ok) throw new Error(tenantId.error.message);

  const webAuthn: Pick<RouterApiWebAuthnService, 'verifyWebAuthnAuthenticationLite'> = {
    verifyWebAuthnAuthenticationLite: unavailableAsyncDependency,
  };
  const emailOtp: Pick<RouterApiEmailOtpRouteService, 'verifyEmailOtpChallenge'> = {
    verifyEmailOtpChallenge: unavailableAsyncDependency,
  };
  const walletAuthMethods: Pick<
    RouterApiWalletAuthMethodService,
    | 'resolveActivePasskeyAuthorityForVerifiedCredential'
    | 'resolveActiveEmailOtpAuthorityForVerifiedSubject'
  > = {
    resolveActivePasskeyAuthorityForVerifiedCredential: unavailableAsyncDependency,
    resolveActiveEmailOtpAuthorityForVerifiedSubject: unavailableAsyncDependency,
  };
  const authorizedOperations: RouterApiAuthorizedOperationService = {
    tenantId: tenantId.value,
    buildVerifiedOwnerProof: unavailableAsyncDependency,
    recordVerifiedWalletOperationFactorEvidenceSet: unavailableAsyncDependency,
    readAuthorizedOperationById: unavailableAsyncDependency,
    readAuthorizedOperation: unavailableAsyncDependency,
    admitAuthorizedOperation: unavailableAsyncDependency,
    completeAuthorizedOperation: unavailableAsyncDependency,
  };
  const resolver = new TargetMaterialActivationResolver(targetIdentity);

  return new RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter(
    webAuthn,
    emailOtp,
    walletAuthMethods,
    authorizedOperations,
    resolver.resolveEd25519MaterialActivation.bind(resolver),
  );
}

async function authorizeAdmission(
  adapter: RouterAbEd25519YaoExportOwnerProofAuthorizationAdapter,
  body: RouterAbEd25519YaoExportAdmissionRequestV1,
): Promise<ExportAuthorizationResult> {
  return await adapter.authorize({
    kind: 'admit',
    request: new Request(`${ROUTER_ORIGIN}/router-ab/ed25519/yao/export/admit`, {
      method: 'POST',
    }),
    body,
    authorization: {
      kind: 'email_otp_factor',
      providerSubjectId: 'google:linked-export-owner',
      challengeId: 'linked-export-challenge',
      otpCode: '123456',
    },
    expectedOrigin: ROUTER_ORIGIN,
  });
}

class CountingExportBackend implements RouterAbEd25519YaoExportBackend {
  admitCalls = 0;
  executeCalls = 0;

  constructor(private readonly receipt: RouterAbEd25519YaoExportAdmissionReceiptV1) {}

  async admitExport(): Promise<RouterAbEd25519YaoExportBackendResult> {
    this.admitCalls += 1;
    return { ok: true, body: this.receipt };
  }

  async executeExport(): Promise<RouterAbEd25519YaoExportBackendResult> {
    this.executeCalls += 1;
    return unavailableAsyncDependency();
  }
}

class CountingCapabilityResolver implements RouterAbEd25519YaoActiveCapabilityResolverV1 {
  calls = 0;
  available = true;

  constructor(private readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1) {}

  async resolveActiveCapability(
    _input: Parameters<RouterAbEd25519YaoActiveCapabilityResolverV1['resolveActiveCapability']>[0],
  ): Promise<RouterAbEd25519YaoActiveCapabilityLookupResultV1> {
    this.calls += 1;
    if (!this.available) {
      return {
        ok: false,
        code: 'unknown_capability',
        message: 'active capability projection is unavailable',
      };
    }
    return { ok: true, capability: this.capability };
  }
}

class StaticExportStateStore implements RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  constructor(private state: RouterAbEd25519YaoProductRegistrationStateV1) {}

  async load(
    lifecycleId: string,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1> {
    const partition = partitionRouterAbEd25519YaoProductRegistrationStateV1(
      this.state,
      lifecycleId,
    );
    return {
      kind: 'router_ab_ed25519_yao_product_registration_partitioned_state_v1',
      state: this.state,
      sharedState: partition.shared,
      sharedVersion: null,
      ceremonyVersion: null,
      execution: null,
      executionVersion: null,
    };
  }

  async commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1> {
    this.state = input.state;
    return {
      kind: 'stored',
      sharedVersion: input.sharedVersion,
      ceremonyVersion: 'static-export-test',
      executionVersion: input.executionVersion,
    };
  }

  async claimRegistrationExecution(
    _input: Parameters<
      RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['claimRegistrationExecution']
    >[0],
  ): ReturnType<
    RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['claimRegistrationExecution']
  > {
    return unavailableAsyncDependency();
  }

  async commitRegistrationExecution(
    _input: Parameters<
      RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['commitRegistrationExecution']
    >[0],
  ): ReturnType<
    RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['commitRegistrationExecution']
  > {
    return unavailableAsyncDependency();
  }

  async consumeRegistrationExecution(
    _input: Parameters<
      RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['consumeRegistrationExecution']
    >[0],
  ): ReturnType<
    RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1['consumeRegistrationExecution']
  > {
    return unavailableAsyncDependency();
  }
}

class DurableRetryAuthorizationAdapter implements RouterAbEd25519YaoExportAuthorizationAdapter {
  authorizeCalls = 0;
  resolveCalls = 0;

  constructor(
    private readonly resolution: RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult,
  ) {}

  async authorize(
    _input: Parameters<RouterAbEd25519YaoExportAuthorizationAdapter['authorize']>[0],
  ): Promise<Awaited<ReturnType<RouterAbEd25519YaoExportAuthorizationAdapter['authorize']>>> {
    this.authorizeCalls += 1;
    return unavailableAsyncDependency();
  }

  async resolveAuthorizationIdentity(
    _request: Request,
  ): Promise<RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult> {
    this.resolveCalls += 1;
    return this.resolution;
  }
}

async function seedAuthorizedExport(
  service: InMemoryRouterAbEd25519YaoExportService,
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  identity: RouterAbEd25519YaoExportServerAuthorizationIdentityV1,
  authorizationFingerprint: string,
): Promise<void> {
  const preparation = service.prepareAuthorizeExport(request, authorizationFingerprint, identity);
  if (preparation.kind !== 'claimed') {
    throw new Error('expected a fresh export authorization claim');
  }
  const committed = service.commitAuthorizeExport({
    request,
    claim: preparation.claim,
    outcome: { ok: true },
  });
  if (!committed.ok) throw new Error(committed.message);
}

async function runScopedAdmission(
  protocol: RouterAbEd25519YaoExportAdmissionRequestV1,
  store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  backend: RouterAbEd25519YaoExportBackend,
  capabilities: RouterAbEd25519YaoActiveCapabilityResolverV1,
  authorization: RouterAbEd25519YaoExportAuthorizationAdapter,
): Promise<Response> {
  const request = new Request(`${ROUTER_ORIGIN}/router-ab/ed25519/yao/export/admit`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ROUTER_ORIGIN,
    },
    body: JSON.stringify(admissionEnvelope(protocol)),
  });
  const input: RouterAbEd25519YaoExportRequestScopedCloudflareInputV1 = {
    request,
    store,
    backend,
    capabilities,
    authorization,
  };
  return await handleRouterAbEd25519YaoExportRequestScopedCloudflareV1(input);
}

async function runDurableRetryCase(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  targetIdentity: RouterAbEd25519YaoExportAuthorizationIdentityV1,
  resolution: RouterAbEd25519YaoExportAuthorizationIdentityResolutionResult,
  expectedStatus: number,
  expectedCode: string,
): Promise<void> {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  const backend = new CountingExportBackend(exportAdmissionReceipt(request));
  const capabilities = new CountingCapabilityResolver(activeCapabilityFixture(request));
  const identity = serverAuthorizationIdentity(targetIdentity);
  const service = new InMemoryRouterAbEd25519YaoExportService(backend, capabilities, state.export);
  await seedAuthorizedExport(
    service,
    request,
    identity,
    await requestScopedAuthorizationFingerprint(identity),
  );
  const authorization = new DurableRetryAuthorizationAdapter(resolution);

  const response = await runScopedAdmission(
    request,
    new StaticExportStateStore(state),
    backend,
    capabilities,
    authorization,
  );

  const responseBody = await response.json();
  expect(response.status).toBe(expectedStatus);
  expect(responseBody).toMatchObject({
    ok: false,
    code: expectedCode,
  });
  expect(authorization.resolveCalls).toBe(1);
  expect(authorization.authorizeCalls).toBe(0);
  expect(backend.admitCalls).toBe(0);
  expect(capabilities.calls).toBe(0);
}

test('linked Ed25519 export admission requires the exact target material identity', async () => {
  const sourceIdentity = await exportIdentityFixture('source', materialActivation('source'), 3);
  const targetIdentity = await exportIdentityFixture('target', materialActivation('target'), 9);
  expect(targetIdentity.scope.lifecycle_id).not.toBe(sourceIdentity.scope.lifecycle_id);
  expect(targetIdentity.scope.material_activation).not.toEqual(
    sourceIdentity.scope.material_activation,
  );
  expect(targetIdentity.state_epoch).not.toBe(sourceIdentity.state_epoch);

  const adapter = exportAuthorizationAdapter(targetIdentity);
  await expect(
    authorizeAdmission(adapter, admissionRequest(targetIdentity)),
  ).resolves.toMatchObject({
    ok: false,
    status: 403,
    code: 'export_authorization_expired',
  });

  await expect(
    authorizeAdmission(adapter, admissionRequest(sourceIdentity)),
  ).resolves.toMatchObject({
    ok: false,
    status: 403,
    code: 'active_identity_mismatch',
  });
});

test('durable authorized export retries resolve the target identity before backend admission', async () => {
  const sourceIdentity = await exportIdentityFixture(
    'retry-source',
    materialActivation('retry-source'),
    3,
  );
  const targetIdentity = await exportIdentityFixture(
    'retry-target',
    materialActivation('retry-target'),
    9,
  );
  const request = admissionRequest(targetIdentity);

  await runDurableRetryCase(
    request,
    targetIdentity,
    {
      ok: true,
      authorizationIdentity: serverAuthorizationIdentity(sourceIdentity),
    },
    409,
    'export_authorization_conflict',
  );
  await runDurableRetryCase(
    request,
    targetIdentity,
    {
      ok: false,
      status: 403,
      code: 'unknown_target_identity',
      message: 'target identity is no longer available',
    },
    403,
    'unknown_target_identity',
  );
});

test('terminal export receipt replay is idempotent without the active projection', async () => {
  const targetIdentity = await exportIdentityFixture('terminal', materialActivation('terminal'), 9);
  const request = admissionRequest(targetIdentity);
  const authorizationIdentity = serverAuthorizationIdentity(targetIdentity);
  const receipt = exportAdmissionReceipt(request);
  const backend = new CountingExportBackend(receipt);
  const capabilities = new CountingCapabilityResolver(activeCapabilityFixture(request));
  const service = new InMemoryRouterAbEd25519YaoExportService(backend, capabilities);

  await seedAuthorizedExport(
    service,
    request,
    authorizationIdentity,
    bytesToHex(request.authorization.authorization_digest),
  );
  const first = await service.admitExport(request, authorizationIdentity);
  expect(first).toMatchObject({ ok: true, status: 200, value: receipt });
  expect(backend.admitCalls).toBe(1);
  expect(capabilities.calls).toBe(1);

  capabilities.available = false;
  const replay = await service.admitExport(request, authorizationIdentity);
  expect(replay).toEqual(first);
  expect(backend.admitCalls).toBe(1);
  expect(capabilities.calls).toBe(1);
});
