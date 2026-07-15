import { expect, test } from '@playwright/test';
import {
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  buildRouterAbEd25519YaoRegistrationCapabilityRecordV1,
  InMemoryRouterAbEd25519YaoRecoveryService,
  createRouterAbEd25519YaoRecoveryModule,
  createRouterAbEd25519YaoRecoveryRuntimePortV1,
  type RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  type RouterAbEd25519YaoRecoveryAuthorizationInput,
  type RouterAbEd25519YaoRecoveryAuthorizationResult,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRecoveryBackendResult,
  type RouterAbEd25519YaoCapabilityPersistenceV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import type { RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1 } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../packages/sdk-server-ts/src/core/WalletStore';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import { coerceRouterLogger } from '../../packages/sdk-server-ts/src/router/logger';

function authorizationClaimsFixture() {
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: 'wallet-1',
    rpId: 'router.example.test',
    credentialIdB64u: 'recovery-credential-id',
  });
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: 'wallet-1',
    walletId: 'wallet-1',
    nearAccountId: 'wallet-1.testnet',
    nearEd25519SigningKeyId: 'ed25519ks_1',
    thresholdSessionId: 'wallet-session-1',
    signingGrantId: 'signing-grant-1',
    relayerKeyId: 'signing-worker-1',
    authority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
    runtimePolicyScope: {
      orgId: 'org-recovery',
      projectId: 'project-recovery',
      envId: 'test',
      signingRootVersion: 'root-epoch-1',
    },
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-1',
    },
  };
}

type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type RecoveryResult = RouterAbEd25519YaoActivationResultV1<'recovery'>;
type RegistrationResult = RouterAbEd25519YaoActivationResultV1<'registration'>;

type ExecutionBehavior =
  | { readonly kind: 'success'; readonly result: RecoveryResult }
  | { readonly kind: 'failure' };

class TestRecoveryBackend implements RouterAbEd25519YaoRecoveryBackend {
  admitCalls = 0;
  executeCalls = 0;
  activateCalls = 0;

  constructor(private readonly executionBehavior: ExecutionBehavior) {}

  admitRecovery(
    request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ): RouterAbEd25519YaoRecoveryBackendResult {
    this.admitCalls += 1;
    return { ok: true, body: recoveryAdmissionReceipt(request) };
  }

  executeRecovery(): RouterAbEd25519YaoRecoveryBackendResult {
    this.executeCalls += 1;
    switch (this.executionBehavior.kind) {
      case 'success':
        return { ok: true, body: this.executionBehavior.result };
      case 'failure':
        return {
          ok: false,
          status: 503,
          code: 'scripted_execution_failure',
          message: 'scripted recovery execution failure',
        };
    }
  }

  activateRecovery(
    request: RouterAbEd25519YaoRecoveryActivationRequestV1,
  ): RouterAbEd25519YaoRecoveryBackendResult {
    this.activateCalls += 1;
    return { ok: true, body: request };
  }
}

class AllowRecoveryAuthorization implements RouterAbEd25519YaoRecoveryAuthorizationAdapter {
  readonly inputs: RouterAbEd25519YaoRecoveryAuthorizationInput[] = [];

  authorize(
    input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  ): RouterAbEd25519YaoRecoveryAuthorizationResult {
    this.inputs.push(input);
    return { ok: true, claims: authorizationClaimsFixture() };
  }
}

class RecordingCapabilityPersistence implements RouterAbEd25519YaoCapabilityPersistenceV1 {
  readonly calls: Array<{
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  }> = [];

  replaceActiveCapability(input: {
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  }) {
    this.calls.push(input);
    return { ok: true } as const;
  }
}

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function requireParsed<T>(parsed: { ok: true; value: T } | { ok: false; message: string }): T {
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function registrationAdmissionRequest(): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
      scope: {
        lifecycle_id: 'registration-1',
        root_share_epoch: 'root-epoch-1',
        account_id: 'wallet-1',
        wallet_session_id: 'wallet-session-1',
        signer_set_id: 'signer-set-1',
        signing_worker_id: 'signing-worker-1',
      },
      application_binding: {
        wallet_id: 'wallet-1',
        near_ed25519_signing_key_id: 'ed25519ks_1',
        signing_root_id: 'project-recovery:test',
        key_creation_signer_slot: 1,
      },
      participant_ids: [1, 2],
    }),
  );
}

function registrationBinding(): Record<string, unknown> {
  return {
    lifecycle: {
      lifecycle_id: 'registration-1',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'root-epoch-1',
      account_id: 'wallet-1',
      session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      selected_server_id: 'signing-worker-1',
    },
    operation: 'registration',
    session_id: bytes(6),
    stable_key_context_binding: bytes(8),
  };
}

function activationClientPackage(
  binding: Record<string, unknown>,
  deriver: 'deriver_a' | 'deriver_b',
): Record<string, unknown> {
  return {
    kind: 'activation_client',
    deriver,
    session: binding.session_id,
    transcript: bytes(11),
    encapsulated_key: bytes(30),
    ciphertext: bytes(31, 16),
  };
}

function registrationResult(): RegistrationResult {
  const binding = registrationBinding();
  return requireParsed(
    parseRouterAbEd25519YaoRegistrationActivationResultV1({
      binding,
      deriver_a_client_package: activationClientPackage(binding, 'deriver_a'),
      deriver_b_client_package: activationClientPackage(binding, 'deriver_b'),
      public_receipt: publicReceipt(1),
    }),
  );
}

function recoveryAdmissionRequest(input?: {
  readonly lifecycleId: string;
  readonly walletSessionId: string;
  readonly activeCapabilitySeed: number;
  readonly replacementCapabilitySeed: number;
  readonly publicKeySeed: number;
}): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const values = input ?? {
    lifecycleId: 'recovery-1',
    walletSessionId: 'wallet-session-1',
    activeCapabilitySeed: 20,
    replacementCapabilitySeed: 21,
    publicKeySeed: 12,
  };
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: values.lifecycleId,
        root_share_epoch: 'root-epoch-1',
        account_id: 'wallet-1',
        wallet_session_id: values.walletSessionId,
        signer_set_id: 'signer-set-1',
        signing_worker_id: 'signing-worker-1',
      },
      application_binding: registrationAdmissionRequest().application_binding,
      participant_ids: [1, 2],
      active_capability_binding: bytes(values.activeCapabilitySeed),
      replacement_capability_binding: bytes(values.replacementCapabilitySeed),
      registered_public_key: bytes(values.publicKeySeed),
    }),
  );
}

function recoveryBinding(request: RouterAbEd25519YaoRecoveryAdmissionRequestV1) {
  return {
    lifecycle: {
      lifecycle_id: request.scope.lifecycle_id,
      work_kind: 'recovery' as const,
      primitive_request_kind: 'recovery' as const,
      root_share_epoch: request.scope.root_share_epoch,
      account_id: request.scope.account_id,
      session_id: request.scope.wallet_session_id,
      signer_set_id: request.scope.signer_set_id,
      selected_server_id: request.scope.signing_worker_id,
    },
    operation: 'recovery' as const,
    session_id: bytes(7),
    stable_key_context_binding: bytes(8),
  };
}

function recoveryAdmissionReceipt(request: RouterAbEd25519YaoRecoveryAdmissionRequestV1) {
  return {
    binding: recoveryBinding(request),
    keyset: {
      deriver_a_input_public_key: bytes(1),
      deriver_b_input_public_key: bytes(2),
      signing_worker_recipient_public_key: bytes(3),
    },
  };
}

function recoveryExecuteRequest(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): RecoveryExecuteRequest {
  const binding = recoveryBinding(request);
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1({
      binding,
      deriver_a_input: encryptedRecoveryInput(binding, 'deriver_a'),
      deriver_b_input: encryptedRecoveryInput(binding, 'deriver_b'),
    }),
  );
}

function encryptedRecoveryInput(
  binding: ReturnType<typeof recoveryBinding>,
  deriver: 'deriver_a' | 'deriver_b',
): Record<string, unknown> {
  return {
    kind: 'activation',
    deriver,
    operation: 'recovery',
    session: binding.session_id,
    stable_context_binding: binding.stable_key_context_binding,
    encapsulated_key: bytes(9),
    ciphertext: bytes(10, 16),
  };
}

function publicReceipt(stateEpoch: number) {
  return publicReceiptForKey(stateEpoch, 12);
}

function publicReceiptForKey(stateEpoch: number, publicKeySeed: number) {
  return {
    transcript: bytes(11),
    registered_public_key: bytes(publicKeySeed),
    joined_client_commitment: bytes(13),
    joined_signing_worker_commitment: bytes(15),
    signing_worker_verifying_share: bytes(15),
    state_epoch: stateEpoch,
  };
}

function recoveryResult(request: RecoveryExecuteRequest): RecoveryResult {
  return recoveryResultForPublicKey(request, 12);
}

function recoveryResultForPublicKey(
  request: RecoveryExecuteRequest,
  publicKeySeed: number,
): RecoveryResult {
  return {
    binding: request.binding,
    deriver_a_client_package: {
      kind: 'activation_client',
      deriver: 'deriver_a',
      session: request.binding.session_id,
      transcript: bytes(11),
      encapsulated_key: bytes(30),
      ciphertext: bytes(31, 16),
    },
    deriver_b_client_package: {
      kind: 'activation_client',
      deriver: 'deriver_b',
      session: request.binding.session_id,
      transcript: bytes(11),
      encapsulated_key: bytes(32),
      ciphertext: bytes(33, 16),
    },
    public_receipt: publicReceiptForKey(2, publicKeySeed),
  };
}

function recoveryActivationRequest(
  result: RecoveryResult,
): RouterAbEd25519YaoRecoveryActivationRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationRequestV1({
      binding: result.binding,
      public_receipt: result.public_receipt,
    }),
  );
}

function registrationCapabilityInstallation(): RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1 {
  return {
    kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
    activeCapabilityBinding: bytes(20),
    nearAccountId: 'wallet-1.testnet',
    registrationAdmissionRequest: registrationAdmissionRequest(),
    registrationResult: registrationResult(),
    runtimePolicyScope: {
      orgId: 'org-recovery',
      projectId: 'project-recovery',
      envId: 'test',
      signingRootVersion: 'root-epoch-1',
    },
  };
}

function installRegistrationCapability(service: InMemoryRouterAbEd25519YaoRecoveryService) {
  return service.installRegistrationFinalizeCapability(registrationCapabilityInstallation());
}

function registrationCapabilityRecord(): WalletEd25519YaoActiveCapabilityRecord {
  const built = buildRouterAbEd25519YaoRegistrationCapabilityRecordV1(
    registrationCapabilityInstallation(),
  );
  if (!built.ok) throw new Error(built.message);
  return built.record;
}

function resolveWalletCapability(
  service: InMemoryRouterAbEd25519YaoRecoveryService,
  nearAccountId = 'wallet-1.testnet',
) {
  return service.resolveActiveCapability({
    kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
    walletId: 'wallet-1',
    nearAccountId,
    nearEd25519SigningKeyId: 'ed25519ks_1',
    signerSlot: 1,
    signingWorkerId: 'signing-worker-1',
    participantIds: [1, 2],
  });
}

function routePath(route: { readonly path: string }): string {
  return route.path;
}

function isWarmRecoveryBootstrapRoute(route: { readonly path: string }): boolean {
  return route.path === ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1;
}

async function recoveryPromotesOnlyAfterExactActivation(): Promise<void> {
  const admission = recoveryAdmissionRequest();
  const execution = recoveryExecuteRequest(admission);
  const result = recoveryResult(execution);
  const backend = new TestRecoveryBackend({ kind: 'success', result });
  const persistence = new RecordingCapabilityPersistence();
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(
    backend,
    undefined,
    persistence,
  );
  const runtime = createRouterAbEd25519YaoRecoveryRuntimePortV1(service);

  expect(installRegistrationCapability(service)).toMatchObject({
    ok: true,
    disposition: 'installed',
    stateEpoch: 1,
  });
  expect(installRegistrationCapability(service)).toMatchObject({
    ok: true,
    disposition: 'exact_retry',
  });
  expect(runtime.kind).toBe('router_ab_ed25519_yao_recovery_runtime_v1');
  expect(resolveWalletCapability(service)).toMatchObject({
    ok: true,
    capability: {
      activeCapabilityBinding: bytes(20),
      registeredPublicKey: bytes(12),
      nearAccountId: 'wallet-1.testnet',
      runtimePolicyScope: {
        orgId: 'org-recovery',
        projectId: 'project-recovery',
        envId: 'test',
        signingRootVersion: 'root-epoch-1',
      },
      stateEpoch: 1,
    },
  });
  expect(resolveWalletCapability(service, 'substituted.testnet')).toMatchObject({
    ok: false,
    code: 'unknown_capability',
  });
  expect(
    service.resolveActiveCapability({
      kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
      walletId: 'wallet-1',
      nearAccountId: 'wallet-1.testnet',
      nearEd25519SigningKeyId: 'ed25519ks_1',
      signerSlot: 1,
      signingWorkerId: 'signing-worker-1',
      participantIds: [1, 1],
    }),
  ).toMatchObject({ ok: false, code: 'invalid_lookup' });

  const admitted = await service.admitRecovery(admission);
  expect(admitted.ok).toBe(true);
  expect(await service.admitRecovery(admission)).toEqual(admitted);
  expect(backend.admitCalls).toBe(1);
  expect(service.installPersistedActiveCapability(registrationCapabilityRecord())).toMatchObject({
    ok: true,
    disposition: 'exact_retry',
    stateEpoch: 1,
  });
  expect(installRegistrationCapability(service)).toMatchObject({
    ok: false,
    code: 'capability_conflict',
  });

  const competingWhileSuspended = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-competing',
      walletSessionId: 'wallet-session-1',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 22,
      publicKeySeed: 12,
    }),
  );
  expect(competingWhileSuspended).toMatchObject({
    ok: false,
    code: 'capability_suspended',
  });
  expect(backend.admitCalls).toBe(1);

  const staged = await service.executeRecovery(execution);
  expect(staged).toEqual({ ok: true, status: 200, value: result });
  expect(await service.executeRecovery(execution)).toEqual(staged);
  expect(backend.executeCalls).toBe(1);
  expect(service.installPersistedActiveCapability(registrationCapabilityRecord())).toMatchObject({
    ok: true,
    disposition: 'exact_retry',
    stateEpoch: 1,
  });

  const activation = recoveryActivationRequest(result);
  const conflictingActivation = recoveryActivationRequest({
    binding: result.binding,
    deriver_a_client_package: result.deriver_a_client_package,
    deriver_b_client_package: result.deriver_b_client_package,
    public_receipt: publicReceipt(3),
  });
  expect(await service.activateRecovery(conflictingActivation)).toMatchObject({
    ok: false,
    code: 'binding_mismatch',
  });
  expect(backend.activateCalls).toBe(0);

  const promoted = await service.activateRecovery(activation);
  expect(promoted).toEqual({
    ok: true,
    status: 200,
    value: {
      binding: activation.binding,
      public_receipt: activation.public_receipt,
      active_capability_binding: bytes(21),
      retired_capability_binding: bytes(20),
    },
  });
  expect(await service.activateRecovery(activation)).toEqual(promoted);
  expect(backend.activateCalls).toBe(1);
  expect(resolveWalletCapability(service)).toMatchObject({
    ok: true,
    capability: {
      activeCapabilityBinding: bytes(21),
      registeredPublicKey: bytes(12),
      nearAccountId: 'wallet-1.testnet',
      runtimePolicyScope: {
        orgId: 'org-recovery',
        projectId: 'project-recovery',
        envId: 'test',
        signingRootVersion: 'root-epoch-1',
      },
      stateEpoch: 2,
    },
  });
  expect(persistence.calls).toHaveLength(1);
  expect(persistence.calls[0]).toMatchObject({
    previous: { version: 'wallet_ed25519_yao_registration_capability_v1' },
    next: {
      version: 'wallet_ed25519_yao_recovery_capability_v1',
      activeCapabilityBinding: bytes(21),
    },
  });
  expect(service.installPersistedActiveCapability(registrationCapabilityRecord())).toMatchObject({
    ok: false,
    code: 'capability_retired',
  });
  const persistedPromotion = persistence.calls[0];
  if (!persistedPromotion) throw new Error('promotion persistence was not recorded');
  expect(service.installPersistedActiveCapability(persistedPromotion.next)).toMatchObject({
    ok: true,
    disposition: 'exact_retry',
    stateEpoch: 2,
  });
  const rehydrated = new InMemoryRouterAbEd25519YaoRecoveryService(
    new TestRecoveryBackend({ kind: 'failure' }),
  );
  expect(rehydrated.installPersistedActiveCapability(persistedPromotion.next)).toMatchObject({
    ok: true,
    disposition: 'installed',
    stateEpoch: 2,
  });
  expect(resolveWalletCapability(rehydrated)).toMatchObject({
    ok: true,
    capability: { activeCapabilityBinding: bytes(21), stateEpoch: 2 },
  });

  const stale = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-stale',
      walletSessionId: 'wallet-session-1',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 22,
      publicKeySeed: 12,
    }),
  );
  expect(stale).toMatchObject({ ok: false, code: 'capability_retired' });
}

async function continuityFailureKeepsCapabilitySuspended(): Promise<void> {
  const admission = recoveryAdmissionRequest();
  const execution = recoveryExecuteRequest(admission);
  const backend = new TestRecoveryBackend({
    kind: 'success',
    result: recoveryResultForPublicKey(execution, 99),
  });
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(backend);
  expect(installRegistrationCapability(service).ok).toBe(true);

  const wrongPublicKey = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-wrong-key',
      walletSessionId: 'wallet-session-1',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 22,
      publicKeySeed: 99,
    }),
  );
  expect(wrongPublicKey).toMatchObject({ ok: false, code: 'continuity_mismatch' });
  expect(backend.admitCalls).toBe(0);

  const wrongWalletSession = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-wrong-wallet-session',
      walletSessionId: 'substituted-wallet-session',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 22,
      publicKeySeed: 12,
    }),
  );
  expect(wrongWalletSession).toMatchObject({ ok: false, code: 'continuity_mismatch' });
  expect(backend.admitCalls).toBe(0);

  expect((await service.admitRecovery(admission)).ok).toBe(true);
  const failed = await service.executeRecovery(execution);
  expect(failed).toMatchObject({ ok: false, code: 'continuity_mismatch' });
  expect(await service.executeRecovery(execution)).toEqual(failed);
  expect(backend.executeCalls).toBe(1);

  const replacementAttempt = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-after-failure',
      walletSessionId: 'wallet-session-1',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 23,
      publicKeySeed: 12,
    }),
  );
  expect(replacementAttempt).toMatchObject({ ok: false, code: 'capability_suspended' });
}

function installationRejectsUnboundRuntimePolicy(): void {
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(
    new TestRecoveryBackend({ kind: 'failure' }),
  );
  const result = service.installRegistrationFinalizeCapability({
    kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
    activeCapabilityBinding: bytes(20),
    nearAccountId: 'wallet-1.testnet',
    registrationAdmissionRequest: registrationAdmissionRequest(),
    registrationResult: registrationResult(),
    runtimePolicyScope: {
      orgId: 'org-recovery',
      projectId: 'substituted-project',
      envId: 'test',
      signingRootVersion: 'root-epoch-1',
    },
  });
  expect(result).toMatchObject({
    ok: false,
    code: 'invalid_installation',
    message: 'registration runtime policy signing root does not match scope',
  });
}

function persistedCapabilityRehydratesFreshRuntime(): void {
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(
    new TestRecoveryBackend({ kind: 'failure' }),
  );
  expect(service.installPersistedActiveCapability(registrationCapabilityRecord())).toMatchObject({
    ok: true,
    disposition: 'installed',
  });
  expect(resolveWalletCapability(service)).toMatchObject({
    ok: true,
    capability: {
      activeCapabilityBinding: bytes(20),
      registeredPublicKey: bytes(12),
      stateEpoch: 1,
    },
  });
}

function recoveryModuleExposesAllFourAuthorizedRoutes(): void {
  const admission = recoveryAdmissionRequest();
  const execution = recoveryExecuteRequest(admission);
  const backend = new TestRecoveryBackend({ kind: 'success', result: recoveryResult(execution) });
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(backend);
  const authorization = new AllowRecoveryAuthorization();
  const module = createRouterAbEd25519YaoRecoveryModule({ service, authorization });
  const extension = module.routeExtensions[0];
  expect(extension?.routes.map(routePath)).toEqual([
    ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
    ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
    ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
    ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ]);
}

async function warmBootstrapReturnsExactActiveCapabilityWithoutMintingSession(): Promise<void> {
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(
    new TestRecoveryBackend({ kind: 'failure' }),
  );
  expect(service.installPersistedActiveCapability(registrationCapabilityRecord())).toMatchObject({
    ok: true,
    disposition: 'installed',
  });
  const authorization = new AllowRecoveryAuthorization();
  const module = createRouterAbEd25519YaoRecoveryModule({ service, authorization });
  const extension = module.routeExtensions[0];
  const route = extension?.routes.find(isWarmRecoveryBootstrapRoute);
  if (!extension || !route) throw new Error('warm recovery bootstrap route is required');
  const response = await extension.handleCloudflareRoute({
    request: new Request(`https://router.example.test${route.path}`, {
      method: 'POST',
      headers: {
        authorization: 'Bearer wallet-session',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
        walletId: 'wallet-1',
        nearAccountId: 'wallet-1.testnet',
        nearEd25519SigningKeyId: 'ed25519ks_1',
        signerSlot: 1,
        thresholdSessionId: 'wallet-session-1',
        signingGrantId: 'signing-grant-1',
        signingWorkerId: 'signing-worker-1',
        participantIds: [1, 2],
      }),
    }),
    route,
    pathname: route.path,
    method: 'POST',
    logger: coerceRouterLogger(null),
  });
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
    walletId: 'wallet-1',
    nearAccountId: 'wallet-1.testnet',
    nearEd25519SigningKeyId: 'ed25519ks_1',
    signerSlot: 1,
    thresholdSessionId: 'wallet-session-1',
    signingGrantId: 'signing-grant-1',
    signingWorkerId: 'signing-worker-1',
    participantIds: [1, 2],
    capability: {
      kind: 'router_ab_ed25519_yao_active_capability_v1',
      activeCapabilityBinding: bytes(20),
      registeredPublicKey: bytes(12),
      lifecycle: { lifecycleId: 'registration-1' },
      stateEpoch: 1,
    },
  });
  expect(authorization.inputs).toHaveLength(1);
  expect(authorization.inputs[0]?.kind).toBe('bootstrap');
}

test(
  'recovery promotes only after exact activation and preserves exact retries',
  recoveryPromotesOnlyAfterExactActivation,
);
test(
  'public-key continuity failure keeps the old capability suspended',
  continuityFailureKeepsCapabilitySuspended,
);
test(
  'registration installation binds the exact runtime policy',
  installationRejectsUnboundRuntimePolicy,
);
test('persisted active capability rehydrates a fresh runtime', persistedCapabilityRehydratesFreshRuntime);
test(
  'recovery module exposes all four authorized routes',
  recoveryModuleExposesAllFourAuthorizedRoutes,
);
test(
  'warm recovery bootstrap returns the exact active capability without minting a session',
  warmBootstrapReturnsExactActiveCapabilityWithoutMintingSession,
);
