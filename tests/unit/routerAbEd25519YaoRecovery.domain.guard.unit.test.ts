import { expect, test } from '@playwright/test';
import {
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
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
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildRouterAbEd25519YaoRegistrationCapabilityRecordV1,
  InMemoryRouterAbEd25519YaoRecoveryService,
  createRouterAbEd25519YaoRecoveryModule,
  recoveryAuthorizationBinding,
  type RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  type RouterAbEd25519YaoRecoveryAuthorizationInput,
  type RouterAbEd25519YaoRecoveryAuthorizationResult,
  type RouterAbEd25519YaoRecoveryAuthorizationBindingV1,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRecoveryBackendResult,
  type RouterAbEd25519YaoCapabilityPersistenceV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type { RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1 } from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../packages/wallet-server/src/core/WalletStore';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import { coerceRouterLogger } from '../../packages/wallet-server/src/router/framework/logger';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type RecoveryResult = RouterAbEd25519YaoActivationResultV1<'recovery'>;
type RegistrationResult = RouterAbEd25519YaoActivationResultV1<'registration'>;

const RECOVERY_AUTHORIZATION = {
  kind: 'wallet_recovery',
  walletId: 'wallet-1',
} as const satisfies RouterAbEd25519YaoRecoveryAuthorizationBindingV1;

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

  constructor(private readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext) {}

  authorize(
    input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  ): RouterAbEd25519YaoRecoveryAuthorizationResult {
    this.inputs.push(input);
    return {
      ok: true,
      authorization: { kind: 'wallet_session_v2', context: this.context },
    };
  }
}

class RecordingCapabilityPersistence implements RouterAbEd25519YaoCapabilityPersistenceV1 {
  readonly calls: Array<{
    readonly operation: {
      readonly kind: 'router_ab_ed25519_yao_capability_replacement_operation_v1';
      readonly operationId: string;
      readonly operationFingerprint: string;
      readonly authorityProjection: {
        readonly kind:
          | 'replace_continuity_authority_projections'
          | 'replace_active_authority_projection';
      };
    };
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  }> = [];

  replaceActiveCapability(input: {
    readonly operation: {
      readonly kind: 'router_ab_ed25519_yao_capability_replacement_operation_v1';
      readonly operationId: string;
      readonly operationFingerprint: string;
      readonly authorityProjection: {
        readonly kind:
          | 'replace_continuity_authority_projections'
          | 'replace_active_authority_projection';
      };
    };
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  }) {
    this.calls.push(input);
    return { ok: true, disposition: 'applied' } as const;
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
        threshold_session_id: 'wallet-session-1',
        signer_set_id: 'signer-set-1',
        signing_worker_id: 'signing-worker-1',
        material_activation: materialActivation('registration-1'),
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

async function exactWalletSessionContextFixture(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const exact = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'recovery-domain-guard',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation: routerAbMpcMaterialActivationRefFromWire(
      materialActivation('registration-1'),
    ),
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: 'wallet-1',
      authorityId: 'authority:recovery-domain-guard',
      walletAuthMethodId: 'auth-method:recovery-domain-guard',
      rpId: 'router.example.test',
    },
  });
  return {
    authorization: exact.issuedSession,
    authority: exact.authority,
    authMethod: exact.authMethod,
    retiredAtMs: null,
  };
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
    material_activation: materialActivation('registration-1'),
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
      public_receipt: publicReceipt(1, binding.material_activation),
    }),
  );
}

function registrationAdmissionReceipt() {
  return requireParsed(
    parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1({
      binding: registrationBinding(),
      keyset: {
        deriver_a_input_public_key: bytes(1),
        deriver_b_input_public_key: bytes(2),
        signing_worker_recipient_public_key: bytes(3),
      },
    }),
  );
}

function recoveryAdmissionRequest(input?: {
  readonly lifecycleId: string;
  readonly accountId?: string;
  readonly walletSessionId: string;
  readonly activeCapabilitySeed: number;
  readonly replacementCapabilitySeed: number;
  readonly publicKeySeed: number;
}): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const values = {
    lifecycleId: input?.lifecycleId ?? 'recovery-1',
    accountId: input?.accountId ?? 'wallet-1',
    walletSessionId: input?.walletSessionId ?? 'wallet-session-1',
    activeCapabilitySeed: input?.activeCapabilitySeed ?? 20,
    replacementCapabilitySeed: input?.replacementCapabilitySeed ?? 21,
    publicKeySeed: input?.publicKeySeed ?? 12,
  };
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: values.lifecycleId,
        root_share_epoch: 'root-epoch-1',
        account_id: values.accountId,
        threshold_session_id: values.walletSessionId,
        signer_set_id: 'signer-set-1',
        signing_worker_id: 'signing-worker-1',
        material_activation: materialActivation(values.lifecycleId, values.accountId),
      },
      active_material_activation: materialActivation('registration-1', values.accountId),
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
      session_id: request.scope.threshold_session_id,
      signer_set_id: request.scope.signer_set_id,
      selected_server_id: request.scope.signing_worker_id,
    },
    operation: 'recovery' as const,
    session_id: bytes(7),
    stable_key_context_binding: bytes(8),
    material_activation: request.scope.material_activation,
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

function publicReceipt(
  stateEpoch: number,
  materialActivationRef: ReturnType<typeof materialActivation>,
) {
  return publicReceiptForKey(stateEpoch, 12, materialActivationRef);
}

function publicReceiptForKey(
  stateEpoch: number,
  publicKeySeed: number,
  materialActivationRef: ReturnType<typeof materialActivation>,
) {
  return {
    transcript: bytes(11),
    registered_public_key: bytes(publicKeySeed),
    joined_client_commitment: bytes(13),
    joined_signing_worker_commitment: bytes(15),
    signing_worker_verifying_share: bytes(15),
    state_epoch: stateEpoch,
    material_activation: materialActivationRef,
  };
}

function materialActivation(lifecycleId: string, materialOwner = 'wallet-1') {
  return {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: `${lifecycleId}-activation`,
    capability: `capability-${materialOwner}`,
    material_owner: materialOwner,
    key_binding: `key-${materialOwner}`,
    lifecycle_binding: `${lifecycleId}-lifecycle-binding`,
    signing_worker: 'signing-worker-1',
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
    public_receipt: publicReceiptForKey(2, publicKeySeed, request.binding.material_activation),
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
    registrationAdmissionReceipt: registrationAdmissionReceipt(),
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
  nearEd25519SigningKeyId = 'ed25519ks_1',
) {
  return service.resolveActiveCapability({
    kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
    walletId: 'wallet-1',
    nearEd25519SigningKeyId,
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
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(backend, undefined, persistence);
  const exactAuthorization = recoveryAuthorizationBinding({
    kind: 'wallet_session_v2',
    context: await exactWalletSessionContextFixture(),
  });

  expect(installRegistrationCapability(service)).toMatchObject({
    ok: true,
    disposition: 'installed',
    stateEpoch: 1,
  });
  expect(installRegistrationCapability(service)).toMatchObject({
    ok: true,
    disposition: 'exact_retry',
  });
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
  expect(resolveWalletCapability(service, 'substituted-ed25519-key')).toMatchObject({
    ok: false,
    code: 'unknown_capability',
  });
  expect(
    service.resolveActiveCapability({
      kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
      walletId: 'wallet-1',
      nearEd25519SigningKeyId: 'ed25519ks_1',
      signerSlot: 1,
      signingWorkerId: 'signing-worker-1',
      participantIds: [1, 1],
    }),
  ).toMatchObject({ ok: false, code: 'invalid_lookup' });

  const admitted = await service.admitRecovery(admission, exactAuthorization);
  expect(admitted.ok).toBe(true);
  expect(await service.admitRecovery(admission, exactAuthorization)).toEqual(admitted);
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
    exactAuthorization,
  );
  expect(competingWhileSuspended).toMatchObject({
    ok: false,
    code: 'capability_suspended',
  });
  expect(backend.admitCalls).toBe(1);

  expect(await service.executeRecovery(execution, RECOVERY_AUTHORIZATION)).toMatchObject({
    ok: false,
    code: 'continuity_mismatch',
  });
  const staged = await service.executeRecovery(execution, exactAuthorization);
  expect(staged).toEqual({ ok: true, status: 200, value: result });
  expect(await service.executeRecovery(execution, exactAuthorization)).toEqual(staged);
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
    public_receipt: publicReceipt(3, result.binding.material_activation),
  });
  expect(await service.activateRecovery(conflictingActivation, exactAuthorization)).toMatchObject({
    ok: false,
    code: 'binding_mismatch',
  });
  expect(backend.activateCalls).toBe(0);

  const promoted = await service.activateRecovery(activation, exactAuthorization);
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
  expect(await service.activateRecovery(activation, exactAuthorization)).toEqual(promoted);
  expect(backend.activateCalls).toBe(1);
  expect(resolveWalletCapability(service)).toMatchObject({
    ok: true,
    capability: {
      activeCapabilityBinding: bytes(21),
      registrationContinuity: {
        kind: 'recovery',
        activationTranscript: activation.public_receipt.transcript,
      },
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
    operation: { authorityProjection: { kind: 'replace_active_authority_projection' } },
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
    capability: {
      activeCapabilityBinding: bytes(21),
      registrationContinuity: {
        kind: 'recovery',
        activationTranscript: activation.public_receipt.transcript,
      },
      stateEpoch: 2,
    },
  });

  const stale = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-stale',
      walletSessionId: 'wallet-session-1',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 22,
      publicKeySeed: 12,
    }),
    exactAuthorization,
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
    RECOVERY_AUTHORIZATION,
  );
  expect(wrongPublicKey).toMatchObject({ ok: false, code: 'continuity_mismatch' });
  expect(backend.admitCalls).toBe(0);

  const wrongAccount = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-wrong-account',
      accountId: 'substituted-account',
      walletSessionId: 'wallet-session-1',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 22,
      publicKeySeed: 12,
    }),
    RECOVERY_AUTHORIZATION,
  );
  expect(wrongAccount).toMatchObject({ ok: false, code: 'continuity_mismatch' });
  expect(backend.admitCalls).toBe(0);

  expect((await service.admitRecovery(admission, RECOVERY_AUTHORIZATION)).ok).toBe(true);
  const failed = await service.executeRecovery(execution, RECOVERY_AUTHORIZATION);
  expect(failed).toMatchObject({ ok: false, code: 'continuity_mismatch' });
  expect(await service.executeRecovery(execution, RECOVERY_AUTHORIZATION)).toEqual(failed);
  expect(backend.executeCalls).toBe(1);

  const replacementAttempt = await service.admitRecovery(
    recoveryAdmissionRequest({
      lifecycleId: 'recovery-after-failure',
      walletSessionId: 'wallet-session-1',
      activeCapabilitySeed: 20,
      replacementCapabilitySeed: 23,
      publicKeySeed: 12,
    }),
    RECOVERY_AUTHORIZATION,
  );
  expect(replacementAttempt).toMatchObject({ ok: false, code: 'capability_suspended' });
}

async function recoveryAcceptsFreshWalletSession(): Promise<void> {
  const request = recoveryAdmissionRequest({
    lifecycleId: 'recovery-fresh-wallet-session',
    accountId: 'wallet-1',
    walletSessionId: 'substituted-wallet-session',
    activeCapabilitySeed: 20,
    replacementCapabilitySeed: 22,
    publicKeySeed: 12,
  });
  const execution = recoveryExecuteRequest(request);
  const backend = new TestRecoveryBackend({
    kind: 'success',
    result: recoveryResult(execution),
  });
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(backend);
  expect(installRegistrationCapability(service).ok).toBe(true);

  await expect(service.admitRecovery(request, RECOVERY_AUTHORIZATION)).resolves.toMatchObject({
    ok: true,
  });
  expect(backend.admitCalls).toBe(1);
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
    registrationAdmissionReceipt: registrationAdmissionReceipt(),
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

async function recoveryModuleExposesAllFourAuthorizedRoutes(): Promise<void> {
  const admission = recoveryAdmissionRequest();
  const execution = recoveryExecuteRequest(admission);
  const backend = new TestRecoveryBackend({ kind: 'success', result: recoveryResult(execution) });
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(backend);
  const context = await exactWalletSessionContextFixture();
  const authorization = new AllowRecoveryAuthorization(context);
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
  const context = await exactWalletSessionContextFixture();
  const authorization = new AllowRecoveryAuthorization(context);
  const module = createRouterAbEd25519YaoRecoveryModule({ service, authorization });
  const extension = module.routeExtensions[0];
  const route = extension?.routes.find(isWarmRecoveryBootstrapRoute);
  if (!extension || !route) throw new Error('warm recovery bootstrap route is required');
  const response = await extension.handleFetchRoute({
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
        signingWorkerId: 'signing-worker-1',
        participantIds: [1, 2],
      }),
    }),
    route,
    pathname: route.path,
    method: 'POST',
    logger: coerceRouterLogger(null),
    runtime: { kind: 'inline' },
  });
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    kind: 'router_ab_ed25519_yao_v2_session_bootstrap_v1',
    walletId: 'wallet-1',
    nearAccountId: 'wallet-1.testnet',
    nearEd25519SigningKeyId: 'ed25519ks_1',
    signerSlot: 1,
    thresholdSessionId: 'wallet-session-1',
    walletSessionId: context.authorization.session.walletSessionId,
    quotaId: context.authorization.quota.quotaId,
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
  'public-key and account continuity failures keep the old capability suspended',
  continuityFailureKeepsCapabilitySuspended,
);
test('recovery accepts a fresh wallet session', recoveryAcceptsFreshWalletSession);
test(
  'registration installation binds the exact runtime policy',
  installationRejectsUnboundRuntimePolicy,
);
test(
  'persisted active capability rehydrates a fresh runtime',
  persistedCapabilityRehydratesFreshRuntime,
);
test(
  'recovery module exposes all four authorized routes',
  recoveryModuleExposesAllFourAuthorizedRoutes,
);
test(
  'warm recovery bootstrap returns the exact active capability without minting a session',
  warmBootstrapReturnsExactActiveCapabilityWithoutMintingSession,
);
