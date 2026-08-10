import {
  parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { VersionedJsonRecordReadResult } from '../../../packages/sdk-server-ts/src/router/framework/versionedJsonRecordStore';
import {
  parseRouterAbEd25519WalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import {
  createRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationStateV1,
} from '../../../packages/sdk-server-ts/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import {
  createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1,
  type RouterAbEd25519YaoProductRegistrationPartitionMutationV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  type RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
} from '../../../packages/sdk-server-ts/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import {
  InMemoryRouterAbEd25519YaoRecoveryService,
  type RouterAbEd25519YaoRecoveryAdmissionCommitInputV1,
  type RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  type RouterAbEd25519YaoRecoveryAuthorizationInput,
  type RouterAbEd25519YaoRecoveryAuthorizationResult,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRecoveryBackendResult,
  type RouterAbEd25519YaoRecoveryExecuteCommitInputV1,
} from '../../../packages/sdk-server-ts/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../../packages/sdk-server-ts/src/core/WalletStore';

const ROOT_SHARE_EPOCH = 'root-recovery-v1';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-recovery',
  projectId: 'project-recovery',
  envId: 'test',
  signingRootVersion: ROOT_SHARE_EPOCH,
} as const;

type RecoveryFixtureIdentity = {
  readonly lifecycleId: string;
  readonly registrationLifecycleId: string;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearSigningKeyId: string;
  readonly authorizationId: string;
  readonly walletSessionId: string;
  readonly thresholdSessionId: string;
  readonly quotaId: string;
  readonly signingWorkerId: string;
  readonly signerSetId: string;
  readonly credentialId: string;
  readonly activeCapabilitySeed: number;
  readonly replacementCapabilitySeed: number;
  readonly registeredPublicKeySeed: number;
};

const PRIMARY_IDENTITY: RecoveryFixtureIdentity = {
  lifecycleId: 'recovery-request-scoped-1',
  registrationLifecycleId: 'registration-recovery-origin-1',
  walletId: 'wallet-recovery-1',
  nearAccountId: 'wallet-recovery-1.testnet',
  nearSigningKeyId: 'ed25519ks_recovery_1',
  authorizationId: 'authorization-grant-recovery-1',
  walletSessionId: 'wallet-session-recovery-1',
  thresholdSessionId: 'threshold-session-recovery-1',
  quotaId: 'wallet-session-quota-recovery-1',
  signingWorkerId: 'signing-worker-recovery-1',
  signerSetId: 'signer-set-recovery-1',
  credentialId: 'recovery-request-scoped-credential-1',
  activeCapabilitySeed: 20,
  replacementCapabilitySeed: 21,
  registeredPublicKeySeed: 12,
};

const SECONDARY_IDENTITY: RecoveryFixtureIdentity = {
  lifecycleId: 'recovery-request-scoped-2',
  registrationLifecycleId: 'registration-recovery-origin-2',
  walletId: 'wallet-recovery-2',
  nearAccountId: 'wallet-recovery-2.testnet',
  nearSigningKeyId: 'ed25519ks_recovery_2',
  authorizationId: 'authorization-grant-recovery-2',
  walletSessionId: 'wallet-session-recovery-2',
  thresholdSessionId: 'threshold-session-recovery-2',
  quotaId: 'wallet-session-quota-recovery-2',
  signingWorkerId: 'signing-worker-recovery-2',
  signerSetId: 'signer-set-recovery-2',
  credentialId: 'recovery-request-scoped-credential-2',
  activeCapabilitySeed: 40,
  replacementCapabilitySeed: 41,
  registeredPublicKeySeed: 42,
};

type RecoveryAdmissionReceipt = RouterAbEd25519YaoActivationAdmissionReceiptV1<'recovery'>;
type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type RecoveryExecutionResult = RouterAbEd25519YaoActivationResultV1<'recovery'>;
type AssertNever<T extends never> = T;
type RecoveryAdmissionUncertaintyCannotCommit = AssertNever<
  Extract<
    RouterAbEd25519YaoRecoveryAdmissionCommitInputV1['outcome'],
    { readonly kind: 'backend_uncertain' }
  >
>;
type RecoveryExecutionUncertaintyCannotCommit = AssertNever<
  Extract<
    RouterAbEd25519YaoRecoveryExecuteCommitInputV1['outcome'],
    { readonly kind: 'backend_uncertain' }
  >
>;

type StoredRecord = {
  readonly value: RouterAbEd25519YaoProductRegistrationPartitionRecordV1;
  readonly version: number;
};

export type RouterAbEd25519YaoRecoveryRequestScopedFixture = {
  readonly lifecycleId: string;
  readonly admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  readonly admissionReceipt: RecoveryAdmissionReceipt;
  readonly execution: RecoveryExecuteRequest;
  readonly executionResult: RecoveryExecutionResult;
  readonly activation: RouterAbEd25519YaoRecoveryActivationRequestV1;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly authorization: RouterAbEd25519YaoRecoveryAuthorizationAdapter;
  readonly capabilities: {
    resolveActiveCapability(): Promise<{
      readonly ok: false;
      readonly code: 'unknown_capability';
      readonly message: string;
    }>;
  };
};

export type RouterAbEd25519YaoCapabilityReplacementFixture = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearSigningKeyId: string;
  readonly signingWorkerId: string;
  readonly previous: WalletEd25519YaoActiveCapabilityRecord;
  readonly next: WalletEd25519YaoActiveCapabilityRecord;
};

class MemoryPartitionRecordStore implements RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1 {
  private readonly records = new Map<string, StoredRecord>();

  async readMany(keys: readonly string[]): Promise<
    readonly {
      readonly key: string;
      readonly result: VersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
    }[]
  > {
    const results: {
      readonly key: string;
      readonly result: VersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
    }[] = [];
    for (const key of keys) {
      const record = this.records.get(key);
      results.push({
        key,
        result: record
          ? {
              kind: 'present' as const,
              value: structuredClone(record.value),
              version: String(record.version),
            }
          : { kind: 'missing' as const },
      });
    }
    return results;
  }

  async putMany(
    mutations: readonly RouterAbEd25519YaoProductRegistrationPartitionMutationV1[],
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1> {
    for (const mutation of mutations) {
      const current = this.records.get(mutation.key);
      if (mutation.expectedVersion === null) {
        if (current) return { kind: 'version_mismatch', key: mutation.key };
      } else if (!current || String(current.version) !== mutation.expectedVersion) {
        return { kind: 'version_mismatch', key: mutation.key };
      }
    }
    for (const mutation of mutations) {
      const current = this.records.get(mutation.key);
      this.records.set(mutation.key, {
        value: structuredClone(mutation.value),
        version: (current?.version ?? 0) + 1,
      });
    }
    const versions: { readonly key: string; readonly version: string }[] = [];
    for (const mutation of mutations) {
      versions.push({
        key: mutation.key,
        version: String(this.records.get(mutation.key)?.version ?? 0),
      });
    }
    return { kind: 'stored', versions };
  }
}

class UnavailableRecoveryBackend implements RouterAbEd25519YaoRecoveryBackend {
  async admitRecovery() {
    return fixtureBackendUnavailable();
  }

  async executeRecovery() {
    return fixtureBackendUnavailable();
  }

  async activateRecovery() {
    return fixtureBackendUnavailable();
  }
}

class AllowRecoveryAuthorization implements RouterAbEd25519YaoRecoveryAuthorizationAdapter {
  private readonly claims;

  constructor(identity: RecoveryFixtureIdentity) {
    this.claims = recoveryClaims(identity);
  }

  authorize(
    _input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  ): RouterAbEd25519YaoRecoveryAuthorizationResult {
    return { ok: true, claims: this.claims };
  }
}

export async function buildRouterAbEd25519YaoRecoveryRequestScopedFixture(): Promise<RouterAbEd25519YaoRecoveryRequestScopedFixture> {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  installActiveCapability(state, PRIMARY_IDENTITY);
  const store = createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(
    new MemoryPartitionRecordStore(),
  );
  await seedState(store, state, PRIMARY_IDENTITY.lifecycleId);
  return recoveryFixture(PRIMARY_IDENTITY, store);
}

export async function buildSecondRouterAbEd25519YaoRecoveryRequestScopedFixture(
  store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
): Promise<RouterAbEd25519YaoRecoveryRequestScopedFixture> {
  const loaded = await store.load(SECONDARY_IDENTITY.lifecycleId);
  installActiveCapability(loaded.state, SECONDARY_IDENTITY);
  const committed = await store.commit({
    lifecycleId: SECONDARY_IDENTITY.lifecycleId,
    state: loaded.state,
    sharedState: loaded.sharedState,
    sharedVersion: loaded.sharedVersion,
    ceremonyVersion: loaded.ceremonyVersion,
    execution: loaded.execution,
    executionVersion: loaded.executionVersion,
  });
  if (committed.kind !== 'stored') {
    throw new Error('secondary recovery fixture state did not commit');
  }
  return recoveryFixture(SECONDARY_IDENTITY, store);
}

export function buildRouterAbEd25519YaoCapabilityReplacementFixture(
  lifecycleId: string = PRIMARY_IDENTITY.lifecycleId,
): RouterAbEd25519YaoCapabilityReplacementFixture {
  return capabilityReplacementFixture({ ...PRIMARY_IDENTITY, lifecycleId });
}

function capabilityReplacementFixture(
  identity: RecoveryFixtureIdentity,
): RouterAbEd25519YaoCapabilityReplacementFixture {
  const registrationRequest = registrationAdmission(identity);
  const registrationActivation = registrationResult(identity);
  const admission = recoveryAdmission(identity);
  const recoveryRequest = requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: admission.scope,
      active_material_activation: admission.active_material_activation,
      application_binding: admission.application_binding,
      participant_ids: admission.participant_ids,
      active_capability_binding: registrationActivation.binding.session_id,
      replacement_capability_binding: admission.replacement_capability_binding,
      registered_public_key: admission.registered_public_key,
    }),
  );
  const recoveryReceipt = recoveryAdmissionReceipt(recoveryRequest);
  const recoveryExecutionRequest = recoveryExecution(recoveryReceipt);
  const recoveryActivation = recoveryExecutionResult(
    recoveryExecutionRequest,
    identity.registeredPublicKeySeed,
  );
  return {
    walletId: identity.walletId,
    nearAccountId: identity.nearAccountId,
    nearSigningKeyId: identity.nearSigningKeyId,
    signingWorkerId: identity.signingWorkerId,
    previous: {
      version: 'wallet_ed25519_yao_registration_capability_v1',
      activeCapabilityBinding: registrationActivation.binding.session_id,
      nearAccountId: identity.nearAccountId,
      admissionRequest: registrationRequest,
      admissionReceipt: registrationAdmissionReceipt(identity),
      activationResult: registrationActivation,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    },
    next: {
      version: 'wallet_ed25519_yao_recovery_capability_v1',
      activeCapabilityBinding: bytes(identity.replacementCapabilitySeed),
      nearAccountId: identity.nearAccountId,
      admissionRequest: recoveryRequest,
      activationResult: recoveryActivation,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    },
  };
}

function recoveryFixture(
  identity: RecoveryFixtureIdentity,
  store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
): RouterAbEd25519YaoRecoveryRequestScopedFixture {
  const admission = recoveryAdmission(identity);
  const admissionReceipt = recoveryAdmissionReceipt(admission);
  const execution = recoveryExecution(admissionReceipt);
  const executionResult = recoveryExecutionResult(execution, identity.registeredPublicKeySeed);
  return {
    lifecycleId: identity.lifecycleId,
    admission,
    admissionReceipt,
    execution,
    executionResult,
    activation: recoveryActivation(executionResult),
    store,
    authorization: new AllowRecoveryAuthorization(identity),
    capabilities: {
      async resolveActiveCapability() {
        return {
          ok: false,
          code: 'unknown_capability' as const,
          message: 'warm bootstrap is not used by this fixture',
        };
      },
    },
  };
}

function recoveryActivation(
  result: RecoveryExecutionResult,
): RouterAbEd25519YaoRecoveryActivationRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationRequestV1({
      binding: result.binding,
      public_receipt: result.public_receipt,
    }),
  );
}

function installActiveCapability(
  state: RouterAbEd25519YaoProductRegistrationStateV1,
  identity: RecoveryFixtureIdentity,
): void {
  const service = new InMemoryRouterAbEd25519YaoRecoveryService(
    unavailableRecoveryBackend(),
    state.recovery,
  );
  const installed = service.installRegistrationFinalizeCapability({
    kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
    activeCapabilityBinding: bytes(identity.activeCapabilitySeed),
    nearAccountId: identity.nearAccountId,
    registrationAdmissionRequest: registrationAdmission(identity),
    registrationAdmissionReceipt: registrationAdmissionReceipt(identity),
    registrationResult: registrationResult(identity),
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  });
  if (!installed.ok) throw new Error(installed.message);
}

async function seedState(
  store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  state: RouterAbEd25519YaoProductRegistrationStateV1,
  lifecycleId: string,
): Promise<void> {
  const loaded = await store.load(lifecycleId);
  const committed = await store.commit({
    lifecycleId,
    state,
    sharedState: loaded.sharedState,
    sharedVersion: loaded.sharedVersion,
    ceremonyVersion: loaded.ceremonyVersion,
    execution: loaded.execution,
    executionVersion: loaded.executionVersion,
  });
  if (committed.kind !== 'stored') throw new Error('recovery fixture state did not commit');
}

function registrationAdmission(identity: RecoveryFixtureIdentity) {
  return requireParsed(
    parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
      scope: {
        lifecycle_id: identity.registrationLifecycleId,
        root_share_epoch: ROOT_SHARE_EPOCH,
        account_id: identity.walletId,
        threshold_session_id: identity.thresholdSessionId,
        signer_set_id: identity.signerSetId,
        signing_worker_id: identity.signingWorkerId,
        material_activation: materialActivation(
          identity.registrationLifecycleId,
          identity.walletId,
          identity.signingWorkerId,
        ),
      },
      application_binding: {
        wallet_id: identity.walletId,
        near_ed25519_signing_key_id: identity.nearSigningKeyId,
        signing_root_id: 'project-recovery:test',
        key_creation_signer_slot: 1,
      },
      participant_ids: [1, 2],
    }),
  );
}

function registrationBinding(identity: RecoveryFixtureIdentity) {
  return {
    lifecycle: {
      lifecycle_id: identity.registrationLifecycleId,
      work_kind: 'registration_prepare' as const,
      primitive_request_kind: 'registration' as const,
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: identity.walletId,
      session_id: identity.thresholdSessionId,
      signer_set_id: identity.signerSetId,
      selected_server_id: identity.signingWorkerId,
    },
    operation: 'registration' as const,
    session_id: bytes(identity.activeCapabilitySeed),
    stable_key_context_binding: bytes(8),
    material_activation: materialActivation(
      identity.registrationLifecycleId,
      identity.walletId,
      identity.signingWorkerId,
    ),
  };
}

function registrationResult(identity: RecoveryFixtureIdentity) {
  const binding = registrationBinding(identity);
  return requireParsed(
    parseRouterAbEd25519YaoRegistrationActivationResultV1({
      binding,
      deriver_a_client_package: activationClientPackage(binding, 'deriver_a'),
      deriver_b_client_package: activationClientPackage(binding, 'deriver_b'),
      public_receipt: publicReceipt(
        1,
        identity.registeredPublicKeySeed,
        binding.material_activation,
      ),
    }),
  );
}

function registrationAdmissionReceipt(identity: RecoveryFixtureIdentity) {
  return requireParsed(
    parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1({
      binding: registrationBinding(identity),
      keyset: {
        deriver_a_input_public_key: bytes(51),
        deriver_b_input_public_key: bytes(52),
        signing_worker_recipient_public_key: bytes(53),
      },
    }),
  );
}

function recoveryAdmission(
  identity: RecoveryFixtureIdentity,
): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: identity.lifecycleId,
        root_share_epoch: ROOT_SHARE_EPOCH,
        account_id: identity.walletId,
        threshold_session_id: identity.thresholdSessionId,
        signer_set_id: identity.signerSetId,
        signing_worker_id: identity.signingWorkerId,
        material_activation: {
          kind: 'mpc_material_activation_ref',
          activation_id: `${identity.lifecycleId}-recovery-material-activation`,
          capability: registrationAdmission(identity).scope.material_activation.capability,
          material_owner: registrationAdmission(identity).scope.material_activation.material_owner,
          key_binding: registrationAdmission(identity).scope.material_activation.key_binding,
          lifecycle_binding: `${identity.lifecycleId}:material-activation`,
          signing_worker: registrationAdmission(identity).scope.material_activation.signing_worker,
        },
      },
      active_material_activation: registrationAdmission(identity).scope.material_activation,
      application_binding: registrationAdmission(identity).application_binding,
      participant_ids: [1, 2],
      active_capability_binding: bytes(identity.activeCapabilitySeed),
      replacement_capability_binding: bytes(identity.replacementCapabilitySeed),
      registered_public_key: bytes(identity.registeredPublicKeySeed),
    }),
  );
}

function recoveryAdmissionReceipt(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): RecoveryAdmissionReceipt {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1({
      binding: recoveryBinding(request),
      keyset: {
        deriver_a_input_public_key: bytes(1),
        deriver_b_input_public_key: bytes(2),
        signing_worker_recipient_public_key: bytes(3),
      },
    }),
  );
}

function recoveryExecution(receipt: RecoveryAdmissionReceipt): RecoveryExecuteRequest {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1({
      binding: receipt.binding,
      deriver_a_input: encryptedRecoveryInput(receipt.binding, 'deriver_a'),
      deriver_b_input: encryptedRecoveryInput(receipt.binding, 'deriver_b'),
    }),
  );
}

function recoveryExecutionResult(
  request: RecoveryExecuteRequest,
  registeredPublicKeySeed: number,
): RecoveryExecutionResult {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationResultV1({
      binding: request.binding,
      deriver_a_client_package: activationClientPackage(request.binding, 'deriver_a'),
      deriver_b_client_package: activationClientPackage(request.binding, 'deriver_b'),
      public_receipt: publicReceipt(
        2,
        registeredPublicKeySeed,
        request.binding.material_activation,
      ),
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

function materialActivation(lifecycleId: string, materialOwner: string, signingWorker: string) {
  return {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: `${lifecycleId}-activation`,
    capability: `${lifecycleId}-capability`,
    material_owner: materialOwner,
    key_binding: `${lifecycleId}-key`,
    lifecycle_binding: `${lifecycleId}-lifecycle-binding`,
    signing_worker: signingWorker,
  };
}

function encryptedRecoveryInput(
  binding: RecoveryAdmissionReceipt['binding'],
  deriver: 'deriver_a' | 'deriver_b',
) {
  return {
    kind: 'activation' as const,
    deriver,
    operation: 'recovery' as const,
    session: binding.session_id,
    stable_context_binding: binding.stable_key_context_binding,
    encapsulated_key: bytes(9),
    ciphertext: bytes(10, 16),
  };
}

function activationClientPackage(
  binding: { readonly session_id: readonly number[] },
  deriver: 'deriver_a' | 'deriver_b',
) {
  return {
    kind: 'activation_client' as const,
    deriver,
    session: binding.session_id,
    transcript: bytes(11),
    encapsulated_key: bytes(30),
    ciphertext: bytes(31, 16),
  };
}

function publicReceipt(
  stateEpoch: number,
  registeredPublicKeySeed: number,
  materialActivationRef: ReturnType<typeof materialActivation>,
) {
  return {
    transcript: bytes(11),
    registered_public_key: bytes(registeredPublicKeySeed),
    joined_client_commitment: bytes(13),
    joined_signing_worker_commitment: bytes(15),
    signing_worker_verifying_share: bytes(15),
    state_epoch: stateEpoch,
    material_activation: materialActivationRef,
  };
}

function recoveryClaims(identity: RecoveryFixtureIdentity) {
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: identity.walletId,
    rpId: 'router.example.test',
    credentialIdB64u: identity.credentialId,
  });
  const claims = parseRouterAbEd25519WalletSessionClaims({
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: identity.walletId,
    walletId: identity.walletId,
    nearAccountId: identity.nearAccountId,
    nearEd25519SigningKeyId: identity.nearSigningKeyId,
    authorizationId: identity.authorizationId,
    walletSessionId: identity.walletSessionId,
    quotaId: identity.quotaId,
    thresholdSessionId: identity.thresholdSessionId,
    relayerKeyId: identity.signingWorkerId,
    authority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: identity.signingWorkerId,
    },
  });
  if (!claims) throw new Error('recovery fixture Wallet Session claims are invalid');
  return claims;
}

function unavailableRecoveryBackend(): RouterAbEd25519YaoRecoveryBackend {
  return new UnavailableRecoveryBackend();
}

function fixtureBackendUnavailable(): RouterAbEd25519YaoRecoveryBackendResult {
  return {
    ok: false as const,
    status: 503,
    code: 'fixture_backend_unavailable',
    message: 'fixture backend unavailable',
  };
}

function requireParsed<T>(parsed: { ok: true; value: T } | { ok: false; message: string }): T {
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}
