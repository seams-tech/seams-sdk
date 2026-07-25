import {
  parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { CloudflareVersionedJsonRecordReadResult } from '../../../packages/sdk-server-ts/src/router/cloudflare/versionedJsonRecordStore';
import {
  parseRouterAbEd25519WalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
} from '../../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import {
  createRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationStateV1,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import {
  createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1,
  type RouterAbEd25519YaoProductRegistrationPartitionMutationV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
  type RouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  type RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import {
  InMemoryRouterAbEd25519YaoRecoveryService,
  type RouterAbEd25519YaoRecoveryAdmissionCommitInputV1,
  type RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  type RouterAbEd25519YaoRecoveryAuthorizationInput,
  type RouterAbEd25519YaoRecoveryAuthorizationResult,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRecoveryBackendResult,
  type RouterAbEd25519YaoRecoveryExecuteCommitInputV1,
} from '../../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';

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
  readonly walletSessionId: string;
  readonly signingGrantId: string;
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
  walletSessionId: 'wallet-session-recovery-1',
  signingGrantId: 'signing-grant-recovery-1',
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
  walletSessionId: 'wallet-session-recovery-2',
  signingGrantId: 'signing-grant-recovery-2',
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
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly authorization: RouterAbEd25519YaoRecoveryAuthorizationAdapter;
};

class MemoryPartitionRecordStore implements RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1 {
  private readonly records = new Map<string, StoredRecord>();

  async readMany(keys: readonly string[]): Promise<
    readonly {
      readonly key: string;
      readonly result: CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
    }[]
  > {
    const results: {
      readonly key: string;
      readonly result: CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
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
  });
  if (committed.kind !== 'stored') {
    throw new Error('secondary recovery fixture state did not commit');
  }
  return recoveryFixture(SECONDARY_IDENTITY, store);
}

function recoveryFixture(
  identity: RecoveryFixtureIdentity,
  store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
): RouterAbEd25519YaoRecoveryRequestScopedFixture {
  const admission = recoveryAdmission(identity);
  const admissionReceipt = recoveryAdmissionReceipt(admission);
  const execution = recoveryExecution(admissionReceipt);
  return {
    lifecycleId: identity.lifecycleId,
    admission,
    admissionReceipt,
    execution,
    executionResult: recoveryExecutionResult(execution, identity.registeredPublicKeySeed),
    store,
    authorization: new AllowRecoveryAuthorization(identity),
  };
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
        wallet_session_id: identity.walletSessionId,
        signer_set_id: identity.signerSetId,
        signing_worker_id: identity.signingWorkerId,
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
      session_id: identity.walletSessionId,
      signer_set_id: identity.signerSetId,
      selected_server_id: identity.signingWorkerId,
    },
    operation: 'registration' as const,
    session_id: bytes(6),
    stable_key_context_binding: bytes(8),
  };
}

function registrationResult(identity: RecoveryFixtureIdentity) {
  const binding = registrationBinding(identity);
  return requireParsed(
    parseRouterAbEd25519YaoRegistrationActivationResultV1({
      binding,
      deriver_a_client_package: activationClientPackage(binding, 'deriver_a'),
      deriver_b_client_package: activationClientPackage(binding, 'deriver_b'),
      public_receipt: publicReceipt(1, identity.registeredPublicKeySeed),
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
        wallet_session_id: identity.walletSessionId,
        signer_set_id: identity.signerSetId,
        signing_worker_id: identity.signingWorkerId,
      },
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
      public_receipt: publicReceipt(2, registeredPublicKeySeed),
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

function publicReceipt(stateEpoch: number, registeredPublicKeySeed: number) {
  return {
    transcript: bytes(11),
    registered_public_key: bytes(registeredPublicKeySeed),
    joined_client_commitment: bytes(13),
    joined_signing_worker_commitment: bytes(15),
    signing_worker_verifying_share: bytes(15),
    state_epoch: stateEpoch,
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
    thresholdSessionId: identity.walletSessionId,
    signingGrantId: identity.signingGrantId,
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
