import type { WalletEd25519YaoActiveCapabilityRecord } from '../../../../core/WalletStore';
import {
  InMemoryRouterAbEd25519YaoRegistrationService,
  type RouterAbEd25519YaoActivationConsumptionRequestV1,
  type RouterAbEd25519YaoActivationConsumptionResultV1,
  type RouterAbEd25519YaoRegistrationBackend,
  type RouterAbEd25519YaoRegistrationBackendResult,
  type RouterAbEd25519YaoRegistrationExecuteRequestV1,
  type RouterAbEd25519YaoRegistrationResultV1,
  type RouterAbEd25519YaoRegistrationServiceResult,
} from '../registration/routerAbEd25519YaoRegistration';
import { InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter } from '../registration/routerAbEd25519YaoRegistrationIntentAuthorization';
import type {
  RouterAbEd25519YaoRegistrationIntentBindingResult,
  RouterAbEd25519YaoVerifiedActivationIntentV1,
} from '../registration/routerAbEd25519YaoRegistrationIntentAuthorization';
import {
  InMemoryRouterAbEd25519YaoRecoveryService,
  type RouterAbEd25519YaoActiveCapabilityLookupResultV1,
  type RouterAbEd25519YaoActiveCapabilityLookupV1,
  type RouterAbEd25519YaoRecoveryBackend,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  type RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1,
} from '../recovery/routerAbEd25519YaoRecovery';
import {
  routerAbEd25519YaoPersistedCapabilityMatchesLookupV1,
  type RouterAbEd25519YaoProductRegistrationRuntimeV1,
  type RouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoVerifiedRegistrationAdmissionResultV1,
} from './routerAbEd25519YaoProductRegistration';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
} from './routerAbEd25519YaoProductRegistrationPartitionedStateStore';

export type RouterAbEd25519YaoProductRegistrationRequestScopedRuntimeInputV1 = {
  readonly signingWorkerId: string;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly registrationBackend: RouterAbEd25519YaoRegistrationBackend;
  /** Loads one canonical signer record for an existing-wallet capability miss. */
  readonly loadPersistedActiveCapability?: (
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ) => Promise<WalletEd25519YaoActiveCapabilityRecord | null>;
};

type RequestScopedMutationResult<T> =
  | { readonly kind: 'commit'; readonly value: T }
  | { readonly kind: 'reject'; readonly value: T };

const SHARED_CAPABILITY_READ_LIFECYCLE_ID = 'shared-capability-read';
const MAX_DETERMINISTIC_COMMIT_ATTEMPTS = 2;

const UNUSED_BACKEND: RouterAbEd25519YaoRegistrationBackend & RouterAbEd25519YaoRecoveryBackend = {
  admit: rejectUnusedBackend,
  execute: rejectUnusedBackend,
  admitRecovery: rejectUnusedBackend,
  executeRecovery: rejectUnusedBackend,
  activateRecovery: rejectUnusedBackend,
};

/**
 * Product-state runtime for wallet start/finalize routes. Each mutation loads
 * fresh partitioned state and reconciles CAS conflicts by reapplying only the
 * deterministic state transition. External account, wallet, and session
 * effects stay outside this adapter and are never repeated here.
 */
export function createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1(
  input: RouterAbEd25519YaoProductRegistrationRequestScopedRuntimeInputV1,
): RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  return new RouterAbEd25519YaoProductRegistrationRequestScopedRuntime(input);
}

class RouterAbEd25519YaoProductRegistrationRequestScopedRuntime implements RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  readonly kind = 'router_ab_ed25519_yao_product_registration_runtime_v1' as const;
  readonly signingWorkerId: string;

  constructor(
    private readonly input: RouterAbEd25519YaoProductRegistrationRequestScopedRuntimeInputV1,
  ) {
    this.signingWorkerId = input.signingWorkerId.trim();
    if (!this.signingWorkerId) throw new Error('Ed25519 Yao SigningWorker ID is required');
  }

  async bindVerifiedIntent(
    input: RouterAbEd25519YaoVerifiedActivationIntentV1,
  ): Promise<RouterAbEd25519YaoRegistrationIntentBindingResult> {
    return await this.commitUntilReconciled(
      input.admissionRequest.scope.lifecycle_id,
      bindVerifiedIntentMutation.bind(undefined, input),
    );
  }

  async bindAndAdmitVerifiedRegistration(
    input: RouterAbEd25519YaoVerifiedActivationIntentV1,
  ): Promise<RouterAbEd25519YaoVerifiedRegistrationAdmissionResultV1> {
    return await bindAndAdmitVerifiedRegistration({
      input,
      store: this.input.store,
      backend: this.input.registrationBackend,
    });
  }

  async consumeActivated(
    input: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ): Promise<RouterAbEd25519YaoActivationConsumptionResultV1> {
    return await this.input.store.consumeRegistrationExecution(input);
  }

  async replayActivatedRegistration(
    request: RouterAbEd25519YaoRegistrationExecuteRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationServiceResult<RouterAbEd25519YaoRegistrationResultV1>> {
    const loaded = await this.input.store.load(request.binding.lifecycle.lifecycle_id);
    return registrationService(loaded.state).replayActivated(request);
  }

  async installRegistrationFinalizeCapability(
    input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  ): Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1> {
    return await this.commitUntilReconciled(
      input.registrationAdmissionRequest.scope.lifecycle_id,
      installRegistrationFinalizeCapabilityMutation.bind(undefined, input),
    );
  }

  async installPersistedActiveCapability(
    input: WalletEd25519YaoActiveCapabilityRecord,
  ): Promise<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1> {
    return await this.commitUntilReconciled(
      input.admissionRequest.scope.lifecycle_id,
      installPersistedActiveCapabilityMutation.bind(undefined, input),
    );
  }

  async resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): Promise<RouterAbEd25519YaoActiveCapabilityLookupResultV1> {
    const loaded = await this.input.store.load(SHARED_CAPABILITY_READ_LIFECYCLE_ID);
    const result = recoveryService(loaded.state).resolveActiveCapability(input);
    if (
      result.ok ||
      result.code !== 'unknown_capability' ||
      !this.input.loadPersistedActiveCapability
    ) {
      return result;
    }
    const persisted = await this.input.loadPersistedActiveCapability(input);
    if (!persisted || !routerAbEd25519YaoPersistedCapabilityMatchesLookupV1(persisted, input)) {
      return result;
    }
    const installed = await this.installPersistedActiveCapability(persisted);
    if (!installed.ok) {
      return {
        ok: false,
        code: 'capability_conflict',
        message: installed.message,
      };
    }
    const refreshed = await this.input.store.load(SHARED_CAPABILITY_READ_LIFECYCLE_ID);
    return recoveryService(refreshed.state).resolveActiveCapability(input);
  }

  private async commitUntilReconciled<T>(
    lifecycleId: string,
    mutate: (
      state: RouterAbEd25519YaoProductRegistrationStateV1,
    ) => Promise<RequestScopedMutationResult<T>>,
  ): Promise<T> {
    for (let attempt = 0; attempt < MAX_DETERMINISTIC_COMMIT_ATTEMPTS; attempt += 1) {
      const loaded = await this.input.store.load(lifecycleId);
      const mutation = await mutate(loaded.state);
      if (mutation.kind === 'reject') return mutation.value;
      const committed = await this.input.store.commit(commitInput(lifecycleId, loaded));
      if (committed.kind === 'stored') return mutation.value;
    }
    throw new Error('Request-scoped product state remained contended after one reconciliation');
  }
}

async function bindAndAdmitVerifiedRegistration(input: {
  readonly input: RouterAbEd25519YaoVerifiedActivationIntentV1;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly backend: RouterAbEd25519YaoRegistrationBackend;
}): Promise<RouterAbEd25519YaoVerifiedRegistrationAdmissionResultV1> {
  const lifecycleId = input.input.admissionRequest.scope.lifecycle_id;
  let backendResult: RouterAbEd25519YaoRegistrationBackendResult | null = null;
  for (let attempt = 0; attempt < MAX_DETERMINISTIC_COMMIT_ATTEMPTS; attempt += 1) {
    const loaded = await input.store.load(lifecycleId);
    const bound = await new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
      loaded.state.authorization,
    ).bindVerifiedIntent(input.input);
    if (!bound.ok) return bound;

    const service = new InMemoryRouterAbEd25519YaoRegistrationService(
      input.backend,
      loaded.state.registration,
    );
    const preparation = service.prepareAdmit(input.input.admissionRequest);
    if (preparation.kind === 'completed') {
      return { ok: true, status: 200, value: preparation.value };
    }
    if (preparation.kind === 'failed') return preparation.failure;

    if (backendResult === null) {
      try {
        backendResult = await input.backend.admit(input.input.admissionRequest);
      } catch (error: unknown) {
        return {
          ok: false,
          status: 503,
          code: 'admission_uncertain',
          message: error instanceof Error ? error.message : String(error),
        };
      }
    }
    const admitted = service.commitAdmit({
      request: input.input.admissionRequest,
      claim: preparation.claim,
      outcome: { kind: 'backend_response', result: backendResult },
    });
    if (!admitted.ok) return admitted;

    const committed = await input.store.commit(commitInput(lifecycleId, loaded));
    if (committed.kind === 'stored') return admitted;
  }
  return {
    ok: false,
    status: 503,
    code: 'admission_uncertain',
    message: 'Yao verified registration admission remained contended after one reconciliation',
  };
}

async function bindVerifiedIntentMutation(
  input: RouterAbEd25519YaoVerifiedActivationIntentV1,
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): Promise<RequestScopedMutationResult<RouterAbEd25519YaoRegistrationIntentBindingResult>> {
  const result = await new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter(
    state.authorization,
  ).bindVerifiedIntent(input);
  return result.ok ? { kind: 'commit', value: result } : { kind: 'reject', value: result };
}

async function installRegistrationFinalizeCapabilityMutation(
  input: RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallationV1,
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): Promise<
  RequestScopedMutationResult<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1>
> {
  const result = recoveryService(state).installRegistrationFinalizeCapability(input);
  return result.ok ? { kind: 'commit', value: result } : { kind: 'reject', value: result };
}

async function installPersistedActiveCapabilityMutation(
  input: WalletEd25519YaoActiveCapabilityRecord,
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): Promise<
  RequestScopedMutationResult<RouterAbEd25519YaoRegistrationFinalizeCapabilityInstallResultV1>
> {
  const result = recoveryService(state).installPersistedActiveCapability(input);
  return result.ok ? { kind: 'commit', value: result } : { kind: 'reject', value: result };
}

function registrationService(
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): InMemoryRouterAbEd25519YaoRegistrationService {
  return new InMemoryRouterAbEd25519YaoRegistrationService(UNUSED_BACKEND, state.registration);
}

function recoveryService(
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): InMemoryRouterAbEd25519YaoRecoveryService {
  return new InMemoryRouterAbEd25519YaoRecoveryService(UNUSED_BACKEND, state.recovery);
}

function commitInput(
  lifecycleId: string,
  loaded: RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
) {
  return {
    lifecycleId,
    state: loaded.state,
    sharedState: loaded.sharedState,
    sharedVersion: loaded.sharedVersion,
    ceremonyVersion: loaded.ceremonyVersion,
    execution: loaded.execution,
    executionVersion: loaded.executionVersion,
  };
}

async function rejectUnusedBackend(): Promise<never> {
  throw new Error('Request-scoped product runtime invoked an unavailable protocol backend');
}
