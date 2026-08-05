import type { RouterAbEd25519YaoProductRegistrationStateV1 } from '../capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
} from '../capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import { routerAbEd25519YaoPartitionedStateAfterStoredCommitV1 } from '../capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitionedStateStore';

export type RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1<T> =
  | { readonly kind: 'response'; readonly value: T }
  | { readonly kind: 'uncertain'; readonly message: string };

export type RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1<TClaim, TResponse, TRejection> =
  | {
      readonly kind: 'claimed';
      readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
      readonly claim: TClaim;
    }
  | { readonly kind: 'completed'; readonly value: TResponse }
  | { readonly kind: 'rejected'; readonly value: TRejection };

export type RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1<TResponse> = {
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly value: TResponse;
};

export type RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1<TClaim, TResponse, TRejection> =
  | {
      readonly kind: 'committed';
      readonly value: TResponse;
      readonly sharedVersion: string | null;
      readonly ceremonyVersion: string;
    }
  | { readonly kind: 'completed'; readonly value: TResponse }
  | { readonly kind: 'rejected'; readonly value: TRejection }
  | {
      readonly kind: 'preclaim_version_mismatch';
      readonly key: 'shared' | 'ceremony' | 'execution';
    }
  | { readonly kind: 'backend_uncertain'; readonly claim: TClaim; readonly message: string }
  | {
      readonly kind: 'terminal_version_mismatch';
      readonly claim: TClaim;
      readonly key: 'shared' | 'ceremony' | 'execution';
    };

export type RouterAbEd25519YaoRegistrationTwoPhaseRunInputV1<
  TClaim,
  TBackend,
  TResponse,
  TRejection,
> = {
  readonly lifecycleId: string;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly prepare: (
    state: RouterAbEd25519YaoProductRegistrationStateV1,
  ) => Promise<
    RouterAbEd25519YaoRegistrationTwoPhasePrepareResultV1<TClaim, TResponse, TRejection>
  >;
  readonly backend: (
    claim: TClaim,
  ) => Promise<RouterAbEd25519YaoRegistrationTwoPhaseBackendResultV1<TBackend>>;
  readonly complete: (
    state: RouterAbEd25519YaoProductRegistrationStateV1,
    claim: TClaim,
    backend: TBackend,
  ) => Promise<RouterAbEd25519YaoRegistrationTwoPhaseCompletionV1<TResponse>>;
};

/**
 * Persists a typed execution claim before calling a remote backend, then
 * persists the terminal state through a fresh CAS snapshot. The backend is
 * never retried here. A terminal CAS conflict is reported as uncertain so a
 * caller can reconcile the already-issued backend request.
 */
export async function runRouterAbEd25519YaoRegistrationTwoPhaseV1<
  TClaim,
  TBackend,
  TResponse,
  TRejection,
>(
  input: RouterAbEd25519YaoRegistrationTwoPhaseRunInputV1<TClaim, TBackend, TResponse, TRejection>,
): Promise<RouterAbEd25519YaoRegistrationTwoPhaseRunResultV1<TClaim, TResponse, TRejection>> {
  const loaded = await input.store.load(input.lifecycleId);
  const prepared = await input.prepare(loaded.state);
  switch (prepared.kind) {
    case 'completed':
      return prepared;
    case 'rejected':
      return prepared;
    case 'claimed': {
      const preclaim = await input.store.commit(
        buildCommitInput(input.lifecycleId, loaded, prepared.state),
      );
      if (preclaim.kind === 'version_mismatch') {
        return { kind: 'preclaim_version_mismatch', key: preclaim.key };
      }

      const backend = await input.backend(prepared.claim);
      if (backend.kind === 'uncertain') {
        return { kind: 'backend_uncertain', claim: prepared.claim, message: backend.message };
      }

      const terminalSnapshot = routerAbEd25519YaoPartitionedStateAfterStoredCommitV1({
        lifecycleId: input.lifecycleId,
        state: prepared.state,
        commit: preclaim,
      });
      const completion = await input.complete(
        terminalSnapshot.state,
        prepared.claim,
        backend.value,
      );
      const terminal = await input.store.commit(
        buildCommitInput(input.lifecycleId, terminalSnapshot, completion.state),
      );
      if (terminal.kind === 'version_mismatch') {
        return { kind: 'terminal_version_mismatch', claim: prepared.claim, key: terminal.key };
      }
      return {
        kind: 'committed',
        value: completion.value,
        sharedVersion: terminal.sharedVersion,
        ceremonyVersion: terminal.ceremonyVersion,
      };
    }
  }
}

function buildCommitInput(
  lifecycleId: string,
  loaded: RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1 {
  return {
    lifecycleId,
    state,
    sharedState: loaded.sharedState,
    sharedVersion: loaded.sharedVersion,
    ceremonyVersion: loaded.ceremonyVersion,
    execution: loaded.execution,
    executionVersion: loaded.executionVersion,
  };
}
