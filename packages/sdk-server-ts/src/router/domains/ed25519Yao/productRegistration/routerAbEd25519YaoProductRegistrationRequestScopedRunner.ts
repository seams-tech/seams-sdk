import type {
  RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1,
  RouterAbEd25519YaoProductRegistrationPartitionedStateV1,
} from './routerAbEd25519YaoProductRegistrationPartitionedStateStore';
import type { RouterAbEd25519YaoProductRegistrationStateV1 } from './routerAbEd25519YaoProductRegistration';

export type RouterAbEd25519YaoProductRegistrationRequestScopedExecutionV1<T> = (
  state: RouterAbEd25519YaoProductRegistrationStateV1,
) => Promise<{
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly value: T;
}>;

export type RouterAbEd25519YaoProductRegistrationRequestScopedRunInputV1<T> = {
  readonly lifecycleId: string;
  readonly store: RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1;
  readonly execute: RouterAbEd25519YaoProductRegistrationRequestScopedExecutionV1<T>;
};

export type RouterAbEd25519YaoProductRegistrationRequestScopedRunResultV1<T> =
  | {
      readonly kind: 'committed';
      readonly value: T;
      readonly sharedVersion: string | null;
      readonly ceremonyVersion: string;
    }
  | {
      readonly kind: 'version_mismatch';
      readonly key: 'shared' | 'ceremony' | 'execution';
    };

/**
 * Runs one request against a request-local product-state snapshot.
 *
 * The executor owns the Yao-specific state transition. Non-Yao request
 * handling stays outside this boundary until the Gateway route can prove an
 * equivalent side-effect and commit boundary.
 */
export async function runRouterAbEd25519YaoProductRegistrationRequestScopedV1<T>(
  input: RouterAbEd25519YaoProductRegistrationRequestScopedRunInputV1<T>,
): Promise<RouterAbEd25519YaoProductRegistrationRequestScopedRunResultV1<T>> {
  const loaded = await input.store.load(input.lifecycleId);
  const execution = await input.execute(loaded.state);
  const committed = await input.store.commit(
    buildCommitInput(input.lifecycleId, loaded, execution.state),
  );
  if (committed.kind === 'version_mismatch') {
    return committed;
  }
  return {
    kind: 'committed',
    value: execution.value,
    sharedVersion: committed.sharedVersion,
    ceremonyVersion: committed.ceremonyVersion,
  };
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
