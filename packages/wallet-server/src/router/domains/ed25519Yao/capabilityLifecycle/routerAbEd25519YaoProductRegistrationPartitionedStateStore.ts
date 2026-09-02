import type {
  VersionedJsonObject,
  VersionedJsonRecordPutResult,
  VersionedJsonRecordReadResult,
  VersionedJsonValue,
} from '../../../framework/versionedJsonRecordStore';
import type {
  RouterAbEd25519YaoActivationConsumptionRequestV1,
  RouterAbEd25519YaoActivationConsumptionResultV1,
  RouterAbEd25519YaoRegistrationFailure,
} from '../registration/routerAbEd25519YaoRegistration';
import {
  routerAbEd25519YaoRegistrationAdmissionBindingJsonV1,
  routerAbEd25519YaoRegistrationExecutionRecordKeyV1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTION_RECORD_KIND_V1,
  encodeRouterAbEd25519YaoRegistrationExecutionRecordV1,
  parseRouterAbEd25519YaoRegistrationExecutionRecordV1,
  type RouterAbEd25519YaoRegistrationExecutionRecordV1,
} from '../registration/routerAbEd25519YaoRegistrationExecutionRecord';
import { routerAbEd25519YaoCredentialDigestHexV1 } from '../registration/routerAbEd25519YaoRegistrationIntentAuthorization';
import { createRouterAbEd25519YaoProductRegistrationStateV1 } from './routerAbEd25519YaoProductRegistration';
import type { RouterAbEd25519YaoProductRegistrationStateV1 } from './routerAbEd25519YaoProductRegistration';
import {
  encodeRouterAbEd25519YaoProductRegistrationStateV1,
  parseRouterAbEd25519YaoProductRegistrationStateJsonV1,
} from './routerAbEd25519YaoProductRegistrationPersistence';
import {
  boundedRouterAbEd25519YaoProductRegistrationSharedStateV1,
  mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1,
  partitionRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationCeremonyStateV1,
  type RouterAbEd25519YaoProductRegistrationSharedStateV1,
} from './routerAbEd25519YaoProductRegistrationPartitioning';

export const ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1 = 'router-ab-ed25519-yao:shared';
const PARTITION_RECORD_CODEC_KIND =
  'router_ab_ed25519_yao_product_registration_partition_record_json_v1';
const SHARED_RECORD_KIND = 'router_ab_ed25519_yao_product_registration_shared_record_v1';
const CEREMONY_RECORD_KIND = 'router_ab_ed25519_yao_product_registration_ceremony_record_v1';
const EXECUTION_RECORD_KIND = ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTION_RECORD_KIND_V1;
const EXECUTION_RECONCILIATION_LEASE_MS = 10_000;

type EncodedPartitionRecord =
  | {
      readonly kind: typeof PARTITION_RECORD_CODEC_KIND;
      readonly recordKind: typeof SHARED_RECORD_KIND | typeof CEREMONY_RECORD_KIND;
      readonly lifecycleId: string;
      readonly state: VersionedJsonObject;
    }
  | {
      readonly kind: typeof PARTITION_RECORD_CODEC_KIND;
      readonly recordKind: typeof EXECUTION_RECORD_KIND;
      readonly lifecycleId: string;
      readonly execution: VersionedJsonObject;
    };

export type RouterAbEd25519YaoProductRegistrationPartitionRecordV1 =
  | {
      readonly kind: typeof SHARED_RECORD_KIND;
      readonly value: RouterAbEd25519YaoProductRegistrationSharedStateV1;
    }
  | {
      readonly kind: typeof CEREMONY_RECORD_KIND;
      readonly lifecycleId: string;
      readonly value: RouterAbEd25519YaoProductRegistrationCeremonyStateV1;
    }
  | {
      readonly kind: typeof EXECUTION_RECORD_KIND;
      readonly lifecycleId: string;
      readonly value: RouterAbEd25519YaoRegistrationExecutionRecordV1;
    };

export type RouterAbEd25519YaoProductRegistrationPartitionMutationV1 = {
  readonly key: string;
  readonly value: RouterAbEd25519YaoProductRegistrationPartitionRecordV1;
  readonly expectedVersion: string | null;
};

export type RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1 =
  | {
      readonly kind: 'stored';
      readonly versions: readonly {
        readonly key: string;
        readonly version: string;
      }[];
    }
  | { readonly kind: 'version_mismatch'; readonly key: string };

export type RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1 = {
  readonly readMany: (keys: readonly string[]) => Promise<
    readonly {
      readonly key: string;
      readonly result: VersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
    }[]
  >;
  readonly putMany: (
    mutations: readonly RouterAbEd25519YaoProductRegistrationPartitionMutationV1[],
  ) => Promise<RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1>;
};

export type RouterAbEd25519YaoProductRegistrationPartitionedStateV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_partitioned_state_v1';
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly sharedState: RouterAbEd25519YaoProductRegistrationSharedStateV1;
  readonly sharedVersion: string | null;
  readonly ceremonyVersion: string | null;
  readonly execution: RouterAbEd25519YaoRegistrationExecutionRecordV1 | null;
  readonly executionVersion: string | null;
};

export type RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1 = {
  readonly lifecycleId: string;
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly sharedState: RouterAbEd25519YaoProductRegistrationSharedStateV1;
  readonly sharedVersion: string | null;
  readonly ceremonyVersion: string | null;
  readonly execution: RouterAbEd25519YaoRegistrationExecutionRecordV1 | null;
  readonly executionVersion: string | null;
};

export type RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1 =
  | {
      readonly kind: 'stored';
      readonly sharedVersion: string | null;
      readonly ceremonyVersion: string;
      readonly executionVersion: string | null;
    }
  | { readonly kind: 'version_mismatch'; readonly key: 'shared' | 'ceremony' | 'execution' };

type ExecuteRequest = Extract<
  RouterAbEd25519YaoRegistrationExecutionRecordV1,
  { readonly kind: 'claimed' }
>['request'];
type ActivationResult = Extract<
  RouterAbEd25519YaoRegistrationExecutionRecordV1,
  { readonly kind: 'completed' }
>['result'];

export type RouterAbEd25519YaoRegistrationExecutionClaimResultV1 =
  | {
      readonly kind: 'claimed';
      readonly value: Extract<
        RouterAbEd25519YaoRegistrationExecutionRecordV1,
        { readonly kind: 'claimed' }
      >;
      readonly version: string;
    }
  | { readonly kind: 'completed'; readonly value: ActivationResult }
  | { readonly kind: 'failed'; readonly value: RouterAbEd25519YaoRegistrationFailure }
  | {
      readonly kind: 'rejected';
      readonly code:
        | 'unknown_registration'
        | 'binding_mismatch'
        | 'credential_rejected'
        | 'credential_expired'
        | 'execution_in_progress';
      readonly message: string;
    };

export type RouterAbEd25519YaoRegistrationExecutionCommitResultV1 =
  | {
      readonly kind: 'stored';
      readonly value: ActivationResult | RouterAbEd25519YaoRegistrationFailure;
    }
  | { readonly kind: 'uncertain' };

export interface RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  load(lifecycleId: string): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1>;
  commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1>;
  claimRegistrationExecution(input: {
    readonly lifecycleId: string;
    readonly request: ExecuteRequest;
    readonly requestDigestSha256Hex: string;
    readonly credentialDigestSha256Hex: string;
    readonly nowMs: number;
  }): Promise<RouterAbEd25519YaoRegistrationExecutionClaimResultV1>;
  commitRegistrationExecution(input: {
    readonly claimed: Extract<
      RouterAbEd25519YaoRegistrationExecutionRecordV1,
      { readonly kind: 'claimed' }
    >;
    readonly claimedVersion: string;
    readonly outcome:
      | { readonly kind: 'completed'; readonly result: ActivationResult }
      | { readonly kind: 'failed'; readonly failure: RouterAbEd25519YaoRegistrationFailure };
  }): Promise<RouterAbEd25519YaoRegistrationExecutionCommitResultV1>;
  consumeRegistrationExecution(
    input: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ): Promise<RouterAbEd25519YaoActivationConsumptionResultV1>;
}

export function routerAbEd25519YaoPartitionedStateAfterStoredCommitV1(input: {
  readonly lifecycleId: string;
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly commit: Extract<
    RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1,
    { readonly kind: 'stored' }
  >;
}): RouterAbEd25519YaoProductRegistrationPartitionedStateV1 {
  const lifecycleId = requireLifecycleId(input.lifecycleId);
  const partition = partitionRouterAbEd25519YaoProductRegistrationStateV1(input.state, lifecycleId);
  const shared = boundedRouterAbEd25519YaoProductRegistrationSharedStateV1(partition.shared);
  const execution = registrationExecutionRecordFromState(input.state, lifecycleId);
  return {
    kind: 'router_ab_ed25519_yao_product_registration_partitioned_state_v1',
    state: input.state,
    sharedState: shared,
    sharedVersion: input.commit.sharedVersion,
    ceremonyVersion: input.commit.ceremonyVersion,
    execution,
    executionVersion: input.commit.executionVersion,
  };
}

export function createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(
  store: RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
  atomicPatch?: AtomicPatch,
): RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  return new RouterAbEd25519YaoProductRegistrationPartitionedStateStore(store, atomicPatch);
}

export function encodeRouterAbEd25519YaoProductRegistrationPartitionRecordV1(
  record: RouterAbEd25519YaoProductRegistrationPartitionRecordV1,
): VersionedJsonObject {
  if (record.kind === EXECUTION_RECORD_KIND) {
    return {
      kind: PARTITION_RECORD_CODEC_KIND,
      recordKind: EXECUTION_RECORD_KIND,
      lifecycleId: record.lifecycleId,
      execution: encodeRouterAbEd25519YaoRegistrationExecutionRecordV1(record.value),
    } satisfies EncodedPartitionRecord;
  }
  const lifecycleId = record.kind === SHARED_RECORD_KIND ? 'shared' : record.lifecycleId;
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  const empty = partitionRouterAbEd25519YaoProductRegistrationStateV1(state, lifecycleId);
  const materialized = mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1(state, {
    kind: 'router_ab_ed25519_yao_product_registration_state_partition_v1',
    lifecycleId,
    shared: record.kind === SHARED_RECORD_KIND ? record.value : empty.shared,
    ceremony: record.kind === CEREMONY_RECORD_KIND ? record.value : empty.ceremony,
  });
  return {
    kind: PARTITION_RECORD_CODEC_KIND,
    recordKind: record.kind,
    lifecycleId,
    state: encodeRouterAbEd25519YaoProductRegistrationStateV1(materialized),
  } satisfies EncodedPartitionRecord;
}

export function parseRouterAbEd25519YaoProductRegistrationPartitionRecordV1(
  input: unknown,
): RouterAbEd25519YaoProductRegistrationPartitionRecordV1 | null {
  if (!isRecord(input) || input.kind !== PARTITION_RECORD_CODEC_KIND) return null;
  if (input.recordKind === EXECUTION_RECORD_KIND) {
    const lifecycleId = readLifecycleId(input.lifecycleId);
    const execution = parseRouterAbEd25519YaoRegistrationExecutionRecordV1(input.execution);
    return lifecycleId !== null && execution?.lifecycleId === lifecycleId
      ? { kind: EXECUTION_RECORD_KIND, lifecycleId, value: execution }
      : null;
  }
  if (input.recordKind !== SHARED_RECORD_KIND && input.recordKind !== CEREMONY_RECORD_KIND) {
    return null;
  }
  const lifecycleId = readLifecycleId(input.lifecycleId);
  if (lifecycleId === null) return null;
  const state = parseRouterAbEd25519YaoProductRegistrationStateJsonV1(input.state);
  if (state === null) return null;
  const partition = partitionRouterAbEd25519YaoProductRegistrationStateV1(state, lifecycleId);
  if (
    stateFingerprint(state) !==
    stateFingerprint(materializeState(partition.shared, partition.ceremony))
  ) {
    return null;
  }
  if (input.recordKind === SHARED_RECORD_KIND) {
    if (lifecycleId !== 'shared') return null;
    return { kind: SHARED_RECORD_KIND, value: partition.shared };
  }
  if (partition.ceremony.lifecycleId !== lifecycleId) return null;
  return { kind: CEREMONY_RECORD_KIND, lifecycleId, value: partition.ceremony };
}

type AtomicPatch = (
  input: {
    readonly key: string;
    readonly expectedVersion: string;
    readonly exactStringPredicates: readonly {
      readonly jsonPath: string;
      readonly value: string;
    }[];
    readonly unexpired: {
      readonly jsonPath: string;
      readonly nowMs: number;
    };
    readonly patch: VersionedJsonObject;
  },
) => Promise<
  VersionedJsonRecordPutResult & {
    readonly value?: RouterAbEd25519YaoProductRegistrationPartitionRecordV1;
  }
>;

class RouterAbEd25519YaoProductRegistrationPartitionedStateStore implements RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  constructor(
    private readonly store: RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
    private readonly atomicPatch?: AtomicPatch,
  ) {}

  async load(
    lifecycleId: string,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1> {
    const normalizedLifecycleId = requireLifecycleId(lifecycleId);
    const entries = await this.store.readMany([
      ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1,
      normalizedLifecycleId,
      routerAbEd25519YaoRegistrationExecutionRecordKeyV1(normalizedLifecycleId),
    ]);
    const sharedResult = readManyEntry(entries, ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1);
    const ceremonyResult = readManyEntry(entries, normalizedLifecycleId);
    const shared = readSharedRecord(sharedResult);
    const ceremony = readCeremonyRecord(ceremonyResult, normalizedLifecycleId);
    const execution = readExecutionRecord(
      readManyEntry(
        entries,
        routerAbEd25519YaoRegistrationExecutionRecordKeyV1(normalizedLifecycleId),
      ),
      normalizedLifecycleId,
    );
    return {
      kind: 'router_ab_ed25519_yao_product_registration_partitioned_state_v1',
      state: materializeState(shared.value, ceremony.value),
      sharedState: shared.value,
      sharedVersion: shared.version,
      ceremonyVersion: ceremony.version,
      execution: execution.value,
      executionVersion: execution.version,
    };
  }

  async commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1> {
    const lifecycleId = requireLifecycleId(input.lifecycleId);
    const partition = partitionRouterAbEd25519YaoProductRegistrationStateV1(
      input.state,
      lifecycleId,
    );
    const shared = boundedRouterAbEd25519YaoProductRegistrationSharedStateV1(partition.shared);
    const mutations: RouterAbEd25519YaoProductRegistrationPartitionMutationV1[] = [];
    if (stateFingerprint(shared) !== stateFingerprint(input.sharedState)) {
      mutations.push({
        key: ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1,
        value: {
          kind: 'router_ab_ed25519_yao_product_registration_shared_record_v1',
          value: shared,
        },
        expectedVersion: input.sharedVersion,
      });
    }
    mutations.push({
      key: lifecycleId,
      value: {
        kind: 'router_ab_ed25519_yao_product_registration_ceremony_record_v1',
        lifecycleId,
        value: partition.ceremony,
      },
      expectedVersion: input.ceremonyVersion,
    });
    const execution = registrationExecutionRecordFromState(input.state, lifecycleId);
    if (input.execution === null && execution !== null) {
      mutations.push({
        key: routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId),
        value: { kind: EXECUTION_RECORD_KIND, lifecycleId, value: execution },
        expectedVersion: input.executionVersion,
      });
    }
    const result = await this.store.putMany(mutations);
    if (result.kind === 'version_mismatch') {
      return {
        kind: 'version_mismatch',
        key:
          result.key === ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1
            ? 'shared'
            : result.key === routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId)
              ? 'execution'
              : 'ceremony',
      };
    }
    const sharedVersion =
      mutations[0]?.key === ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1
        ? findStoredVersion(result.versions, ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1)
        : input.sharedVersion;
    const ceremonyVersion = findStoredVersion(result.versions, lifecycleId);
    const executionVersion =
      execution !== null && input.execution === null
        ? findStoredVersion(
            result.versions,
            routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId),
          )
        : input.executionVersion;
    return { kind: 'stored', sharedVersion, ceremonyVersion, executionVersion };
  }

  async claimRegistrationExecution(input: {
    readonly lifecycleId: string;
    readonly request: ExecuteRequest;
    readonly requestDigestSha256Hex: string;
    readonly credentialDigestSha256Hex: string;
    readonly nowMs: number;
  }): Promise<RouterAbEd25519YaoRegistrationExecutionClaimResultV1> {
    const lifecycleId = requireLifecycleId(input.lifecycleId);
    const key = routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId);
    const admissionBindingJson = JSON.stringify(input.request.binding);
    if (this.atomicPatch) {
      const patch = await this.atomicPatch({
        key,
        expectedVersion: '1',
        exactStringPredicates: [
          { jsonPath: '$.recordKind', value: EXECUTION_RECORD_KIND },
          { jsonPath: '$.lifecycleId', value: lifecycleId },
          { jsonPath: '$.execution.kind', value: 'ready' },
          {
            jsonPath: '$.execution.admissionBindingJson',
            value: admissionBindingJson,
          },
          {
            jsonPath: '$.execution.credentialDigestSha256Hex',
            value: input.credentialDigestSha256Hex,
          },
        ],
        unexpired: { jsonPath: '$.execution.expiresAtMs', nowMs: input.nowMs },
        patch: {
          execution: {
            kind: 'claimed',
            requestDigestSha256Hex: input.requestDigestSha256Hex,
            request: versionedJsonObject(input.request),
            claimedAtMs: input.nowMs,
            reconcileAfterMs: input.nowMs + EXECUTION_RECONCILIATION_LEASE_MS,
          },
        },
      });
      if (patch.kind === 'stored') {
        const stored = patch.value;
        if (stored?.kind !== EXECUTION_RECORD_KIND || stored.value.kind !== 'claimed') {
          throw new Error('Yao registration atomic claim returned an invalid execution record');
        }
        return { kind: 'claimed', value: stored.value, version: patch.version };
      }
    }
    return await this.reconcileRegistrationExecutionClaim(input);
  }

  async commitRegistrationExecution(input: {
    readonly claimed: Extract<
      RouterAbEd25519YaoRegistrationExecutionRecordV1,
      { readonly kind: 'claimed' }
    >;
    readonly claimedVersion: string;
    readonly outcome:
      | { readonly kind: 'completed'; readonly result: ActivationResult }
      | { readonly kind: 'failed'; readonly failure: RouterAbEd25519YaoRegistrationFailure };
  }): Promise<RouterAbEd25519YaoRegistrationExecutionCommitResultV1> {
    const terminal: RouterAbEd25519YaoRegistrationExecutionRecordV1 =
      input.outcome.kind === 'completed'
        ? {
            ...input.claimed,
            kind: 'completed',
            result: input.outcome.result,
            consumerBinding: null,
          }
        : { ...input.claimed, kind: 'failed', failure: input.outcome.failure };
    const key = routerAbEd25519YaoRegistrationExecutionRecordKeyV1(input.claimed.lifecycleId);
    const stored = await this.store.putMany([
      {
        key,
        value: {
          kind: EXECUTION_RECORD_KIND,
          lifecycleId: input.claimed.lifecycleId,
          value: terminal,
        },
        expectedVersion: input.claimedVersion,
      },
    ]);
    if (stored.kind === 'stored') {
      return {
        kind: 'stored',
        value: terminal.kind === 'completed' ? terminal.result : terminal.failure,
      };
    }
    const current = await this.readRegistrationExecution(input.claimed.lifecycleId);
    if (
      current?.kind === terminal.kind &&
      current.requestDigestSha256Hex === input.claimed.requestDigestSha256Hex
    ) {
      if (
        terminal.kind === 'completed' &&
        current.kind === 'completed' &&
        stateFingerprint(current.result) === stateFingerprint(terminal.result)
      ) {
        return { kind: 'stored', value: current.result };
      }
      if (
        terminal.kind === 'failed' &&
        current.kind === 'failed' &&
        stateFingerprint(current.failure) === stateFingerprint(terminal.failure)
      ) {
        return { kind: 'stored', value: current.failure };
      }
    }
    return { kind: 'uncertain' };
  }

  async consumeRegistrationExecution(
    input: RouterAbEd25519YaoActivationConsumptionRequestV1,
  ): Promise<RouterAbEd25519YaoActivationConsumptionResultV1> {
    const lifecycleId = requireLifecycleId(input.reference.lifecycleId);
    const key = routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const entry = readManyEntry(await this.store.readMany([key]), key);
      if (entry.kind === 'missing') {
        return {
          ok: false,
          code: 'unknown_registration',
          message: 'registration lifecycle was not found',
        };
      }
      if (entry.value.kind !== EXECUTION_RECORD_KIND || entry.value.lifecycleId !== lifecycleId) {
        throw new Error('Yao registration execution record does not match its lifecycle');
      }
      const execution = entry.value.value;
      if (execution.kind !== 'completed') {
        return {
          ok: false,
          code: 'registration_not_activated',
          message: 'registration lifecycle has no verified Yao activation',
        };
      }
      if (
        stateFingerprint(execution.result.binding.session_id) !==
        stateFingerprint(input.reference.sessionId)
      ) {
        return {
          ok: false,
          code: 'activation_reference_mismatch',
          message: 'Yao activation reference does not match the admitted registration',
        };
      }
      if (
        execution.consumerBinding !== null &&
        execution.consumerBinding !== input.consumerBinding
      ) {
        return {
          ok: false,
          code: 'activation_consumed',
          message: 'Yao activation was already consumed by wallet finalization',
        };
      }
      if (execution.consumerBinding !== null) {
        return {
          ok: true,
          activation: {
            admissionRequest: execution.admissionRequest,
            admissionReceipt: execution.admissionReceipt,
            result: execution.result,
          },
        };
      }
      const consumed = { ...execution, consumerBinding: input.consumerBinding };
      const result = await this.store.putMany([
        {
          key,
          value: { kind: EXECUTION_RECORD_KIND, lifecycleId, value: consumed },
          expectedVersion: entry.version,
        },
      ]);
      if (result.kind === 'stored') {
        return {
          ok: true,
          activation: {
            admissionRequest: execution.admissionRequest,
            admissionReceipt: execution.admissionReceipt,
            result: execution.result,
          },
        };
      }
    }
    throw new Error('Yao registration execution consumer claim did not converge');
  }

  private async reconcileRegistrationExecutionClaim(input: {
    readonly lifecycleId: string;
    readonly request: ExecuteRequest;
    readonly requestDigestSha256Hex: string;
    readonly credentialDigestSha256Hex: string;
    readonly nowMs: number;
  }): Promise<RouterAbEd25519YaoRegistrationExecutionClaimResultV1> {
    const lifecycleId = requireLifecycleId(input.lifecycleId);
    const key = routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId);
    const entry = readManyEntry(await this.store.readMany([key]), key);
    if (entry.kind === 'missing') {
      return {
        kind: 'rejected',
        code: 'unknown_registration',
        message: 'registration admission was not found',
      };
    }
    if (entry.value.kind !== EXECUTION_RECORD_KIND || entry.value.lifecycleId !== lifecycleId) {
      throw new Error('Yao registration execution record does not match its lifecycle');
    }
    const execution = entry.value.value;
    if (execution.admissionBindingJson !== JSON.stringify(input.request.binding)) {
      return {
        kind: 'rejected',
        code: 'binding_mismatch',
        message: 'registration execution does not match the admitted binding',
      };
    }
    if (execution.credentialDigestSha256Hex !== input.credentialDigestSha256Hex) {
      return {
        kind: 'rejected',
        code: 'credential_rejected',
        message: 'registration execution credential does not match its admission subject',
      };
    }
    if (execution.expiresAtMs <= input.nowMs) {
      return {
        kind: 'rejected',
        code: 'credential_expired',
        message: 'registration intent credential is expired',
      };
    }
    switch (execution.kind) {
      case 'completed':
        return execution.requestDigestSha256Hex === input.requestDigestSha256Hex
          ? { kind: 'completed', value: execution.result }
          : {
              kind: 'rejected',
              code: 'binding_mismatch',
              message: 'completed registration rejects a different execution payload',
            };
      case 'failed':
        return execution.requestDigestSha256Hex === input.requestDigestSha256Hex
          ? { kind: 'failed', value: execution.failure }
          : {
              kind: 'rejected',
              code: 'binding_mismatch',
              message: 'failed registration rejects a different execution payload',
            };
      case 'claimed':
        if (execution.requestDigestSha256Hex !== input.requestDigestSha256Hex) {
          return {
            kind: 'rejected',
            code: 'execution_in_progress',
            message: 'registration execution is already in progress',
          };
        }
        if (execution.reconcileAfterMs > input.nowMs) {
          return {
            kind: 'rejected',
            code: 'execution_in_progress',
            message: 'registration execution is already in progress',
          };
        }
        return await this.renewRegistrationExecutionClaim(execution, entry.version, input.nowMs);
      case 'ready': {
        const claimed: RouterAbEd25519YaoRegistrationExecutionRecordV1 = {
          ...execution,
          kind: 'claimed',
          requestDigestSha256Hex: input.requestDigestSha256Hex,
          request: input.request,
          claimedAtMs: input.nowMs,
          reconcileAfterMs: input.nowMs + EXECUTION_RECONCILIATION_LEASE_MS,
        };
        const result = await this.store.putMany([
          {
            key,
            value: { kind: EXECUTION_RECORD_KIND, lifecycleId, value: claimed },
            expectedVersion: entry.version,
          },
        ]);
        return result.kind === 'stored'
          ? {
              kind: 'claimed',
              value: claimed,
              version: findStoredVersion(result.versions, key),
            }
          : await this.reconcileRegistrationExecutionClaim(input);
      }
    }
  }

  private async renewRegistrationExecutionClaim(
    execution: Extract<
      RouterAbEd25519YaoRegistrationExecutionRecordV1,
      { readonly kind: 'claimed' }
    >,
    expectedVersion: string,
    nowMs: number,
  ): Promise<RouterAbEd25519YaoRegistrationExecutionClaimResultV1> {
    const renewed = {
      ...execution,
      claimedAtMs: nowMs,
      reconcileAfterMs: nowMs + EXECUTION_RECONCILIATION_LEASE_MS,
    };
    const key = routerAbEd25519YaoRegistrationExecutionRecordKeyV1(execution.lifecycleId);
    const result = await this.store.putMany([
      {
        key,
        value: {
          kind: EXECUTION_RECORD_KIND,
          lifecycleId: execution.lifecycleId,
          value: renewed,
        },
        expectedVersion,
      },
    ]);
    return result.kind === 'stored'
      ? {
          kind: 'claimed',
          value: renewed,
          version: findStoredVersion(result.versions, key),
        }
      : {
          kind: 'rejected',
          code: 'execution_in_progress',
          message: 'registration execution reconciliation was claimed concurrently',
        };
  }

  private async readRegistrationExecution(
    lifecycleId: string,
  ): Promise<RouterAbEd25519YaoRegistrationExecutionRecordV1 | null> {
    const key = routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId);
    const entry = readManyEntry(await this.store.readMany([key]), key);
    if (entry.kind === 'missing') return null;
    if (entry.value.kind !== EXECUTION_RECORD_KIND || entry.value.lifecycleId !== lifecycleId) {
      throw new Error('Yao registration execution record does not match its lifecycle');
    }
    return entry.value.value;
  }
}

type ReadPartitionRecordResult = {
  readonly value: RouterAbEd25519YaoProductRegistrationSharedStateV1;
  readonly version: string | null;
};

function readManyEntry<T>(
  entries: readonly { readonly key: string; readonly result: T }[],
  key: string,
): T {
  const entry = entries.find((candidate) => candidate.key === key);
  if (!entry) throw new Error(`Router A/B batch read omitted ${key}`);
  return entry.result;
}

type ReadCeremonyRecordResult = {
  readonly value: RouterAbEd25519YaoProductRegistrationCeremonyStateV1;
  readonly version: string | null;
};

type ReadExecutionRecordResult = {
  readonly value: RouterAbEd25519YaoRegistrationExecutionRecordV1 | null;
  readonly version: string | null;
};

function readSharedRecord(
  result: VersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>,
): ReadPartitionRecordResult {
  if (result.kind === 'missing') {
    const empty = partitionRouterAbEd25519YaoProductRegistrationStateV1(
      createRouterAbEd25519YaoProductRegistrationStateV1(),
      'initial',
    );
    return { value: empty.shared, version: null };
  }
  if (result.value.kind !== 'router_ab_ed25519_yao_product_registration_shared_record_v1') {
    throw new Error('Router A/B shared state record has an invalid kind');
  }
  return { value: structuredClone(result.value.value), version: result.version };
}

function readCeremonyRecord(
  result: VersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>,
  lifecycleId: string,
): ReadCeremonyRecordResult {
  if (result.kind === 'missing') {
    const empty = partitionRouterAbEd25519YaoProductRegistrationStateV1(
      createRouterAbEd25519YaoProductRegistrationStateV1(),
      lifecycleId,
    );
    return { value: empty.ceremony, version: null };
  }
  if (
    result.value.kind !== 'router_ab_ed25519_yao_product_registration_ceremony_record_v1' ||
    result.value.lifecycleId !== lifecycleId ||
    result.value.value.lifecycleId !== lifecycleId
  ) {
    throw new Error('Router A/B ceremony state record does not match its lifecycle key');
  }
  return { value: structuredClone(result.value.value), version: result.version };
}

function readExecutionRecord(
  result: VersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>,
  lifecycleId: string,
): ReadExecutionRecordResult {
  if (result.kind === 'missing') return { value: null, version: null };
  if (
    result.value.kind !== EXECUTION_RECORD_KIND ||
    result.value.lifecycleId !== lifecycleId ||
    result.value.value.lifecycleId !== lifecycleId
  ) {
    throw new Error('Router A/B execution record does not match its lifecycle key');
  }
  return { value: structuredClone(result.value.value), version: result.version };
}

function registrationExecutionRecordFromState(
  state: RouterAbEd25519YaoProductRegistrationStateV1,
  lifecycleId: string,
): RouterAbEd25519YaoRegistrationExecutionRecordV1 | null {
  const sessionKey = state.registration.lifecycleSessions.get(lifecycleId);
  const registration =
    sessionKey === undefined ? undefined : state.registration.states.get(sessionKey);
  const authority = state.authorization.authorities.find(
    (candidate) => candidate.admissionRequest.scope.lifecycle_id === lifecycleId,
  );
  if (!registration || registration.kind !== 'admitted' || !authority) return null;
  return {
    kind: 'ready',
    lifecycleId,
    admissionRequest: structuredClone(registration.admissionRequest),
    admissionReceipt: structuredClone(registration.admissionReceipt),
    admissionBindingJson: routerAbEd25519YaoRegistrationAdmissionBindingJsonV1(
      registration.admissionReceipt,
    ),
    credentialDigestSha256Hex: routerAbEd25519YaoCredentialDigestHexV1(
      authority.credentialDigestSha256,
    ),
    expiresAtMs: authority.expiresAtMs,
  };
}

function materializeState(
  shared: RouterAbEd25519YaoProductRegistrationSharedStateV1,
  ceremony: RouterAbEd25519YaoProductRegistrationCeremonyStateV1,
): RouterAbEd25519YaoProductRegistrationStateV1 {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  return mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1(state, {
    kind: 'router_ab_ed25519_yao_product_registration_state_partition_v1',
    lifecycleId: ceremony.lifecycleId,
    shared,
    ceremony,
  });
}

function findStoredVersion(
  versions: readonly { readonly key: string; readonly version: string }[],
  key: string,
): string {
  const entry = versions.find((candidate) => candidate.key === key);
  if (!entry) throw new Error(`Router A/B batch result omitted ${key}`);
  return entry.version;
}

function requireLifecycleId(value: string): string {
  if (!isVisibleLifecycleId(value)) throw new Error('Router A/B lifecycle ID is invalid');
  return value;
}

function isVisibleLifecycleId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    /^[\x21-\x7e]+$/u.test(value)
  );
}

function readLifecycleId(value: unknown): string | null {
  return isVisibleLifecycleId(value) ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stateFingerprint(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return `string:${JSON.stringify(value)}`;
  if (typeof value === 'boolean') return `boolean:${value ? '1' : '0'}`;
  if (typeof value === 'number') return `number:${String(value)}`;
  if (value instanceof Uint8Array) return `bytes:${Array.from(value).join(',')}`;
  if (value instanceof Map) {
    return `map:${Array.from(value.entries())
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${stateFingerprint(key)}=${stateFingerprint(entry)}`)
      .join('|')}`;
  }
  if (value instanceof Set) {
    return `set:${Array.from(value, stateFingerprint).sort().join('|')}`;
  }
  if (Array.isArray(value)) return `array:${value.map(stateFingerprint).join('|')}`;
  if (typeof value === 'object') {
    return `object:${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${key}:${stateFingerprint(entry)}`)
      .join('|')}`;
  }
  throw new Error('Router A/B shared state contains an unsupported value');
}

function versionedJsonObject(input: unknown): VersionedJsonObject {
  const value = JSON.parse(JSON.stringify(input));
  if (!isVersionedJsonObject(value)) {
    throw new Error('Router A/B execution request is not canonical JSON');
  }
  return value;
}

function isVersionedJsonObject(input: unknown): input is VersionedJsonObject {
  return isRecord(input) && Object.values(input).every(isVersionedJsonValue);
}

function isVersionedJsonValue(input: unknown): input is VersionedJsonValue {
  if (
    input === null ||
    typeof input === 'string' ||
    typeof input === 'boolean' ||
    typeof input === 'number'
  ) {
    return typeof input !== 'number' || Number.isFinite(input);
  }
  if (Array.isArray(input)) return input.every(isVersionedJsonValue);
  return isVersionedJsonObject(input);
}
