import type {
  InMemoryRouterAbEd25519YaoRegistrationStateV1,
  RouterAbEd25519YaoRegistrationAdmissionClaimV1,
} from '../registration/routerAbEd25519YaoRegistration';
import type { InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1 } from '../registration/routerAbEd25519YaoRegistrationIntentAuthorization';
import type { InMemoryRouterAbEd25519YaoRecoveryStateV1 } from '../recovery/routerAbEd25519YaoRecovery';
import type { InMemoryRouterAbEd25519YaoExportStateV1 } from '../export/routerAbEd25519YaoExport';
import type { RouterAbEd25519YaoProductRegistrationStateV1 } from './routerAbEd25519YaoProductRegistration';

type MapValue<T> = T extends Map<string, infer Value> ? Value : never;

type RegistrationLifecycleState = MapValue<InMemoryRouterAbEd25519YaoRegistrationStateV1['states']>;
type RegistrationAdmissionClaim = RouterAbEd25519YaoRegistrationAdmissionClaimV1;
type RegistrationIntentAuthority =
  InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationStateV1['authorities'][number];
type RecoveryCapabilityState = MapValue<InMemoryRouterAbEd25519YaoRecoveryStateV1['capabilities']>;
type RecoveryLifecycleState = MapValue<InMemoryRouterAbEd25519YaoRecoveryStateV1['recoveries']>;
type ExportLifecycleState = MapValue<InMemoryRouterAbEd25519YaoExportStateV1['exports']>;

const MAX_SHARED_RECOVERY_CAPABILITIES = 32;

export type RouterAbEd25519YaoProductRegistrationSharedStateV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_shared_state_v1';
  readonly recoveryCapabilities: Map<string, RecoveryCapabilityState>;
  readonly recoveryIdentityCapabilities: Map<string, string>;
  readonly recoverySessions: Map<string, string>;
  readonly exportAuthorizationNonces: Set<string>;
  readonly exportAuthorizationUncertain: Set<string>;
};

export type RouterAbEd25519YaoProductRegistrationCeremonyStateV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_ceremony_state_v1';
  readonly lifecycleId: string;
  readonly registration: {
    readonly states: Map<string, RegistrationLifecycleState>;
    readonly lifecycleSessions: Map<string, string>;
    readonly admissionClaims: Map<string, RegistrationAdmissionClaim>;
  };
  readonly authorization: {
    readonly authorities: readonly RegistrationIntentAuthority[];
  };
  readonly recovery: {
    readonly recoveries: Map<string, RecoveryLifecycleState>;
  };
  readonly export: {
    readonly exports: Map<string, ExportLifecycleState>;
  };
};

export type RouterAbEd25519YaoProductRegistrationStatePartitionV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_state_partition_v1';
  readonly lifecycleId: string;
  readonly shared: RouterAbEd25519YaoProductRegistrationSharedStateV1;
  readonly ceremony: RouterAbEd25519YaoProductRegistrationCeremonyStateV1;
};

/**
 * Projects the tenant-wide state into shared and lifecycle-owned records.
 * Capability ownership and export nonce replay state deliberately stay in the
 * shared record; only lifecycle-indexed entries enter the ceremony record.
 */
export function partitionRouterAbEd25519YaoProductRegistrationStateV1(
  state: RouterAbEd25519YaoProductRegistrationStateV1,
  lifecycleId: string,
): RouterAbEd25519YaoProductRegistrationStatePartitionV1 {
  const normalizedLifecycleId = requireLifecycleId(lifecycleId);
  const registrationStates = selectMapEntries(
    state.registration.states,
    normalizedLifecycleId,
    registrationStateLifecycleId,
  );
  const recoveryStates = selectMapEntries(
    state.recovery.recoveries,
    normalizedLifecycleId,
    recoveryStateLifecycleId,
  );
  const exportStates = selectMapEntries(
    state.export.exports,
    normalizedLifecycleId,
    exportStateLifecycleId,
  );

  return {
    kind: 'router_ab_ed25519_yao_product_registration_state_partition_v1',
    lifecycleId: normalizedLifecycleId,
    shared: {
      kind: 'router_ab_ed25519_yao_product_registration_shared_state_v1',
      recoveryCapabilities: cloneMapValues(state.recovery.capabilities),
      recoveryIdentityCapabilities: new Map(state.recovery.identityCapabilities),
      recoverySessions: new Map(state.recovery.recoverySessions),
      exportAuthorizationNonces: new Set(state.export.authorizationNonces),
      exportAuthorizationUncertain: new Set(state.export.authorizationUncertain),
    },
    ceremony: {
      kind: 'router_ab_ed25519_yao_product_registration_ceremony_state_v1',
      lifecycleId: normalizedLifecycleId,
      registration: {
        states: registrationStates,
        lifecycleSessions: selectMapLifecycleEntry(
          state.registration.lifecycleSessions,
          normalizedLifecycleId,
        ),
        admissionClaims: selectMapLifecycleEntry(
          state.registration.admissionClaims,
          normalizedLifecycleId,
        ),
      },
      authorization: {
        authorities: state.authorization.authorities
          .filter((authority) => authorityLifecycleId(authority) === normalizedLifecycleId)
          .map((authority) => structuredClone(authority)),
      },
      recovery: {
        recoveries: recoveryStates,
      },
      export: { exports: exportStates },
    },
  };
}

/**
 * Applies one request's partition back onto a complete snapshot. Existing
 * lifecycle entries are replaced while unrelated ceremonies and all shared
 * records remain intact.
 */
export function mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1(
  base: RouterAbEd25519YaoProductRegistrationStateV1,
  partition: RouterAbEd25519YaoProductRegistrationStatePartitionV1,
): RouterAbEd25519YaoProductRegistrationStateV1 {
  const lifecycleId = requireLifecycleId(partition.lifecycleId);
  if (partition.ceremony.lifecycleId !== lifecycleId) {
    throw new Error('Ed25519 Yao ceremony partition lifecycle IDs must match');
  }

  const registrationStates = replaceLifecycleEntries(
    base.registration.states,
    partition.ceremony.registration.states,
    registrationStateLifecycleId,
    lifecycleId,
  );
  const lifecycleSessions = new Map(base.registration.lifecycleSessions);
  lifecycleSessions.delete(lifecycleId);
  for (const [key, value] of partition.ceremony.registration.lifecycleSessions) {
    lifecycleSessions.set(key, value);
  }
  const admissionClaims = new Map(base.registration.admissionClaims);
  admissionClaims.delete(lifecycleId);
  for (const [key, value] of partition.ceremony.registration.admissionClaims) {
    admissionClaims.set(key, value);
  }

  const authorities = base.authorization.authorities
    .filter((authority) => authorityLifecycleId(authority) !== lifecycleId)
    .map((authority) => structuredClone(authority));
  authorities.push(
    ...partition.ceremony.authorization.authorities.map((authority) => structuredClone(authority)),
  );

  const recoveries = replaceLifecycleEntries(
    base.recovery.recoveries,
    partition.ceremony.recovery.recoveries,
    recoveryStateLifecycleId,
    lifecycleId,
  );
  const exports = replaceLifecycleEntries(
    base.export.exports,
    partition.ceremony.export.exports,
    exportStateLifecycleId,
    lifecycleId,
  );

  return {
    kind: 'router_ab_ed25519_yao_product_registration_state_v1',
    registration: {
      states: registrationStates,
      lifecycleSessions,
      admissionClaims: cloneMapValues(admissionClaims),
    },
    authorization: { authorities },
    recovery: {
      capabilities: cloneMapValues(partition.shared.recoveryCapabilities),
      identityCapabilities: new Map(partition.shared.recoveryIdentityCapabilities),
      recoveries,
      recoverySessions: new Map(partition.shared.recoverySessions),
    },
    export: {
      exports,
      authorizationNonces: new Set(partition.shared.exportAuthorizationNonces),
      authorizationUncertain: new Set(partition.shared.exportAuthorizationUncertain),
    },
  };
}

function selectMapEntries<T>(
  source: Map<string, T>,
  lifecycleId: string,
  lifecycleOf: (value: T) => string,
): Map<string, T> {
  const selected = new Map<string, T>();
  for (const [key, value] of source) {
    if (lifecycleOf(value) === lifecycleId) selected.set(key, structuredClone(value));
  }
  return selected;
}

function selectMapLifecycleEntry<T>(source: Map<string, T>, lifecycleId: string): Map<string, T> {
  const value = source.get(lifecycleId);
  return value === undefined ? new Map() : new Map([[lifecycleId, structuredClone(value)]]);
}

function replaceLifecycleEntries<T>(
  base: Map<string, T>,
  replacement: Map<string, T>,
  lifecycleOf: (value: T) => string,
  lifecycleId: string,
): Map<string, T> {
  const merged = new Map<string, T>();
  for (const [key, value] of base) {
    if (lifecycleOf(value) !== lifecycleId) merged.set(key, structuredClone(value));
  }
  for (const [key, value] of replacement) merged.set(key, structuredClone(value));
  return merged;
}

function cloneMapValues<T>(source: Map<string, T>): Map<string, T> {
  const cloned = new Map<string, T>();
  for (const [key, value] of source) cloned.set(key, structuredClone(value));
  return cloned;
}

export function boundedRouterAbEd25519YaoProductRegistrationSharedStateV1(
  source: RouterAbEd25519YaoProductRegistrationSharedStateV1,
): RouterAbEd25519YaoProductRegistrationSharedStateV1 {
  const recoveryCapabilities = boundedRecoveryCapabilities(source.recoveryCapabilities);
  return {
    kind: 'router_ab_ed25519_yao_product_registration_shared_state_v1',
    recoveryCapabilities,
    recoveryIdentityCapabilities: retainedRecoveryIdentityCapabilities(
      source.recoveryIdentityCapabilities,
      recoveryCapabilities,
    ),
    recoverySessions: new Map(source.recoverySessions),
    exportAuthorizationNonces: new Set(source.exportAuthorizationNonces),
    exportAuthorizationUncertain: new Set(source.exportAuthorizationUncertain),
  };
}

function boundedRecoveryCapabilities(
  source: Map<string, RecoveryCapabilityState>,
): Map<string, RecoveryCapabilityState> {
  if (source.size <= MAX_SHARED_RECOVERY_CAPABILITIES) return cloneMapValues(source);

  // Durable signer rows are canonical. This shared map is a request cache, so
  // retain active recovery ceremonies first and let older wallets rehydrate.
  const entries = [...source.entries()];
  const suspended = entries.filter(([, capability]) => capability.kind === 'suspended');
  const retained = new Set<string>();
  for (const [key] of suspended.slice(-MAX_SHARED_RECOVERY_CAPABILITIES)) retained.add(key);
  for (
    let index = entries.length - 1;
    index >= 0 && retained.size < MAX_SHARED_RECOVERY_CAPABILITIES;
    index -= 1
  ) {
    const entry = entries[index];
    if (entry) retained.add(entry[0]);
  }

  const bounded = new Map<string, RecoveryCapabilityState>();
  for (const [key, capability] of entries) {
    if (retained.has(key)) bounded.set(key, structuredClone(capability));
  }
  return bounded;
}

function retainedRecoveryIdentityCapabilities(
  source: Map<string, string>,
  capabilities: Map<string, RecoveryCapabilityState>,
): Map<string, string> {
  const retained = new Map<string, string>();
  for (const [identity, capabilityKey] of source) {
    if (capabilities.has(capabilityKey)) retained.set(identity, capabilityKey);
  }
  return retained;
}

function registrationStateLifecycleId(state: RegistrationLifecycleState): string {
  return state.admissionRequest.scope.lifecycle_id;
}

function authorityLifecycleId(authority: RegistrationIntentAuthority): string {
  return authority.admissionRequest.scope.lifecycle_id;
}

function recoveryStateLifecycleId(state: RecoveryLifecycleState): string {
  return state.context.admissionRequest.scope.lifecycle_id;
}

function exportStateLifecycleId(state: ExportLifecycleState): string {
  return state.request.scope.lifecycle_id;
}

function requireLifecycleId(value: string): string {
  const lifecycleId = value.trim();
  if (!lifecycleId || lifecycleId.length > 256 || !/^[\x21-\x7e]+$/u.test(lifecycleId)) {
    throw new Error('Ed25519 Yao ceremony lifecycle ID is invalid');
  }
  return lifecycleId;
}
