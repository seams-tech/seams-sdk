import { expect, test } from '@playwright/test';
import {
  createRouterAbEd25519YaoCeremonyStateStoreV1,
  encodeRouterAbEd25519YaoProductRegistrationStateV1,
  parseRouterAbEd25519YaoProductRegistrationStateJsonV1,
  resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1,
} from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationPersistence';
import { createRouterAbEd25519YaoProductRegistrationStateV1 } from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import {
  mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1,
  partitionRouterAbEd25519YaoProductRegistrationStateV1,
} from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationPartitioning';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';

function isUnknownRecord(value: unknown): value is { [key: string]: unknown } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function removeEncodedAuthorizationUncertain(value: unknown): unknown {
  const cloned: unknown = structuredClone(value);
  if (!isUnknownRecord(cloned) || !isUnknownRecord(cloned.state)) {
    throw new Error('Expected an encoded product-state envelope');
  }
  if (!isUnknownRecord(cloned.state.export)) {
    throw new Error('Expected encoded product export state');
  }
  delete cloned.state.export.authorizationUncertain;
  return cloned;
}

test.describe('Ed25519 Yao request-scoped persistence boundary', () => {
  test('round-trips all four lifecycle collections without JSON.stringify', () => {
    const state = createRouterAbEd25519YaoProductRegistrationStateV1();
    state.registration.lifecycleSessions.set('registration-lifecycle', 'session-key');
    state.export.authorizationNonces.add('export-nonce');

    const encoded = encodeRouterAbEd25519YaoProductRegistrationStateV1(state);
    expect(encoded.kind).toBe('router_ab_ed25519_yao_product_registration_state_json_v1');
    const decoded = parseRouterAbEd25519YaoProductRegistrationStateJsonV1(encoded);

    expect(decoded).not.toBeNull();
    expect(decoded?.registration.lifecycleSessions).toEqual(
      new Map([['registration-lifecycle', 'session-key']]),
    );
    expect(decoded?.export.authorizationNonces).toEqual(new Set(['export-nonce']));
    expect(decoded?.registration.states).toBeInstanceOf(Map);
    expect(decoded?.recovery.recoveries).toBeInstanceOf(Map);
    expect(decoded?.export.exports).toBeInstanceOf(Map);
  });

  test('normalizes persisted state written before export uncertainty tracking', () => {
    const encoded = encodeRouterAbEd25519YaoProductRegistrationStateV1(
      createRouterAbEd25519YaoProductRegistrationStateV1(),
    );
    const decoded = parseRouterAbEd25519YaoProductRegistrationStateJsonV1(
      removeEncodedAuthorizationUncertain(encoded),
    );

    expect(decoded?.export.authorizationUncertain).toEqual(new Set());
  });

  test('rejects records that are not the versioned product-state envelope', () => {
    expect(parseRouterAbEd25519YaoProductRegistrationStateJsonV1({})).toBeNull();
    expect(
      parseRouterAbEd25519YaoProductRegistrationStateJsonV1({
        kind: 'router_ab_ed25519_yao_product_registration_state_json_v1',
        state: { registration: {} },
      }),
    ).toBeNull();
  });

  test('binds the CAS adapter to the opaque lifecycle key', async () => {
    const calls: string[] = [];
    const state = createRouterAbEd25519YaoProductRegistrationStateV1();
    const store = createRouterAbEd25519YaoCeremonyStateStoreV1({
      read: async (key) => {
        calls.push(`read:${key}`);
        return { kind: 'missing' };
      },
      put: async (key, _value, expectedVersion) => {
        calls.push(`put:${key}:${expectedVersion ?? 'none'}`);
        return { kind: 'version_mismatch' };
      },
    });
    const key = { kind: 'router_ab_ed25519_yao_ceremony_key_v1' as const, lifecycleId: 'opaque-1' };

    await store.read(key);
    await store.put(key, state, null);
    expect(calls).toEqual(['read:opaque-1', 'put:opaque-1:none']);
  });

  test('resolves only the lifecycle field owned by each Yao route', async () => {
    const registration = await resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1(
      jsonRequest(ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1, {
        scope: { lifecycle_id: 'registration-1' },
        account_id: 'must-not-be-used-as-the-key',
      }),
    );
    expect(registration).toEqual({
      kind: 'ceremony',
      value: {
        kind: 'router_ab_ed25519_yao_ceremony_key_v1',
        lifecycleId: 'registration-1',
      },
    });

    const exportExecute = await resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1(
      jsonRequest(ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1, {
        binding: { ceremony: { lifecycle: { lifecycle_id: 'export-1' } } },
      }),
    );
    expect(exportExecute).toMatchObject({
      kind: 'ceremony',
      value: { lifecycleId: 'export-1' },
    });
  });

  test('does not route unrelated identifiers or malformed ceremony requests', async () => {
    await expect(
      resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1(
        jsonRequest('/healthz', { scope: { lifecycle_id: 'ignored' } }),
      ),
    ).resolves.toEqual({ kind: 'none' });

    await expect(
      resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1(
        jsonRequest(ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1, {
          account_id: 'not-a-lifecycle',
        }),
      ),
    ).resolves.toEqual({
      kind: 'invalid',
      message: 'Yao ceremony lifecycle_id is required',
    });

    await expect(
      resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1(
        jsonRequest(ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1, {
          scope: { lifecycle_id: 'contains space' },
        }),
      ),
    ).resolves.toEqual({
      kind: 'invalid',
      message: 'Yao ceremony lifecycle_id is invalid',
    });
  });

  test('partitions ceremony records without isolating shared replay and capability indexes', () => {
    const state = createRouterAbEd25519YaoProductRegistrationStateV1();
    state.registration.lifecycleSessions.set('ceremony-a', 'session-a');
    state.registration.lifecycleSessions.set('ceremony-b', 'session-b');
    state.recovery.identityCapabilities.set('identity-a', 'capability-a');
    state.recovery.identityCapabilities.set('identity-b', 'capability-b');
    state.recovery.recoverySessions.set('recovery-session-a', 'recovery-a');
    state.recovery.recoverySessions.set('recovery-session-b', 'recovery-b');
    state.export.authorizationNonces.add('nonce-a');
    state.export.authorizationNonces.add('nonce-b');

    const partition = partitionRouterAbEd25519YaoProductRegistrationStateV1(state, 'ceremony-a');
    expect(partition.ceremony.registration.lifecycleSessions).toEqual(
      new Map([['ceremony-a', 'session-a']]),
    );
    expect(partition.shared.recoveryIdentityCapabilities).toEqual(
      new Map([
        ['identity-a', 'capability-a'],
        ['identity-b', 'capability-b'],
      ]),
    );
    expect(partition.shared.recoverySessions).toEqual(state.recovery.recoverySessions);
    expect(partition.shared.exportAuthorizationNonces).toEqual(new Set(['nonce-a', 'nonce-b']));

    partition.ceremony.registration.lifecycleSessions.set('ceremony-a', 'session-a-updated');
    const merged = mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1(state, partition);
    expect(merged.registration.lifecycleSessions).toEqual(
      new Map([
        ['ceremony-a', 'session-a-updated'],
        ['ceremony-b', 'session-b'],
      ]),
    );
    expect(merged.recovery.identityCapabilities).toEqual(state.recovery.identityCapabilities);
    expect(merged.recovery.recoverySessions).toEqual(state.recovery.recoverySessions);
    expect(merged.export.authorizationNonces).toEqual(state.export.authorizationNonces);
  });
});

function jsonRequest(pathname: string, body: unknown): Request {
  return new Request(`https://gateway.invalid${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}
