import { expect, test } from '@playwright/test';
import {
  encodeRouterAbEd25519YaoProductRegistrationStateV1,
  parseRouterAbEd25519YaoProductRegistrationStateJsonV1,
  resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPersistence';
import { createRouterAbEd25519YaoProductRegistrationStateV1 } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';

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

  test('rejects records that are not the versioned product-state envelope', () => {
    expect(parseRouterAbEd25519YaoProductRegistrationStateJsonV1({})).toBeNull();
    expect(
      parseRouterAbEd25519YaoProductRegistrationStateJsonV1({
        kind: 'router_ab_ed25519_yao_product_registration_state_json_v1',
        state: { registration: {} },
      }),
    ).toBeNull();
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

    const finalize = await resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1(
      jsonRequest('/wallets/register/finalize', {
        ed25519: { activationReference: { lifecycle_id: 'registration-1' } },
      }),
    );
    expect(finalize).toMatchObject({
      kind: 'ceremony',
      value: { lifecycleId: 'registration-1' },
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
});

function jsonRequest(pathname: string, body: unknown): Request {
  return new Request(`https://gateway.invalid${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}
