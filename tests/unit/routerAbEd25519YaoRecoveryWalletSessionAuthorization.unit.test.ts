import { expect, test } from '@playwright/test';
import {
  ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { parseTenantId } from '@shared/authorization/capabilityKinds';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { base64UrlDecode } from '@shared/utils/base64';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  deriveWalletRecoveryKeyLifecycleId,
  parseRecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type { PreparedEd25519RecoveryAdmissionV1 } from '../../packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryKeyManifest';
import type {
  RouterAbEd25519YaoRecoveryAuthorizationInput,
  RouterAbEd25519YaoRecoveryAuthorizationServicesV1,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecoveryWalletSessionAuthorization';
import { RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter } from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecoveryWalletSessionAuthorization';
import type { RouterApiAuthorizationSessionService } from '../../packages/wallet-server/src/router/framework/authServicePort';
import type {
  RouterApiWalletRegistrationService,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;

const WALLET_ID = 'recovery-wallet.testnet';
const WALLET_ID_VALUE = walletIdFromString(WALLET_ID);
const RESERVATION_ID = parseRecoveryCodeReservationId('recovery-reservation-1');
const KEY_SET_ID = 'near_ed25519:recovery-signer-1' as const;
const NEAR_SIGNING_KEY_ID = 'ed25519ks_recovery_wallet';
const SIGNING_WORKER_ID = 'signing-worker-recovery-1';
const PARTICIPANT_IDS = [1, 2] as const;
const RECOVERY_CHALLENGE_ID = 'webauthn-recovery-challenge-1';
const RECOVERY_URL = 'https://router.example.test/recovery';

function requireParsed<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly message: string },
): T {
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function requireTenantId(): RouterApiAuthorizationSessionService['tenantId'] {
  const parsed = parseTenantId('org-recovery');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function materialActivation(label: string) {
  return {
    kind: 'mpc_material_activation_ref' as const,
    activation_id: `recovery-wallet-${label}-material-activation-1`,
    capability: 'recovery-wallet-capability-1',
    material_owner: WALLET_ID,
    key_binding: 'recovery-wallet-key-1',
    lifecycle_binding: `recovery-wallet-${label}-lifecycle-binding-1`,
    signing_worker: SIGNING_WORKER_ID,
  };
}

async function admissionRequestFixture(): Promise<RouterAbEd25519YaoRecoveryAdmissionRequestV1> {
  const lifecycleId = await deriveWalletRecoveryKeyLifecycleId({
    reservationId: RESERVATION_ID,
    keySetId: KEY_SET_ID,
  });
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: lifecycleId,
        root_share_epoch: 'root-epoch-recovery-1',
        account_id: WALLET_ID,
        threshold_session_id: `${lifecycleId}:threshold-session`,
        signer_set_id: 'signer-set-recovery-1',
        signing_worker_id: SIGNING_WORKER_ID,
        material_activation: materialActivation('replacement'),
      },
      active_material_activation: materialActivation('active'),
      application_binding: {
        wallet_id: WALLET_ID,
        near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
        signing_root_id: 'signing-root-recovery-1',
        key_creation_signer_slot: 1,
      },
      participant_ids: PARTICIPANT_IDS,
      active_capability_binding: bytes(20),
      replacement_capability_binding: bytes(21),
      registered_public_key: bytes(12),
    }),
  );
}

function preparedEntryFixture(
  admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): PreparedEd25519RecoveryAdmissionV1['entries'][number] {
  return {
    kind: 'near_ed25519',
    keySetId: KEY_SET_ID,
    signerId: 'recovery-signer-1',
    nearAccountId: WALLET_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    publicKey: 'ed25519:recovery-public-key',
    registeredPublicKeyB64u: 'recovery-registered-public-key',
    recordedKeyManifestDigestB64u: 'recovery-key-manifest-digest',
    recoveryBasis: {
      capabilityKind: 'recovery',
      activeCapabilityBinding: admission.active_capability_binding,
      activeMaterialActivation: admission.active_material_activation,
      scope: admission.scope,
      applicationBinding: admission.application_binding,
      participantIds: admission.participant_ids,
      registeredPublicKey: admission.registered_public_key,
      runtimePolicyScope: {
        orgId: 'org-recovery',
        projectId: 'project-recovery',
        envId: 'test',
        signingRootVersion: admission.scope.root_share_epoch,
      },
      activationTranscript: bytes(13),
      activationStateEpoch: 2,
      signingWorkerVerifyingShare: bytes(14),
    },
  };
}

async function preparedAdmissionFixture(
  admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): Promise<PreparedEd25519RecoveryAdmissionV1> {
  return {
    kind: 'prepared_ed25519_recovery_admission_v1',
    walletId: WALLET_ID_VALUE,
    reservationId: RESERVATION_ID,
    entries: [preparedEntryFixture(admission)],
  };
}

function recoveryBindingFixture(admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1) {
  return {
    lifecycle: {
      lifecycle_id: admission.scope.lifecycle_id,
      work_kind: 'recovery' as const,
      primitive_request_kind: 'recovery' as const,
      root_share_epoch: admission.scope.root_share_epoch,
      account_id: admission.scope.account_id,
      session_id: admission.scope.threshold_session_id,
      signer_set_id: admission.scope.signer_set_id,
      selected_server_id: admission.scope.signing_worker_id,
    },
    operation: 'recovery' as const,
    session_id: bytes(7),
    stable_key_context_binding: bytes(8),
    material_activation: admission.scope.material_activation,
  };
}

function encryptedRecoveryInput(
  binding: ReturnType<typeof recoveryBindingFixture>,
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

function executeRequestFixture(
  admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): RecoveryExecuteRequest {
  const binding = recoveryBindingFixture(admission);
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1({
      binding,
      deriver_a_input: encryptedRecoveryInput(binding, 'deriver_a'),
      deriver_b_input: encryptedRecoveryInput(binding, 'deriver_b'),
    }),
  );
}

function activationRequestFixture(
  execute: RecoveryExecuteRequest,
): RouterAbEd25519YaoRecoveryActivationRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryActivationRequestV1({
      binding: execute.binding,
      public_receipt: {
        transcript: bytes(11),
        registered_public_key: bytes(12),
        joined_client_commitment: bytes(13),
        joined_signing_worker_commitment: bytes(14),
        signing_worker_verifying_share: bytes(15),
        state_epoch: 2,
        material_activation: execute.binding.material_activation,
      },
    }),
  );
}

function warmRecoveryBootstrapRequestFixture(): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
      kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
      walletId: WALLET_ID,
      nearAccountId: WALLET_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      signerSlot: 1,
      thresholdSessionId: 'warm-recovery-threshold-session',
      signingWorkerId: SIGNING_WORKER_ID,
      participantIds: PARTICIPANT_IDS,
    }),
  );
}

class PreparedAdmissionReaderFixture {
  readonly calls: { readonly challengeId: string; readonly nowMs: number }[] = [];

  constructor(private readonly prepared: PreparedEd25519RecoveryAdmissionV1 | null) {}

  async readPreparedEd25519RecoveryAdmission(input: {
    readonly challengeId: string;
    readonly nowMs: number;
  }): Promise<PreparedEd25519RecoveryAdmissionV1 | null> {
    this.calls.push(input);
    return this.prepared;
  }
}

async function unsupportedAuthorizationSessionOperation(): Promise<never> {
  throw new Error('authorization session operation is outside this test boundary');
}

async function noOpaqueWalletSession(): Promise<null> {
  return null;
}

class AuthorizationSessionsFixture implements RouterApiAuthorizationSessionService {
  readonly tenantId: RouterApiAuthorizationSessionService['tenantId'];
  exactReads = 0;
  opaqueReads = 0;

  constructor(
    private readonly exactContext: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {
    this.tenantId = exactContext?.authorization.session.tenantId ?? requireTenantId();
  }

  async issueOpaqueWalletSessionToken(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async resolveOpaqueWalletSessionToken() {
    this.opaqueReads += 1;
    return await noOpaqueWalletSession();
  }

  async readWalletSessionAuthorizationV2ByOperationCredential(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    this.exactReads += 1;
    return this.exactContext;
  }

  async readLinkedDeviceWalletSessionAuthorization(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async renewLinkedDeviceWalletSession(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async mintHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async redeemHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }
}

type Ed25519MaterialResolution = Awaited<
  ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>
>;

class Ed25519MaterialResolverFixture {
  readonly calls: Parameters<
    RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']
  >[0][] = [];

  constructor(private readonly result: Ed25519MaterialResolution) {}

  async resolve(
    input: Parameters<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>[0],
  ): Promise<Ed25519MaterialResolution> {
    this.calls.push(input);
    return this.result;
  }
}

async function unsupportedEd25519MaterialResolution(): Promise<Ed25519MaterialResolution> {
  throw new Error('Ed25519 material resolution is outside this test boundary');
}

function authorizationServicesFixture(
  prepared: PreparedEd25519RecoveryAdmissionV1 | null,
  exactContext: RouterApiWalletSessionAuthorizationV2AdmissionContext | null = null,
  resolveEd25519MaterialActivation: RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'] = unsupportedEd25519MaterialResolution,
): {
  readonly services: RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
  readonly reader: PreparedAdmissionReaderFixture;
  readonly authorizationSessions: AuthorizationSessionsFixture;
} {
  const reader = new PreparedAdmissionReaderFixture(prepared);
  const authorizationSessions = new AuthorizationSessionsFixture(exactContext);
  const services = {
    authorizationSessions,
    preparedRecoveryAdmission: reader,
    resolveEd25519MaterialActivation,
  } satisfies RouterAbEd25519YaoRecoveryAuthorizationServicesV1;
  return { services, reader, authorizationSessions };
}

async function exactAdmissionContextFixture(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext> {
  const exact = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'recovery-bootstrap',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation: routerAbMpcMaterialActivationRefFromWire(materialActivation('active')),
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: WALLET_ID,
      authorityId: 'authority:recovery-bootstrap',
      walletAuthMethodId: 'wallet-auth-method:recovery-bootstrap',
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

function activeEd25519MaterialFixture(
  context: RouterApiWalletSessionAuthorizationV2AdmissionContext,
): Extract<Ed25519MaterialResolution, { readonly ok: true }> {
  const activation = context.authority.signerActivations.ed25519;
  if (!activation) throw new Error('exact Ed25519 activation fixture is missing');
  return {
    ok: true,
    materialActivation: materialActivation('active'),
    nearAccountId: WALLET_ID,
    signerSlot: 1,
    signingWorkerId: SIGNING_WORKER_ID,
    participantIds: PARTICIPANT_IDS,
    runtimePolicyScope: {
      orgId: 'org-recovery',
      projectId: 'project-recovery',
      envId: 'test',
      signingRootVersion: 'root-epoch-recovery-1',
    },
    exportIdentity: {
      scope: {
        lifecycle_id: 'recovery-bootstrap-lifecycle',
        root_share_epoch: 'root-epoch-recovery-1',
        account_id: WALLET_ID,
        threshold_session_id: 'warm-recovery-threshold-session',
        signer_set_id: 'signer-set-recovery-1',
        signing_worker_id: SIGNING_WORKER_ID,
        material_activation: materialActivation('active'),
      },
      application_binding: {
        wallet_id: WALLET_ID,
        near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
        signing_root_id: 'signing-root-recovery-1',
        key_creation_signer_slot: 1,
      },
      participant_ids: PARTICIPANT_IDS,
      registered_public_key: Array.from(base64UrlDecode(activation.signer.registeredPublicKeyB64u)),
      state_epoch: 1,
      runtime_policy_binding: bytes(25),
    },
  };
}

function authorizationInput(
  phase: RouterAbEd25519YaoRecoveryAuthorizationInput['kind'],
  request: Request,
  admission: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
): RouterAbEd25519YaoRecoveryAuthorizationInput {
  switch (phase) {
    case 'bootstrap':
      return { kind: phase, request, body: warmRecoveryBootstrapRequestFixture() };
    case 'admit':
      return { kind: phase, request, body: admission };
    case 'execute': {
      const execute = executeRequestFixture(admission);
      return { kind: phase, request, body: execute };
    }
    case 'activate': {
      const execute = executeRequestFixture(admission);
      return { kind: phase, request, body: activationRequestFixture(execute) };
    }
  }
}

function recoveryRequest(headers?: Record<string, string>): Request {
  return new Request(RECOVERY_URL, { method: 'POST', headers });
}

test.describe('Router A/B Ed25519 Yao recovery admission authorization', () => {
  test('admits an exact durable prepared Near binding from the challenge header', async () => {
    const admission = await admissionRequestFixture();
    const prepared = await preparedAdmissionFixture(admission);
    const { services, reader } = authorizationServicesFixture(prepared);
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );

    const result = await authorization.authorize(
      authorizationInput(
        'admit',
        recoveryRequest({
          [ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1]: RECOVERY_CHALLENGE_ID,
        }),
        admission,
      ),
    );

    expect(result).toEqual({
      ok: true,
      authorization: { kind: 'wallet_recovery', walletId: WALLET_ID },
    });
    expect(reader.calls).toHaveLength(1);
    expect(reader.calls[0]?.challengeId).toBe(RECOVERY_CHALLENGE_ID);
    expect(reader.calls[0]?.nowMs).toBeGreaterThan(0);
  });

  test('rejects admission without the durable challenge header', async () => {
    const admission = await admissionRequestFixture();
    const { services, reader, authorizationSessions } = authorizationServicesFixture(
      await preparedAdmissionFixture(admission),
    );
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );

    await expect(
      authorization.authorize(
        authorizationInput(
          'admit',
          recoveryRequest({ authorization: 'Bearer wst_retired-recovery-session' }),
          admission,
        ),
      ),
    ).resolves.toEqual({
      ok: false,
      status: 401,
      code: 'wallet_recovery_challenge_missing',
      message: 'wallet recovery admission is unavailable',
    });
    expect(reader.calls).toHaveLength(0);
    expect(authorizationSessions.opaqueReads).toBe(0);
  });

  test('rejects an unknown or spent durable challenge', async () => {
    const admission = await admissionRequestFixture();
    const { services, reader } = authorizationServicesFixture(null);
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );

    await expect(
      authorization.authorize(
        authorizationInput(
          'admit',
          recoveryRequest({
            [ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1]: RECOVERY_CHALLENGE_ID,
          }),
          admission,
        ),
      ),
    ).resolves.toEqual({
      ok: false,
      status: 401,
      code: 'wallet_recovery_challenge_invalid',
      message: 'wallet recovery admission is unavailable',
    });
    expect(reader.calls).toHaveLength(1);
  });

  test('rejects exact Near lifecycle substitutions', async () => {
    const admission = await admissionRequestFixture();
    const prepared = await preparedAdmissionFixture(admission);
    const { services } = authorizationServicesFixture(prepared);
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );
    const substitutions = [
      {
        label: 'root share epoch',
        request: requireParsed(
          parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
            scope: {
              lifecycle_id: admission.scope.lifecycle_id,
              root_share_epoch: 'substituted-root-epoch',
              account_id: admission.scope.account_id,
              threshold_session_id: admission.scope.threshold_session_id,
              signer_set_id: admission.scope.signer_set_id,
              signing_worker_id: admission.scope.signing_worker_id,
              material_activation: admission.scope.material_activation,
            },
            active_material_activation: admission.active_material_activation,
            application_binding: admission.application_binding,
            participant_ids: admission.participant_ids,
            active_capability_binding: admission.active_capability_binding,
            replacement_capability_binding: admission.replacement_capability_binding,
            registered_public_key: admission.registered_public_key,
          }),
        ),
      },
      {
        label: 'participant ids',
        request: requireParsed(
          parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
            scope: admission.scope,
            active_material_activation: admission.active_material_activation,
            application_binding: admission.application_binding,
            participant_ids: [1, 3],
            active_capability_binding: admission.active_capability_binding,
            replacement_capability_binding: admission.replacement_capability_binding,
            registered_public_key: admission.registered_public_key,
          }),
        ),
      },
      {
        label: 'active material activation',
        request: requireParsed(
          parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
            scope: admission.scope,
            active_material_activation: materialActivation('substituted-active'),
            application_binding: admission.application_binding,
            participant_ids: admission.participant_ids,
            active_capability_binding: admission.active_capability_binding,
            replacement_capability_binding: admission.replacement_capability_binding,
            registered_public_key: admission.registered_public_key,
          }),
        ),
      },
    ];

    for (const substitution of substitutions) {
      await expect(
        authorization.authorize(
          authorizationInput(
            'admit',
            recoveryRequest({
              [ROUTER_AB_ED25519_YAO_RECOVERY_CHALLENGE_ID_HEADER_V1]: RECOVERY_CHALLENGE_ID,
            }),
            substitution.request,
          ),
        ),
      ).resolves.toMatchObject({
        ok: false,
        status: 403,
        code: 'wallet_recovery_scope_mismatch',
      });
    }
  });

  test('keeps execute and activate on the protocol receipt path despite a retired opaque bearer', async () => {
    const admission = await admissionRequestFixture();
    const { services, reader, authorizationSessions } = authorizationServicesFixture(null);
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );

    for (const phase of ['execute', 'activate'] as const) {
      await expect(
        authorization.authorize(
          authorizationInput(
            phase,
            recoveryRequest({ authorization: 'Bearer wst_retired-recovery-session' }),
            admission,
          ),
        ),
      ).resolves.toEqual({
        ok: true,
        authorization: { kind: 'wallet_recovery', walletId: WALLET_ID },
      });
    }
    expect(reader.calls).toHaveLength(0);
    expect(authorizationSessions.opaqueReads).toBe(0);
  });

  test('authorizes warm recovery from the exact Ed25519 operation credential and active material', async () => {
    const admission = await admissionRequestFixture();
    const exactContext = await exactAdmissionContextFixture();
    const materialResolver = new Ed25519MaterialResolverFixture(
      activeEd25519MaterialFixture(exactContext),
    );
    const { services, authorizationSessions } = authorizationServicesFixture(
      null,
      exactContext,
      materialResolver.resolve.bind(materialResolver),
    );
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );

    await expect(
      authorization.authorize(
        authorizationInput(
          'bootstrap',
          recoveryRequest({ authorization: 'Bearer wso_warm-recovery' }),
          admission,
        ),
      ),
    ).resolves.toMatchObject({
      ok: true,
      authorization: { kind: 'wallet_session_v2', context: exactContext },
    });
    expect(authorizationSessions.exactReads).toBe(1);
    expect(authorizationSessions.opaqueReads).toBe(0);
    expect(materialResolver.calls).toEqual([
      {
        walletId: WALLET_ID,
        materialActivation: materialActivation('active'),
      },
    ]);
  });

  test('rejects opaque warm recovery without probing the legacy token store', async () => {
    const admission = await admissionRequestFixture();
    const { services, authorizationSessions } = authorizationServicesFixture(null);
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );

    await expect(
      authorization.authorize(
        authorizationInput(
          'bootstrap',
          recoveryRequest({ authorization: 'Bearer wst_warm-recovery' }),
          admission,
        ),
      ),
    ).resolves.toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_invalid',
      message: 'Wallet Session is invalid',
    });
    expect(authorizationSessions.exactReads).toBe(1);
    expect(authorizationSessions.opaqueReads).toBe(0);
  });

  test('rejects warm recovery when the request substitutes the active threshold session', async () => {
    const admission = await admissionRequestFixture();
    const exactContext = await exactAdmissionContextFixture();
    const materialResolver = new Ed25519MaterialResolverFixture(
      activeEd25519MaterialFixture(exactContext),
    );
    const { services, authorizationSessions } = authorizationServicesFixture(
      null,
      exactContext,
      materialResolver.resolve.bind(materialResolver),
    );
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );
    const baseInput = authorizationInput(
      'bootstrap',
      recoveryRequest({ authorization: 'Bearer wso_warm-recovery' }),
      admission,
    );
    if (baseInput.kind !== 'bootstrap') throw new Error('bootstrap fixture is invalid');
    const substituted = requireParsed(
      parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
        ...baseInput.body,
        thresholdSessionId: 'substituted-threshold-session',
      }),
    );

    await expect(
      authorization.authorize({ ...baseInput, body: substituted }),
    ).resolves.toMatchObject({
      ok: false,
      status: 403,
      code: 'wallet_session_scope_mismatch',
    });
    expect(authorizationSessions.exactReads).toBe(1);
    expect(authorizationSessions.opaqueReads).toBe(0);
  });

  test('does not accept the removed JWT admission path', async () => {
    const admission = await admissionRequestFixture();
    const { services } = authorizationServicesFixture(await preparedAdmissionFixture(admission));
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      async () => services,
    );

    await expect(
      authorization.authorize(
        authorizationInput(
          'admit',
          recoveryRequest({ authorization: 'Bearer recovery-wallet-jwt' }),
          admission,
        ),
      ),
    ).resolves.toEqual({
      ok: false,
      status: 401,
      code: 'wallet_recovery_challenge_missing',
      message: 'wallet recovery admission is unavailable',
    });
  });
});
