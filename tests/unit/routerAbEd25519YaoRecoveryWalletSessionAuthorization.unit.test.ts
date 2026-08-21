import { expect, test } from '@playwright/test';
import {
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationRequestV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  parseRouterAbEd25519LinkedDeviceWalletSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
} from '../../packages/wallet-server/src/core/ThresholdService/validation';
import type {
  SessionParseFailureReason,
  SessionParseResult,
} from '../../packages/wallet-server/src/core/sessionValidation';
import type {
  SessionAdapter,
  SessionClaims,
} from '../../packages/wallet-server/src/router/framework/routerApi';
import {
  buildRouterAbEd25519YaoLinkedDeviceExportBootstrapV1,
  warmBootstrapCapabilityMatchesLinkedDeviceIdentity,
  type RouterAbEd25519YaoActiveCapabilityDescriptorV1,
  type RouterAbEd25519YaoRecoveryAuthorizationInput,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter } from '../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecoveryWalletSessionAuthorization';

type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type AuthorizationPhase = RouterAbEd25519YaoRecoveryAuthorizationInput['kind'];

const WALLET_ID = 'recovery-wallet.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519ks_recovery_wallet';
const ROOT_SHARE_EPOCH = 'root-epoch-recovery-1';
const WALLET_SESSION_ID = 'wallet-session-recovery-1';
const THRESHOLD_SESSION_ID = 'threshold-session-recovery-1';
const OWNER_SOURCE_THRESHOLD_SESSION_ID = 'threshold-session-owner-source-1';
const SIGNING_WORKER_ID = 'signing-worker-recovery-1';
const PARTICIPANT_IDS = [1, 2] as const;

type ClaimsFixtureInput = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  walletSessionId: string;
  quotaId: string;
  thresholdSessionId: string;
  rootShareEpoch: string;
  participantIds: readonly number[];
  signingWorkerId: string;
  thresholdExpiresAtMs: number;
};

type SessionFixtureOutcome =
  | {
      readonly kind: 'parsed';
      readonly result: SessionParseResult<SessionClaims>;
    }
  | {
      readonly kind: 'unavailable';
      readonly error: Error;
    };

class SessionFixture implements SessionAdapter {
  parsedAuthorization: string | string[] | undefined;

  constructor(private readonly outcome: SessionFixtureOutcome) {}

  async signJwt(): Promise<string> {
    throw new Error('signJwt is outside the recovery authorization test boundary');
  }

  async parse(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<SessionParseResult<SessionClaims>> {
    this.parsedAuthorization = headers.authorization ?? headers.Authorization;
    switch (this.outcome.kind) {
      case 'parsed':
        return this.outcome.result;
      case 'unavailable':
        throw this.outcome.error;
    }
  }

  buildSetCookie(): string {
    throw new Error('buildSetCookie is outside the recovery authorization test boundary');
  }

  buildClearCookie(): string {
    throw new Error('buildClearCookie is outside the recovery authorization test boundary');
  }

  async refresh(): Promise<{ ok: false }> {
    return { ok: false };
  }
}

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function requireParsed<T>(parsed: { ok: true; value: T } | { ok: false; message: string }): T {
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
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

function parsedSessionFixture(result: SessionParseResult<SessionClaims>): SessionFixture {
  return new SessionFixture({ kind: 'parsed', result });
}

function failedSessionFixture(reason: SessionParseFailureReason): SessionFixture {
  return parsedSessionFixture({ ok: false, reason });
}

function unavailableSessionFixture(): SessionFixture {
  return new SessionFixture({
    kind: 'unavailable',
    error: new Error('session verifier unavailable'),
  });
}

function admissionRequestFixture(): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: 'recovery-lifecycle-1',
        root_share_epoch: ROOT_SHARE_EPOCH,
        account_id: WALLET_ID,
        threshold_session_id: THRESHOLD_SESSION_ID,
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

function bootstrapRequestFixture(): RouterAbEd25519YaoWarmRecoveryBootstrapRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoWarmRecoveryBootstrapRequestV1({
      kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_request_v1',
      walletId: WALLET_ID,
      nearAccountId: WALLET_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      signerSlot: 1,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingWorkerId: SIGNING_WORKER_ID,
      participantIds: PARTICIPANT_IDS,
    }),
  );
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

function authorizationInputFixture(
  phase: AuthorizationPhase,
  authenticated: boolean,
): RouterAbEd25519YaoRecoveryAuthorizationInput {
  const admission = admissionRequestFixture();
  const execute = executeRequestFixture(admission);
  const request = new Request('https://router.example.test/recovery', {
    method: 'POST',
    headers: authenticated ? { authorization: 'Bearer recovery-wallet-session' } : {},
  });
  switch (phase) {
    case 'bootstrap':
      return { kind: phase, request, body: bootstrapRequestFixture() };
    case 'admit':
      return { kind: phase, request, body: admission };
    case 'execute':
      return { kind: phase, request, body: execute };
    case 'activate':
      return { kind: phase, request, body: activationRequestFixture(execute) };
  }
}

function validClaimsFixture(input?: Partial<ClaimsFixtureInput>): SessionClaims {
  const values: ClaimsFixtureInput = {
    walletId: input?.walletId ?? WALLET_ID,
    nearAccountId: input?.nearAccountId ?? WALLET_ID,
    nearEd25519SigningKeyId: input?.nearEd25519SigningKeyId ?? NEAR_SIGNING_KEY_ID,
    walletSessionId: input?.walletSessionId ?? WALLET_SESSION_ID,
    quotaId: input?.quotaId ?? 'quota-recovery-1',
    thresholdSessionId: input?.thresholdSessionId ?? THRESHOLD_SESSION_ID,
    rootShareEpoch: input?.rootShareEpoch ?? ROOT_SHARE_EPOCH,
    participantIds: input?.participantIds ?? PARTICIPANT_IDS,
    signingWorkerId: input?.signingWorkerId ?? SIGNING_WORKER_ID,
    thresholdExpiresAtMs: input?.thresholdExpiresAtMs ?? Date.now() + 60_000,
  };
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: values.walletId,
    rpId: 'router.example.test',
    credentialIdB64u: 'recovery-credential-id',
  });
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'owner_wallet_session',
    sub: values.walletId,
    walletId: values.walletId,
    nearAccountId: values.nearAccountId,
    nearEd25519SigningKeyId: values.nearEd25519SigningKeyId,
    walletSessionId: values.walletSessionId,
    quotaId: values.quotaId,
    thresholdSessionId: values.thresholdSessionId,
    relayerKeyId: values.signingWorkerId,
    authority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
    thresholdExpiresAtMs: values.thresholdExpiresAtMs,
    participantIds: [...values.participantIds],
    runtimePolicyScope: {
      orgId: 'org-recovery',
      projectId: 'project-recovery',
      envId: 'test',
      signingRootVersion: values.rootShareEpoch,
    },
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: values.signingWorkerId,
    },
  };
}

async function authorizeWithClaims(
  input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  claims: SessionClaims,
) {
  const session = parsedSessionFixture({ ok: true, claims });
  const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(session);
  const result = await authorization.authorize(input);
  return { result, session };
}

function linkedClaimsFixture(input?: {
  readonly walletId?: string;
  readonly nearEd25519SigningKeyId?: string;
  readonly walletKeyId?: string;
  readonly permission?: ReturnType<typeof buildFullOwnerDelegatedWalletAuthorityV1>;
}): SessionClaims {
  const walletId = input?.walletId ?? WALLET_ID;
  const nearEd25519SigningKeyId = input?.nearEd25519SigningKeyId ?? NEAR_SIGNING_KEY_ID;
  const issuedAtMs = Math.floor(Date.now() / 1_000) * 1_000;
  const expiresAtMs = issuedAtMs + 60_000;
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'linked_device_wallet_session',
    sub: 'linked-device:device:recovery-2',
    walletId,
    tenantId: 'tenant:recovery',
    deviceId: 'device:recovery-2',
    enrollmentId: 'enrollment:recovery-2',
    walletKeyId: input?.walletKeyId ?? `wallet-key:ed25519:${walletId}:${nearEd25519SigningKeyId}`,
    keyManifestDigestB64u: base64UrlEncode(new Uint8Array(32).fill(7)),
    revocationEpoch: 0,
    permission: input?.permission ?? buildFullOwnerDelegatedWalletAuthorityV1(),
    issuedAtMs,
    expiresAtMs,
    authorizationId: 'linked-device-wallet-session-authorization:recovery-2',
    walletSessionId: 'wallet-session:linked-recovery-2',
    quotaId: 'wallet-quota:linked-recovery-2',
    iat: issuedAtMs / 1_000,
    exp: expiresAtMs / 1_000,
  };
}

function parsedLinkedClaimsFixture(): NonNullable<
  ReturnType<typeof parseRouterAbEd25519LinkedDeviceWalletSessionClaims>
> {
  const claims = parseRouterAbEd25519LinkedDeviceWalletSessionClaims(linkedClaimsFixture());
  if (!claims) throw new Error('linked Wallet Session fixture is invalid');
  return claims;
}

function activeCapabilityFixture(): RouterAbEd25519YaoActiveCapabilityDescriptorV1 {
  const thresholdSessionId = parseThresholdEd25519SessionId(OWNER_SOURCE_THRESHOLD_SESSION_ID);
  if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation: {
      kind: 'mpc_material_activation_ref',
      activation_id: 'owner-source-material-activation-1',
      capability: 'owner-source-capability-1',
      material_owner: WALLET_ID,
      key_binding: 'owner-source-key-1',
      lifecycle_binding: 'owner-source-lifecycle-1',
      signing_worker: SIGNING_WORKER_ID,
    },
    activeCapabilityBinding: bytes(22),
    registeredPublicKey: bytes(23),
    nearAccountId: WALLET_ID,
    applicationBinding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: 'owner-source-signing-root-1',
      key_creation_signer_slot: 1,
    },
    runtimePolicyScope: {
      orgId: 'org-recovery',
      projectId: 'project-recovery',
      envId: 'test',
      signingRootVersion: ROOT_SHARE_EPOCH,
    },
    participantIds: PARTICIPANT_IDS,
    lifecycle: {
      lifecycleId: 'owner-source-lifecycle-1',
      rootShareEpoch: ROOT_SHARE_EPOCH,
      accountId: WALLET_ID,
      thresholdSessionId: thresholdSessionId.value,
      signerSetId: 'owner-source-signer-set-1',
      signingWorkerId: SIGNING_WORKER_ID,
    },
    stateEpoch: 1,
    registrationContinuity: {
      kind: 'recovery',
      activationTranscript: bytes(24),
    },
  };
}

test.describe('Router A/B Ed25519 Yao recovery Wallet Session authorization', () => {
  test('rejects an owner JWT for bootstrap because bootstrap requires an opaque owner session', async () => {
    const authorized = await authorizeWithClaims(
      authorizationInputFixture('bootstrap', true),
      validClaimsFixture(),
    );
    expect(authorized.result).toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_missing',
      message: 'Wallet Session is missing',
    });
  });

  test('authorizes only an export-capable linked Ed25519 Wallet Session for bootstrap', async () => {
    const authorized = await authorizeWithClaims(
      authorizationInputFixture('bootstrap', true),
      linkedClaimsFixture(),
    );
    expect(authorized.result).toMatchObject({
      ok: true,
      authorization: { kind: 'linked_device_wallet_session' },
    });

    const denied = await authorizeWithClaims(
      authorizationInputFixture('bootstrap', true),
      linkedClaimsFixture({ permission: buildSigningOnlyDelegatedWalletAuthorityV1() }),
    );
    expect(denied.result).toMatchObject({
      ok: false,
      status: 403,
      code: 'wallet_session_scope_mismatch',
    });

    const wrongCurve = await authorizeWithClaims(authorizationInputFixture('bootstrap', true), {
      ...linkedClaimsFixture(),
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    });
    expect(wrongCurve.result).toMatchObject({
      ok: false,
      status: 401,
      code: 'wallet_session_missing',
    });
  });

  test('returns the owner-source threshold identity when linked session identity differs', () => {
    const request = bootstrapRequestFixture();
    const claims = parsedLinkedClaimsFixture();
    const capability = activeCapabilityFixture();
    expect(request.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
    expect(capability.lifecycle.thresholdSessionId).toBe(OWNER_SOURCE_THRESHOLD_SESSION_ID);
    expect(
      warmBootstrapCapabilityMatchesLinkedDeviceIdentity({ request, claims, capability }),
    ).toBe(true);

    const response = buildRouterAbEd25519YaoLinkedDeviceExportBootstrapV1({
      request,
      claims,
      capability,
    });
    expect(response.thresholdSessionId).toBe(OWNER_SOURCE_THRESHOLD_SESSION_ID);
    expect(response.thresholdSessionId).not.toBe(request.thresholdSessionId);
    expect(response.capability).toEqual(capability);
  });

  test('rejects linked Wallet Sessions for recovery admission, execution, and activation', async () => {
    const phases: readonly AuthorizationPhase[] = ['admit', 'execute', 'activate'];
    for (const phase of phases) {
      const authorized = await authorizeWithClaims(
        authorizationInputFixture(phase, true),
        linkedClaimsFixture(),
      );
      expect(authorized.result, phase).toMatchObject({
        ok: false,
        status: 401,
        code: 'wallet_session_claims_invalid',
      });
    }
  });

  test('rejects linked bootstrap wallet and child-key substitutions', async () => {
    const substitutions: ReadonlyArray<{ readonly label: string; readonly claims: SessionClaims }> =
      [
        {
          label: 'wallet',
          claims: linkedClaimsFixture({ walletId: 'substituted-wallet.testnet' }),
        },
        {
          label: 'child key',
          claims: linkedClaimsFixture({ walletKeyId: 'wallet-key:ed25519:substituted-child' }),
        },
      ];
    for (const substitution of substitutions) {
      const authorized = await authorizeWithClaims(
        authorizationInputFixture('bootstrap', true),
        substitution.claims,
      );
      expect(authorized.result, substitution.label).toMatchObject({
        ok: false,
        status: 403,
        code: 'wallet_session_scope_mismatch',
      });
    }
  });

  test('rejects a missing Wallet Session bearer credential', async () => {
    const session = failedSessionFixture('missing');
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(session);

    await expect(
      authorization.authorize(authorizationInputFixture('admit', false)),
    ).resolves.toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_missing',
      message: 'Wallet Session is missing',
    });
    expect(session.parsedAuthorization).toBeUndefined();
  });

  test('rejects malformed Router A/B Ed25519 Wallet Session claims', async () => {
    const authorized = await authorizeWithClaims(authorizationInputFixture('admit', true), {
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      authorizationKind: 'owner_wallet_session',
      sub: WALLET_ID,
    });

    expect(authorized.result).toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_claims_invalid',
      message: 'Wallet Session claims are invalid',
    });
  });

  test('rejects a Wallet Session with an invalid signature', async () => {
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      failedSessionFixture('signature_invalid'),
    );

    await expect(
      authorization.authorize(authorizationInputFixture('admit', true)),
    ).resolves.toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_signature_invalid',
      message: 'Wallet Session signature is invalid',
    });
  });

  test('rejects Wallet Session claims rejected by the session parser', async () => {
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      failedSessionFixture('claims_invalid'),
    );

    await expect(
      authorization.authorize(authorizationInputFixture('admit', true)),
    ).resolves.toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_claims_invalid',
      message: 'Wallet Session claims are invalid',
    });
  });

  test('reports Wallet Session verification as unavailable', async () => {
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      unavailableSessionFixture(),
    );

    await expect(
      authorization.authorize(authorizationInputFixture('admit', true)),
    ).resolves.toEqual({
      ok: false,
      status: 503,
      code: 'wallet_session_unavailable',
      message: 'Wallet Session status is unavailable',
    });
  });
});
