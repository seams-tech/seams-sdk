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
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type {
  SessionAdapter,
  SessionClaims,
} from '../../packages/sdk-server-ts/src/router/routerApi';
import type { RouterAbEd25519YaoRecoveryAuthorizationInput } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import { RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecoveryWalletSessionAuthorization';

type RecoveryExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type AuthorizationPhase = RouterAbEd25519YaoRecoveryAuthorizationInput['kind'];

const WALLET_ID = 'recovery-wallet.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519ks_recovery_wallet';
const ROOT_SHARE_EPOCH = 'root-epoch-recovery-1';
const WALLET_SESSION_ID = 'wallet-session-recovery-1';
const SIGNING_WORKER_ID = 'signing-worker-recovery-1';
const PARTICIPANT_IDS = [1, 2] as const;

type ClaimsFixtureInput = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  rootShareEpoch: string;
  participantIds: readonly number[];
  signingWorkerId: string;
  thresholdExpiresAtMs: number;
};

class SessionFixture implements SessionAdapter {
  parsedAuthorization: string | string[] | undefined;

  constructor(
    private readonly parseResult:
      | { readonly ok: true; readonly claims: SessionClaims }
      | { readonly ok: false },
  ) {}

  async signJwt(): Promise<string> {
    throw new Error('signJwt is outside the recovery authorization test boundary');
  }

  async parse(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<{ ok: true; claims: SessionClaims } | { ok: false }> {
    this.parsedAuthorization = headers.authorization ?? headers.Authorization;
    return this.parseResult;
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

function base64UrlJson(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function expiredUnverifiedWalletSessionJwt(): string {
  return `${base64UrlJson({ alg: 'HS256', typ: 'JWT' })}.${base64UrlJson({
    exp: Math.floor(Date.now() / 1000) - 1,
  })}.invalid-signature`;
}

function admissionRequestFixture(): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  return requireParsed(
    parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: 'recovery-lifecycle-1',
        root_share_epoch: ROOT_SHARE_EPOCH,
        account_id: WALLET_ID,
        wallet_session_id: WALLET_SESSION_ID,
        signer_set_id: 'signer-set-recovery-1',
        signing_worker_id: SIGNING_WORKER_ID,
      },
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
      thresholdSessionId: WALLET_SESSION_ID,
      signingGrantId: 'signing-grant-recovery-1',
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
      session_id: admission.scope.wallet_session_id,
      signer_set_id: admission.scope.signer_set_id,
      selected_server_id: admission.scope.signing_worker_id,
    },
    operation: 'recovery' as const,
    session_id: bytes(7),
    stable_key_context_binding: bytes(8),
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
    thresholdSessionId: input?.thresholdSessionId ?? WALLET_SESSION_ID,
    signingGrantId: input?.signingGrantId ?? 'signing-grant-recovery-1',
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
    sub: values.walletId,
    walletId: values.walletId,
    nearAccountId: values.nearAccountId,
    nearEd25519SigningKeyId: values.nearEd25519SigningKeyId,
    thresholdSessionId: values.thresholdSessionId,
    signingGrantId: values.signingGrantId,
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
  const session = new SessionFixture({ ok: true, claims });
  const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(session);
  const result = await authorization.authorize(input);
  return { result, session };
}

test.describe('Router A/B Ed25519 Yao recovery Wallet Session authorization', () => {
  test('authorizes exact Wallet Session claims for bootstrap, admit, execute, and activate', async () => {
    const phases: readonly AuthorizationPhase[] = ['bootstrap', 'admit', 'execute', 'activate'];
    for (const phase of phases) {
      const authorized = await authorizeWithClaims(
        authorizationInputFixture(phase, true),
        validClaimsFixture(),
      );
      expect(authorized.result, phase).toMatchObject({ ok: true });
      expect(authorized.session.parsedAuthorization, phase).toBe(
        'Bearer recovery-wallet-session',
      );
    }
  });

  test('rejects a missing Wallet Session bearer credential', async () => {
    const session = new SessionFixture({ ok: false });
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(session);

    await expect(authorization.authorize(authorizationInputFixture('admit', false))).resolves.toEqual(
      {
        ok: false,
        status: 401,
        code: 'recovery_wallet_session_missing',
        message: 'Ed25519 Yao recovery requires a valid Wallet Session JWT',
      },
    );
    expect(session.parsedAuthorization).toBeUndefined();
  });

  test('rejects malformed Router A/B Ed25519 Wallet Session claims', async () => {
    const authorized = await authorizeWithClaims(authorizationInputFixture('admit', true), {
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      sub: WALLET_ID,
    });

    expect(authorized.result).toEqual({
      ok: false,
      status: 401,
      code: 'recovery_wallet_session_invalid',
      message: 'Ed25519 Yao recovery requires Router A/B Ed25519 Wallet Session claims',
    });
  });

  test('rejects wallet, session, and SigningWorker substitutions in every phase', async () => {
    const phases: readonly AuthorizationPhase[] = ['bootstrap', 'admit', 'execute', 'activate'];
    const substitutions: ReadonlyArray<{
      label: string;
      claims: SessionClaims;
    }> = [
      {
        label: 'wallet',
        claims: validClaimsFixture({ walletId: 'substituted-wallet.testnet' }),
      },
      {
        label: 'session',
        claims: validClaimsFixture({ thresholdSessionId: 'substituted-wallet-session' }),
      },
      {
        label: 'SigningWorker',
        claims: validClaimsFixture({ signingWorkerId: 'substituted-signing-worker' }),
      },
    ];

    for (const phase of phases) {
      for (const substitution of substitutions) {
        const authorized = await authorizeWithClaims(
          authorizationInputFixture(phase, true),
          substitution.claims,
        );
        expect(authorized.result, `${phase}: ${substitution.label}`).toMatchObject({
          ok: false,
          status: 403,
          code: 'recovery_wallet_session_scope_mismatch',
        });
      }
    }
  });

  test('rejects every warm-bootstrap identity substitution', async () => {
    const substitutions: ReadonlyArray<{ label: string; claims: SessionClaims }> = [
      {
        label: 'NEAR account',
        claims: validClaimsFixture({ nearAccountId: 'substituted-near.testnet' }),
      },
      {
        label: 'Ed25519 key',
        claims: validClaimsFixture({ nearEd25519SigningKeyId: 'ed25519ks_substituted' }),
      },
      {
        label: 'signing grant',
        claims: validClaimsFixture({ signingGrantId: 'substituted-signing-grant' }),
      },
      {
        label: 'participants',
        claims: validClaimsFixture({ participantIds: [1, 3] }),
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
        code: 'recovery_wallet_session_scope_mismatch',
      });
    }
  });

  test('classifies an expired verified Wallet Session for WebAuthn fallback', async () => {
    const authorization = await authorizeWithClaims(
      authorizationInputFixture('bootstrap', true),
      validClaimsFixture({ thresholdExpiresAtMs: Date.now() - 1 }),
    );
    expect(authorization.result).toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_expired',
      message: 'Ed25519 Yao recovery Wallet Session expired',
    });
  });

  test('classifies an expired bearer rejected by JWT verification for WebAuthn fallback', async () => {
    const input = authorizationInputFixture('bootstrap', true);
    if (input.kind !== 'bootstrap') throw new Error('bootstrap authorization input is required');
    const authorization = new RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter(
      new SessionFixture({ ok: false }),
    );
    const result = await authorization.authorize({
      kind: 'bootstrap',
      request: new Request('https://router.example.test/recovery/bootstrap', {
        method: 'POST',
        headers: { authorization: `Bearer ${expiredUnverifiedWalletSessionJwt()}` },
      }),
      body: input.body,
    });
    expect(result).toEqual({
      ok: false,
      status: 401,
      code: 'wallet_session_expired',
      message: 'Ed25519 Yao recovery Wallet Session expired',
    });
  });

  test('rejects root and participant substitutions at recovery admission', async () => {
    const substitutions: ReadonlyArray<{ label: string; claims: SessionClaims }> = [
      {
        label: 'root',
        claims: validClaimsFixture({ rootShareEpoch: 'substituted-root-epoch' }),
      },
      {
        label: 'participants',
        claims: validClaimsFixture({ participantIds: [1, 3] }),
      },
    ];

    for (const substitution of substitutions) {
      const authorized = await authorizeWithClaims(
        authorizationInputFixture('admit', true),
        substitution.claims,
      );
      expect(authorized.result, substitution.label).toMatchObject({
        ok: false,
        status: 403,
        code: 'recovery_wallet_session_scope_mismatch',
      });
    }
  });
});
