import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/encoders';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  deriveRouterAbEd25519YaoExportAuthorizationDigestV1,
  deriveRouterAbEd25519YaoExportConfirmationDigestV1,
  deriveRouterAbEd25519YaoRuntimePolicyBindingV1,
  parseRouterAbEd25519YaoExportAdmissionRequestV1,
  parseRouterAbEd25519YaoExportExecuteRequestV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportAuthorizationIdentityV1,
  type RouterAbEd25519YaoExportAuthorityBindingV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-server-ts/src/core/types';
import type { RouterApiWebAuthnService } from '../../packages/sdk-server-ts/src/router/authServicePort';
import { coerceRouterLogger } from '../../packages/sdk-server-ts/src/router/logger';
import type {
  SessionAdapter,
  SessionClaims,
} from '../../packages/sdk-server-ts/src/router/routerApi';
import {
  InMemoryRouterAbEd25519YaoExportService,
  RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter,
  createRouterAbEd25519YaoExportModule,
  type RouterAbEd25519YaoExportAuthorizationAdapter,
  type RouterAbEd25519YaoExportAuthorizationInput,
  type RouterAbEd25519YaoExportAuthorizationResult,
  type RouterAbEd25519YaoExportBackend,
  type RouterAbEd25519YaoExportBackendResult,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoExport';
import type {
  RouterAbEd25519YaoActiveCapabilityLookupV1,
  RouterAbEd25519YaoActiveCapabilityLookupResultV1,
  RouterAbEd25519YaoActiveCapabilityResolverV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';

const WALLET_ID = 'wallet-export-1';
const NEAR_ACCOUNT_ID = '0c'.repeat(32);
const NEAR_SIGNING_KEY_ID = 'ed25519ks_export_1';
const ROOT_SHARE_EPOCH = 'root-export-1';
const WALLET_SESSION_ID = 'wallet-session-export-1';
const SIGNING_GRANT_ID = 'signing-grant-export-1';
const SIGNING_WORKER_ID = 'signing-worker-export-1';
const PARTICIPANTS = [11, 29] as const;
const CREDENTIAL_ID = 'ZXhwb3J0LWNyZWRlbnRpYWwtMQ';
const RP_ID = 'router.example.test';
const ORIGIN = 'https://router.example.test';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-export',
  projectId: 'project-export',
  envId: 'test',
  signingRootVersion: ROOT_SHARE_EPOCH,
} as const;

type WebAuthnVerificationInput = Parameters<
  RouterApiWebAuthnService['verifyWebAuthnAuthenticationLite']
>[0];

type AdmissionFixtureOptions = {
  readonly lifecycleId: string;
  readonly nowMs: number;
  readonly nonce: readonly number[];
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly authorizationDigestOverride: readonly number[] | null;
  readonly registeredPublicKey: readonly number[];
  readonly authority?: RouterAbEd25519YaoExportAuthorityBindingV1;
};

type BackendExecution =
  | { readonly kind: 'success' }
  | { readonly kind: 'failure'; readonly message: string };

type ActiveCapabilitySubstitution = 'none' | 'subject' | 'key' | 'slot' | 'epoch' | 'scope';

type ReceiptScopeSubstitution =
  | 'none'
  | 'root'
  | 'account'
  | 'wallet_session'
  | 'signer_set'
  | 'worker';

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function requireParsed<T>(parsed: { ok: true; value: T } | { ok: false; message: string }): T {
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function defaultAdmissionFixtureOptions(nowMs: number): AdmissionFixtureOptions {
  return {
    lifecycleId: 'export-lifecycle-1',
    nowMs,
    nonce: bytes(41),
    issuedAtMs: nowMs - 1_000,
    expiresAtMs: nowMs + 30_000,
    authorizationDigestOverride: null,
    registeredPublicKey: bytes(12),
  };
}

function exportIdentity(input: {
  readonly lifecycleId: string;
  readonly runtimePolicyBinding: readonly number[];
  readonly registeredPublicKey: readonly number[];
}): RouterAbEd25519YaoExportAuthorizationIdentityV1 {
  return {
    scope: {
      lifecycle_id: input.lifecycleId,
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: WALLET_ID,
      wallet_session_id: WALLET_SESSION_ID,
      signer_set_id: 'signer-set-export-1',
      signing_worker_id: SIGNING_WORKER_ID,
    },
    application_binding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: 'project-export:test',
      key_creation_signer_slot: 3,
    },
    participant_ids: PARTICIPANTS,
    registered_public_key: input.registeredPublicKey,
    state_epoch: 7,
    runtime_policy_binding: input.runtimePolicyBinding,
  };
}

async function admissionFixture(
  options: AdmissionFixtureOptions,
): Promise<RouterAbEd25519YaoExportAdmissionRequestV1> {
  const runtimePolicyBinding =
    await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(RUNTIME_POLICY_SCOPE);
  const identity = exportIdentity({
    lifecycleId: options.lifecycleId,
    runtimePolicyBinding,
    registeredPublicKey: options.registeredPublicKey,
  });
  const confirmationDigest = await deriveRouterAbEd25519YaoExportConfirmationDigestV1({
    identity,
    nonce: options.nonce,
    issuedAtMs: options.issuedAtMs,
    expiresAtMs: options.expiresAtMs,
  });
  const derivedAuthorizationDigest = await deriveRouterAbEd25519YaoExportAuthorizationDigestV1({
    identity,
    confirmationDigest,
    nonce: options.nonce,
    issuedAtMs: options.issuedAtMs,
    expiresAtMs: options.expiresAtMs,
    thresholdSessionId: WALLET_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
    authority: options.authority || { kind: 'passkey', credentialIdB64u: CREDENTIAL_ID },
  });
  return requireParsed(
    parseRouterAbEd25519YaoExportAdmissionRequestV1({
      scope: identity.scope,
      application_binding: identity.application_binding,
      participant_ids: identity.participant_ids,
      registered_public_key: identity.registered_public_key,
      state_epoch: identity.state_epoch,
      runtime_policy_binding: identity.runtime_policy_binding,
      authorization: {
        confirmation_digest: confirmationDigest,
        authorization_digest: options.authorizationDigestOverride ?? derivedAuthorizationDigest,
        nonce: options.nonce,
        issued_at_ms: options.issuedAtMs,
        expires_at_ms: options.expiresAtMs,
      },
    }),
  );
}

function exportBinding(request: RouterAbEd25519YaoExportAdmissionRequestV1) {
  return {
    ceremony: {
      lifecycle: {
        lifecycle_id: request.scope.lifecycle_id,
        work_kind: 'key_export' as const,
        primitive_request_kind: 'export' as const,
        root_share_epoch: request.scope.root_share_epoch,
        account_id: request.scope.account_id,
        session_id: request.scope.wallet_session_id,
        signer_set_id: request.scope.signer_set_id,
        selected_server_id: request.scope.signing_worker_id,
      },
      operation: 'export' as const,
      session_id: bytes(71),
      stable_key_context_binding: bytes(72),
    },
    registered_public_key: request.registered_public_key,
    state_epoch: request.state_epoch,
    runtime_policy_binding: request.runtime_policy_binding,
    authorization_digest: request.authorization.authorization_digest,
  };
}

function exportReceipt(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  substitution: ReceiptScopeSubstitution,
): unknown {
  const binding = exportBinding(request);
  const lifecycle = binding.ceremony.lifecycle;
  return {
    binding: {
      ceremony: {
        lifecycle: {
          lifecycle_id: lifecycle.lifecycle_id,
          work_kind: lifecycle.work_kind,
          primitive_request_kind: lifecycle.primitive_request_kind,
          root_share_epoch:
            substitution === 'root' ? 'substituted-root' : lifecycle.root_share_epoch,
          account_id:
            substitution === 'account' ? 'substituted-account.testnet' : lifecycle.account_id,
          session_id:
            substitution === 'wallet_session' ? 'substituted-wallet-session' : lifecycle.session_id,
          signer_set_id:
            substitution === 'signer_set' ? 'substituted-signer-set' : lifecycle.signer_set_id,
          selected_server_id:
            substitution === 'worker' ? 'substituted-worker' : lifecycle.selected_server_id,
        },
        operation: binding.ceremony.operation,
        session_id: binding.ceremony.session_id,
        stable_key_context_binding: binding.ceremony.stable_key_context_binding,
      },
      registered_public_key: binding.registered_public_key,
      state_epoch: binding.state_epoch,
      runtime_policy_binding: binding.runtime_policy_binding,
      authorization_digest: binding.authorization_digest,
    },
    keyset: {
      deriver_a_input_public_key: bytes(81),
      deriver_b_input_public_key: bytes(82),
      signing_worker_recipient_public_key: bytes(83),
    },
  };
}

function exportInput(
  binding: ReturnType<typeof exportBinding>,
  deriver: 'deriver_a' | 'deriver_b',
): Record<string, unknown> {
  return {
    kind: 'export',
    deriver,
    operation: 'export',
    session: binding.ceremony.session_id,
    stable_context_binding: binding.ceremony.stable_key_context_binding,
    encapsulated_key: deriver === 'deriver_a' ? bytes(91) : bytes(92),
    ciphertext: bytes(93, 16),
  };
}

function executeFixture(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  bindingOverride: ReturnType<typeof exportBinding> | null = null,
): RouterAbEd25519YaoExportExecuteRequestV1 {
  const binding = bindingOverride ?? exportBinding(request);
  return requireParsed(
    parseRouterAbEd25519YaoExportExecuteRequestV1({
      binding,
      deriver_a_input: exportInput(binding, 'deriver_a'),
      deriver_b_input: exportInput(binding, 'deriver_b'),
    }),
  );
}

function exportResult(request: RouterAbEd25519YaoExportExecuteRequestV1): unknown {
  const transcript = bytes(101);
  return {
    binding: request.binding,
    transcript,
    deriver_a_client_package: {
      kind: 'export_client',
      deriver: 'deriver_a',
      session: request.binding.ceremony.session_id,
      transcript,
      encapsulated_key: bytes(102),
      ciphertext: bytes(103, 16),
    },
    deriver_b_client_package: {
      kind: 'export_client',
      deriver: 'deriver_b',
      session: request.binding.ceremony.session_id,
      transcript,
      encapsulated_key: bytes(104),
      ciphertext: bytes(105, 16),
    },
  };
}

class ExportBackendFixture implements RouterAbEd25519YaoExportBackend {
  admitCalls = 0;
  executeCalls = 0;

  constructor(
    private readonly execution: BackendExecution = { kind: 'success' },
    private readonly receiptSubstitution: ReceiptScopeSubstitution = 'none',
  ) {}

  admitExport(
    request: RouterAbEd25519YaoExportAdmissionRequestV1,
  ): RouterAbEd25519YaoExportBackendResult {
    this.admitCalls += 1;
    return { ok: true, body: exportReceipt(request, this.receiptSubstitution) };
  }

  executeExport(
    request: RouterAbEd25519YaoExportExecuteRequestV1,
  ): RouterAbEd25519YaoExportBackendResult {
    this.executeCalls += 1;
    switch (this.execution.kind) {
      case 'success':
        return { ok: true, body: exportResult(request) };
      case 'failure':
        return {
          ok: false,
          status: 503,
          code: 'deriver_failed',
          message: this.execution.message,
        };
    }
  }
}

class ActiveCapabilityFixture implements RouterAbEd25519YaoActiveCapabilityResolverV1 {
  constructor(private readonly substitution: ActiveCapabilitySubstitution = 'none') {}

  resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): RouterAbEd25519YaoActiveCapabilityLookupResultV1 {
    return {
      ok: true,
      capability: {
        kind: 'router_ab_ed25519_yao_active_capability_v1',
        activeCapabilityBinding: bytes(110),
        registeredPublicKey: bytes(12),
        nearAccountId:
          this.substitution === 'subject' ? 'substituted-subject.testnet' : input.nearAccountId,
        applicationBinding: {
          wallet_id: WALLET_ID,
          near_ed25519_signing_key_id:
            this.substitution === 'key' ? 'substituted-ed25519-key' : NEAR_SIGNING_KEY_ID,
          signing_root_id: 'project-export:test',
          key_creation_signer_slot: this.substitution === 'slot' ? 4 : 3,
        },
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        participantIds: PARTICIPANTS,
        lifecycle: {
          lifecycleId: 'export-lifecycle-1',
          rootShareEpoch: ROOT_SHARE_EPOCH,
          accountId: WALLET_ID,
          walletSessionId: WALLET_SESSION_ID,
          signerSetId:
            this.substitution === 'scope' ? 'substituted-signer-set' : 'signer-set-export-1',
          signingWorkerId: SIGNING_WORKER_ID,
        },
        stateEpoch: this.substitution === 'epoch' ? 8 : 7,
      },
    };
  }
}

class SessionFixture implements SessionAdapter {
  constructor(
    private readonly result:
      | { readonly ok: true; readonly claims: SessionClaims }
      | { readonly ok: false },
  ) {}

  async signJwt(): Promise<string> {
    throw new Error('signJwt is outside the export authorization test boundary');
  }

  async parse(): Promise<
    { readonly ok: true; readonly claims: SessionClaims } | { readonly ok: false }
  > {
    return this.result;
  }

  buildSetCookie(): string {
    throw new Error('buildSetCookie is outside the export authorization test boundary');
  }

  buildClearCookie(): string {
    throw new Error('buildClearCookie is outside the export authorization test boundary');
  }

  async refresh(): Promise<{ readonly ok: false }> {
    return { ok: false };
  }
}

class WebAuthnFixture {
  input: WebAuthnVerificationInput | null = null;

  constructor(private readonly verified: boolean) {}

  async verifyWebAuthnAuthenticationLite(input: WebAuthnVerificationInput) {
    this.input = input;
    return this.verified
      ? { success: true, verified: true }
      : {
          success: false,
          verified: false,
          code: 'fresh_assertion_rejected',
          message: 'Fresh assertion rejected',
        };
  }
}

class AuthorizationFixture implements RouterAbEd25519YaoExportAuthorizationAdapter {
  readonly inputs: RouterAbEd25519YaoExportAuthorizationInput[] = [];

  authorize(
    input: RouterAbEd25519YaoExportAuthorizationInput,
  ): RouterAbEd25519YaoExportAuthorizationResult {
    this.inputs.push(input);
    return { ok: true };
  }
}

function claimsForAuthority(authority: WalletAuthAuthority): SessionClaims {
  return {
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: WALLET_ID,
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    thresholdSessionId: WALLET_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
    relayerKeyId: SIGNING_WORKER_ID,
    authority,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [...PARTICIPANTS],
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: SIGNING_WORKER_ID,
    },
  };
}

function validClaims(): SessionClaims {
  return claimsForAuthority(
    buildPasskeyWalletAuthAuthority({
      walletId: WALLET_ID,
      rpId: RP_ID,
      credentialIdB64u: CREDENTIAL_ID,
    }),
  );
}

function validEmailOtpClaims(): SessionClaims {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: 'google:ed25519-export-user',
    emailHashHex: 'ab'.repeat(32),
  });
  return claimsForAuthority(authority);
}

function webAuthnCredential(): WebAuthnAuthenticationCredential {
  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

function substitutedWebAuthnCredential(): WebAuthnAuthenticationCredential {
  return {
    id: 'c3Vic3RpdHV0ZWQtY3JlZGVudGlhbA',
    rawId: 'c3Vic3RpdHV0ZWQtY3JlZGVudGlhbA',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

function authorizationInput(
  body: RouterAbEd25519YaoExportAdmissionRequestV1,
): Extract<RouterAbEd25519YaoExportAuthorizationInput, { kind: 'admit' }> {
  return {
    kind: 'admit',
    request: new Request(`${ORIGIN}${ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1}`, {
      method: 'POST',
      headers: { authorization: 'Bearer export-wallet-session' },
    }),
    body,
    authorization: {
      kind: 'passkey',
      webauthnAuthentication: webAuthnCredential(),
    },
    expectedOrigin: ORIGIN,
  };
}

function jsonAdmissionRequest(
  body: RouterAbEd25519YaoExportAdmissionRequestV1,
  origin: string | null,
): Request {
  return jsonAdmissionEnvelopeRequest(
    body,
    {
      kind: 'passkey',
      webauthnAuthentication: webAuthnCredential(),
    },
    origin,
  );
}

function jsonAdmissionEnvelopeRequest(
  body: RouterAbEd25519YaoExportAdmissionRequestV1,
  authorization: unknown,
  origin: string | null,
): Request {
  const headers = new Headers({
    authorization: 'Bearer export-wallet-session',
    'content-type': 'application/json',
  });
  if (origin) headers.set('origin', origin);
  return new Request(`${ORIGIN}${ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      protocol: body,
      authorization,
    }),
  });
}

test.describe('Router A/B Ed25519 Yao export server boundary', () => {
  test('verifies a fresh WebAuthn assertion against the exact digest, wallet, RP, and Origin', async () => {
    const nowMs = Date.now();
    const body = await admissionFixture(defaultAdmissionFixtureOptions(nowMs));
    const webAuthn = new WebAuthnFixture(true);
    const authorization = new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
      new SessionFixture({ ok: true, claims: validClaims() }),
      webAuthn,
    );

    await expect(authorization.authorize(authorizationInput(body))).resolves.toEqual({ ok: true });
    expect(webAuthn.input).toEqual({
      userId: WALLET_ID,
      rpId: RP_ID,
      expectedChallenge: base64UrlEncode(Uint8Array.from(body.authorization.confirmation_digest)),
      webauthn_authentication: webAuthnCredential(),
      expected_origin: ORIGIN,
    });
  });

  test('rejects expired, substituted-digest, and failed fresh WebAuthn authorizations', async () => {
    const nowMs = Date.now();
    const expiredOptions = defaultAdmissionFixtureOptions(nowMs);
    const expired = await admissionFixture({
      lifecycleId: expiredOptions.lifecycleId,
      nowMs,
      nonce: expiredOptions.nonce,
      issuedAtMs: nowMs - 61_000,
      expiresAtMs: nowMs - 1,
      authorizationDigestOverride: null,
      registeredPublicKey: expiredOptions.registeredPublicKey,
    });
    const substitutedOptions = defaultAdmissionFixtureOptions(nowMs);
    const substituted = await admissionFixture({
      lifecycleId: 'export-lifecycle-substituted-digest',
      nowMs,
      nonce: bytes(42),
      issuedAtMs: substitutedOptions.issuedAtMs,
      expiresAtMs: substitutedOptions.expiresAtMs,
      authorizationDigestOverride: bytes(250),
      registeredPublicKey: substitutedOptions.registeredPublicKey,
    });
    const exact = await admissionFixture({
      lifecycleId: 'export-lifecycle-webauthn-failure',
      nowMs,
      nonce: bytes(43),
      issuedAtMs: substitutedOptions.issuedAtMs,
      expiresAtMs: substitutedOptions.expiresAtMs,
      authorizationDigestOverride: null,
      registeredPublicKey: substitutedOptions.registeredPublicKey,
    });
    const session = new SessionFixture({ ok: true, claims: validClaims() });

    const expiredResult = await new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
      session,
      new WebAuthnFixture(true),
    ).authorize(authorizationInput(expired));
    expect(expiredResult).toMatchObject({ ok: false, code: 'export_authorization_expired' });

    const substitutedResult = await new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
      session,
      new WebAuthnFixture(true),
    ).authorize(authorizationInput(substituted));
    expect(substitutedResult).toMatchObject({ ok: false, code: 'export_authorization_invalid' });

    const failedAssertion = await new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
      session,
      new WebAuthnFixture(false),
    ).authorize(authorizationInput(exact));
    expect(failedAssertion).toEqual({
      ok: false,
      status: 403,
      code: 'fresh_assertion_rejected',
      message: 'Fresh assertion rejected',
    });
  });

  test('rejects a fresh assertion from another passkey on the same wallet', async () => {
    const body = await admissionFixture(defaultAdmissionFixtureOptions(Date.now()));
    const webAuthn = new WebAuthnFixture(true);
    const authorization = new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
      new SessionFixture({ ok: true, claims: validClaims() }),
      webAuthn,
    );
    const input = authorizationInput(body);
    const result = await authorization.authorize({
      kind: 'admit',
      request: input.request,
      body: input.body,
      authorization: {
        kind: 'passkey',
        webauthnAuthentication: substitutedWebAuthnCredential(),
      },
      expectedOrigin: input.expectedOrigin,
    });

    expect(result).toEqual({
      ok: false,
      status: 403,
      code: 'export_webauthn_credential_mismatch',
      message: 'Fresh export assertion used a different passkey credential',
    });
    expect(webAuthn.input).toBeNull();
  });

  test('accepts Email OTP factor possession for the exact Email OTP wallet authority', async () => {
    const providerSubjectId = 'google:ed25519-export-user';
    const options = defaultAdmissionFixtureOptions(Date.now());
    const body = await admissionFixture({
      ...options,
      authority: { kind: 'email_otp', providerSubjectId },
    });
    const webAuthn = new WebAuthnFixture(true);
    const authorization = new RouterAbEd25519YaoExportWalletSessionAuthorizationAdapter(
      new SessionFixture({ ok: true, claims: validEmailOtpClaims() }),
      webAuthn,
    );
    const input = authorizationInput(body);

    await expect(
      authorization.authorize({
        ...input,
        authorization: { kind: 'email_otp_factor', providerSubjectId },
      }),
    ).resolves.toEqual({ ok: true });
    expect(webAuthn.input).toBeNull();

    await expect(
      authorization.authorize({
        ...input,
        authorization: {
          kind: 'email_otp_factor',
          providerSubjectId: 'google:substituted-user',
        },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'export_authorization_method_mismatch' });
  });

  test('rejects active subject, key, slot, epoch, and lifecycle-scope substitutions', async () => {
    const substitutions: readonly ActiveCapabilitySubstitution[] = [
      'subject',
      'key',
      'slot',
      'epoch',
      'scope',
    ];
    for (let index = 0; index < substitutions.length; index += 1) {
      const substitution = substitutions[index];
      if (!substitution) throw new Error('capability substitution is required');
      const request = await admissionFixture({
        lifecycleId: `export-lifecycle-capability-${substitution}`,
        nowMs: Date.now(),
        nonce: bytes(120 + index),
        issuedAtMs: Date.now() - 1_000,
        expiresAtMs: Date.now() + 30_000,
        authorizationDigestOverride: null,
        registeredPublicKey: bytes(12),
      });
      const backend = new ExportBackendFixture();
      const service = new InMemoryRouterAbEd25519YaoExportService(
        backend,
        new ActiveCapabilityFixture(substitution),
      );

      expect(await service.admitExport(request), substitution).toMatchObject({
        ok: false,
        status: 409,
        code: 'active_identity_mismatch',
      });
      expect(backend.admitCalls, substitution).toBe(0);
    }
  });

  test('rejects backend receipt changes to every stable admitted scope field', async () => {
    const substitutions: readonly ReceiptScopeSubstitution[] = [
      'root',
      'account',
      'wallet_session',
      'signer_set',
      'worker',
    ];
    for (let index = 0; index < substitutions.length; index += 1) {
      const substitution = substitutions[index];
      if (!substitution) throw new Error('receipt substitution is required');
      const nowMs = Date.now();
      const request = await admissionFixture({
        lifecycleId: `export-lifecycle-receipt-${substitution}`,
        nowMs,
        nonce: bytes(130 + index),
        issuedAtMs: nowMs - 1_000,
        expiresAtMs: nowMs + 30_000,
        authorizationDigestOverride: null,
        registeredPublicKey: bytes(12),
      });
      const backend = new ExportBackendFixture({ kind: 'success' }, substitution);
      const service = new InMemoryRouterAbEd25519YaoExportService(
        backend,
        new ActiveCapabilityFixture(),
      );

      expect(await service.admitExport(request), substitution).toMatchObject({
        ok: false,
        status: 502,
        code: 'invalid_backend_response',
      });
      expect(backend.admitCalls, substitution).toBe(1);
    }
  });

  test('burns authorization replay, binding substitution, and backend execution failure', async () => {
    const nowMs = Date.now();
    const request = await admissionFixture(defaultAdmissionFixtureOptions(nowMs));
    const backend = new ExportBackendFixture();
    const service = new InMemoryRouterAbEd25519YaoExportService(
      backend,
      new ActiveCapabilityFixture(),
    );
    expect((await service.admitExport(request)).ok).toBe(true);
    expect(await service.admitExport(request)).toMatchObject({
      ok: false,
      status: 409,
      code: 'admission_failed',
    });
    expect(backend.admitCalls).toBe(1);

    const substitutedBinding = exportBinding(request);
    substitutedBinding.authorization_digest = bytes(251);
    const substituted = executeFixture(request, substitutedBinding);
    expect(await service.executeExport(substituted)).toMatchObject({
      ok: false,
      status: 409,
      code: 'binding_mismatch',
    });
    expect(await service.executeExport(executeFixture(request))).toMatchObject({
      ok: false,
      status: 409,
      code: 'export_consumed',
    });
    expect(backend.executeCalls).toBe(0);

    const failureRequest = await admissionFixture({
      lifecycleId: 'export-lifecycle-backend-failure',
      nowMs,
      nonce: bytes(44),
      issuedAtMs: nowMs - 1_000,
      expiresAtMs: nowMs + 30_000,
      authorizationDigestOverride: null,
      registeredPublicKey: bytes(12),
    });
    const failingBackend = new ExportBackendFixture({
      kind: 'failure',
      message: 'Deriver B disconnected',
    });
    const failingService = new InMemoryRouterAbEd25519YaoExportService(
      failingBackend,
      new ActiveCapabilityFixture(),
    );
    expect((await failingService.admitExport(failureRequest)).ok).toBe(true);
    const failureExecute = executeFixture(failureRequest);
    expect(await failingService.executeExport(failureExecute)).toMatchObject({
      ok: false,
      status: 503,
      code: 'execution_failed',
    });
    expect(await failingService.executeExport(failureExecute)).toMatchObject({
      ok: false,
      status: 409,
      code: 'export_consumed',
    });
    expect(failingBackend.executeCalls).toBe(1);
  });

  test('accepts distinct one-use authorizations for repeated exports of one active capability', async () => {
    const nowMs = Date.now();
    const first = await admissionFixture(defaultAdmissionFixtureOptions(nowMs));
    const second = await admissionFixture({
      lifecycleId: first.scope.lifecycle_id,
      nowMs,
      nonce: bytes(45),
      issuedAtMs: nowMs - 500,
      expiresAtMs: nowMs + 30_000,
      authorizationDigestOverride: null,
      registeredPublicKey: bytes(12),
    });
    const backend = new ExportBackendFixture();
    const service = new InMemoryRouterAbEd25519YaoExportService(
      backend,
      new ActiveCapabilityFixture(),
    );

    expect((await service.admitExport(first)).ok).toBe(true);
    expect((await service.executeExport(executeFixture(first))).ok).toBe(true);
    expect((await service.admitExport(second)).ok).toBe(true);
    expect((await service.executeExport(executeFixture(second))).ok).toBe(true);
    expect(await service.admitExport(second)).toMatchObject({
      ok: false,
      status: 409,
      code: 'admission_failed',
    });
    expect(backend.admitCalls).toBe(2);
    expect(backend.executeCalls).toBe(2);
  });

  test('derives the verifier Origin only from the actual Origin header', async () => {
    const body = await admissionFixture(defaultAdmissionFixtureOptions(Date.now()));
    const backend = new ExportBackendFixture();
    const authorization = new AuthorizationFixture();
    const module = createRouterAbEd25519YaoExportModule({
      service: new InMemoryRouterAbEd25519YaoExportService(backend, new ActiveCapabilityFixture()),
      authorization,
    });
    const extension = module.routeExtensions[0];
    const route = extension?.routes[0];
    if (!extension || !route) throw new Error('export admission route is required');
    const response = await extension.handleCloudflareRoute({
      request: jsonAdmissionRequest(body, `${ORIGIN}/ignored-path`),
      route,
      pathname: route.path,
      method: 'POST',
      logger: coerceRouterLogger(null),
    });
    expect(response.status).toBe(200);
    expect(authorization.inputs).toHaveLength(1);
    const captured = authorization.inputs[0];
    expect(captured?.kind).toBe('admit');
    if (captured?.kind !== 'admit') throw new Error('admit authorization input is required');
    expect(captured.expectedOrigin).toBe(ORIGIN);

    const missingOrigin = await extension.handleCloudflareRoute({
      request: jsonAdmissionRequest(body, null),
      route,
      pathname: route.path,
      method: 'POST',
      logger: coerceRouterLogger(null),
    });
    expect(missingOrigin.status).toBe(403);
    expect(authorization.inputs).toHaveLength(1);
  });

  test('rejects unknown authorization kinds and branch-specific fields at the route boundary', async () => {
    const body = await admissionFixture(defaultAdmissionFixtureOptions(Date.now()));
    const authorization = new AuthorizationFixture();
    const module = createRouterAbEd25519YaoExportModule({
      service: new InMemoryRouterAbEd25519YaoExportService(
        new ExportBackendFixture(),
        new ActiveCapabilityFixture(),
      ),
      authorization,
    });
    const extension = module.routeExtensions[0];
    const route = extension?.routes[0];
    if (!extension || !route) throw new Error('export admission route is required');
    const invalidAuthorizations = [
      { kind: 'voice_id', evidence: 'unreviewed-factor' },
      {
        kind: 'passkey',
        webauthnAuthentication: webAuthnCredential(),
        providerSubjectId: 'google:cross-branch-field',
      },
      {
        kind: 'email_otp_factor',
        providerSubjectId: 'google:ed25519-export-user',
        webauthnAuthentication: webAuthnCredential(),
      },
      {
        kind: 'email_otp_factor',
        providerSubjectId: { provider: 'google', subject: 'ed25519-export-user' },
      },
    ] as const;

    for (const invalidAuthorization of invalidAuthorizations) {
      const response = await extension.handleCloudflareRoute({
        request: jsonAdmissionEnvelopeRequest(body, invalidAuthorization, ORIGIN),
        route,
        pathname: route.path,
        method: 'POST',
        logger: coerceRouterLogger(null),
      });
      expect(response.status).toBe(400);
    }
    expect(authorization.inputs).toHaveLength(0);
  });
});
