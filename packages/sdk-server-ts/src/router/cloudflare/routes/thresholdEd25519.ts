import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import {
  ROUTER_AB_ED25519_HEALTH_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH,
} from '@shared/utils/signingSessionSeal';
import { resolveThresholdRuntimePolicyScope } from '../../commonRouterUtils';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import {
  authenticateRouterAbOperationStepUpAppSession,
  authorizeRouterAbEd25519NormalSigningRoute,
  buildRouterAbEd25519PrivateSigningWorkerBody,
  parseRouterAbEd25519OperationStepUpScope,
  parseRouterAbOperationStepUpOperation,
  type RouterAbEd25519NormalSigningRoutePhase,
} from '../../routerAbPrivateSigningWorker';
import {
  parseThresholdEd25519OperationStepUpGrantRequest,
  parseThresholdEd25519SessionRouteRequest,
} from '../../thresholdEd25519RequestValidation';
import {
  isPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { isPlainObject } from '@shared/utils/validation';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseAuthorizationAuditEventId,
  parseAuthFactorId,
  parseCapabilityBindingId,
  parseCapabilityGrantId,
  parseCapabilityGrantUseId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationResultStorageRef,
  parseGrantEvidenceId,
  parseGrantEvidenceSetId,
  parsePrincipalId,
  parseTenantId,
  type CapabilityGrantUseId,
  type CapabilityOperationRef,
} from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  parseCapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import {
  buildActiveCapabilityGrant,
  buildCapabilityOperationCompletionClaimRef,
  type CapabilityGrantUse,
} from '../../../authorization/domain';
import { buildVerifiedPasskeyFactorResult } from '../../../authorization/factorEvidence';
import {
  parseAppSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import type {
  RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
  RouterAbEd25519YaoOperationStepUpGrantCommandV1,
  RouterAbEd25519YaoSessionRouteCommandV1,
} from '../../routerAbEd25519YaoWalletSession';
import { proxyNormalSigningRequestToMpcRouter } from './normalSigningRouterProxy';

type Ed25519ReusableOperationClaimReceipt = {
  readonly kind: 'reusable_wallet_session_operation_claim_v1';
  readonly use_id: string;
  readonly grant_id: string;
  readonly operation_id: string;
  readonly capability_kind: 'near_ed25519_mpc_signing';
  readonly operation_kind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
  readonly lane_digest_b64u: string;
  readonly intent_digest_b64u: string;
  readonly display_digest_b64u: string;
  readonly operation_fingerprint_digest: string;
};

type Ed25519OperationKind = Ed25519ReusableOperationClaimReceipt['operation_kind'];

function requireReceiptString(record: Record<string, unknown>, name: string): string {
  const field = typeof record[name] === 'string' ? record[name].trim() : '';
  if (!field) throw new Error(`authorization_claim.${name} is required`);
  return field;
}

function requireEd25519OperationKind(value: unknown): Ed25519OperationKind {
  if (
    value !== 'near.sign_transaction' &&
    value !== 'near.sign_delegate_action' &&
    value !== 'near.sign_nep413_message'
  ) {
    throw new Error('authorization_claim.operation_kind is invalid');
  }
  return value;
}

function requireExactAuthorizationClaimFields(record: Record<string, unknown>): void {
  const expected = [
    'capability_kind',
    'display_digest_b64u',
    'grant_id',
    'intent_digest_b64u',
    'kind',
    'lane_digest_b64u',
    'operation_fingerprint_digest',
    'operation_id',
    'operation_kind',
    'use_id',
  ];
  const actual = Object.keys(record).sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    throw new Error('authorization_claim has invalid fields');
  }
}

type PasskeyEd25519AuthorizationResult =
  | {
      ok: true;
      authorization: Extract<
        RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
        {
          kind:
            | 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1'
            | 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1';
        }
      >;
    }
  | { ok: false; response: Response };

async function validatePasskeyEd25519SessionAuthorization(input: {
  ctx: CloudflareRouterApiContext;
  request: RouterAbEd25519YaoSessionRouteCommandV1;
  authority: PasskeyWalletAuthAuthority;
}): Promise<PasskeyEd25519AuthorizationResult> {
  const credential = input.request.routeAuth;
  if (credential.kind !== 'passkey') {
    throw new Error('validatePasskeyEd25519SessionAuthorization requires passkey route auth');
  }
  const credentialIdB64u = String(
    credential.webauthnAuthentication.rawId || credential.webauthnAuthentication.id || '',
  ).trim();
  if (!credentialIdB64u || credentialIdB64u !== input.authority.factor.credentialIdB64u) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'WebAuthn proof does not match the active Ed25519 Wallet Session authority',
        },
        { status: 401 },
      ),
    };
  }
  const expectedOrigin = normalizeCorsOrigin(input.ctx.request.headers.get('origin') || undefined);
  if (!expectedOrigin) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        },
        { status: 400 },
      ),
    };
  }
  const expectedChallenge = base64UrlEncode(
    await sha256BytesUtf8(alphabetizeStringify(input.request.sessionPolicy)),
  );
  const verified = await input.ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
    userId: input.authority.walletId,
    rpId: input.authority.verifier.rpId,
    expectedChallenge,
    expected_origin: expectedOrigin,
    webauthn_authentication: credential.webauthnAuthentication,
  });
  if (verified.success && verified.verified) {
    return {
      ok: true,
      authorization: {
        kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1',
        authority: input.authority,
        verifiedChallengeId: expectedChallenge,
      },
    };
  }
  return {
    ok: false,
    response: json(
      {
        ok: false,
        code: verified.code || 'not_verified',
        message: verified.message || 'WebAuthn authentication verification failed',
      },
      { status: 401 },
    ),
  };
}

async function validateSignedEd25519SessionAuthorization(input: {
  ctx: CloudflareRouterApiContext;
  request: RouterAbEd25519YaoSessionRouteCommandV1;
  authority: PasskeyWalletAuthAuthority;
}): Promise<PasskeyEd25519AuthorizationResult> {
  if (input.request.routeAuth.kind !== 'signed_session') {
    throw new Error('validateSignedEd25519SessionAuthorization requires signed-session route auth');
  }
  const session = input.ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      response: json(
        { ok: false, code: 'unauthorized', message: 'Signed session authorization is unavailable' },
        { status: 401 },
      ),
    };
  }
  const parsedSession = await session.parse(
    Object.fromEntries(input.ctx.request.headers.entries()),
  );
  if (!parsedSession.ok) {
    return {
      ok: false,
      response: json(
        { ok: false, code: 'unauthorized', message: 'Signed session authorization is required' },
        { status: 401 },
      ),
    };
  }
  let appSessionClaims = parseAppSessionClaims(parsedSession.claims);
  if (
    appSessionClaims &&
    (!isPlainObject(parsedSession.claims) || parsedSession.claims.provider !== 'passkey')
  ) {
    appSessionClaims = null;
  }
  if (appSessionClaims) {
    const version = await input.ctx.service.sessionVersions.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!version.ok) appSessionClaims = null;
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    input.authority.walletId,
  );
  if (!appSessionClaims || appSessionWalletId !== input.authority.walletId) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'Passkey app session does not authorize the active Ed25519 wallet',
        },
        { status: 401 },
      ),
    };
  }
  const expectedAuthorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  const signedAuthorityRef = appSessionClaims.walletAuthAuthorityRef;
  if (
    !signedAuthorityRef ||
    signedAuthorityRef.walletId !== expectedAuthorityRef.walletId ||
    signedAuthorityRef.authorityDigest !== expectedAuthorityRef.authorityDigest
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'Passkey app session authority does not match the active Ed25519 authority',
        },
        { status: 401 },
      ),
    };
  }
  const signedRuntimePolicyScope = appSessionClaims.runtimePolicyScope;
  if (
    !signedRuntimePolicyScope ||
    alphabetizeStringify(signedRuntimePolicyScope) !==
      alphabetizeStringify(input.request.sessionPolicy.runtimePolicyScope)
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'Passkey app session runtime scope does not match the Ed25519 session policy',
        },
        { status: 403 },
      ),
    };
  }
  return {
    ok: true,
    authorization: {
      kind: 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1',
      authority: input.authority,
      authorityRef: signedAuthorityRef,
      runtimePolicyScope: signedRuntimePolicyScope,
    },
  };
}

function requireAuthorizationValue<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function digestWireB64u(value: unknown, label: string): string {
  const record = isPlainObject(value) ? value : null;
  const bytes = Array.isArray(record?.bytes) ? record.bytes.map(Number) : [];
  if (
    bytes.length !== 32 ||
    !bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
  ) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  return base64UrlEncode(Uint8Array.from(bytes));
}

function parseEd25519ReusableOperationClaimReceipt(
  value: unknown,
): Ed25519ReusableOperationClaimReceipt {
  const record = isPlainObject(value) ? value : null;
  if (!record || record.kind !== 'reusable_wallet_session_operation_claim_v1') {
    throw new Error('Ed25519 reusable Wallet Session operation claim is required');
  }
  requireExactAuthorizationClaimFields(record);
  const capabilityKind = requireReceiptString(record, 'capability_kind');
  if (capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error('authorization_claim.capability_kind is invalid');
  }
  const operationKind = requireEd25519OperationKind(
    requireReceiptString(record, 'operation_kind'),
  );
  const laneDigest = requireReceiptString(record, 'lane_digest_b64u');
  const intentDigest = requireReceiptString(record, 'intent_digest_b64u');
  const displayDigest = requireReceiptString(record, 'display_digest_b64u');
  parseDigestB64u(laneDigest);
  parseDigestB64u(intentDigest);
  parseDigestB64u(displayDigest);
  const fingerprint = requireReceiptString(record, 'operation_fingerprint_digest');
  parseCapabilityOperationFingerprintDigest(fingerprint);
  return {
    kind: 'reusable_wallet_session_operation_claim_v1',
    use_id: requireReceiptString(record, 'use_id'),
    grant_id: requireReceiptString(record, 'grant_id'),
    operation_id: requireReceiptString(record, 'operation_id'),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operationKind,
    lane_digest_b64u: laneDigest,
    intent_digest_b64u: intentDigest,
    display_digest_b64u: displayDigest,
    operation_fingerprint_digest: fingerprint,
  };
}

async function claimEd25519ReusableWalletSessionOperation(input: {
  ctx: CloudflareRouterApiContext;
  body: Record<string, unknown>;
  authorization: Extract<
    Awaited<ReturnType<typeof authorizeRouterAbEd25519NormalSigningRoute>>,
    { readonly ok: true; readonly kind: 'reusable_wallet_session' }
  >;
}): Promise<
  | {
      readonly ok: true;
      readonly receipt: Ed25519ReusableOperationClaimReceipt;
      readonly use: Extract<CapabilityGrantUse, { readonly kind: 'claimed' }>;
    }
  | { readonly ok: false; readonly response: Response }
> {
  try {
    const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
    if (scope.authorization.kind !== 'reusable_wallet_session') {
      throw new Error('Reusable Wallet Session authority is required');
    }
    const operation = parseRouterAbOperationStepUpOperation(input.body.intent);
    if (!operation.ok) throw new Error(operation.message);
    const intent = isPlainObject(input.body.intent) ? input.body.intent : null;
    if (!intent) throw new Error('Ed25519 normal-signing intent is required');
    const privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
      phase: 'prepare',
      body: input.body,
      authorization: {
        kind: 'reusable_wallet_session',
        claims: input.authorization.validated.claims,
      },
      headers: Object.fromEntries(input.ctx.request.headers.entries()),
    });
    if (!('admission_candidate' in privateBody)) {
      throw new Error('Ed25519 normal-signing prepare admission is required');
    }
    const claims = input.authorization.validated.claims;
    const nowMs = Date.now();
    const tenantId = requireAuthorizationValue(parseTenantId(claims.runtimePolicyScope.orgId));
    const principalId = requireAuthorizationValue(parsePrincipalId(claims.sub));
    if (
      tenantId !== input.ctx.service.authorizationClaims.tenantId ||
      tenantId !== input.ctx.service.authorizationSessions.tenantId ||
      scope.authorization.wallet_session_id !== claims.walletSessionId
    ) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'wallet_session_mismatch', message: 'Wallet Session changed' },
          { status: 403 },
        ),
      };
    }
    const capabilityId = requireAuthorizationValue(
      parseCapabilityId(scope.material_activation.capability),
    );
    const laneDigest = parseDigestB64u(intent.operation_fingerprint);
    const intentDigest = parseDigestB64u(
      base64UrlEncode(Uint8Array.from(privateBody.admission_candidate.intent_digest.bytes)),
    );
    const displayDigest = parseDigestB64u(digestWireB64u(input.body.display_digest, 'display_digest'));
    const envelope = buildCapabilityOperationEnvelope({
      tenantId,
      principalId,
      capabilityId,
      operationId: operation.operationId,
      operation: operation.operation,
      digests: { laneDigest, intentDigest, displayDigest },
    });
    const grantId = requireAuthorizationValue(
      parseCapabilityGrantId(`ed25519-operation-grant:${operation.operationId}`),
    );
    const useId = requireAuthorizationValue(
      parseCapabilityGrantUseId(`ed25519-operation-use:${operation.operationId}:${scope.request_id}`),
    );
    const outcome = await input.ctx.service.authorizationClaims.claimReusableWalletSessionOperation({
      tenantId,
      grantId,
      useId,
      auditEventId: requireAuthorizationValue(
        parseAuthorizationAuditEventId(`ed25519-operation-audit:${operation.operationId}`),
      ),
      walletSessionId: claims.walletSessionId,
      quotaId: claims.quotaId,
      principalId,
      capabilityId,
      operationId: operation.operationId,
      operation: operation.operation,
      laneDigest,
      intentDigest,
      displayDigest,
      claimedAtMs: nowMs,
    });
    if (
      outcome.result.kind !== 'claimed' &&
      outcome.result.kind !== 'operation_in_progress'
    ) {
      const status = outcome.result.kind === 'wallet_session_expired' ? 401 : 409;
      return {
        ok: false,
        response: json(
          { ok: false, code: outcome.result.kind, message: 'Ed25519 operation claim rejected' },
          { status },
        ),
      };
    }
    if (outcome.result.use.useId !== useId) {
      throw new Error('Ed25519 operation claim belongs to another request');
    }
    return {
      ok: true,
      use: outcome.result.use,
      receipt: {
        kind: 'reusable_wallet_session_operation_claim_v1',
        use_id: outcome.result.use.useId,
        grant_id: outcome.result.use.grantId,
        operation_id: outcome.result.use.operationId,
        capability_kind: 'near_ed25519_mpc_signing',
        operation_kind: requireEd25519OperationKind(
          outcome.result.use.operation.operationKind,
        ),
        lane_digest_b64u: laneDigest,
        intent_digest_b64u: intentDigest,
        display_digest_b64u: displayDigest,
        operation_fingerprint_digest: outcome.result.use.operationFingerprintDigest,
      },
    };
  } catch (error: unknown) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_body',
          message: error instanceof Error ? error.message : 'Ed25519 operation claim is invalid',
        },
        { status: 400 },
      ),
    };
  }
}

async function validateEd25519ReusableOperationClaim(input: {
  ctx: CloudflareRouterApiContext;
  body: Record<string, unknown>;
  authorization: Extract<
    Awaited<ReturnType<typeof authorizeRouterAbEd25519NormalSigningRoute>>,
    { readonly ok: true; readonly kind: 'reusable_wallet_session' }
  >;
}): Promise<
  | {
      readonly ok: true;
      readonly receipt: Ed25519ReusableOperationClaimReceipt;
      readonly use: CapabilityGrantUse;
    }
  | { readonly ok: false; readonly response: Response }
> {
  try {
    const receipt = parseEd25519ReusableOperationClaimReceipt(input.body.authorization_claim);
    const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
    if (scope.authorization.kind !== 'reusable_wallet_session') {
      throw new Error('Reusable Wallet Session authority is required');
    }
    const claims = input.authorization.validated.claims;
    const tenantId = requireAuthorizationValue(parseTenantId(claims.runtimePolicyScope.orgId));
    const principalId = requireAuthorizationValue(parsePrincipalId(claims.sub));
    const capabilityId = requireAuthorizationValue(
      parseCapabilityId(scope.material_activation.capability),
    );
    const operationId = requireAuthorizationValue(parseCapabilityOperationId(receipt.operation_id));
    const envelope = buildCapabilityOperationEnvelope({
      tenantId,
      principalId,
      capabilityId,
      operationId,
      operation: {
        capabilityKind: 'near_ed25519_mpc_signing',
        operationKind: receipt.operation_kind,
      },
      digests: {
        laneDigest: parseDigestB64u(receipt.lane_digest_b64u),
        intentDigest: parseDigestB64u(receipt.intent_digest_b64u),
        displayDigest: parseDigestB64u(receipt.display_digest_b64u),
      },
    });
    const fingerprint = await computeCapabilityOperationFingerprintDigest(envelope);
    if (fingerprint !== parseCapabilityOperationFingerprintDigest(receipt.operation_fingerprint_digest)) {
      throw new Error('Ed25519 operation claim fingerprint changed');
    }
    const prepareBinding = isPlainObject(input.body.prepare_binding)
      ? input.body.prepare_binding
      : null;
    if (
      digestWireB64u(prepareBinding?.intent_digest, 'prepare_binding.intent_digest') !==
      receipt.intent_digest_b64u
    ) {
      throw new Error('Ed25519 operation claim intent changed after prepare');
    }
    const result = await input.ctx.service.authorizationClaims.lookupOperationClaim(envelope);
    if (!result || (result.kind !== 'operation_in_progress' && result.kind !== 'replayed')) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'operation_claim_missing', message: 'Operation claim is unavailable' },
          { status: 409 },
        ),
      };
    }
    if (
      result.use.useId !== requireAuthorizationValue(parseCapabilityGrantUseId(receipt.use_id)) ||
      result.use.grantId !== requireAuthorizationValue(parseCapabilityGrantId(receipt.grant_id)) ||
      result.use.operationFingerprintDigest !== fingerprint
    ) {
      throw new Error('Ed25519 operation claim identity changed after prepare');
    }
    return { ok: true, receipt, use: result.use };
  } catch (error: unknown) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_authorization_claim',
          message: error instanceof Error ? error.message : 'Operation claim is invalid',
        },
        { status: 400 },
      ),
    };
  }
}

async function completeEd25519ReusableOperation(input: {
  ctx: CloudflareRouterApiContext;
  use: CapabilityGrantUse;
  requestId: string;
  result: 'succeeded' | 'failed_before_side_effect' | 'failed_after_side_effect';
  response: unknown;
}): Promise<void> {
  const resultDigest = parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input.response))),
  );
  const completed = await input.ctx.service.authorizationClaims.completeOperation({
    claim: buildCapabilityOperationCompletionClaimRef({
      tenantId: input.use.tenantId,
      useId: input.use.useId,
      grantId: input.use.grantId,
      operationFingerprintDigest: input.use.operationFingerprintDigest,
    }),
    result: input.result,
    resultRef: {
      resultDigest,
      resultStorageRef: requireAuthorizationValue(
        parseCapabilityOperationResultStorageRef(`router-signing-result:${input.requestId}`),
      ),
    },
    completedAtMs: Date.now(),
  });
  if (completed.kind === 'claim_missing' || completed.kind === 'claim_mismatch') {
    throw new Error('Ed25519 operation completion did not match its claim');
  }
}

function parseRouterUpstreamResponseBody(bodyText: string, status: number): unknown {
  if (!bodyText) return { status };
  try {
    return JSON.parse(bodyText);
  } catch {
    return { status, message: bodyText };
  }
}

export function isRouterAbEd25519OperationInProgressResponse(input: {
  readonly status: number;
  readonly bodyText: string;
}): boolean {
  return (
    input.status === 409 &&
    input.bodyText.includes('ReplayedLocalRequest:') &&
    input.bodyText.includes('SigningWorker normal-signing effect is already in progress')
  );
}

async function issuePasskeyEd25519OperationStepUpGrant(input: {
  ctx: CloudflareRouterApiContext;
  request: RouterAbEd25519YaoOperationStepUpGrantCommandV1;
}): Promise<Response> {
  const scope = parseRouterAbEd25519OperationStepUpScope(input.request.normalSigningRequest.scope);
  if (scope.authorization.kind !== 'operation_step_up') {
    return json(
      { ok: false, code: 'invalid_body', message: 'Operation step-up scope is required' },
      { status: 400 },
    );
  }
  const authenticated = await authenticateRouterAbOperationStepUpAppSession({
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    scope,
    authorizationClaims: input.ctx.service.authorizationClaims,
    authorizationSessions: input.ctx.service.authorizationSessions,
  });
  if (!authenticated.ok) {
    return json(authenticated.error.body, { status: authenticated.error.status });
  }
  let privateBody: Awaited<ReturnType<typeof buildRouterAbEd25519PrivateSigningWorkerBody>>;
  try {
    privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
      phase: 'prepare',
      body: input.request.normalSigningRequest,
      authorization: { kind: 'operation_step_up', session: authenticated.session },
      headers: Object.fromEntries(input.ctx.request.headers.entries()),
    });
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Operation step-up request is invalid',
      },
      { status: 400 },
    );
  }
  if (!('admission_candidate' in privateBody)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Operation step-up prepare is required' },
      { status: 400 },
    );
  }
  const operation = parseRouterAbOperationStepUpOperation(
    input.request.normalSigningRequest.intent,
  );
  if (!operation.ok) {
    return json({ ok: false, code: 'invalid_body', message: operation.message }, { status: 400 });
  }
  const intent = input.request.normalSigningRequest.intent;
  if (!isPlainObject(intent)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Operation step-up intent is invalid' },
      { status: 400 },
    );
  }
  const grantId = requireAuthorizationValue(parseCapabilityGrantId(scope.authorization.grant_id));
  const capabilityId = requireAuthorizationValue(
    parseCapabilityId(scope.material_activation.capability),
  );
  const envelope = buildCapabilityOperationEnvelope({
    tenantId: authenticated.session.tenantId,
    principalId: authenticated.session.principalId,
    capabilityId,
    operationId: operation.operationId,
    operation: operation.operation,
    digests: {
      laneDigest: parseDigestB64u(intent.operation_fingerprint),
      intentDigest: parseDigestB64u(
        base64UrlEncode(Uint8Array.from(privateBody.admission_candidate.intent_digest.bytes)),
      ),
      displayDigest: parseDigestB64u(input.request.displayDigest),
    },
  });
  const challengeB64u = await computeCapabilityOperationFingerprintDigest(envelope);
  const authorityRef = await walletAuthAuthorityRef({ authority: input.request.authority });
  const activeAuthSource = authenticated.activeSession.authSource;
  if (
    activeAuthSource.kind !== 'passkey' ||
    authorityRef.walletId !== authenticated.authorityRef.walletId ||
    authorityRef.authorityDigest !== authenticated.authorityRef.authorityDigest ||
    input.request.authority.walletId !== authenticated.session.walletId ||
    input.request.authority.factor.credentialIdB64u !== activeAuthSource.credentialIdB64u
  ) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'Passkey authority changed' },
      { status: 403 },
    );
  }
  const activeSession = authenticated.activeSession;
  if (activeSession.authSource.kind !== 'passkey') {
    return json(
      { ok: false, code: 'unauthorized', message: 'Passkey app session is required' },
      { status: 401 },
    );
  }
  const credentialId = String(
    input.request.webauthnAuthentication.rawId || input.request.webauthnAuthentication.id || '',
  ).trim();
  if (credentialId !== activeSession.authSource.credentialIdB64u) {
    return json(
      { ok: false, code: 'unauthorized', message: 'Passkey credential changed' },
      { status: 401 },
    );
  }
  const origin =
    activeSession.audience.kind === 'first_party_web'
      ? activeSession.audience.origin
      : activeSession.audience.walletOrigin;
  const verified = await input.ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
    userId: authenticated.session.walletId,
    rpId: input.request.authority.verifier.rpId,
    expectedChallenge: challengeB64u,
    expected_origin: origin,
    webauthn_authentication: input.request.webauthnAuthentication,
  });
  if (!verified.success || !verified.verified) {
    return json(
      {
        ok: false,
        code: verified.code || 'not_verified',
        message: verified.message || 'WebAuthn authentication verification failed',
      },
      { status: 401 },
    );
  }
  const nowMs = Date.now();
  const expiresAtMs = Math.min(
    Number(input.request.normalSigningRequest.expires_at_ms),
    authenticated.expiresAtMs,
  );
  const requestId = String(scope.request_id);
  const evidenceId = requireAuthorizationValue(parseGrantEvidenceId(`evidence:${requestId}`));
  const evidenceSetId = requireAuthorizationValue(
    parseGrantEvidenceSetId(`evidence-set:${requestId}`),
  );
  const factor = buildVerifiedPasskeyFactorResult({
    tenantId: authenticated.session.tenantId,
    principalId: authenticated.session.principalId,
    sessionId: authenticated.session.sessionId,
    deviceId: activeSession.deviceId,
    factorId: requireAuthorizationValue(
      parseAuthFactorId(`passkey:${activeSession.authSource.credentialIdB64u}`),
    ),
    authorityRef: authenticated.authorityRef,
    operation: envelope,
    credentialIdB64u: activeSession.authSource.credentialIdB64u,
    assertionDigest: parseDigestB64u(
      base64UrlEncode(
        await sha256BytesUtf8(alphabetizeStringify(input.request.webauthnAuthentication)),
      ),
    ),
    verifiedAtMs: nowMs,
    expiresAtMs,
  });
  const evidenceSet = await input.ctx.service.authorizationClaims.recordVerifiedFactorEvidenceSet({
    session: activeSession,
    operation: envelope,
    evidenceId,
    evidenceSetId,
    factor,
  });
  const grant = buildActiveCapabilityGrant({
    tenantId: authenticated.session.tenantId,
    principalId: authenticated.session.principalId,
    grantId,
    bindingId: requireAuthorizationValue(parseCapabilityBindingId(`binding:${requestId}`)),
    evidenceSetId,
    evidenceSetDigest: evidenceSet.evidenceSetDigest,
    capabilityId,
    operationId: envelope.operationId,
    operation: envelope.operation,
    laneDigest: envelope.digests.laneDigest,
    intentDigest: envelope.digests.intentDigest,
    displayDigest: envelope.digests.displayDigest,
    authority: { kind: 'operation_step_up' },
    remainingUses: 1,
    createdAtMs: nowMs,
    expiresAtMs,
  });
  await input.ctx.service.authorizationClaims.issueGrant({
    operation: envelope,
    evidenceSet,
    grant,
  });
  return json(
    {
      ok: true,
      kind: 'operation_step_up',
      grantId,
      authorizationSessionId: authenticated.session.sessionId,
      expiresAtMs,
    },
    { status: 200 },
  );
}

async function handleRouterAbEd25519NormalSigningRoute(input: {
  ctx: CloudflareRouterApiContext;
  body: Record<string, unknown>;
  phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<Response> {
  const authorization = await authorizeRouterAbEd25519NormalSigningRoute({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    authorizationClaims: input.ctx.service.authorizationClaims,
    authorizationSessions: input.ctx.service.authorizationSessions,
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    phase: input.phase,
  });
  if (!authorization.ok) {
    return json(authorization.result.body, { status: authorization.result.status });
  }
  if (authorization.kind === 'operation_step_up') {
    return await proxyNormalSigningRequestToMpcRouter({
      request: input.ctx.request,
      proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
    });
  }
  if (input.phase === 'prepare') {
    const claimed = await claimEd25519ReusableWalletSessionOperation({
      ctx: input.ctx,
      body: input.body,
      authorization,
    });
    if (!claimed.ok) return claimed.response;
    const upstream = await proxyNormalSigningRequestToMpcRouter({
      request: input.ctx.request,
      proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
    });
    const upstreamBody = await upstream.clone().json().catch(() => null);
    const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
    if (!upstream.ok || !isPlainObject(upstreamBody)) {
      await completeEd25519ReusableOperation({
        ctx: input.ctx,
        use: claimed.use,
        requestId: scope.request_id,
        result: upstream.status < 500 ? 'failed_before_side_effect' : 'failed_after_side_effect',
        response: upstreamBody ?? { status: upstream.status },
      });
      return upstream;
    }
    return new Response(
      JSON.stringify({ ...upstreamBody, authorization_claim: claimed.receipt }),
      {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: new Headers(upstream.headers),
      },
    );
  }
  const validatedClaim = await validateEd25519ReusableOperationClaim({
    ctx: input.ctx,
    body: input.body,
    authorization,
  });
  if (!validatedClaim.ok) return validatedClaim.response;
  const upstream = await proxyNormalSigningRequestToMpcRouter({
    request: input.ctx.request,
    proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
    body: input.body,
  });
  const upstreamBodyText = await upstream.clone().text().catch(() => '');
  if (
    isRouterAbEd25519OperationInProgressResponse({
      status: upstream.status,
      bodyText: upstreamBodyText,
    })
  ) {
    return upstream;
  }
  const upstreamBody = parseRouterUpstreamResponseBody(upstreamBodyText, upstream.status);
  const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
  await completeEd25519ReusableOperation({
    ctx: input.ctx,
    use: validatedClaim.use,
    requestId: scope.request_id,
    result: upstream.ok
      ? 'succeeded'
      : upstream.status < 500
        ? 'failed_before_side_effect'
        : 'failed_after_side_effect',
    response: upstreamBody,
  });
  return upstream;
}

export async function handleThresholdEd25519(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ED25519_HEALTH_PATH) {
    if (!ctx.opts.routerAbNormalSigningRouterProxy) {
      const body = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B Ed25519 signing runtime is not configured on this server',
        configured: false,
      };
      return json(body, { status: thresholdEd25519StatusCode(body) });
    }
    return json({ ok: true, configured: true }, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== ROUTER_AB_ED25519_WALLET_SESSION_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request.clone());
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};

  switch (pathname) {
    case ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        phase: 'prepare',
      });

    case ROUTER_AB_ED25519_NORMAL_SIGNING_PATH:
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        phase: 'finalize',
      });
  }

  switch (pathname) {
    case ROUTER_AB_ED25519_WALLET_SESSION_PATH: {
      const session = ctx.opts.session;
      if (!session) {
        ctx.logger.warn('[threshold-ed25519] request', {
          route: pathname,
          method: ctx.method,
          sessions: false,
        });
        return json(
          {
            ok: false,
            code: 'sessions_disabled',
            message: 'Sessions are not configured on this server',
          },
          { status: 501 },
        );
      }

      if (body.kind === 'router_ab_ed25519_yao_operation_step_up_grant_v1') {
        const parsedGrant = parseThresholdEd25519OperationStepUpGrantRequest(body);
        if (!parsedGrant.ok) {
          return json(parsedGrant.body, {
            status: thresholdEd25519StatusCode(parsedGrant.body),
          });
        }
        return await issuePasskeyEd25519OperationStepUpGrant({
          ctx,
          request: parsedGrant.request,
        });
      }

      const parsedBody = parseThresholdEd25519SessionRouteRequest(body);
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEd25519StatusCode(parsedBody.body) });
      }
      const b = parsedBody.request;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        sessionPolicy: b.sessionPolicy ? { version: b.sessionPolicy.version } : undefined,
      });

      const authority = b.sessionPolicy.authority;
      if (!isPasskeyWalletAuthAuthority(authority)) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'Ed25519 Yao WebAuthn budget refresh requires passkey authority',
          },
          { status: 400 },
        );
      }
      if (b.relayerKeyId !== b.sessionPolicy.relayerKeyId) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'relayerKeyId must match the Ed25519 Yao session policy',
          },
          { status: 400 },
        );
      }

      const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: b.sessionPolicy.runtimePolicyScope,
        projectEnvironmentIdRaw: b.projectEnvironmentId,
        headers: ctx.request.headers,
        origin: ctx.request.headers.get('origin'),
        publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
        orgProjectEnv: ctx.opts.orgProjectEnv || null,
      });
      if (!runtimePolicyScopeResolution.ok) {
        return json(
          {
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          },
          { status: runtimePolicyScopeResolution.status },
        );
      }
      const runtimePolicyScope = runtimePolicyScopeResolution.scope;
      if (
        !runtimePolicyScope ||
        alphabetizeStringify(runtimePolicyScope) !==
          alphabetizeStringify(b.sessionPolicy.runtimePolicyScope)
      ) {
        return json(
          {
            ok: false,
            code: 'scope_mismatch',
            message: 'Ed25519 Yao runtime policy scope does not match the active environment',
          },
          { status: 403 },
        );
      }
      const authorization =
        b.routeAuth.kind === 'passkey'
          ? await validatePasskeyEd25519SessionAuthorization({
              ctx,
              request: b,
              authority,
            })
          : await validateSignedEd25519SessionAuthorization({
              ctx,
              request: b,
              authority,
            });
      if (!authorization.ok) return authorization.response;

      const result = await ctx.service.walletRegistration.refreshEd25519YaoWalletSession({
        kind: 'router_ab_ed25519_yao_budget_refresh_v1',
        sessionPolicy: b.sessionPolicy,
        authorization: authorization.authorization,
      });
      const status = thresholdEd25519StatusCode(result);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status,
        ok: result.ok,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status });
    }
    default:
      return null;
  }
}
