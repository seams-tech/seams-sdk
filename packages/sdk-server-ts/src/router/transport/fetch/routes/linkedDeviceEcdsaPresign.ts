import { buildLinkedDevicePrincipalId } from '../../../../authorization/domain';
import type { AuthorizedOperation } from '../../../../authorization/domain';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json } from '../../../framework/http';
import {
  admitLinkedDeviceAuthorizedOperation,
  parseLinkedDeviceExecutionEnvelopeV1,
  parseLinkedDeviceWalletSessionForCurve,
  verifyLinkedDeviceLocalPresenceForOperation,
} from '../../../domains/signingOperations/linkedDeviceNormalSigning';
import {
  prepareLinkedDeviceWalletExecution,
  type LinkedDeviceExecutionAdmissionResolverV1,
} from '../../../domains/signingOperations/walletExecutionAdmission';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  type OperationDigestSet,
} from '@shared/authorization/operationFingerprint';
import {
  buildEvmEcdsaMpcOperationRef,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { mpcMaterialActivationRefsEqual, parseWalletId } from '@shared/utils/domainIds';
import {
  parseLinkedDeviceEcdsaNormalSigningScopeV1,
  type LinkedDeviceEcdsaNormalSigningScopeV1,
} from '@shared/signing-lanes/linkedEcdsaScope';
import {
  routerAbMpcMaterialActivationRefFromWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { RouterAbEcdsaPresignSessionProgress } from '../../../../core/ThresholdService/routerAb/ecdsaDerivationPresignBridge';

export const ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_INIT_PATH =
  '/router-ab/ecdsa-derivation/linked-device/presign/init' as const;
export const ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_STEP_PATH =
  '/router-ab/ecdsa-derivation/linked-device/presign/step' as const;

type LinkedPresignPhase = 'init' | 'step';

type LinkedEcdsaPresignRequest = {
  readonly scope: LinkedDeviceEcdsaNormalSigningScopeV1;
  readonly requestId: string;
  readonly operationId: ReturnType<typeof requireOperationId>;
  readonly capabilityId: ReturnType<typeof requireCapabilityId>;
  readonly authorizedOperationId: ReturnType<typeof requireAuthorizedOperationId>;
  readonly auditEventId: ReturnType<typeof requireAuditEventId>;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly materialActivationValue: ReturnType<typeof routerAbMpcMaterialActivationRefFromWire>;
  readonly expiresAtMs: number;
  readonly clientPresignatureId: string;
  readonly signingDigest: DigestB64u;
  readonly digests: OperationDigestSet;
  readonly requestBody: Record<string, unknown>;
};

type LinkedEcdsaPresignAuthenticated = Extract<
  Awaited<ReturnType<typeof parseLinkedDeviceWalletSessionForCurve>>,
  { readonly kind: 'linked_device'; readonly curve: 'ecdsa' }
>;

/**
 * Starts or advances the linked ECDSA presign protocol. Init is the only
 * branch that claims the reusable operation quota; steps read that claim and
 * forward the exact same operation identity to the private worker.
 */
export async function handleLinkedDeviceEcdsaPresign(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const phase =
    ctx.pathname === ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_INIT_PATH
      ? ('init' as const)
      : ctx.pathname === ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_STEP_PATH
        ? ('step' as const)
        : null;
  if (ctx.method !== 'POST' || !phase) return null;

  const authenticated = await parseLinkedDeviceWalletSessionForCurve({
    curve: 'ecdsa',
    session: ctx.opts.session,
    headers: Object.fromEntries(ctx.request.headers.entries()),
  });
  if (authenticated.kind !== 'linked_device' || authenticated.curve !== 'ecdsa') return null;

  const runtime = ctx.service.thresholdRuntime.getRouterAbEcdsaPresignRuntime();
  const linkedDeviceExecution = ctx.service.linkedDeviceExecution;
  const localPresenceVerifier = ctx.service.linkedDeviceLocalPresence;
  if (!runtime || !linkedDeviceExecution || !localPresenceVerifier) {
    return json(
      {
        ok: false,
        code: 'not_configured',
        message: 'Linked-device ECDSA presign is not configured',
      },
      { status: 501 },
    );
  }

  if (authenticated.claims.tenantId !== ctx.service.authorizedOperations.tenantId) {
    return json(
      { ok: false, code: 'wallet_session_mismatch', message: 'Linked-device tenant changed' },
      { status: 403 },
    );
  }

  try {
    const raw = await readJsonRecord(ctx.request);
    const operation = parseLinkedEcdsaPresignRequest(raw);
    const envelope = parseLinkedDeviceExecutionEnvelopeV1(raw.linkedDeviceExecution);
    assertLinkedPresignScopeMatches({
      claims: authenticated,
      envelope,
      scope: operation.scope,
      materialActivation: operation.materialActivationValue,
    });
    assertRequestLifetime({
      expiresAtMs: operation.expiresAtMs,
      walletSessionExpiresAtMs: authenticated.claims.expiresAtMs,
    });
    const localPresence = await verifyLinkedDeviceLocalPresenceForOperation({
      assertion: raw.localPresenceAssertion,
      verifier: localPresenceVerifier,
      authorizedOperationId: operation.authorizedOperationId,
      deviceId: authenticated.claims.deviceId,
      enrollmentId: authenticated.claims.enrollmentId,
      intentDigestB64u: operation.digests.intentDigest,
    });
    if (localPresence.kind === 'refused') {
      return json(
        {
          ok: false,
          code: 'local_presence_required',
          message: `Linked-device local presence was refused: ${localPresence.reason}`,
        },
        { status: 403 },
      );
    }

    const admissionInput = buildAdmissionInput({
      authenticated,
      operation,
      envelope,
      claimedAtMs: Date.now(),
      authorizedOperations: ctx.service.authorizedOperations,
    });
    let authorizedOperation: AuthorizedOperation;
    if (phase === 'init') {
      const admission = await admitLinkedDeviceAuthorizedOperation(admissionInput);
      switch (admission.kind) {
        case 'authorization_grant_rejected':
        case 'verified_step_up_rejected':
        case 'wallet_session_quota_exhausted':
        case 'material_mismatch':
          return json(
            {
              ok: false,
              code: 'linked_device_authorization_rejected',
              message: `Linked-device authorization was rejected: ${admission.kind}`,
            },
            { status: admission.kind === 'wallet_session_quota_exhausted' ? 409 : 403 },
          );
        case 'operation_in_progress':
          return json(
            {
              ok: false,
              code: 'operation_in_progress',
              message: 'Linked-device ECDSA presign operation is already in progress',
            },
            { status: 409 },
          );
        case 'replayed':
          return replayAuthorizedOperation(admission.operation);
        case 'claimed':
          authorizedOperation = admission.operation;
          break;
      }
    } else {
      const existing = await readClaimedOperation({
        ...admissionInput,
        authorizedOperations: ctx.service.authorizedOperations,
      });
      if (!existing) {
        return json(
          {
            ok: false,
            code: 'authorized_operation_missing',
            message: 'Linked-device ECDSA presign step requires a claimed init operation',
          },
          { status: 409 },
        );
      }
      authorizedOperation = existing;
      if (authorizedOperation.lifecycle === 'completed') {
        return replayAuthorizedOperation(authorizedOperation);
      }
    }

    const projection = await resolveLinkedProjection({
      authenticated,
      envelope,
      authorizedOperation,
      linkedDeviceExecution,
    });
    if (projection.kind === 'refused') {
      return json(
        {
          ok: false,
          code: 'wallet_execution_lane_refused',
          message: `Linked-device wallet execution lane admission failed: ${projection.reason}`,
        },
        { status: 403 },
      );
    }
    if (!projection.projection.ecdsaNormalSigningScope) {
      throw new Error('active linked execution projection is missing the ECDSA scope');
    }
    if (
      alphabetizeStringify(projection.projection.ecdsaNormalSigningScope) !==
      alphabetizeStringify(operation.scope)
    ) {
      throw new Error('active linked ECDSA scope changed after operation admission');
    }
    if (String(projection.projection.product.operationId) !== String(operation.scope.operationId)) {
      throw new Error('active linked ECDSA lane operation changed after operation admission');
    }
    const prepared = await prepareLinkedDeviceWalletExecution({
      authorizedOperation,
      evidence: {
        ...projection.projection,
        expectedMaterialActivation: operation.materialActivationValue,
      },
      localPresence: localPresence.evidence,
    });
    if (prepared.kind === 'refused') {
      return json(
        {
          ok: false,
          code: 'wallet_execution_lane_refused',
          message: `Linked-device wallet execution lane admission failed: ${prepared.reason}`,
        },
        { status: 403 },
      );
    }

    const runtimeResult =
      phase === 'init'
        ? await runtime.initializeLinkedDevicePresign({
            request: operation.requestBody,
            materialSource: projection.projection.materialSource,
            presignSessionId: requirePresignSessionId(raw.presign_session_id, phase),
            expiresAtMs: operation.expiresAtMs,
          })
        : await runtime.advanceLinkedDevicePresign({
            request: operation.requestBody,
            materialSource: projection.projection.materialSource,
            presignSessionId: requirePresignSessionId(raw.presign_session_id, phase),
            requestedStage: requireRequestedStage(raw.requested_stage),
            outgoingMessagesB64u: requireMessages(raw.outgoing_messages_b64u),
            expiresAtMs: operation.expiresAtMs,
          });
    if (!runtimeResult.ok) {
      await completeFailedPresignOperation(ctx, authorizedOperation, runtimeResult.message);
      return json(
        { ok: false, code: 'linked_presign_failed', message: runtimeResult.message },
        { status: 502 },
      );
    }
    return json(
      phase === 'init'
        ? linkedPresignInitResponse(runtimeResult.value, operation.expiresAtMs)
        : linkedPresignStepResponse(runtimeResult.value, operation),
      { status: 200 },
    );
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 400 },
    );
  }
}

function linkedPresignInitResponse(
  value: RouterAbEcdsaPresignSessionProgress,
  materialExpiresAtMs: number,
): Record<string, unknown> {
  if (value.kind === 'complete') {
    throw new Error('linked presign init completed before the holder supplied a presign step');
  }
  return {
    ok: true,
    presign_session_id: value.presignSessionId,
    material_expires_at_ms: materialExpiresAtMs,
    stage: value.stage,
    outgoing_messages_b64u: value.outgoingMessagesB64u,
  };
}

function linkedPresignStepResponse(
  value: RouterAbEcdsaPresignSessionProgress,
  operation: LinkedEcdsaPresignRequest,
): Record<string, unknown> {
  if (value.kind === 'complete') {
    if (value.linkedPrepareResponse) {
      assertLinkedPrepareResponse(value.linkedPrepareResponse, operation);
    }
    return {
      ok: true,
      presign_session_id: value.presignSessionId,
      stage: 'done',
      event: 'presign_done',
      outgoing_messages_b64u: [],
      server_presignature_id: value.serverPresignatureId,
      server_big_r33_b64u: value.serverBigR33B64u,
      ...(value.signingWorkerRerandomizationContribution32B64u
        ? {
            signing_worker_rerandomization_contribution32_b64u:
              value.signingWorkerRerandomizationContribution32B64u,
          }
        : {}),
      ...(value.linkedPrepareResponse ?? {}),
    };
  }
  return {
    ok: true,
    presign_session_id: value.presignSessionId,
    stage: value.stage,
    event: value.event,
    outgoing_messages_b64u: value.outgoingMessagesB64u,
  };
}

function assertLinkedPrepareResponse(
  response: Record<string, unknown>,
  operation: LinkedEcdsaPresignRequest,
): void {
  if (
    alphabetizeStringify(response.scope) !== alphabetizeStringify(operation.scope) ||
    response.request_id !== operation.requestId ||
    response.server_presignature_id !== operation.clientPresignatureId ||
    response.signature_scheme !== 'ecdsa_secp256k1_recoverable_v1' ||
    response.expires_at_ms !== operation.expiresAtMs
  ) {
    throw new Error('linked ECDSA presign completion does not match the admitted request');
  }
  const signingDigest = requirePublicDigestBytes(response.signing_digest, 'signing_digest');
  if (base64UrlEncode(signingDigest) !== operation.signingDigest) {
    throw new Error('linked ECDSA presign completion signing digest changed');
  }
  requirePublicDigestBytes(response.request_digest, 'request_digest');
  requireFixedBase64Url(response.server_big_r33_b64u, 'server_big_r33_b64u', 33);
  requireFixedBase64Url(
    response.signing_worker_rerandomization_contribution32_b64u,
    'signing_worker_rerandomization_contribution32_b64u',
    32,
  );
  const preparedAtMs = response.prepared_at_ms;
  if (
    typeof preparedAtMs !== 'number' ||
    !Number.isSafeInteger(preparedAtMs) ||
    preparedAtMs <= 0 ||
    preparedAtMs >= operation.expiresAtMs
  ) {
    throw new Error('linked ECDSA presign completion timestamp is invalid');
  }
}

function requirePublicDigestBytes(value: unknown, label: string): Uint8Array {
  const record = requireRecord(value, label);
  if (!Array.isArray(record.bytes) || record.bytes.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  const bytes = record.bytes.map((item) => {
    if (!Number.isInteger(item) || Number(item) < 0 || Number(item) > 255) {
      throw new Error(`${label} contains an invalid byte`);
    }
    return Number(item);
  });
  return Uint8Array.from(bytes);
}

function parseLinkedEcdsaPresignRequest(body: Record<string, unknown>): LinkedEcdsaPresignRequest {
  const scope = parseLinkedDeviceEcdsaNormalSigningScopeV1(body.scope);
  const requestId = requireText(body.request_id, 'request_id');
  const operationId = requireOperationId(body.operation_id);
  const operationDigests = requireRecord(body.operation_digests, 'operation_digests');
  const digests = {
    laneDigest: parseDigestB64u(requireText(operationDigests.lane_digest_b64u, 'lane_digest_b64u')),
    intentDigest: parseDigestB64u(
      requireText(operationDigests.intent_digest_b64u, 'intent_digest_b64u'),
    ),
    displayDigest: parseDigestB64u(
      requireText(operationDigests.display_digest_b64u, 'display_digest_b64u'),
    ),
  } satisfies OperationDigestSet;
  const materialActivation = requireMaterialActivation(body.material_activation);
  const materialActivationValue = routerAbMpcMaterialActivationRefFromWire(materialActivation);
  if (!mpcMaterialActivationRefsEqual(materialActivationValue, scope.materialActivation)) {
    throw new Error('linked ECDSA material activation does not match scope');
  }
  const signingDigest = parseDigestB64u(
    requireText(body.signing_digest_b64u, 'signing_digest_b64u'),
  );
  const commitment = requireFixedBase64Url(
    body.client_rerandomization_commitment32_b64u,
    'client_rerandomization_commitment32_b64u',
    32,
  );
  const clientPresignatureId = requireText(body.client_presignature_id, 'client_presignature_id');
  const expiresAtMs = requirePositiveMs(body.expires_at_ms, 'expires_at_ms');
  const authorization = requireRecord(body.authorization, 'authorization');
  if (authorization.kind !== 'reusable_wallet_session') {
    throw new Error('linked ECDSA presign requires reusable Wallet Session authorization');
  }
  if (String(scope.operationId) !== requireText(body.lane_operation_id, 'lane_operation_id')) {
    throw new Error('linked ECDSA scope lane operation does not match request');
  }
  const operation = buildEvmEcdsaMpcOperationRef('evm.sign_transaction');
  return {
    scope,
    requestId,
    operationId,
    capabilityId: requireCapabilityId(materialActivation.capability),
    authorizedOperationId: requireAuthorizedOperationId(
      `linked-ecdsa-authorized-operation:${requestId}`,
    ),
    auditEventId: requireAuditEventId(`linked-ecdsa-audit:${requestId}`),
    materialActivation,
    materialActivationValue,
    expiresAtMs,
    clientPresignatureId,
    signingDigest,
    digests,
    requestBody: stripGatewayBoundaryFields({
      ...body,
      client_rerandomization_commitment32_b64u: commitment,
    }),
  };
}

function buildAdmissionInput(input: {
  readonly authenticated: LinkedEcdsaPresignAuthenticated;
  readonly operation: LinkedEcdsaPresignRequest;
  readonly envelope: ReturnType<typeof parseLinkedDeviceExecutionEnvelopeV1>;
  readonly claimedAtMs: number;
  readonly authorizedOperations: FetchRouterApiContext['service']['authorizedOperations'];
}): Parameters<typeof admitLinkedDeviceAuthorizedOperation>[0] {
  return {
    authorizedOperations: input.authorizedOperations,
    tenantId: input.authenticated.claims.tenantId,
    principalId: buildLinkedDevicePrincipalId(input.authenticated.claims.deviceId),
    capabilityId: input.operation.capabilityId,
    operationId: input.operation.operationId,
    operation: buildEvmEcdsaMpcOperationRef('evm.sign_transaction'),
    digests: input.operation.digests,
    authorizedOperationId: input.operation.authorizedOperationId,
    auditEventId: input.operation.auditEventId,
    authorizationId: input.authenticated.claims.authorizationId,
    quotaId: input.authenticated.claims.quotaId,
    material: {
      kind: 'linked_device_lane',
      walletId: input.operation.scope.walletId,
      enrollmentId: input.authenticated.claims.enrollmentId,
      deviceId: input.authenticated.claims.deviceId,
      walletKeyId: input.envelope.walletKeyId,
      laneId: input.envelope.laneId,
      laneShareEpoch: input.envelope.laneShareEpoch,
      revocationEpoch: input.authenticated.claims.revocationEpoch,
      materialActivation: input.operation.materialActivation,
    },
    claimedAtMs: input.claimedAtMs,
  };
}

async function resolveLinkedProjection(input: {
  readonly authenticated: LinkedEcdsaPresignAuthenticated;
  readonly envelope: ReturnType<typeof parseLinkedDeviceExecutionEnvelopeV1>;
  readonly authorizedOperation: AuthorizedOperation;
  readonly linkedDeviceExecution: LinkedDeviceExecutionAdmissionResolverV1;
}): Promise<
  Awaited<
    ReturnType<LinkedDeviceExecutionAdmissionResolverV1['resolveActiveLinkedDeviceExecutionV1']>
  >
> {
  const authorization = input.authorizedOperation.authorization;
  if (
    authorization.kind !== 'authorization_grant' ||
    authorization.authorizationGrantRef.kind !== 'linked_device_wallet_session_authorization_v1'
  ) {
    return { kind: 'refused', reason: 'linked_execution_unavailable' };
  }
  return await input.linkedDeviceExecution.resolveActiveLinkedDeviceExecutionV1({
    tenantId: input.authenticated.claims.tenantId,
    walletSessionId: input.authenticated.claims.walletSessionId,
    quotaId: input.authenticated.claims.quotaId,
    walletId: requireWalletId(input.authenticated.claims.walletId),
    enrollmentId: input.authenticated.claims.enrollmentId,
    deviceId: input.authenticated.claims.deviceId,
    walletKeyId: input.envelope.walletKeyId,
    laneId: input.envelope.laneId,
    laneShareEpoch: input.envelope.laneShareEpoch,
    materialActivation: input.envelope.materialActivationValue,
    authorizationId: authorization.authorizationGrantRef.authorizationId,
    authorizedOperationId: input.authorizedOperation.authorizedOperationId,
  });
}

async function readClaimedOperation(input: {
  readonly authorizedOperations: Pick<
    FetchRouterApiContext['service']['authorizedOperations'],
    'readAuthorizedOperation'
  >;
  readonly tenantId: Parameters<typeof buildCapabilityOperationEnvelope>[0]['tenantId'];
  readonly principalId: Parameters<typeof buildCapabilityOperationEnvelope>[0]['principalId'];
  readonly capabilityId: ReturnType<typeof requireCapabilityId>;
  readonly operationId: ReturnType<typeof requireOperationId>;
  readonly operation: Parameters<typeof admitLinkedDeviceAuthorizedOperation>[0]['operation'];
  readonly digests: OperationDigestSet;
  readonly authorizedOperationId: ReturnType<typeof requireAuthorizedOperationId>;
  readonly auditEventId: ReturnType<typeof requireAuditEventId>;
  readonly authorizationId: string;
  readonly quotaId: string;
}): Promise<AuthorizedOperation | null> {
  const envelope = buildCapabilityOperationEnvelope({
    tenantId: input.tenantId,
    principalId: input.principalId,
    capabilityId: input.capabilityId,
    operationId: input.operationId,
    operation: input.operation,
    digests: input.digests,
  });
  const fingerprint = await computeCapabilityOperationFingerprintDigest(envelope);
  const existing = await input.authorizedOperations.readAuthorizedOperation({
    tenantId: input.tenantId,
    operationFingerprintDigest: fingerprint,
  });
  if (!existing) return null;
  if (
    existing.authorizedOperationId !== input.authorizedOperationId ||
    existing.auditEventId !== input.auditEventId ||
    existing.operationFingerprintDigest !== fingerprint ||
    existing.authorization.kind !== 'authorization_grant' ||
    existing.authorization.authorizationGrantRef.kind !==
      'linked_device_wallet_session_authorization_v1' ||
    existing.authorization.authorizationGrantRef.authorizationId !== input.authorizationId ||
    existing.quota.kind !== 'consume_reusable_wallet_session' ||
    existing.quota.quotaId !== input.quotaId
  ) {
    throw new Error('linked-device ECDSA presign operation changed after init');
  }
  return existing;
}

async function completeFailedPresignOperation(
  ctx: FetchRouterApiContext,
  operation: AuthorizedOperation,
  message: string,
): Promise<void> {
  if (operation.lifecycle !== 'claimed') return;
  await ctx.service.authorizedOperations.completeAuthorizedOperation({
    operation,
    result: 'failed_before_side_effect',
    response: {
      status: 502,
      contentType: 'application/json',
      bodyText: JSON.stringify({ ok: false, code: 'linked_presign_failed', message }),
    },
    completedAtMs: Date.now(),
  });
}

function assertLinkedPresignScopeMatches(input: {
  readonly claims: LinkedEcdsaPresignAuthenticated;
  readonly envelope: ReturnType<typeof parseLinkedDeviceExecutionEnvelopeV1>;
  readonly scope: LinkedDeviceEcdsaNormalSigningScopeV1;
  readonly materialActivation: ReturnType<typeof routerAbMpcMaterialActivationRefFromWire>;
}): void {
  const claims = input.claims.claims;
  if (
    input.scope.walletId !== claims.walletId ||
    input.scope.walletKeyId !== claims.walletKeyId ||
    String(input.scope.enrollmentId) !== String(claims.enrollmentId) ||
    input.envelope.walletId !== claims.walletId ||
    String(input.envelope.deviceId) !== String(claims.deviceId) ||
    String(input.envelope.enrollmentId) !== String(claims.enrollmentId) ||
    String(input.envelope.walletKeyId) !== String(claims.walletKeyId) ||
    !mpcMaterialActivationRefsEqual(
      input.materialActivation,
      input.envelope.materialActivationValue,
    )
  ) {
    throw new Error('linked-device ECDSA execution identity does not match the Wallet Session');
  }
}

function assertRequestLifetime(input: {
  readonly expiresAtMs: number;
  readonly walletSessionExpiresAtMs: number;
}): void {
  if (input.expiresAtMs <= Date.now() || input.expiresAtMs > input.walletSessionExpiresAtMs) {
    throw new Error('linked-device ECDSA presign request expiry is outside the Wallet Session');
  }
}

async function readJsonRecord(request: Request): Promise<Record<string, unknown>> {
  const value: unknown = await request.json();
  return requireRecord(value, 'request');
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function requireText(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
  return value.trim();
}

function requirePositiveMs(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0)
    throw new Error(`${label} must be a positive safe integer`);
  return value;
}

function requireFixedBase64Url(value: unknown, label: string, byteLength: number): string {
  const text = requireText(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new Error(`${label} must be base64url`);
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(text);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (decoded.length !== byteLength) throw new Error(`${label} must decode to ${byteLength} bytes`);
  return text;
}

function stripGatewayBoundaryFields(body: Record<string, unknown>): Record<string, unknown> {
  const {
    linkedDeviceExecution: _linkedDeviceExecution,
    localPresenceAssertion: _localPresenceAssertion,
    lane_operation_id: _laneOperationId,
    presign_session_id: _presignSessionId,
    requested_stage: _requestedStage,
    outgoing_messages_b64u: _outgoingMessages,
    ...request
  } = body;
  return request;
}

function requireMaterialActivation(value: unknown): RouterAbMpcMaterialActivationRefWire {
  const record = requireRecord(value, 'material_activation');
  const activationId = requireText(record.activation_id, 'material_activation.activation_id');
  const capability = requireText(record.capability, 'material_activation.capability');
  const materialOwner = requireText(record.material_owner, 'material_activation.material_owner');
  const keyBinding = requireText(record.key_binding, 'material_activation.key_binding');
  const lifecycleBinding = requireText(
    record.lifecycle_binding,
    'material_activation.lifecycle_binding',
  );
  const signingWorker = requireText(record.signing_worker, 'material_activation.signing_worker');
  return {
    kind: 'mpc_material_activation_ref',
    activation_id: activationId,
    capability,
    material_owner: materialOwner,
    key_binding: keyBinding,
    lifecycle_binding: lifecycleBinding,
    signing_worker: signingWorker,
  };
}

function requireOperationId(value: unknown) {
  const parsed = parseCapabilityOperationId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireWalletId(value: unknown) {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireCapabilityId(value: unknown) {
  const parsed = parseCapabilityId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireAuthorizedOperationId(value: unknown) {
  const parsed = parseAuthorizedOperationId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireAuditEventId(value: unknown) {
  const parsed = parseAuthorizationAuditEventId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requirePresignSessionId(value: unknown, phase: LinkedPresignPhase): string {
  if (phase === 'init' && value !== undefined) return requireText(value, 'presign_session_id');
  if (phase === 'step') return requireText(value, 'presign_session_id');
  return `linked-ecdsa-presign:${Date.now()}:${Math.random().toString(36).slice(2)}`;
}

function requireRequestedStage(value: unknown): 'triples' | 'presign' {
  if (value !== 'triples' && value !== 'presign')
    throw new Error('requested_stage must be triples or presign');
  return value;
}

function requireMessages(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error('outgoing_messages_b64u must be an array');
  return value.map((message) => requireText(message, 'outgoing_messages_b64u[]'));
}

function replayAuthorizedOperation(operation: AuthorizedOperation): Response {
  if (operation.lifecycle !== 'completed') {
    return json(
      { ok: false, code: 'operation_in_progress', message: 'Operation is already in progress' },
      { status: 409 },
    );
  }
  return json(operation.response.bodyText ? JSON.parse(operation.response.bodyText) : {}, {
    status: operation.response.status,
  });
}
