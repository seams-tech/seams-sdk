import {
  buildLinkedDevicePrincipalId,
} from '../../../../authorization/domain';
import type { AuthorizedOperation } from '../../../../authorization/domain';
import {
  authorizedOperationReplayBodyInit,
} from '../../../../authorization/domain';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json } from '../../../framework/http';
import {
  computeRouterAbEd25519NormalSigningAdmissionMaterial,
  parseRouterAbEd25519NormalSigningScopeV2,
  parseRouterAbOperationStepUpOperation,
} from '../../../domains/signingOperations/routerAbPrivateSigningWorker';
import {
  admitLinkedDeviceAuthorizedOperation,
  parseLinkedDeviceExecutionEnvelopeV1,
  parseLinkedDeviceWalletSessionForCurve,
  stripLinkedDeviceNormalSigningBoundaryFields,
  verifyLinkedDeviceLocalPresenceForOperation,
} from '../../../domains/signingOperations/linkedDeviceNormalSigning';
import {
  proxyLinkedDeviceLaneAdmittedNormalSigningRequest,
} from './normalSigningRouterProxy';
import {
  buildEvmEcdsaMpcOperationRef,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  mpcMaterialActivationRefsEqual,
  parseWalletId,
} from '@shared/utils/domainIds';
import { parseSigningOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import {
  routerAbMpcMaterialActivationRefFromWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  LinkedDeviceExecutionAdmissionResolverV1,
  LinkedDeviceLocalPresenceEvidenceV1,
} from '../../../domains/signingOperations/walletExecutionAdmission';

type LinkedNormalSigningPhase = 'prepare' | 'finalize';

/**
 * Handles the linked-device branch before the owner Wallet Session branch. A
 * null result means the JWT is an owner session (or no usable JWT) and lets
 * the existing route continue unchanged.
 */
export async function handleLinkedDeviceEd25519NormalSigning(
  input: {
    readonly ctx: FetchRouterApiContext;
    readonly body: Record<string, unknown>;
    readonly phase: LinkedNormalSigningPhase;
  },
): Promise<Response | null> {
  const authenticated = await parseLinkedDeviceWalletSessionForCurve({
    curve: 'ed25519',
    session: input.ctx.opts.session,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
  });
  if (authenticated.kind !== 'linked_device' || authenticated.curve !== 'ed25519') {
    return null;
  }
  return await handleLinkedDeviceNormalSigning({
    ...input,
    curve: 'ed25519',
    authenticated,
  });
}

export async function handleLinkedDeviceEcdsaNormalSigning(
  input: {
    readonly ctx: FetchRouterApiContext;
    readonly body: Record<string, unknown>;
    readonly phase: LinkedNormalSigningPhase;
  },
): Promise<Response | null> {
  const authenticated = await parseLinkedDeviceWalletSessionForCurve({
    curve: 'ecdsa',
    session: input.ctx.opts.session,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
  });
  if (authenticated.kind !== 'linked_device' || authenticated.curve !== 'ecdsa') {
    return null;
  }
  return await handleLinkedDeviceNormalSigning({
    ...input,
    curve: 'ecdsa',
    authenticated,
  });
}

type LinkedDeviceNormalSigningInput = {
  readonly ctx: FetchRouterApiContext;
  readonly body: Record<string, unknown>;
  readonly phase: LinkedNormalSigningPhase;
} & (
  | {
      readonly curve: 'ed25519';
      readonly authenticated: Extract<
        Awaited<ReturnType<typeof parseLinkedDeviceWalletSessionForCurve>>,
        { readonly kind: 'linked_device'; readonly curve: 'ed25519' }
      >;
    }
  | {
      readonly curve: 'ecdsa';
      readonly authenticated: Extract<
        Awaited<ReturnType<typeof parseLinkedDeviceWalletSessionForCurve>>,
        { readonly kind: 'linked_device'; readonly curve: 'ecdsa' }
      >;
    }
);

async function handleLinkedDeviceNormalSigning(
  input: LinkedDeviceNormalSigningInput,
): Promise<Response> {
  const linkedDeviceExecution = input.ctx.service.linkedDeviceExecution;
  const localPresenceVerifier = input.ctx.service.linkedDeviceLocalPresence;
  if (!linkedDeviceExecution || !localPresenceVerifier) {
    return json(
      {
        ok: false,
        code: 'not_configured',
        message: 'Linked-device normal-signing admission is not configured',
      },
      { status: 501 },
    );
  }

  try {
    const operation =
      input.curve === 'ed25519'
        ? await parseEd25519Operation(input.body, input.authenticated.claims)
        : parseEcdsaOperation(input.body, input.phase, input.authenticated.claims);
    const envelope = parseLinkedDeviceExecutionEnvelopeV1(input.body.linkedDeviceExecution);
    assertLinkedScopeMatches({
      curve: input.curve,
      claims: input.authenticated.claims,
      envelope,
      requestMaterialActivation: operation.materialActivation,
      body: input.body,
    });
    const localPresence = await verifyLinkedDeviceLocalPresenceForOperation({
      assertion: input.body.localPresenceAssertion,
      verifier: localPresenceVerifier,
      authorizedOperationId: operation.authorizedOperationId,
      deviceId: input.authenticated.claims.deviceId,
      enrollmentId: input.authenticated.claims.enrollmentId,
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

    const admission = await admitLinkedDeviceAuthorizedOperation({
      authorizedOperations: input.ctx.service.authorizedOperations,
      tenantId: input.authenticated.claims.tenantId,
      principalId: buildLinkedDevicePrincipalId(input.authenticated.claims.deviceId),
      capabilityId: operation.capabilityId,
      operationId: operation.operationId,
      operation: operation.operation,
      digests: operation.digests,
      authorizedOperationId: operation.authorizedOperationId,
      auditEventId: operation.auditEventId,
      authorizationId: input.authenticated.claims.authorizationId,
      quotaId: input.authenticated.claims.quotaId,
      material: {
        kind: 'linked_device_lane',
        walletId: operation.walletId,
        enrollmentId: input.authenticated.claims.enrollmentId,
        deviceId: input.authenticated.claims.deviceId,
        walletKeyId: envelope.walletKeyId,
        laneId: envelope.laneId,
        laneShareEpoch: envelope.laneShareEpoch,
        revocationEpoch: input.authenticated.claims.revocationEpoch,
        materialActivation: operation.materialActivation,
      },
      claimedAtMs: Date.now(),
    });
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
          { ok: false, code: 'operation_in_progress', message: 'Signing operation is already in progress' },
          { status: 409 },
        );
      case 'replayed':
        return replayAuthorizedOperation(admission.operation);
      case 'claimed':
        if (input.phase === 'finalize') {
          return json(
            { ok: false, code: 'authorized_operation_missing', message: 'Finalize requires a claimed prepare operation' },
            { status: 409 },
          );
        }
        return await executeLinkedDeviceSigning({
          ...input,
          operation: admission.operation,
          envelope,
          localPresence: localPresence.evidence,
          walletSessionId: input.authenticated.claims.walletSessionId,
          quotaId: input.authenticated.claims.quotaId,
          linkedDeviceExecution,
          body: stripLinkedDeviceNormalSigningBoundaryFields(input.body),
        });
    }
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

async function executeLinkedDeviceSigning(input: {
  readonly ctx: FetchRouterApiContext;
  readonly body: Record<string, unknown>;
  readonly phase: LinkedNormalSigningPhase;
  readonly curve: 'ed25519' | 'ecdsa';
  readonly operation: AuthorizedOperation;
  readonly envelope: ReturnType<typeof parseLinkedDeviceExecutionEnvelopeV1>;
  readonly localPresence: LinkedDeviceLocalPresenceEvidenceV1;
  readonly walletSessionId: Extract<
    Awaited<ReturnType<typeof parseLinkedDeviceWalletSessionForCurve>>,
    { readonly kind: 'linked_device' }
  >['claims']['walletSessionId'];
  readonly quotaId: Extract<
    Awaited<ReturnType<typeof parseLinkedDeviceWalletSessionForCurve>>,
    { readonly kind: 'linked_device' }
  >['claims']['quotaId'];
  readonly linkedDeviceExecution: LinkedDeviceExecutionAdmissionResolverV1;
}): Promise<Response> {
  const upstream = await proxyLinkedDeviceLaneAdmittedNormalSigningRequest({
    request: input.ctx.request,
    proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
    body: input.body,
    authorizedOperation: input.operation,
    walletId: input.envelope.walletId,
    enrollmentId: input.envelope.enrollmentId,
    deviceId: input.envelope.deviceId,
    walletKeyId: input.envelope.walletKeyId,
    laneId: input.envelope.laneId,
    laneShareEpoch: input.envelope.laneShareEpoch,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    expectedMaterialActivation: input.envelope.materialActivation,
    localPresence: input.localPresence,
    linkedDeviceExecution: input.linkedDeviceExecution,
  });
  if (input.phase === 'prepare' && upstream.ok) return upstream;
  const bodyText = await upstream.clone().text().catch(() => '');
  const completed = await input.ctx.service.authorizedOperations.completeAuthorizedOperation({
    operation: input.operation,
    result: upstream.ok
      ? 'succeeded'
      : upstream.status < 500
        ? 'failed_before_side_effect'
        : 'failed_after_side_effect',
    response: {
      status: upstream.status,
      contentType: upstream.headers.get('content-type') || 'application/json',
      bodyText,
    },
    completedAtMs: Date.now(),
  });
  if (completed.lifecycle !== 'completed') {
    throw new Error('linked signing operation did not complete');
  }
  return upstream;
}

async function parseEd25519Operation(
  body: Record<string, unknown>,
  claims: Extract<
    Awaited<ReturnType<typeof parseLinkedDeviceWalletSessionForCurve>>,
    { readonly kind: 'linked_device'; readonly curve: 'ed25519' }
  >['claims'],
): Promise<ParsedLinkedOperation> {
  const scope = parseRouterAbEd25519NormalSigningScopeV2(body.scope);
  if (scope.authorization.kind !== 'reusable_wallet_session') {
    throw new Error('linked-device Ed25519 signing requires reusable session authorization');
  }
  const material = await computeRouterAbEd25519NormalSigningAdmissionMaterial({
    intent: body.intent,
    signingPayload: body.signing_payload,
  });
  const operationResult = parseRouterAbOperationStepUpOperation(body.intent);
  if (!operationResult.ok) throw new Error(operationResult.message);
  const intent = requireRecord(body.intent, 'intent');
  const laneDigest = parseSigningOperationFingerprintDigest(intent.operation_fingerprint);
  const displayDigest = parseEd25519Digest(body.display_digest, 'display_digest');
  const operationId = operationResult.operationId;
  return {
    walletId: requireWalletId(claims.walletId),
    operation: operationResult.operation,
    operationId,
    capabilityId: requireCapabilityId(scope.material_activation.capability),
    authorizedOperationId: requireAuthorizedOperationId(
      `linked-ed25519-authorized-operation:${scope.request_id}`,
    ),
    auditEventId: requireAuditEventId(`linked-ed25519-audit:${scope.request_id}`),
    materialActivation: scope.material_activation,
    digests: {
      laneDigest,
      intentDigest: digestBytes(material.intentDigest.bytes),
      displayDigest,
    },
  };
}

function parseEcdsaOperation(
  body: Record<string, unknown>,
  phase: LinkedNormalSigningPhase,
  claims: Extract<
    Awaited<ReturnType<typeof parseLinkedDeviceWalletSessionForCurve>>,
    { readonly kind: 'linked_device'; readonly curve: 'ecdsa' }
  >['claims'],
): ParsedLinkedOperation {
  const request =
    phase === 'prepare'
      ? parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(body)
      : parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(body);
  if (request.authorization.kind !== 'reusable_wallet_session') {
    throw new Error('linked-device ECDSA signing requires reusable session authorization');
  }
  return {
    walletId: requireWalletId(claims.walletId),
    operation: buildEvmEcdsaMpcOperationRef('evm.sign_transaction'),
    operationId: requireOperationId(request.operation_id),
    capabilityId: requireCapabilityId(request.material_activation.capability),
    authorizedOperationId: requireAuthorizedOperationId(
      `linked-ecdsa-authorized-operation:${request.request_id}`,
    ),
    auditEventId: requireAuditEventId(`linked-ecdsa-audit:${request.request_id}`),
    materialActivation: request.material_activation,
    digests: {
      laneDigest: parseDigestB64u(request.operation_digests.lane_digest_b64u),
      intentDigest: parseDigestB64u(request.operation_digests.intent_digest_b64u),
      displayDigest: parseDigestB64u(request.operation_digests.display_digest_b64u),
    },
  };
}

type ParsedLinkedOperation = {
  readonly walletId: ReturnType<typeof requireWalletId>;
  readonly operation: Parameters<typeof admitLinkedDeviceAuthorizedOperation>[0]['operation'];
  readonly operationId: ReturnType<typeof requireOperationId>;
  readonly capabilityId: ReturnType<typeof requireCapabilityId>;
  readonly authorizedOperationId: ReturnType<typeof requireAuthorizedOperationId>;
  readonly auditEventId: ReturnType<typeof requireAuditEventId>;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly digests: {
    readonly laneDigest: DigestB64u;
    readonly intentDigest: DigestB64u;
    readonly displayDigest: DigestB64u;
  };
};

function assertLinkedScopeMatches(input: {
  readonly curve: 'ed25519' | 'ecdsa';
  readonly claims: {
    readonly walletId: string;
    readonly walletSessionId: unknown;
    readonly deviceId: unknown;
    readonly enrollmentId: unknown;
    readonly walletKeyId: unknown;
  };
  readonly envelope: ReturnType<typeof parseLinkedDeviceExecutionEnvelopeV1>;
  readonly requestMaterialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly body: Record<string, unknown>;
}): void {
  const scope = requireRecord(input.body.scope, 'scope');
  const scopeMaterial = requireRecord(scope.material_activation, 'scope.material_activation');
  const scopeWallet = input.curve === 'ed25519' ? scope.account_id : scope.wallet_id;
  if (String(scopeWallet) !== input.claims.walletId) {
    throw new Error('linked-device signing wallet does not match the Wallet Session');
  }
  const requestMaterial = input.requestMaterialActivation;
  if (!mpcMaterialActivationRefsEqual(
    routerAbMpcMaterialActivationRefFromWire(requestMaterial),
    input.envelope.materialActivationValue,
  )) {
    throw new Error('linked-device execution material activation does not match signing scope');
  }
  if (
    String(input.envelope.walletId) !== input.claims.walletId ||
    String(input.envelope.deviceId) !== String(input.claims.deviceId) ||
    String(input.envelope.enrollmentId) !== String(input.claims.enrollmentId) ||
    String(input.envelope.walletKeyId) !== String(input.claims.walletKeyId)
  ) {
    throw new Error('linked-device execution envelope identity does not match the Wallet Session');
  }
  if (input.envelope.materialActivation.capability !== String(scopeMaterial.capability)) {
    throw new Error('linked-device execution capability does not match signing scope');
  }
}

function parseEd25519Digest(value: unknown, label: string): DigestB64u {
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
  return parseDigestB64u(base64UrlEncode(Uint8Array.from(bytes)));
}

function digestBytes(bytes: readonly number[]): DigestB64u {
  if (bytes.length !== 32) throw new Error('digest must contain exactly 32 bytes');
  return parseDigestB64u(base64UrlEncode(Uint8Array.from(bytes)));
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
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

function requireOperationId(value: unknown) {
  const parsed = parseCapabilityOperationId(value);
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

function replayAuthorizedOperation(operation: AuthorizedOperation): Response {
  if (operation.lifecycle !== 'completed') {
    return json(
      { ok: false, code: 'operation_in_progress', message: 'Signing operation is already in progress' },
      { status: 409 },
    );
  }
  return new Response(authorizedOperationReplayBodyInit(operation.response), {
    status: operation.response.status,
    headers: { 'content-type': operation.response.contentType },
  });
}
