import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceProvisioningCommandV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceSessionTransportRequestV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceApprovalDeliveryV1,
  parseLinkedDeviceEnrollmentReceiptV1,
  parseLinkedDeviceHolderDeliveryAcknowledgementV1,
  parseLinkedDeviceProvisioningCommandV1,
  parseLinkedDeviceProvisioningDeliveriesV1,
  parseLinkedDeviceReceiptAcknowledgementV1,
  parseLinkedDeviceSessionClaimRequestV1,
  parseLinkedDeviceSessionTransportRequestV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceApprovalV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking/parsers';
import { assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1 } from '@shared/device-linking/digests';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  parseLinkDeviceSessionId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256Bytes } from '@shared/utils/digests';
import type {
  LinkedDeviceSessionRecordV1,
  LinkedDeviceSessionState,
  LinkedDeviceSessionServiceResultV1,
  LinkedDeviceSessionServiceV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import {
  computeLinkedDevicePublicKeyDigestV1,
  LINKED_DEVICE_REQUEST_PROOF_HEADER_V1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  parseLinkedDeviceRequestProofV1,
  type LinkedDeviceRequestProofV1,
} from '../../../../core/deviceLinking/requestProof';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';

const DEVICE_LINKING_BASE = '/wallet/device-linking/v1/sessions';
export const DEVICE_LINKING_REQUEST_PROOF_HEADER_V1 = LINKED_DEVICE_REQUEST_PROOF_HEADER_V1;

export type DeviceLinkingAuthDeniedV1 = {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid' | 'replayed';
  readonly message: string;
};

export type DeviceLinkingAuthenticatedRequestV1 = {
  readonly kind: 'authorized';
  /** Owner verifier owns the request body read, keeping authentication first. */
  readonly body: unknown;
  /** Owner auth binds method/path/body and its authorization expiry. */
  readonly binding: DeviceLinkingRequestBindingV1;
};

export type DeviceLinkingRequestBindingV1 = {
  readonly kind: 'linked_device_owner_request_binding_v1';
  readonly method: 'GET' | 'POST';
  readonly pathname: string;
  readonly bodyDigestB64u: DigestB64u;
  readonly expiresAtMs: number;
};

export type DeviceLinkingOwnerRequestInputV1 = {
  readonly request: Request;
  readonly method: string;
  readonly pathname: string;
  /** SHA-256 of the exact request body bytes, computed before authentication. */
  readonly bodyDigestB64u: DigestB64u;
  readonly requestedAtMs: number;
};

/** Signed Device2 proof. The verifier must reject a nonce replay durably. */
export type DeviceLinkingRequestProofV1 = LinkedDeviceRequestProofV1;

export type DeviceLinkingDeviceAuthenticatedRequestV1 = {
  readonly kind: 'authorized';
  /** Device verifier owns the request body read, keeping authentication first. */
  readonly body: unknown;
  /** The verifier returns the exact proof it verified, including replay nonce. */
  readonly proof: DeviceLinkingRequestProofV1;
};

export type DeviceLinkingRouteMutationResultV1 =
  | { readonly outcome: 'applied' | 'replayed'; readonly record: LinkedDeviceSessionRecordV1 }
  | {
      readonly outcome: 'conflict';
      readonly expectedRevision: number;
      readonly actualRevision: number | null;
      readonly record: LinkedDeviceSessionRecordV1 | null;
    }
  | { readonly outcome: 'expired'; readonly record: LinkedDeviceSessionRecordV1 }
  | {
      readonly outcome: 'invalid_state';
      readonly state: LinkedDeviceSessionState['state'];
      readonly record: LinkedDeviceSessionRecordV1;
    }
  | { readonly outcome: 'invalid_input'; readonly message: string };

type LinkedDevicePendingSessionStateV1 = Extract<
  LinkedDeviceSessionState,
  {
    readonly state:
      | 'awaiting_target_passkey'
      | 'provisioning'
      | 'awaiting_aggregate_receipt'
      | 'committed_completion_required';
  }
>;

type LinkedDeviceApprovalRouteResultV1 =
  | {
      readonly outcome: 'pending';
      readonly state: LinkedDevicePendingSessionStateV1;
    }
  | {
      readonly outcome: 'active';
      readonly state: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
      readonly manifestDigestB64u: DigestB64u;
      readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    }
  | {
      readonly outcome: 'replayed';
      readonly replay:
        | {
            readonly state: 'pending';
            readonly session: LinkedDevicePendingSessionStateV1;
          }
        | {
            readonly state: 'active';
            readonly session: Extract<LinkedDeviceSessionState, { readonly state: 'active' }>;
            readonly manifestDigestB64u: DigestB64u;
            readonly receipt: LinkedDeviceEnrollmentReceiptV1;
          };
    };

export type DeviceLinkingProvisioningProviderV1 = {
  provisionLinkedDeviceV1(input: {
    readonly command: LinkedDeviceProvisioningCommandV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceProvisioningDeliveriesV1>;
  recordHolderDeliveriesV1(input: {
    readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceEnrollmentReceiptV1>;
};

export type DeviceLinkingProvisioningVerifierV1 = {
  verifyProvisioningDeliveriesV1(input: {
    readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
    readonly approval: LinkedDeviceApprovalV1;
  }): Promise<void>;
  verifyHolderDeliveriesV1(input: {
    readonly acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1;
    readonly approval: LinkedDeviceApprovalV1;
  }): Promise<void>;
};

export type DeviceLinkingTargetCredentialProviderV1 = {
  getTargetPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetPreparationV1>;
  registerTargetCredentialV1(input: {
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<DeviceLinkingRouteMutationResultV1>;
};

export type DeviceLinkingRouteServiceV1 = {
  readonly sessionService: Pick<
    LinkedDeviceSessionServiceV1,
    | 'createUnclaimedSessionV1'
    | 'claimSessionV1'
    | 'recordOwnerApprovalV1'
    | 'cancelSessionV1'
    | 'getSessionV1'
  >;
  readonly nowV1: () => number;
  verifyPublicSessionProofV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV4;
    readonly proof: DeviceLinkingRequestProofV1;
    readonly method: string;
    readonly canonicalPath: string;
    readonly bodyDigestB64u: DigestB64u;
    readonly devicePublicKeyDigestB64u: DigestB64u;
    readonly requestedAtMs: number;
  }): Promise<{ readonly kind: 'authorized' } | DeviceLinkingAuthDeniedV1>;
  authenticateOwnerRequestV1(
    input: DeviceLinkingOwnerRequestInputV1,
  ): Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1>;
  authenticateDeviceRequestV1(input: {
    readonly request: Request;
    readonly method: string;
    readonly pathname: string;
    readonly linkSessionId: string;
    /** SHA-256 of the exact request body bytes, computed before authentication. */
    readonly bodyDigestB64u: DigestB64u;
    readonly expectedDevicePublicKeyB64u: string;
    readonly expectedDevicePublicKeyDigestB64u: DigestB64u;
    readonly proof: DeviceLinkingRequestProofV1;
    readonly requestedAtMs: number;
  }): Promise<DeviceLinkingDeviceAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1>;
  readonly targetCredential: DeviceLinkingTargetCredentialProviderV1;
  acknowledgeReceiptV1(input: {
    readonly acknowledgement: LinkedDeviceReceiptAcknowledgementV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<DeviceLinkingRouteMutationResultV1>;
  retryCommittedDeliveryV1(input: {
    readonly request: Extract<
      LinkedDeviceSessionTransportRequestV1,
      { readonly kind: 'linked_device_session_retry_committed_delivery_request_v1' }
    >;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<DeviceLinkingRouteMutationResultV1>;
  readonly provisioning: DeviceLinkingProvisioningProviderV1;
  readonly provisioningVerifier: DeviceLinkingProvisioningVerifierV1;
};

type DeviceLinkingCreateRequestV1 = {
  readonly kind: 'linked_device_session_create_request_v1';
  readonly payload: QrLinkedDeviceSessionPayloadV4;
};

export async function handleDeviceLinking(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (!ctx.pathname.startsWith(`${DEVICE_LINKING_BASE}`)) return null;
  const service = ctx.service.deviceLinking;
  if (!service)
    return json(
      { ok: false, code: 'not_supported', message: 'Device linking is not configured' },
      { status: 501 },
    );
  const action = parseRoutePath(ctx.pathname);
  if (!action) return null;
  const nowMs = service.nowV1();
  try {
    if (action.kind === 'create') return await handleCreate(ctx, service, nowMs);
    if (action.kind === 'get') return await handleGet(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'claim')
      return await handleClaim(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'approval')
      return await handleApproval(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'provision')
      return await handleProvision(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'holder-receipts')
      return await handleHolderReceipts(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'target-preparation')
      return await handleTargetPreparation(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'credential')
      return await handleCredential(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'receipt')
      return await handleReceipt(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'retry')
      return await handleRetry(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'cancel')
      return await handleCancel(ctx, service, action.linkSessionId, nowMs);
    return null;
  } catch (error: unknown) {
    if (error instanceof DeviceLinkingInputError) return invalidInputResponse(error.message);
    return json({ ok: false, code: 'internal', message: errorMessage(error) }, { status: 500 });
  }
}

async function handleCreate(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  nowMs: number,
): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const rawBody = await readJson(ctx.request);
  const body = parseBoundary(() => parseCreateRequest(rawBody));
  const devicePublicKeyDigestB64u = await computeDevicePublicKeyDigestB64u(
    body.payload.devicePublicKeyB64u,
  );
  const requestProof = parseBoundary(() => parseRequestProofHeader(ctx.request));
  validateRequestProof(
    requestProof,
    ctx.method,
    ctx.pathname,
    body.payload.linkSessionId,
    bodyDigestB64u,
    devicePublicKeyDigestB64u,
    nowMs,
  );
  const verification = await service.verifyPublicSessionProofV1({
    payload: body.payload,
    proof: requestProof,
    method: ctx.method,
    canonicalPath: ctx.pathname,
    bodyDigestB64u,
    devicePublicKeyDigestB64u,
    requestedAtMs: nowMs,
  });
  if (verification.kind === 'denied') return authDeniedResponse(verification);
  const result = await service.sessionService.createUnclaimedSessionV1({
    payload: body.payload,
    nowMs,
  });
  return sessionResultResponse(result);
}

async function handleGet(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'GET') return methodNotAllowedResponse();
  return sessionProjectionResponse(authenticated.session, 'applied');
}

async function handleClaim(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const authentication = await authenticateOwner(
    service,
    ctx.request,
    ctx.method,
    ctx.pathname,
    bodyDigestB64u,
    nowMs,
  );
  if (authentication.kind === 'denied') return authDeniedResponse(authentication);
  validateOwnerRequestBinding(
    authentication.binding,
    ctx.method,
    ctx.pathname,
    bodyDigestB64u,
    nowMs,
  );
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const body = parseBoundary(() => parseClaimRequest(authentication.body));
  const linkSessionId = parseBoundary(() => parseSessionId(rawLinkSessionId));
  if (body.payload.linkSessionId !== linkSessionId)
    return invalidInputResponse('link session id does not match route');
  return claimResultResponse(
    await service.sessionService.claimSessionV1({ payload: body.payload, nowMs }),
  );
}

async function handleApproval(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  if (ctx.method === 'GET') {
    const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
    if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
    if (authenticated.kind === 'not_found') return notFoundResponse();
    const approval = authenticated.session.approvalTranscript?.value;
    if (!approval) return invalidStateResponse(authenticated.session);
    assertApprovalMatchesPersistedSession(authenticated.session, approval);
    return json(
      parseBoundary(() =>
        parseLinkedDeviceApprovalDeliveryV1({
          kind: 'linked_device_approval_delivery_v1',
          approval,
        }),
      ),
      { status: 200 },
    );
  }
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const authentication = await authenticateOwner(
    service,
    ctx.request,
    ctx.method,
    ctx.pathname,
    bodyDigestB64u,
    nowMs,
  );
  if (authentication.kind === 'denied') return authDeniedResponse(authentication);
  validateOwnerRequestBinding(
    authentication.binding,
    ctx.method,
    ctx.pathname,
    bodyDigestB64u,
    nowMs,
  );
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const approval = parseBoundary(() => parseLinkedDeviceApprovalV1(authentication.body));
  const linkSessionId = parseBoundary(() => parseSessionId(rawLinkSessionId));
  if (approval.linkSessionId !== linkSessionId)
    return invalidInputResponse('link session id does not match route');
  return approvalResultResponse(
    await service.sessionService.recordOwnerApprovalV1({ approval, nowMs }),
  );
}

async function handleProvision(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const command = parseBoundary(() => parseLinkedDeviceProvisioningCommandV1(authenticated.body));
  const session = authenticated.session;
  const approval = requireProvisioningApproval(session);
  assertProvisioningIdentityMatches({
    linkSessionId: command.linkSessionId,
    enrollmentId: command.enrollmentId,
    deviceId: command.deviceId,
    session,
    approval,
  });
  const provisioningResult = await service.provisioning.provisionLinkedDeviceV1({
    command,
    session,
    approval,
    requestedAtMs: nowMs,
  });
  const deliveries = parseBoundary(() =>
    parseLinkedDeviceProvisioningDeliveriesV1(provisioningResult),
  );
  assertProvisioningIdentityMatches({
    linkSessionId: deliveries.linkSessionId,
    enrollmentId: deliveries.enrollmentId,
    deviceId: deliveries.deviceId,
    session,
    approval,
  });
  await service.provisioningVerifier.verifyProvisioningDeliveriesV1({
    deliveries,
    approval,
  });
  return json(deliveries, { status: 200 });
}

async function handleHolderReceipts(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const acknowledgement = parseBoundary(() =>
    parseLinkedDeviceHolderDeliveryAcknowledgementV1(authenticated.body),
  );
  if (acknowledgement.acknowledgedAtMs > nowMs) {
    return invalidInputResponse('holder delivery acknowledgement is from the future');
  }
  const session = authenticated.session;
  const approval = requireHolderDeliveryApproval(session);
  assertProvisioningIdentityMatches({
    linkSessionId: acknowledgement.linkSessionId,
    enrollmentId: acknowledgement.enrollmentId,
    deviceId: acknowledgement.deviceId,
    session,
    approval,
  });
  await service.provisioningVerifier.verifyHolderDeliveriesV1({
    acknowledgement,
    approval,
  });
  const holderDeliveryResult = await service.provisioning.recordHolderDeliveriesV1({
    acknowledgement,
    session,
    approval,
    requestedAtMs: nowMs,
  });
  const receipt = parseBoundary(() => parseLinkedDeviceEnrollmentReceiptV1(holderDeliveryResult));
  assertAggregateReceiptMatchesSession(receipt, session, approval);
  return json(receipt, { status: 200 });
}

async function handleCredential(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const registration = parseBoundary(() =>
    parseLinkedDeviceTargetCredentialRegistrationV1(authenticated.body),
  );
  const linkSessionId = authenticated.linkSessionId;
  if (registration.linkSessionId !== linkSessionId)
    return invalidInputResponse('link session id does not match route');
  if (registration.registeredAtMs > nowMs)
    return invalidInputResponse('credential registration is from the future');
  const session = authenticated.session;
  if (
    session.state.state !== 'awaiting_target_passkey' ||
    session.state.walletId !== registration.walletId ||
    session.state.enrollmentId !== registration.enrollmentId ||
    session.claimTranscript?.value.deviceId !== registration.deviceId
  )
    return invalidInputResponse('target credential binding does not match session');
  const approval = requireProvisioningApproval(session);
  const rawPreparation = await awaitTargetPreparation(service, session, approval, nowMs);
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  assertTargetPreparationMatchesSession(preparation, session, approval, nowMs);
  await assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1({
    preparation,
    registration,
  });
  return mutationResultResponse(
    await service.targetCredential.registerTargetCredentialV1({
      registration,
      preparation,
      session,
      requestedAtMs: nowMs,
    }),
  );
}

async function handleTargetPreparation(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'GET') return methodNotAllowedResponse();
  const session = authenticated.session;
  const approval = requireProvisioningApproval(session);
  const rawPreparation = await awaitTargetPreparation(service, session, approval, nowMs);
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  assertTargetPreparationMatchesSession(preparation, session, approval, nowMs);
  return json(preparation, { status: 200 });
}

function awaitTargetPreparation(
  service: DeviceLinkingRouteServiceV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  requestedAtMs: number,
): Promise<LinkedDeviceTargetPreparationV1> {
  return service.targetCredential.getTargetPreparationV1({
    session,
    approval,
    requestedAtMs,
  });
}

function assertTargetPreparationMatchesSession(
  preparation: LinkedDeviceTargetPreparationV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  nowMs: number,
): void {
  if (
    session.state.state !== 'awaiting_target_passkey' ||
    preparation.linkSessionId !== session.linkSessionId ||
    preparation.linkSessionId !== approval.linkSessionId ||
    preparation.walletId !== approval.walletId ||
    preparation.enrollmentId !== approval.enrollmentId ||
    preparation.deviceId !== approval.deviceId ||
    preparation.orderedChildren.length !== approval.orderedKeyBindings.length ||
    preparation.expiresAtMs <= nowMs
  ) {
    throw new DeviceLinkingInputError(
      'target preparation does not match the approved linked-device session',
    );
  }
  for (let index = 0; index < preparation.orderedChildren.length; index += 1) {
    const child = preparation.orderedChildren[index];
    const approved = approval.orderedKeyBindings[index];
    if (
      !child ||
      !approved ||
      child.walletKeyId !== approved.walletKeyId ||
      child.keyFamily !== approved.keyFamily ||
      child.targetLaneId !== approved.targetLaneId ||
      child.targetLaneShareEpoch !== approved.targetLaneShareEpoch
    ) {
      throw new DeviceLinkingInputError(
        `target preparation child ${index} differs from its approved key binding`,
      );
    }
  }
}

async function handleReceipt(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const acknowledgement = parseBoundary(() =>
    parseLinkedDeviceReceiptAcknowledgementV1(authenticated.body),
  );
  const linkSessionId = authenticated.linkSessionId;
  if (acknowledgement.linkSessionId !== linkSessionId)
    return invalidInputResponse('link session id does not match route');
  if (acknowledgement.acknowledgedAtMs > nowMs)
    return invalidInputResponse('receipt acknowledgement is from the future');
  const session = authenticated.session;
  if (
    session.claimTranscript?.value.deviceId !== acknowledgement.deviceId ||
    !('enrollmentId' in session.state) ||
    session.state.enrollmentId !== acknowledgement.enrollmentId
  )
    return invalidInputResponse('receipt acknowledgement binding does not match session');
  return mutationResultResponse(
    await service.acknowledgeReceiptV1({ acknowledgement, session, requestedAtMs: nowMs }),
  );
}

async function handleRetry(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const request = parseBoundary(() => parseRetryRequest(authenticated.body));
  const linkSessionId = authenticated.linkSessionId;
  if (request.linkSessionId !== linkSessionId)
    return invalidInputResponse('link session id does not match route');
  if (request.requestedAtMs > nowMs)
    return invalidInputResponse('delivery retry request is from the future');
  const session = authenticated.session;
  if (
    session.state.state !== 'committed_completion_required' ||
    session.state.enrollmentId !== request.enrollmentId ||
    session.claimTranscript?.value.deviceId !== request.deviceId
  )
    return invalidInputResponse('delivery retry binding does not match session');
  return mutationResultResponse(
    await service.retryCommittedDeliveryV1({ request, session, requestedAtMs: nowMs }),
  );
}

async function handleCancel(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const request = parseBoundary(() =>
    parseLinkedDeviceSessionTransportRequestV1(authenticated.body),
  );
  const linkSessionId = authenticated.linkSessionId;
  if (
    request.kind !== 'linked_device_session_cancel_unclaimed_request_v1' &&
    request.kind !== 'linked_device_session_cancel_claimed_request_v1'
  )
    return invalidInputResponse('cancel request kind is invalid');
  if (request.requestedAtMs > nowMs)
    return invalidInputResponse('cancel request is from the future');
  if (request.linkSessionId !== linkSessionId)
    return invalidInputResponse('link session id does not match route');
  const session = authenticated.session;
  if (
    request.kind === 'linked_device_session_cancel_claimed_request_v1' &&
    (session.claimTranscript?.value.deviceId !== request.deviceId ||
      !('enrollmentId' in session.state) ||
      session.state.enrollmentId !== request.enrollmentId)
  )
    return invalidInputResponse('cancel binding does not match session');
  const result = await service.sessionService.cancelSessionV1({
    linkSessionId,
    expectedRevision: session.revision,
    nowMs,
  });
  return sessionResultResponse(result);
}

async function authenticateOwner(
  service: DeviceLinkingRouteServiceV1,
  request: Request,
  method: string,
  pathname: string,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
): Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1> {
  return service.authenticateOwnerRequestV1({
    request,
    method,
    pathname,
    bodyDigestB64u,
    requestedAtMs: nowMs,
  });
}

type DeviceLinkingDeviceAuthenticatedContextV1 =
  | {
      readonly kind: 'authorized';
      readonly body: unknown;
      readonly proof: DeviceLinkingRequestProofV1;
      readonly linkSessionId: LinkDeviceSessionId;
      readonly session: LinkedDeviceSessionRecordV1;
    }
  | DeviceLinkingAuthDeniedV1
  | { readonly kind: 'not_found' };

async function authenticateDeviceForSession(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<DeviceLinkingDeviceAuthenticatedContextV1> {
  const linkSessionId = parseBoundary(() => parseSessionId(rawLinkSessionId));
  // Resolve the persisted QR key before proof verification. The string form is
  // deliberately a raw read; expiry projection runs only after authentication.
  const rawSession = await service.sessionService.getSessionV1(linkSessionId);
  if (!rawSession) return { kind: 'not_found' };
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const devicePublicKeyDigestB64u = await computeDevicePublicKeyDigestB64u(
    rawSession.qrPayload.devicePublicKeyB64u,
  );
  const requestProof = parseBoundary(() => parseRequestProofHeader(ctx.request));
  validateRequestProof(
    requestProof,
    ctx.method,
    ctx.pathname,
    linkSessionId,
    bodyDigestB64u,
    devicePublicKeyDigestB64u,
    nowMs,
  );
  const authentication = await service.authenticateDeviceRequestV1({
    request: ctx.request,
    method: ctx.method,
    pathname: ctx.pathname,
    linkSessionId: String(linkSessionId),
    bodyDigestB64u,
    expectedDevicePublicKeyB64u: rawSession.qrPayload.devicePublicKeyB64u,
    expectedDevicePublicKeyDigestB64u: devicePublicKeyDigestB64u,
    proof: requestProof,
    requestedAtMs: nowMs,
  });
  if (authentication.kind === 'denied') return authentication;
  validateRequestProof(
    authentication.proof,
    ctx.method,
    ctx.pathname,
    linkSessionId,
    bodyDigestB64u,
    devicePublicKeyDigestB64u,
    nowMs,
  );
  const session = await service.sessionService.getSessionV1({ linkSessionId, nowMs });
  if (!session) return { kind: 'not_found' };
  return {
    kind: 'authorized',
    body: authentication.body,
    proof: authentication.proof,
    linkSessionId,
    session,
  };
}

function parseRoutePath(pathname: string):
  | { readonly kind: 'create' }
  | { readonly kind: 'get'; readonly linkSessionId: string }
  | {
      readonly kind:
        | 'claim'
        | 'approval'
        | 'target-preparation'
        | 'provision'
        | 'holder-receipts'
        | 'credential'
        | 'receipt'
        | 'retry'
        | 'cancel';
      readonly linkSessionId: string;
    }
  | null {
  if (pathname === DEVICE_LINKING_BASE) return { kind: 'create' };
  const suffix = pathname.startsWith(`${DEVICE_LINKING_BASE}/`)
    ? pathname.slice(DEVICE_LINKING_BASE.length + 1)
    : '';
  if (!suffix) return null;
  const parts = suffix.split('/');
  if (parts.length === 1 && parts[0]) return { kind: 'get', linkSessionId: parts[0] };
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  if (
    parts[1] !== 'claim' &&
    parts[1] !== 'approval' &&
    parts[1] !== 'target-preparation' &&
    parts[1] !== 'provision' &&
    parts[1] !== 'holder-receipts' &&
    parts[1] !== 'credential' &&
    parts[1] !== 'receipt' &&
    parts[1] !== 'retry' &&
    parts[1] !== 'cancel'
  )
    return null;
  return { kind: parts[1], linkSessionId: parts[0] };
}

function requireProvisioningApproval(session: LinkedDeviceSessionRecordV1): LinkedDeviceApprovalV1 {
  const approval = session.approvalTranscript?.value;
  if (!approval || !isProvisioningSessionState(session.state)) {
    throw new DeviceLinkingInputError('linked-device session is not ready for provisioning');
  }
  assertApprovalMatchesPersistedSession(session, approval);
  return approval;
}

function requireHolderDeliveryApproval(
  session: LinkedDeviceSessionRecordV1,
): LinkedDeviceApprovalV1 {
  const approval = session.approvalTranscript?.value;
  if (
    !approval ||
    (!isProvisioningSessionState(session.state) && session.state.state !== 'active')
  ) {
    throw new DeviceLinkingInputError('linked-device session cannot accept holder receipts');
  }
  assertApprovalMatchesPersistedSession(session, approval);
  return approval;
}

function assertApprovalMatchesPersistedSession(
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): void {
  if (
    approval.linkSessionId !== session.linkSessionId ||
    approval.linkPublicKeyB64u !== session.qrPayload.linkPublicKeyB64u ||
    approval.devicePublicKeyB64u !== session.qrPayload.devicePublicKeyB64u ||
    approval.permission.kind !== session.qrPayload.requestedPermission.kind ||
    approval.permission.administrationScope !==
      session.qrPayload.requestedPermission.administrationScope ||
    approval.permission.localUserPresence !==
      session.qrPayload.requestedPermission.localUserPresence ||
    session.claimTranscript?.value.deviceId !== approval.deviceId ||
    !('walletId' in session.state) ||
    !('enrollmentId' in session.state) ||
    session.state.walletId !== approval.walletId ||
    session.state.enrollmentId !== approval.enrollmentId
  ) {
    throw new DeviceLinkingInputError('stored approval does not match linked-device session');
  }
}

function assertAggregateReceiptMatchesSession(
  receipt: LinkedDeviceEnrollmentReceiptV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): void {
  const expectedManifestDigest = manifestDigestFromSession(session);
  if (
    receipt.enrollmentId !== approval.enrollmentId ||
    receipt.walletId !== approval.walletId ||
    receipt.deviceId !== approval.deviceId ||
    receipt.orderedChildReceipts.length !== approval.orderedKeyBindings.length ||
    (expectedManifestDigest !== null && receipt.manifestDigestB64u !== expectedManifestDigest)
  ) {
    throw new DeviceLinkingInputError('aggregate receipt does not match approved enrollment');
  }
}

function manifestDigestFromSession(session: LinkedDeviceSessionRecordV1): string | null {
  switch (session.state.state) {
    case 'provisioning':
    case 'awaiting_aggregate_receipt':
      return session.state.keyManifestDigestB64u;
    case 'active':
      if (!session.aggregateReceipt) {
        throw new DeviceLinkingInputError('active linked-device session has no aggregate receipt');
      }
      return session.aggregateReceipt.manifestDigestB64u;
    case 'displaying_qr':
    case 'claimed_by_owner':
    case 'awaiting_target_passkey':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
    case 'committed_completion_required':
      return null;
    default:
      return assertNever(session.state);
  }
}

function isProvisioningSessionState(state: LinkedDeviceSessionState): boolean {
  return (
    state.state === 'awaiting_target_passkey' ||
    state.state === 'provisioning' ||
    state.state === 'awaiting_aggregate_receipt' ||
    state.state === 'committed_completion_required'
  );
}

function assertProvisioningIdentityMatches(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceApprovalV1['enrollmentId'];
  readonly deviceId: LinkedDeviceId;
  readonly session: LinkedDeviceSessionRecordV1;
  readonly approval: LinkedDeviceApprovalV1;
}): void {
  if (
    input.linkSessionId !== input.session.linkSessionId ||
    input.linkSessionId !== input.approval.linkSessionId ||
    input.enrollmentId !== input.approval.enrollmentId ||
    input.deviceId !== input.approval.deviceId ||
    input.session.claimTranscript?.value.deviceId !== input.deviceId
  ) {
    throw new DeviceLinkingInputError('provisioning identity does not match approved session');
  }
}

function parseCreateRequest(raw: unknown): DeviceLinkingCreateRequestV1 {
  const record = requireRecord(raw, 'device-linking create request');
  requireExactKeys(record, ['kind', 'payload']);
  if (record.kind !== 'linked_device_session_create_request_v1')
    throw new Error('device-linking create request kind is invalid');
  return {
    kind: 'linked_device_session_create_request_v1',
    payload: parseQrLinkedDeviceSessionPayloadV4(record.payload),
  };
}

function parseClaimRequest(raw: unknown) {
  return parseLinkedDeviceSessionClaimRequestV1(raw);
}

function parseRetryRequest(
  raw: unknown,
): Extract<
  LinkedDeviceSessionTransportRequestV1,
  { readonly kind: 'linked_device_session_retry_committed_delivery_request_v1' }
> {
  const request = parseLinkedDeviceSessionTransportRequestV1(raw);
  if (request.kind !== 'linked_device_session_retry_committed_delivery_request_v1')
    throw new Error('retry request kind is invalid');
  return request;
}

function parseSessionId(raw: string): LinkDeviceSessionId {
  let decoded = raw;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    throw new Error('link session id is invalid');
  }
  const parsed = parseLinkDeviceSessionId(decoded);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

type DeviceLinkingSessionProjectionV1 = {
  readonly kind: 'linked_device_session_projection_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly qrPayload: QrLinkedDeviceSessionPayloadV4;
  readonly revision: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
} & (
  | {
      readonly state: UnclaimedDeviceLinkingSessionRecordV1['state'];
      readonly deviceId?: never;
    }
  | {
      readonly state: ClaimedDeviceLinkingSessionRecordV1['state'];
      readonly deviceId: LinkedDeviceId;
    }
);

type UnclaimedDeviceLinkingSessionRecordV1 = Extract<
  LinkedDeviceSessionRecordV1,
  {
    readonly state: {
      readonly state: 'displaying_qr' | 'expired_unclaimed' | 'cancelled_unclaimed';
    };
  }
>;

type ClaimedDeviceLinkingSessionRecordV1 = Exclude<
  LinkedDeviceSessionRecordV1,
  UnclaimedDeviceLinkingSessionRecordV1
>;

function projectSession(record: LinkedDeviceSessionRecordV1): DeviceLinkingSessionProjectionV1 {
  const base = {
    kind: 'linked_device_session_projection_v1',
    linkSessionId: record.linkSessionId,
    qrPayload: record.qrPayload,
    revision: record.revision,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
  } as const;
  if (isUnclaimedSessionRecord(record)) {
    return { ...base, state: record.state };
  }
  return {
    ...base,
    state: record.state,
    deviceId: requireClaimedDeviceId(record),
  };
}

function isUnclaimedSessionRecord(
  record: LinkedDeviceSessionRecordV1,
): record is UnclaimedDeviceLinkingSessionRecordV1 {
  return (
    record.state.state === 'displaying_qr' ||
    record.state.state === 'expired_unclaimed' ||
    record.state.state === 'cancelled_unclaimed'
  );
}

function requireClaimedDeviceId(record: ClaimedDeviceLinkingSessionRecordV1): LinkedDeviceId {
  return record.claimTranscript.value.deviceId;
}

function sessionProjectionResponse(
  record: LinkedDeviceSessionRecordV1,
  outcome: 'applied' | 'replayed',
): Response {
  return json({ ok: true, outcome, session: projectSession(record) }, { status: 200 });
}

function claimResultResponse(result: LinkedDeviceSessionServiceResultV1): Response {
  switch (result.outcome) {
    case 'applied':
    case 'replayed': {
      const claim = claimFromRecord(result.record);
      if (!claim) return invalidStateResponse(result.record);
      return json(claim, { status: 200 });
    }
    default:
      return sessionResultResponse(result);
  }
}

function approvalResultResponse(result: LinkedDeviceSessionServiceResultV1): Response {
  switch (result.outcome) {
    case 'applied':
    case 'replayed': {
      const approval = approvalResultFromRecord(result.record, result.outcome);
      if (!approval) return invalidStateResponse(result.record);
      return json(approval, { status: 200 });
    }
    default:
      return sessionResultResponse(result);
  }
}

function claimFromRecord(record: LinkedDeviceSessionRecordV1): LinkedDeviceSessionClaimV1 | null {
  if (isUnclaimedSessionRecord(record)) return null;
  return record.claimTranscript.value;
}

function approvalResultFromRecord(
  record: LinkedDeviceSessionRecordV1,
  outcome: 'applied' | 'replayed',
): LinkedDeviceApprovalRouteResultV1 | null {
  if (record.state.state === 'active') {
    if (!record.aggregateReceipt) return null;
    const active = {
      state: record.state,
      manifestDigestB64u: record.aggregateReceipt.manifestDigestB64u,
      receipt: record.aggregateReceipt,
    } as const;
    return outcome === 'replayed'
      ? {
          outcome: 'replayed',
          replay: {
            state: 'active',
            session: active.state,
            manifestDigestB64u: active.manifestDigestB64u,
            receipt: active.receipt,
          },
        }
      : { outcome: 'active', ...active };
  }
  if (!isPendingSessionState(record.state)) return null;
  return outcome === 'replayed'
    ? { outcome: 'replayed', replay: { state: 'pending', session: record.state } }
    : { outcome: 'pending', state: record.state };
}

function isPendingSessionState(
  state: LinkedDeviceSessionState,
): state is LinkedDevicePendingSessionStateV1 {
  return (
    state.state === 'awaiting_target_passkey' ||
    state.state === 'provisioning' ||
    state.state === 'awaiting_aggregate_receipt' ||
    state.state === 'committed_completion_required'
  );
}

function invalidStateResponse(record: LinkedDeviceSessionRecordV1): Response {
  return json(
    {
      ok: false,
      outcome: 'invalid_state',
      state: record.state.state,
      session: projectSession(record),
    },
    { status: 409 },
  );
}

function sessionResultResponse(result: LinkedDeviceSessionServiceResultV1): Response {
  switch (result.outcome) {
    case 'applied':
    case 'replayed':
      return sessionProjectionResponse(result.record, result.outcome);
    case 'conflict':
      return json(
        {
          ok: false,
          outcome: result.outcome,
          expectedRevision: result.expectedRevision,
          actualRevision: result.actualRevision,
          session: result.record ? projectSession(result.record) : null,
        },
        { status: 409 },
      );
    case 'expired':
      return json(
        { ok: false, outcome: result.outcome, session: projectSession(result.record) },
        { status: 410 },
      );
    case 'invalid_state':
      return json(
        {
          ok: false,
          outcome: result.outcome,
          state: result.state,
          session: projectSession(result.record),
        },
        { status: 409 },
      );
    case 'unauthorized':
      return json(
        { ok: false, outcome: result.outcome, code: result.code, message: result.message },
        { status: 401 },
      );
    case 'invalid_input':
      return invalidInputResponse(result.message);
    default:
      return assertNever(result);
  }
}

function mutationResultResponse(result: DeviceLinkingRouteMutationResultV1): Response {
  switch (result.outcome) {
    case 'invalid_input':
      return invalidInputResponse(result.message);
    case 'applied':
    case 'replayed':
      return sessionProjectionResponse(result.record, result.outcome);
    case 'conflict':
      return json(
        {
          ok: false,
          outcome: result.outcome,
          expectedRevision: result.expectedRevision,
          actualRevision: result.actualRevision,
          session: result.record ? projectSession(result.record) : null,
        },
        { status: 409 },
      );
    case 'expired':
      return json(
        { ok: false, outcome: result.outcome, session: projectSession(result.record) },
        { status: 410 },
      );
    case 'invalid_state':
      return json(
        {
          ok: false,
          outcome: result.outcome,
          state: result.state,
          session: projectSession(result.record),
        },
        { status: 409 },
      );
    default:
      return assertNever(result);
  }
}

function authDeniedResponse(result: DeviceLinkingAuthDeniedV1): Response {
  return json(
    { ok: false, outcome: 'unauthorized', code: result.code, message: result.message },
    { status: result.code === 'expired' ? 410 : 401 },
  );
}

function invalidInputResponse(message: string): Response {
  return json(
    { ok: false, outcome: 'invalid_input', code: 'invalid_input', message },
    { status: 400 },
  );
}

function notFoundResponse(): Response {
  return json(
    { ok: false, code: 'not_found', message: 'Linked-device session not found' },
    { status: 404 },
  );
}

function methodNotAllowedResponse(): Response {
  return json(
    { ok: false, code: 'method_not_allowed', message: 'Method is not allowed' },
    { status: 405 },
  );
}

function parseB64u(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]+$/.test(raw))
    throw new Error(`${field} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(raw);
  } catch {
    throw new Error(`${field} is invalid`);
  }
  if (bytes.length === 0 || base64UrlEncode(bytes) !== raw)
    throw new Error(`${field} is not canonical base64url`);
  return raw;
}

function parseRequestProofHeader(request: Request): DeviceLinkingRequestProofV1 {
  const encoded = request.headers.get(DEVICE_LINKING_REQUEST_PROOF_HEADER_V1);
  if (!encoded) throw new Error(`missing ${DEVICE_LINKING_REQUEST_PROOF_HEADER_V1} header`);
  const bytes = parseB64uBytes(encoded, DEVICE_LINKING_REQUEST_PROOF_HEADER_V1);
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error('device-linking request proof is not valid JSON');
  }
  try {
    return parseLinkedDeviceRequestProofV1(raw);
  } catch (error: unknown) {
    throw new Error(errorMessage(error));
  }
}

function validateRequestProof(
  proof: DeviceLinkingRequestProofV1,
  method: string,
  pathname: string,
  linkSessionId: LinkDeviceSessionId,
  bodyDigestB64u: DigestB64u,
  devicePublicKeyDigestB64u: DigestB64u,
  nowMs: number,
): void {
  try {
    parseLinkedDeviceRequestProofV1(proof);
  } catch (error: unknown) {
    throw new DeviceLinkingInputError(errorMessage(error));
  }
  if (
    proof.method !== method ||
    proof.canonicalPath !== pathname ||
    proof.linkSessionId !== linkSessionId
  ) {
    throw new DeviceLinkingInputError('request proof does not match method, path, or session');
  }
  if (proof.bodyDigestB64u !== bodyDigestB64u) {
    throw new DeviceLinkingInputError('request body digest does not match authenticated bytes');
  }
  if (proof.devicePublicKeyDigestB64u !== devicePublicKeyDigestB64u) {
    throw new DeviceLinkingInputError('request proof device identity does not match QR session');
  }
  const issuedAtMs = proof.issuedAtMs;
  const expiresAtMs = proof.expiresAtMs;
  if (expiresAtMs <= nowMs || issuedAtMs > nowMs || expiresAtMs <= issuedAtMs) {
    throw new DeviceLinkingInputError('request proof is expired');
  }
  if (expiresAtMs - issuedAtMs > LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1) {
    throw new DeviceLinkingInputError('request proof lifetime exceeds the maximum');
  }
}

function validateOwnerRequestBinding(
  binding: DeviceLinkingRequestBindingV1,
  method: string,
  pathname: string,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
): void {
  if (binding.kind !== 'linked_device_owner_request_binding_v1') {
    throw new DeviceLinkingInputError('owner request binding kind is invalid');
  }
  if (binding.method !== method || binding.pathname !== pathname) {
    throw new DeviceLinkingInputError('owner request binding does not match method or path');
  }
  if (binding.bodyDigestB64u !== bodyDigestB64u) {
    throw new DeviceLinkingInputError(
      'owner request body digest does not match authenticated bytes',
    );
  }
  if (!Number.isSafeInteger(binding.expiresAtMs) || binding.expiresAtMs <= nowMs) {
    throw new DeviceLinkingInputError('owner request proof is expired');
  }
}

async function requestBodyDigest(request: Request): Promise<DigestB64u> {
  const bytes = new Uint8Array(await request.clone().arrayBuffer());
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(bytes)));
}

async function computeDevicePublicKeyDigestB64u(publicKeyB64u: string): Promise<DigestB64u> {
  try {
    return await computeLinkedDevicePublicKeyDigestV1(publicKeyB64u);
  } catch (error: unknown) {
    throw new DeviceLinkingInputError(errorMessage(error));
  }
}

function requireRecord(raw: unknown, field: string): Record<string, unknown> {
  if (!isRecord(raw)) throw new Error(`${field} must be an object`);
  return raw;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}

function parseB64uBytes(raw: unknown, field: string): Uint8Array {
  const value = parseB64u(raw, field);
  return base64UrlDecode(value);
}

function requireExactKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index]))
    throw new Error('record contains invalid fields');
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'invalid device-linking request');
}

function parseBoundary<T>(parse: () => T): T {
  try {
    return parse();
  } catch (error: unknown) {
    throw new DeviceLinkingInputError(errorMessage(error));
  }
}

class DeviceLinkingInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeviceLinkingInputError';
  }
}

function assertNever(value: never): never {
  throw new Error(`unsupported device-linking result: ${String(value)}`);
}
