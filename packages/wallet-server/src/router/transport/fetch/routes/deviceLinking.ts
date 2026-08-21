import type {
  LinkedDeviceLocalAccountProjectionV1,
  LinkedDeviceWebAuthnRegistrationV1,
} from '@shared/device-linking';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  LinkedDeviceEmailOtpVerificationGrantV1,
  LinkedDeviceEmailOtpVerificationResultV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceSessionClaimV1,
  LinkedDeviceProvisioningCommandV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceProvisioningDeliveriesSubmissionV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceSessionTransportRequestV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceTargetReadyR102InputV1,
  LinkedDeviceWalletSessionTokenV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/contracts';
import {
  buildLinkedDeviceWalletSessionDeliveryV1,
  parseLinkedDeviceApprovalDeliveryV1,
  parseLinkedDeviceEnrollmentReceiptV1,
  parseLinkedDeviceHolderDeliveryAcknowledgementV1,
  parseLinkedDeviceProvisioningCommandV1,
  parseLinkedDeviceProvisioningDeliveriesV1,
  parseLinkedDeviceProvisioningDeliveriesSubmissionV1,
  parseLinkedDeviceReceiptAcknowledgementV1,
  parseLinkedDeviceSessionClaimRequestV1,
  parseLinkedDeviceSessionTransportRequestV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceOwnerFinalizeRequestV1,
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceTargetReadyR102InputV1,
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceEmailOtpChallengeResultV1,
  parseLinkedDeviceEmailOtpChallengeResendRequestV1,
  parseLinkedDeviceEmailOtpChallengeStartRequestV1,
  parseLinkedDeviceEmailOtpChallengeVerifyRequestV1,
  parseLinkedDeviceEmailOtpVerificationResultV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import { assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1 } from '@shared/device-linking/digests';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  parseLinkDeviceSessionId,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletId } from '@shared/utils/domainIds';
import {
  parseLinkedDeviceEd25519ExportRootRecipientV1,
  parseLinkedDeviceEd25519ExportRootSubmissionV1,
} from '@shared/device-linking/ed25519ExportRoot';
import type {
  LinkedDeviceEd25519ExportRootPortV1,
  LinkedDeviceEd25519ExportRootWriteResultV1,
} from '../../../../core/deviceLinking/linkedDeviceEd25519ExportRoot';
import { alphabetizeStringify, sha256Bytes } from '@shared/utils/digests';
import {
  hasDelegatedWalletPermissionV1,
  sameDelegatedWalletAuthorityV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import type {
  LinkedDeviceSessionRecordV1,
  LinkedDeviceSessionState,
  LinkedDeviceSessionServiceResultV1,
  LinkedDeviceSessionServiceV1,
  LinkedOwnerEnrollmentCompletionRefusalV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LinkedDeviceOwnerAuthorizationContextV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { IssuedLinkedDeviceWalletSession } from '../../../../authorization/service';
import {
  computeLinkedDevicePublicKeyDigestV1,
  LINKED_DEVICE_REQUEST_PROOF_HEADER_V1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  parseLinkedDeviceRequestProofV1,
  type LinkedDeviceRequestProofV1,
} from '../../../../core/deviceLinking/requestProof';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { admitLinkedOwnerEnrollmentFinalizeV1 } from '../../../../core/deviceLinking/linkedOwnerEnrollmentAdmission';
import type { LinkedOwnerEnrollmentAdmissionV1 } from '../../../../core/deviceLinking/linkedOwnerEnrollmentAdmission';
import type { WalletAddAuthMethodFinalizeResponse } from '../../../../core/registrationContracts';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { json, readJson } from '../../../framework/http';
import type { SessionAdapter } from '../../../framework/routerApi';
import {
  signRouterAbEcdsaDerivationLinkedDeviceWalletSessionJwt,
  signRouterAbEd25519LinkedDeviceWalletSessionJwt,
  type RouterAbEd25519LinkedDeviceWalletSessionJwtSigningInput,
} from '../../../auth/commonRouterUtils';

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
  /** Verified owner Wallet Session context retained for claim/approval authorization. */
  readonly owner: LinkedDeviceOwnerAuthorizationContextV1;
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
    readonly state: 'awaiting_target_factor' | 'provisioning' | 'committed_completion_required';
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

export type DeviceLinkingOwnerSourceHandoffProviderV1 = {
  getTargetReadyV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetReadyR102InputV1 | null>;
  submitPreparedProvisioningDeliveriesV1(input: {
    readonly submission: LinkedDeviceProvisioningDeliveriesSubmissionV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceProvisioningDeliveriesSubmissionV1>;
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
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<
    | {
        readonly outcome: 'applied' | 'replayed';
        readonly keyManifestDigestB64u: DigestB64u;
      }
    | { readonly outcome: 'invalid_input'; readonly message: string }
  >;
};

/**
 * The Email OTP target-factor surface (Refactor 103 Phase 6.2). The server
 * resolves the destination from the approved base factor; Device 2 supplies
 * only the code it received and its worker's ephemeral recipient key. Every
 * response carries public challenge state or an opaque encrypted release —
 * never an OTP, factor secret, KEK, or raw holder share.
 */
export type DeviceLinkingEmailOtpTargetFactorProviderV1 = {
  startChallengeV1(
    input:
      | {
          readonly session: LinkedDeviceSessionRecordV1;
          readonly approval: LinkedDeviceApprovalV1;
          readonly preparation: LinkedDeviceTargetPreparationV1;
          readonly resend: false;
          readonly requestedAtMs: number;
        }
      | {
          readonly session: LinkedDeviceSessionRecordV1;
          readonly approval: LinkedDeviceApprovalV1;
          readonly preparation: LinkedDeviceTargetPreparationV1;
          readonly resend: true;
          readonly requestedAtMs: number;
        },
  ): Promise<
    | {
        readonly kind: 'sent';
        readonly challengeId: string;
        readonly maskedEmailHint: string;
        readonly expiresAtMs: number;
        readonly resendAvailableAtMs: number;
      }
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  >;
  verifyChallengeV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly challengeId: string;
    readonly otpCode: string;
    readonly requestedAtMs: number;
  }): Promise<
    | {
        readonly kind: 'verified';
        readonly grant: LinkedDeviceEmailOtpVerificationGrantV1;
        readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
      }
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  >;
};

export type DeviceLinkingRouteServiceV1 = {
  readonly sessionService: Pick<
    LinkedDeviceSessionServiceV1,
    | 'createUnclaimedSessionV1'
    | 'claimSessionV1'
    | 'recordOwnerApprovalV1'
    | 'recordTargetCredentialV1'
    | 'recordEmailOtpChallengeStateV1'
    | 'cancelSessionV1'
    | 'getSessionV1'
  > & {
    readonly listSessionsForWalletV1: LinkedDeviceSessionServiceV1['listSessionsForWalletV1'];
  };
  /** Optional only when the Email OTP target factor is intentionally disabled. */
  readonly emailOtpTargetFactor?: DeviceLinkingEmailOtpTargetFactorProviderV1;
  readonly nowV1: () => number;
  verifyPublicSessionProofV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV5;
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
  /**
   * The canonical add-auth-method finalizer, reached with a server-derived
   * linked-device admission. Same finalizer the owner route calls.
   *
   * The admission is passed rather than a whole command so the tenant stays the
   * implementation's own: the route never names a tenant it could get wrong.
   */
  finalizeLinkedOwnerEnrollmentV1(input: {
    readonly addAuthMethodCeremonyId: string;
    readonly webauthnRegistration: unknown;
    readonly admission: LinkedOwnerEnrollmentAdmissionV1;
    readonly linkSessionId: LinkDeviceSessionId;
    readonly expectedRevision: number;
    readonly nowMs: number;
  }): Promise<
    | {
        readonly outcome: 'finalized';
        readonly response: WalletAddAuthMethodFinalizeResponse;
        /**
         * Present only on success. Device 2 cannot discover these by unlocking —
         * unlock is fail-closed on the local records they build — so they travel
         * with the finalize that made the credential.
         */
        readonly localAccount?: LinkedDeviceLocalAccountProjectionV1;
      }
    | {
        readonly outcome: 'completion_refused';
        readonly completion: LinkedOwnerEnrollmentCompletionRefusalV1;
      }
  >;
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
  readWalletSessionAuthorizationV1(input: {
    readonly session: Extract<
      LinkedDeviceSessionRecordV1,
      {
        readonly state: {
          readonly state: 'committed_completion_required' | 'active';
        };
      }
    >;
    readonly requestedAtMs: number;
  }): Promise<
    | {
        readonly kind: 'active';
        readonly authorization: IssuedLinkedDeviceWalletSession;
      }
    | { readonly kind: 'unavailable' }
  >;
  renewWalletSessionAuthorizationV1(input: {
    readonly session: Extract<
      LinkedDeviceSessionRecordV1,
      { readonly state: { readonly state: 'active' } }
    >;
    readonly requestedAtMs: number;
    readonly localPresenceAssertion: unknown;
  }): Promise<
    | {
        readonly kind: 'active';
        readonly authorization: IssuedLinkedDeviceWalletSession;
      }
    | { readonly kind: 'unavailable' }
    | { readonly kind: 'local_presence_refused'; readonly reason: string }
  >;
  resolveNearAccountIdForEd25519WalletKeyV1(input: {
    readonly walletId: LinkedDeviceApprovalV1['walletId'];
    readonly walletKeyId: LinkedDeviceApprovalV1['orderedKeyBindings'][number]['walletKeyId'];
  }): Promise<string>;
  readonly provisioning: DeviceLinkingProvisioningProviderV1;
  readonly provisioningVerifier: DeviceLinkingProvisioningVerifierV1;
  /** Owner-authenticated R102 source handoff and Device2 refetch source. */
  readonly sourceHandoff: DeviceLinkingOwnerSourceHandoffProviderV1;
  readonly ed25519ExportRoot?: LinkedDeviceEd25519ExportRootPortV1;
};

type DeviceLinkingCreateRequestV1 = {
  readonly kind: 'linked_device_session_create_request_v1';
  readonly payload: QrLinkedDeviceSessionPayloadV5;
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
    if (action.kind === 'target-ready')
      return await handleTargetReady(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'prepared-deliveries')
      return await handlePreparedDeliveries(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'provision')
      return await handleProvision(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'holder-receipts')
      return await handleHolderReceipts(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'target-preparation')
      return await handleTargetPreparation(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'owner-finalize')
      return await handleOwnerFinalize(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'credential')
      return await handleCredential(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'email-otp-challenge')
      return await handleEmailOtpChallenge(ctx, service, action.linkSessionId, nowMs, {
        resend: false,
      });
    if (action.kind === 'email-otp-resend')
      return await handleEmailOtpChallenge(ctx, service, action.linkSessionId, nowMs, {
        resend: true,
      });
    if (action.kind === 'email-otp-verify')
      return await handleEmailOtpVerify(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'ed25519-export-root-recipient')
      return await handleEd25519ExportRootRecipient(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'ed25519-export-root')
      return await handleEd25519ExportRoot(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'receipt')
      return await handleReceipt(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'wallet-session')
      return await handleWalletSession(ctx, service, action.linkSessionId, nowMs);
    if (action.kind === 'wallet-session-renew')
      return await handleWalletSessionRenewal(ctx, service, action.linkSessionId, nowMs);
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
    await service.sessionService.claimSessionV1({
      payload: body.payload,
      nowMs,
      owner: authentication.owner,
    }),
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
    await service.sessionService.recordOwnerApprovalV1({
      approval,
      nowMs,
      owner: authentication.owner,
    }),
  );
}

async function handleTargetReady(
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
  const sourceHandoff = service.sourceHandoff;
  const linkSessionId = parseBoundary(() => parseSessionId(rawLinkSessionId));
  const session = await service.sessionService.getSessionV1({ linkSessionId, nowMs });
  if (!session) return notFoundResponse();
  const approval = requireProvisioningApproval(session);
  if (ctx.method !== 'GET') return methodNotAllowedResponse();
  const rawTargetReady = await sourceHandoff.getTargetReadyV1({
    session,
    approval,
    requestedAtMs: nowMs,
  });
  if (!rawTargetReady) {
    return json(
      { ok: false, code: 'not_ready', message: 'R102 target-ready input is not persisted' },
      { status: 404 },
    );
  }
  const targetReady = parseBoundary(() => parseLinkedDeviceTargetReadyR102InputV1(rawTargetReady));
  assertTargetReadySourceIdentity(targetReady, session, approval, nowMs);
  return json(targetReady, { status: 200 });
}

async function handlePreparedDeliveries(
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
  const sourceHandoff = service.sourceHandoff;
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const linkSessionId = parseBoundary(() => parseSessionId(rawLinkSessionId));
  const session = await service.sessionService.getSessionV1({ linkSessionId, nowMs });
  if (!session) return notFoundResponse();
  const approval = requireProvisioningApproval(session);
  const submission = parseBoundary(() =>
    parseLinkedDeviceProvisioningDeliveriesSubmissionV1(authentication.body),
  );
  if (submission.linkSessionId !== linkSessionId) {
    return invalidInputResponse('prepared deliveries link session id does not match route');
  }
  assertProvisioningIdentityMatches({
    linkSessionId: submission.linkSessionId,
    enrollmentId: submission.enrollmentId,
    deviceId: submission.deviceId,
    session,
    approval,
  });
  if (submission.walletId !== approval.walletId) {
    return invalidInputResponse('prepared deliveries wallet identity does not match approval');
  }
  const rawPersisted = await sourceHandoff.submitPreparedProvisioningDeliveriesV1({
    submission,
    session,
    approval,
    requestedAtMs: nowMs,
  });
  const persisted = parseBoundary(() =>
    parseLinkedDeviceProvisioningDeliveriesSubmissionV1(rawPersisted),
  );
  if (alphabetizeStringify(persisted) !== alphabetizeStringify(submission)) {
    throw new DeviceLinkingInputError(
      'persisted prepared deliveries differ from the authenticated submission',
    );
  }
  return json(persisted, { status: 200 });
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
    (session.state.state !== 'awaiting_target_factor' && session.state.state !== 'provisioning') ||
    session.state.walletId !== registration.walletId ||
    session.state.enrollmentId !== registration.enrollmentId ||
    session.claimTranscript?.value.deviceId !== registration.deviceId
  )
    return invalidInputResponse('target credential binding does not match session');
  // The immutable factor branch: a Passkey artifact against an Email OTP
  // session (and vice versa) fails here, before any credential or lane exists.
  if (registration.targetFactor.kind !== session.qrPayload.targetFactor.kind)
    return invalidInputResponse('target credential factor does not match session');
  const approval = requireProvisioningApproval(session);
  if (registration.targetFactor.kind !== approval.targetFactor.kind)
    return invalidInputResponse('target credential factor does not match approval');
  const rawPreparation = await awaitTargetPreparation(service, session, approval, nowMs);
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  assertTargetPreparationMatchesSession(preparation, session, approval, nowMs);
  await assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1({
    preparation,
    registration,
  });
  const registrationResult = await service.targetCredential.registerTargetCredentialV1({
    registration,
    preparation,
    session,
    approval,
    requestedAtMs: nowMs,
  });
  if (registrationResult.outcome === 'invalid_input') {
    return invalidInputResponse(registrationResult.message);
  }
  return mutationResultResponse(
    await service.sessionService.recordTargetCredentialV1({
      linkSessionId,
      expectedRevision: session.revision,
      keyManifestDigestB64u: registrationResult.keyManifestDigestB64u,
      nowMs,
    }),
  );
}

type DeviceLinkingEmailOtpSessionContextV1 = {
  readonly session: LinkedDeviceSessionRecordV1;
  readonly approval: LinkedDeviceApprovalV1;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly emailOtpChallenge: Extract<
    LinkedDeviceSessionState,
    {
      readonly state: 'awaiting_target_factor';
      readonly targetFactor: { readonly kind: 'email_otp' };
    }
  >['emailOtpChallenge'];
};

function requireSentEmailOtpChallengeV1(
  challenge: DeviceLinkingEmailOtpSessionContextV1['emailOtpChallenge'],
): Extract<DeviceLinkingEmailOtpSessionContextV1['emailOtpChallenge'], { readonly state: 'sent' }> {
  if (challenge.state !== 'sent') {
    throw new DeviceLinkingInputError('email OTP challenge has not been sent');
  }
  return challenge;
}

/**
 * Shared admission for the three Email OTP challenge routes: the session must
 * be an approved `email_otp` session still awaiting its target factor, and
 * the durable preparation must match it. Everything else — destination,
 * base factor, derived authority — is the provider's to resolve server-side.
 */
async function requireEmailOtpAwaitingSession(
  service: DeviceLinkingRouteServiceV1,
  session: LinkedDeviceSessionRecordV1,
  nowMs: number,
): Promise<DeviceLinkingEmailOtpSessionContextV1> {
  if (
    session.state.state !== 'awaiting_target_factor' ||
    session.state.targetFactor.kind !== 'email_otp' ||
    session.qrPayload.targetFactor.kind !== 'email_otp' ||
    !session.state.emailOtpChallenge
  ) {
    throw new DeviceLinkingInputError('link session is not awaiting an email OTP factor');
  }
  const approval = requireProvisioningApproval(session);
  if (approval.targetFactor.kind !== 'email_otp') {
    throw new DeviceLinkingInputError('approved target factor is not email OTP');
  }
  const rawPreparation = await awaitTargetPreparation(service, session, approval, nowMs);
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  assertTargetPreparationMatchesSession(preparation, session, approval, nowMs);
  if (preparation.targetFactor.kind !== 'email_otp') {
    throw new DeviceLinkingInputError('target preparation factor is not email OTP');
  }
  return { session, approval, preparation, emailOtpChallenge: session.state.emailOtpChallenge };
}

async function handleEmailOtpChallenge(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
  options: { readonly resend: boolean },
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const request = options.resend
    ? parseBoundary(() => parseLinkedDeviceEmailOtpChallengeResendRequestV1(authenticated.body))
    : parseBoundary(() => parseLinkedDeviceEmailOtpChallengeStartRequestV1(authenticated.body));
  if (request.linkSessionId !== authenticated.linkSessionId) {
    return invalidInputResponse('link session id does not match route');
  }
  const provider = service.emailOtpTargetFactor;
  if (!provider) {
    return json(
      { ok: false, code: 'not_supported', message: 'Email OTP linking is not configured' },
      { status: 501 },
    );
  }
  const context = await requireEmailOtpAwaitingSession(service, authenticated.session, nowMs);
  const current = context.emailOtpChallenge;
  if (request.kind === 'linked_device_email_otp_challenge_resend_request_v1') {
    if (current.state !== 'sent' || current.challengeId !== request.challengeId) {
      return invalidInputResponse('email OTP challenge does not match this session');
    }
    if (nowMs < current.resendAvailableAtMs) {
      return json(
        {
          ok: false,
          code: 'resend_unavailable',
          message: 'Email OTP resend is not yet available',
          resendAvailableAtMs: current.resendAvailableAtMs,
        },
        { status: 429 },
      );
    }
  }
  const started =
    request.kind === 'linked_device_email_otp_challenge_start_request_v1'
      ? await provider.startChallengeV1({
          session: context.session,
          approval: context.approval,
          preparation: context.preparation,
          resend: false,
          requestedAtMs: nowMs,
        })
      : await provider.startChallengeV1({
          session: context.session,
          approval: context.approval,
          preparation: context.preparation,
          resend: true,
          requestedAtMs: nowMs,
        });
  if (started.kind === 'refused') {
    return json({ ok: false, code: started.code, message: started.message }, { status: 403 });
  }
  const recorded = await service.sessionService.recordEmailOtpChallengeStateV1({
    linkSessionId: context.session.linkSessionId,
    expectedRevision: context.session.revision,
    challenge: {
      challengeId: started.challengeId,
      workerEphemeralPublicKey65B64u:
        request.kind === 'linked_device_email_otp_challenge_start_request_v1'
          ? request.workerEphemeralPublicKey65B64u
          : requireSentEmailOtpChallengeV1(current).workerEphemeralPublicKey65B64u,
      maskedEmailHint: started.maskedEmailHint,
      expiresAtMs: started.expiresAtMs,
      resendAvailableAtMs: started.resendAvailableAtMs,
    },
    nowMs,
  });
  if (recorded.outcome === 'unauthorized') {
    return json({ ok: false, code: recorded.code, message: recorded.message }, { status: 403 });
  }
  if (recorded.outcome !== 'applied' && recorded.outcome !== 'replayed') {
    return mutationResultResponse(recorded);
  }
  const response = parseBoundary(() =>
    parseLinkedDeviceEmailOtpChallengeResultV1({
      kind: 'linked_device_email_otp_challenge_result_v1',
      challengeId: started.challengeId,
      maskedEmailHint: started.maskedEmailHint,
      expiresAtMs: started.expiresAtMs,
      resendAvailableAtMs: started.resendAvailableAtMs,
    }),
  );
  return json(response, { status: 200 });
}

async function handleEmailOtpVerify(
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
    parseLinkedDeviceEmailOtpChallengeVerifyRequestV1(authenticated.body),
  );
  if (request.linkSessionId !== authenticated.linkSessionId) {
    return invalidInputResponse('link session id does not match route');
  }
  const provider = service.emailOtpTargetFactor;
  if (!provider) {
    return json(
      { ok: false, code: 'not_supported', message: 'Email OTP linking is not configured' },
      { status: 501 },
    );
  }
  const context = await requireEmailOtpAwaitingSession(service, authenticated.session, nowMs);
  const current = context.emailOtpChallenge;
  if (current.state !== 'sent' || current.challengeId !== request.challengeId) {
    return invalidInputResponse('email OTP challenge does not match this session');
  }
  if (nowMs >= current.expiresAtMs) {
    return json(
      { ok: false, code: 'challenge_expired', message: 'Email OTP challenge has expired' },
      { status: 410 },
    );
  }
  const verified = await provider.verifyChallengeV1({
    session: context.session,
    approval: context.approval,
    preparation: context.preparation,
    challengeId: request.challengeId,
    otpCode: request.otpCode,
    requestedAtMs: nowMs,
  });
  if (verified.kind === 'refused') {
    return json({ ok: false, code: verified.code, message: verified.message }, { status: 403 });
  }
  const response: LinkedDeviceEmailOtpVerificationResultV1 = parseBoundary(() =>
    parseLinkedDeviceEmailOtpVerificationResultV1({
      kind: 'linked_device_email_otp_verification_result_v1',
      verificationGrant: verified.grant,
      factorRelease: verified.factorRelease,
    }),
  );
  return json(response, { status: 200 });
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

/**
 * Device 2's canonical add-auth-method finalize.
 *
 * The finalize itself is the ordinary one — same verification, same atomic
 * write. What this route adds is the admission: the public add-auth-method
 * route is owner-authenticated and cannot speak for a linked device, so the
 * only way linked-device facts reach the finalizer is by being derived here,
 * from an authenticated link session and its persisted preparation.
 *
 * Replay is the server's, not the client's: a finalize that succeeded but whose
 * local persistence failed can be sent again and returns the same response.
 */
async function handleOwnerFinalize(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const request = parseBoundary(() => parseLinkedDeviceOwnerFinalizeRequestV1(authenticated.body));
  const session = authenticated.session;
  const approval = requireProvisioningApproval(session);
  const rawPreparation = await awaitTargetPreparation(service, session, approval, nowMs);
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  const admitted = admitLinkedOwnerEnrollmentFinalizeV1({
    session,
    preparation,
    addAuthMethodCeremonyId: request.addAuthMethodCeremonyId,
    requestedAtMs: nowMs,
  });
  if (!admitted.ok) {
    return json(
      {
        ok: false,
        code: 'unauthorized',
        message: `linked owner finalize refused: ${admitted.reason}`,
      },
      { status: 403 },
    );
  }
  // One call, one transaction. The credential and the session advance commit
  // together or neither does, so a cancel or an expiry racing this request can
  // no longer land between them and leave a terminal session holding a live
  // owner credential.
  const finalized = await service.finalizeLinkedOwnerEnrollmentV1({
    addAuthMethodCeremonyId: request.addAuthMethodCeremonyId,
    webauthnRegistration: linkedDeviceWebAuthnRegistrationCredentialV1(
      request.webauthnRegistration,
    ),
    admission: admitted.admission,
    linkSessionId: session.linkSessionId,
    expectedRevision: session.revision,
    nowMs,
  });
  switch (finalized.outcome) {
    case 'completion_refused':
      // Refused before the credential was created, so there is nothing
      // outstanding to reconcile.
      return linkedOwnerEnrollmentCompletionFailureResponse(finalized.completion);
    case 'finalized':
      return finalized.response.ok
        ? json(
            {
              ...finalized.response,
              ...(finalized.localAccount ? { localAccount: finalized.localAccount } : {}),
            },
            { status: 200 },
          )
        : json(finalized.response, { status: 400 });
    default:
      return assertNever(finalized);
  }
}

function linkedDeviceWebAuthnRegistrationCredentialV1(
  registration: LinkedDeviceWebAuthnRegistrationV1,
): Record<string, unknown> {
  return {
    id: registration.credentialIdB64u,
    rawId: registration.credentialIdB64u,
    type: 'public-key',
    ...(registration.authenticatorAttachment === null
      ? {}
      : { authenticatorAttachment: registration.authenticatorAttachment }),
    response: {
      clientDataJSON: registration.clientDataJsonB64u,
      attestationObject: registration.attestationObjectB64u,
      transports: [...registration.transports],
    },
    clientExtensionResults: {},
  };
}

function linkedOwnerEnrollmentCompletionFailureResponse(
  result: LinkedOwnerEnrollmentCompletionRefusalV1,
): Response {
  switch (result.outcome) {
    case 'conflict':
      return json(
        {
          ok: false,
          code: 'completion_conflict',
          message: 'linked owner enrollment finalized but session completion conflicted',
          outcome: result.outcome,
          expectedRevision: result.expectedRevision,
          actualRevision: result.actualRevision,
        },
        { status: 409 },
      );
    case 'expired':
      return json(
        {
          ok: false,
          code: 'completion_expired',
          message: 'linked owner enrollment finalized but the link session expired',
          outcome: result.outcome,
        },
        { status: 410 },
      );
    case 'invalid_state':
      return json(
        {
          ok: false,
          code: 'completion_invalid_state',
          message: 'linked owner enrollment finalized but the session cannot complete',
          outcome: result.outcome,
          state: result.state,
        },
        { status: 409 },
      );
    case 'invalid_input':
      return json(
        {
          ok: false,
          code: 'completion_invalid_input',
          message: result.message,
          outcome: result.outcome,
        },
        { status: 400 },
      );
    default:
      return assertNever(result);
  }
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
    (session.state.state !== 'awaiting_target_factor' && session.state.state !== 'provisioning') ||
    preparation.linkSessionId !== session.linkSessionId ||
    preparation.linkSessionId !== approval.linkSessionId ||
    preparation.walletId !== approval.walletId ||
    preparation.enrollmentId !== approval.enrollmentId ||
    preparation.deviceId !== approval.deviceId ||
    preparation.orderedChildren.length !== approval.orderedKeyBindings.length ||
    (session.state.state === 'awaiting_target_factor' && preparation.expiresAtMs <= nowMs)
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

/**
 * The recipient key Device 1 seals the Ed25519 Yao Client export root to.
 *
 * POST is Device 2 publishing it — device-authenticated, because only the
 * device holding the link identity key may say where its own seed should go.
 * GET is Device 1 reading it before sealing, and is owner-authenticated
 * against the claimed session for the same reason the approval route is.
 */
async function handleEd25519ExportRootRecipient(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const ed25519ExportRoot = service.ed25519ExportRoot;
  if (!ed25519ExportRoot) return exportRootUnsupportedResponse();
  if (ctx.method === 'GET') {
    const owner = await authenticateOwnerForSession(ctx, service, rawLinkSessionId, nowMs);
    if (owner.kind !== 'authorized') return ownerSessionAuthResponse(owner);
    const parentAuthorization = authorizeExportRootParentAuthorityV1(owner.permission);
    if (parentAuthorization.kind === 'denied') {
      return exportRootPermissionDeniedResponse(parentAuthorization.message);
    }
    const childAuthorization = authorizeExportRootChildAuthorityV1(owner.session);
    if (childAuthorization.kind === 'denied') {
      return exportRootPermissionDeniedResponse(childAuthorization.message);
    }
    const approval = childAuthorization.approval;
    const transfer = await ed25519ExportRoot.readTransferV1(owner.linkSessionId);
    if (!transfer) return new Response(null, { status: 204 });
    assertEd25519ExportRootWalletKeyIdV1(transfer.recipient.walletKeyId, approval);
    return json(transfer.recipient, { status: 200 });
  }
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  const childAuthorization = authorizeExportRootChildAuthorityV1(authenticated.session);
  if (childAuthorization.kind === 'denied') {
    return exportRootPermissionDeniedResponse(childAuthorization.message);
  }
  const approval = childAuthorization.approval;
  const recipient = parseBoundary(() =>
    parseLinkedDeviceEd25519ExportRootRecipientV1(authenticated.body),
  );
  if (recipient.linkSessionId !== String(authenticated.linkSessionId))
    return invalidInputResponse('link session id does not match route');
  if (recipient.registeredAtMs > nowMs)
    return invalidInputResponse('export-root recipient is from the future');
  const identity = requireClaimedExportRootIdentity(authenticated.session);
  if (
    !identity ||
    identity.walletId !== recipient.walletId ||
    identity.enrollmentId !== recipient.enrollmentId ||
    identity.deviceId !== recipient.deviceId
  ) {
    return invalidInputResponse('export-root recipient binding does not match session');
  }
  assertEd25519ExportRootWalletKeyIdV1(recipient.walletKeyId, approval);
  return exportRootWriteResponse(await ed25519ExportRoot.registerRecipientV1({ recipient }));
}

/**
 * The sealed package itself.
 *
 * POST is Device 1 submitting it — owner-authenticated, because only the
 * approving owner holds a seed to seal. GET is Device 2 collecting it, and is
 * device-authenticated. Neither direction carries a secret: the package is
 * ciphertext plus public routing facts, and the recipient private key never
 * leaves Device 2's custody module.
 */
async function handleEd25519ExportRoot(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const ed25519ExportRoot = service.ed25519ExportRoot;
  if (!ed25519ExportRoot) return exportRootUnsupportedResponse();
  if (ctx.method === 'GET') {
    const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
    if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
    if (authenticated.kind === 'not_found') return notFoundResponse();
    const childAuthorization = authorizeExportRootChildAuthorityV1(authenticated.session);
    if (childAuthorization.kind === 'denied') {
      return exportRootPermissionDeniedResponse(childAuthorization.message);
    }
    const approval = childAuthorization.approval;
    const transfer = await ed25519ExportRoot.readTransferV1(authenticated.linkSessionId);
    if (!transfer || transfer.state !== 'sealed') return new Response(null, { status: 204 });
    assertEd25519ExportRootWalletKeyIdV1(transfer.package.walletKeyId, approval);
    return json(transfer.package, { status: 200 });
  }
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const owner = await authenticateOwnerForSession(ctx, service, rawLinkSessionId, nowMs);
  if (owner.kind !== 'authorized') return ownerSessionAuthResponse(owner);
  const parentAuthorization = authorizeExportRootParentAuthorityV1(owner.permission);
  if (parentAuthorization.kind === 'denied') {
    return exportRootPermissionDeniedResponse(parentAuthorization.message);
  }
  const childAuthorization = authorizeExportRootChildAuthorityV1(owner.session);
  if (childAuthorization.kind === 'denied') {
    return exportRootPermissionDeniedResponse(childAuthorization.message);
  }
  const approval = childAuthorization.approval;
  const submission = parseBoundary(() =>
    parseLinkedDeviceEd25519ExportRootSubmissionV1(owner.body),
  );
  if (submission.linkSessionId !== String(owner.linkSessionId))
    return invalidInputResponse('link session id does not match route');
  if (submission.package.sealedAtMs > nowMs)
    return invalidInputResponse('export-root package is from the future');
  const identity = requireClaimedExportRootIdentity(owner.session);
  if (
    !identity ||
    identity.walletId !== submission.package.walletId ||
    identity.enrollmentId !== submission.package.enrollmentId ||
    identity.deviceId !== submission.package.deviceId
  ) {
    return invalidInputResponse('export-root package binding does not match session');
  }
  if (owner.walletId !== submission.package.walletId) {
    return invalidInputResponse('export-root package names another wallet');
  }
  assertEd25519ExportRootWalletKeyIdV1(submission.package.walletKeyId, approval);
  return exportRootWriteResponse(
    await ed25519ExportRoot.submitPackageV1({
      linkSessionId: owner.linkSessionId,
      package: submission.package,
    }),
  );
}

type DeviceLinkingOwnerSessionContextV1 =
  | {
      readonly kind: 'authorized';
      readonly body: unknown;
      readonly walletId: WalletId;
      readonly permission: LinkedDeviceOwnerAuthorizationContextV1['permission'];
      readonly linkSessionId: LinkDeviceSessionId;
      readonly session: LinkedDeviceSessionRecordV1;
    }
  | DeviceLinkingAuthDeniedV1
  | { readonly kind: 'not_found' };

async function authenticateOwnerForSession(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<DeviceLinkingOwnerSessionContextV1> {
  const linkSessionId = parseBoundary(() => parseSessionId(rawLinkSessionId));
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const authenticated = await authenticateOwner(
    service,
    ctx.request,
    ctx.method,
    ctx.pathname,
    bodyDigestB64u,
    nowMs,
  );
  if (authenticated.kind === 'denied') return authenticated;
  const session = await service.sessionService.getSessionV1({ linkSessionId, nowMs });
  if (!session) return { kind: 'not_found' };
  return {
    kind: 'authorized',
    body: authenticated.body,
    walletId: authenticated.owner.walletId,
    permission: authenticated.owner.permission,
    linkSessionId,
    session,
  };
}

function ownerSessionAuthResponse(
  context: Exclude<DeviceLinkingOwnerSessionContextV1, { readonly kind: 'authorized' }>,
): Response {
  return context.kind === 'denied' ? authDeniedResponse(context) : notFoundResponse();
}

function authorizeExportRootChildAuthorityV1(
  session: LinkedDeviceSessionRecordV1,
):
  | { readonly kind: 'authorized'; readonly approval: LinkedDeviceApprovalV1 }
  | { readonly kind: 'denied'; readonly message: string } {
  const approval = session.approvalTranscript?.value;
  if (!approval) {
    return { kind: 'denied', message: 'export-root relay requires an approved link session' };
  }
  assertApprovalMatchesPersistedSession(session, approval);
  if (!hasDelegatedWalletPermissionV1(approval.permission, 'export_keys')) {
    return { kind: 'denied', message: 'export-root relay requires export_keys permission' };
  }
  if (!approval.orderedKeyBindings.some((binding) => binding.keyFamily === 'ed25519')) {
    return { kind: 'denied', message: 'export-root relay requires an Ed25519 enrollment child' };
  }
  return { kind: 'authorized', approval };
}

function authorizeExportRootParentAuthorityV1(
  permission: DelegatedWalletAuthorityV1,
): { readonly kind: 'authorized' } | { readonly kind: 'denied'; readonly message: string } {
  if (!hasDelegatedWalletPermissionV1(permission, 'link_devices')) {
    return { kind: 'denied', message: 'export-root publication requires link_devices permission' };
  }
  return { kind: 'authorized' };
}

function exportRootPermissionDeniedResponse(message: string): Response {
  return json(
    { ok: false, outcome: 'unauthorized', code: 'unauthorized', message },
    { status: 403 },
  );
}

function assertEd25519ExportRootWalletKeyIdV1(
  walletKeyId: LinkedDeviceApprovalV1['orderedKeyBindings'][number]['walletKeyId'],
  approval: LinkedDeviceApprovalV1,
): void {
  if (
    !approval.orderedKeyBindings.some(
      (binding) => binding.keyFamily === 'ed25519' && binding.walletKeyId === walletKeyId,
    )
  ) {
    throw new DeviceLinkingInputError(
      'export-root package wallet key is not an approved Ed25519 enrollment child',
    );
  }
}

/**
 * The claim and the approval must already agree before a transfer identity is
 * usable; an unclaimed session has no wallet to seal for.
 */
function requireClaimedExportRootIdentity(session: LinkedDeviceSessionRecordV1): {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
} | null {
  const claim = session.claimTranscript?.value;
  if (!claim) return null;
  if (!('enrollmentId' in session.state) || session.state.enrollmentId !== claim.enrollmentId) {
    return null;
  }
  return {
    walletId: claim.walletId,
    enrollmentId: claim.enrollmentId,
    deviceId: claim.deviceId,
  };
}

function exportRootWriteResponse(result: LinkedDeviceEd25519ExportRootWriteResultV1): Response {
  switch (result.outcome) {
    case 'applied':
    case 'replayed':
      return json({ ok: true, outcome: result.outcome }, { status: 200 });
    case 'conflict':
      return json(
        { ok: false, code: result.reason, message: 'export-root relay conflict' },
        { status: 409 },
      );
  }
  result satisfies never;
  throw new Error('unsupported export-root relay write outcome');
}

function exportRootUnsupportedResponse(): Response {
  return json(
    {
      ok: false,
      code: 'not_supported',
      message: 'Linked-device Ed25519 export-root relay is not configured',
    },
    { status: 501 },
  );
}

async function handleWalletSession(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'GET') return methodNotAllowedResponse();
  if (!isWalletSessionEligibleLinkedDeviceSessionRecord(authenticated.session)) {
    return invalidStateResponse(authenticated.session);
  }
  const session = authenticated.session;
  const approval = session.approvalTranscript.value;
  assertApprovalMatchesPersistedSession(session, approval);
  const resolution = await service.readWalletSessionAuthorizationV1({
    session,
    requestedAtMs: nowMs,
  });
  if (resolution.kind === 'unavailable') {
    return json(
      {
        ok: false,
        code: 'authorization_unavailable',
        message: 'Linked-device Wallet Session authorization is unavailable',
      },
      { status: 409 },
    );
  }
  assertIssuedAuthorizationMatchesSession(resolution.authorization, session, nowMs);
  return await respondWithLinkedDeviceWalletSessionDelivery({
    ctx,
    service,
    session,
    approval,
    authorization: resolution.authorization,
    nowMs,
  });
}

async function handleWalletSessionRenewal(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const authenticated = await authenticateWalletSessionRenewal(
    ctx,
    service,
    rawLinkSessionId,
    nowMs,
  );
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (!isActiveLinkedDeviceSessionRecord(authenticated.session)) {
    return invalidStateResponse(authenticated.session);
  }
  const session = authenticated.session;
  const approval = session.approvalTranscript.value;
  assertApprovalMatchesPersistedSession(session, approval);
  const renewal = await service.renewWalletSessionAuthorizationV1({
    session,
    requestedAtMs: nowMs,
    localPresenceAssertion: authenticated.request.localPresenceAssertion,
  });
  if (renewal.kind === 'unavailable') {
    return json(
      {
        ok: false,
        code: 'authorization_unavailable',
        message: 'Linked-device Wallet Session authorization is unavailable',
      },
      { status: 409 },
    );
  }
  if (renewal.kind === 'local_presence_refused') {
    return json(
      { ok: false, code: 'local_presence_required', message: renewal.reason },
      { status: 403 },
    );
  }
  assertIssuedAuthorizationMatchesSession(
    renewal.authorization,
    session,
    renewal.authorization.authorization.issuedAtMs,
  );
  return await respondWithLinkedDeviceWalletSessionDelivery({
    ctx,
    service,
    session,
    approval,
    authorization: renewal.authorization,
    nowMs,
  });
}

type WalletSessionRenewalRequestV1 = {
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly localPresenceAssertion: unknown;
};

type WalletSessionRenewalAuthenticatedContextV1 =
  | {
      readonly kind: 'authorized';
      readonly request: WalletSessionRenewalRequestV1;
      readonly session: LinkedDeviceSessionRecordV1;
    }
  | DeviceLinkingAuthDeniedV1
  | { readonly kind: 'not_found' };

async function authenticateWalletSessionRenewal(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<WalletSessionRenewalAuthenticatedContextV1> {
  const linkSessionId = parseBoundary(() => parseSessionId(rawLinkSessionId));
  const session = await service.sessionService.getSessionV1({ linkSessionId, nowMs });
  if (!session) return { kind: 'not_found' };
  const rawBody = await readJson(ctx.request);
  const request = parseBoundary(() => parseWalletSessionRenewalRequest(rawBody));
  return { kind: 'authorized', request, session };
}

async function respondWithLinkedDeviceWalletSessionDelivery(input: {
  readonly ctx: FetchRouterApiContext;
  readonly service: DeviceLinkingRouteServiceV1;
  readonly session: WalletSessionEligibleLinkedDeviceSessionRecordV1;
  readonly approval: LinkedDeviceApprovalV1;
  readonly authorization: IssuedLinkedDeviceWalletSession;
  readonly nowMs: number;
}): Promise<Response> {
  const signed = await signLinkedDeviceWalletSessionTokens({
    sessionAdapter: input.ctx.opts.session,
    authorization: input.authorization,
    approval: input.approval,
  });
  if (signed.kind === 'failed') {
    return json(
      { ok: false, code: signed.code, message: signed.message },
      { status: signed.status },
    );
  }
  const authorization = input.authorization.authorization;
  let ed25519Token: Extract<LinkedDeviceWalletSessionTokenV1, { keyFamily: 'ed25519' }> | null =
    null;
  for (const token of signed.orderedTokens) {
    if (token.keyFamily === 'ed25519') ed25519Token = token;
  }
  const nearAccountId = ed25519Token
    ? await input.service.resolveNearAccountIdForEd25519WalletKeyV1({
        walletId: authorization.walletId,
        walletKeyId: ed25519Token.walletKeyId,
      })
    : null;
  return json(
    buildLinkedDeviceWalletSessionDeliveryV1({
      kind: 'linked_device_wallet_session_delivery_v1',
      tenantId: authorization.tenantId,
      walletId: authorization.walletId,
      enrollmentId: authorization.enrollmentId,
      deviceId: authorization.deviceId,
      authorizationId: authorization.authorizationGrantRef.authorizationId,
      walletSessionId: authorization.walletSessionId,
      quotaId: authorization.quotaId,
      keyManifestDigestB64u: authorization.keyManifestDigestB64u,
      permission: authorization.permission,
      revocationEpoch: authorization.revocationEpoch,
      remainingUses: input.authorization.quota.remainingUses,
      issuedAtMs: authorization.issuedAtMs,
      expiresAtMs: authorization.expiresAtMs,
      ...(nearAccountId ? { nearAccountId } : {}),
      orderedTokens: signed.orderedTokens,
    }),
    { status: 200 },
  );
}

function isActiveLinkedDeviceSessionRecord(
  session: LinkedDeviceSessionRecordV1,
): session is Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'active' } }
> {
  return session.state.state === 'active';
}

type CommittedLinkedDeviceSessionRecordV1 = Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'committed_completion_required' } }
>;

type ActiveLinkedDeviceSessionRecordV1 = Extract<
  LinkedDeviceSessionRecordV1,
  { readonly state: { readonly state: 'active' } }
>;

type WalletSessionEligibleLinkedDeviceSessionRecordV1 =
  | CommittedLinkedDeviceSessionRecordV1
  | ActiveLinkedDeviceSessionRecordV1;

function isWalletSessionEligibleLinkedDeviceSessionRecord(
  session: LinkedDeviceSessionRecordV1,
): session is WalletSessionEligibleLinkedDeviceSessionRecordV1 {
  return session.state.state === 'committed_completion_required' || session.state.state === 'active';
}

type LinkedDeviceWalletSessionTokenSigningResultV1 =
  | {
      readonly kind: 'signed';
      readonly orderedTokens: readonly [
        LinkedDeviceWalletSessionTokenV1,
        ...LinkedDeviceWalletSessionTokenV1[],
      ];
    }
  | {
      readonly kind: 'failed';
      readonly status: 400 | 500;
      readonly code: 'sessions_disabled' | 'invalid_body' | 'internal';
      readonly message: string;
    };

async function signLinkedDeviceWalletSessionTokens(input: {
  readonly sessionAdapter: SessionAdapter | null | undefined;
  readonly authorization: IssuedLinkedDeviceWalletSession;
  readonly approval: LinkedDeviceApprovalV1;
}): Promise<LinkedDeviceWalletSessionTokenSigningResultV1> {
  const authorization = input.authorization.authorization;
  const sessionInfoBase = {
    sessionKind: 'jwt' as const,
    authorizationKind: 'linked_device_wallet_session' as const,
    walletId: authorization.walletId,
    tenantId: authorization.tenantId,
    deviceId: authorization.deviceId,
    enrollmentId: authorization.enrollmentId,
    keyManifestDigestB64u: authorization.keyManifestDigestB64u,
    revocationEpoch: authorization.revocationEpoch,
    permission: authorization.permission,
    issuedAtMs: authorization.issuedAtMs,
    authorizationId: authorization.authorizationGrantRef.authorizationId,
    walletSessionId: authorization.walletSessionId,
    quotaId: authorization.quotaId,
    expiresAtMs: authorization.expiresAtMs,
  };
  const orderedTokens: LinkedDeviceWalletSessionTokenV1[] = [];
  for (const binding of input.approval.orderedKeyBindings) {
    const signingInput = {
      session: input.sessionAdapter,
      userId: authorization.walletId,
      sessionInfo: {
        ...sessionInfoBase,
        walletKeyId: binding.walletKeyId,
        // JWT admission is lane-scoped. The authorization record's epoch is
        // the enrollment fence and may be higher than this child epoch.
        revocationEpoch: binding.sourceRevocationEpoch,
      },
      requireJwtErrorMessage: 'Linked-device Wallet Session JWT is required',
      invalidPayloadErrorMessage: 'Linked-device Wallet Session claims are invalid',
      sessionsDisabledMessage: 'Linked-device Wallet Session signing is unavailable',
    };
    const signed = await signLinkedDeviceWalletSessionTokenForFamily(
      binding.keyFamily,
      signingInput,
    );
    if (!signed.ok) {
      return {
        kind: 'failed',
        status: signed.status,
        code: signed.code,
        message: signed.message,
      };
    }
    if (signed.authorizationKind !== 'linked_device_wallet_session') {
      throw new Error('linked-device Wallet Session signer returned owner claims');
    }
    orderedTokens.push({
      kind: 'linked_device_wallet_session_token_v1',
      walletKeyId: binding.walletKeyId,
      keyFamily: binding.keyFamily,
      walletSessionJwt: signed.jwt,
      revocationEpoch: binding.sourceRevocationEpoch,
    });
  }
  const [first, ...remaining] = orderedTokens;
  if (!first) throw new Error('linked-device approval has no Wallet Session key binding');
  return { kind: 'signed', orderedTokens: [first, ...remaining] };
}

async function signLinkedDeviceWalletSessionTokenForFamily(
  keyFamily: LinkedDeviceApprovalV1['orderedKeyBindings'][number]['keyFamily'],
  input: RouterAbEd25519LinkedDeviceWalletSessionJwtSigningInput,
) {
  switch (keyFamily) {
    case 'ed25519':
      return await signRouterAbEd25519LinkedDeviceWalletSessionJwt(input);
    case 'ecdsa_secp256k1':
      return await signRouterAbEcdsaDerivationLinkedDeviceWalletSessionJwt(input);
    default:
      return assertNever(keyFamily);
  }
}

function assertIssuedAuthorizationMatchesSession(
  issued: IssuedLinkedDeviceWalletSession,
  session: WalletSessionEligibleLinkedDeviceSessionRecordV1,
  nowMs: number,
): void {
  const authorization = issued.authorization;
  const quota = issued.quota;
  const approval = session.approvalTranscript.value;
  const manifestDigestB64u = walletSessionEligibleManifestDigestV1(session);
  const eligibleAtMs = walletSessionEligibleAtMsV1(session);
  if (
    authorization.walletId !== approval.walletId ||
    authorization.enrollmentId !== approval.enrollmentId ||
    authorization.deviceId !== approval.deviceId ||
    authorization.keyManifestDigestB64u !== manifestDigestB64u ||
    !sameDelegatedWalletAuthorityV1(authorization.permission, approval.permission) ||
    authorization.issuedAtMs < eligibleAtMs ||
    authorization.issuedAtMs > nowMs ||
    authorization.expiresAtMs <= nowMs ||
    quota.tenantId !== authorization.tenantId ||
    quota.principalId !== authorization.principalId ||
    quota.walletSessionId !== authorization.walletSessionId ||
    quota.quotaId !== authorization.quotaId ||
    quota.expiresAtMs !== authorization.expiresAtMs ||
    quota.remainingUses <= 0
  ) {
    throw new DeviceLinkingInputError(
      'linked-device Wallet Session authorization does not match the eligible session',
    );
  }
}

function walletSessionEligibleManifestDigestV1(
  session: WalletSessionEligibleLinkedDeviceSessionRecordV1,
): DigestB64u {
  if (isActiveLinkedDeviceSessionRecord(session)) {
    return session.aggregateReceipt.manifestDigestB64u;
  }
  return session.state.keyManifestDigestB64u;
}

function walletSessionEligibleAtMsV1(
  session: WalletSessionEligibleLinkedDeviceSessionRecordV1,
): number {
  if (isActiveLinkedDeviceSessionRecord(session)) {
    return session.aggregateReceipt.activatedAtMs;
  }
  return session.updatedAtMs;
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
  // Every linked-device request, including committed-delivery retry, stays
  // authenticated by the original proof key carried in the QR payload.
  const expectedDevicePublicKeyB64u = rawSession.qrPayload.devicePublicKeyB64u;
  const devicePublicKeyDigestB64u = await computeDevicePublicKeyDigestB64u(
    expectedDevicePublicKeyB64u,
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
    expectedDevicePublicKeyB64u,
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
        | 'target-ready'
        | 'prepared-deliveries'
        | 'target-preparation'
        | 'owner-finalize'
        | 'provision'
        | 'holder-receipts'
        | 'credential'
        | 'email-otp-challenge'
        | 'email-otp-resend'
        | 'email-otp-verify'
        | 'ed25519-export-root'
        | 'ed25519-export-root-recipient'
        | 'receipt'
        | 'wallet-session'
        | 'wallet-session-renew'
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
  if (parts.length === 3 && parts[0] && parts[1] === 'email-otp' && parts[2] === 'challenge') {
    return { kind: 'email-otp-challenge', linkSessionId: parts[0] };
  }
  if (
    parts.length === 4 &&
    parts[0] &&
    parts[1] === 'email-otp' &&
    parts[2] === 'challenge' &&
    parts[3] === 'resend'
  ) {
    return { kind: 'email-otp-resend', linkSessionId: parts[0] };
  }
  if (
    parts.length === 4 &&
    parts[0] &&
    parts[1] === 'email-otp' &&
    parts[2] === 'challenge' &&
    parts[3] === 'verify'
  ) {
    return { kind: 'email-otp-verify', linkSessionId: parts[0] };
  }
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  if (
    parts[1] !== 'claim' &&
    parts[1] !== 'approval' &&
    parts[1] !== 'target-ready' &&
    parts[1] !== 'prepared-deliveries' &&
    parts[1] !== 'target-preparation' &&
    parts[1] !== 'owner-finalize' &&
    parts[1] !== 'provision' &&
    parts[1] !== 'holder-receipts' &&
    parts[1] !== 'credential' &&
    parts[1] !== 'ed25519-export-root' &&
    parts[1] !== 'ed25519-export-root-recipient' &&
    parts[1] !== 'receipt' &&
    parts[1] !== 'wallet-session' &&
    parts[1] !== 'wallet-session-renew' &&
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
    approval.targetFactor.kind !== session.qrPayload.targetFactor.kind ||
    !sameDelegatedWalletAuthorityV1(
      approval.permission,
      session.qrPayload.requestedPermission,
    ) ||
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
    case 'committed_completion_required':
      return session.state.keyManifestDigestB64u;
    case 'active':
      if (!session.aggregateReceipt) {
        throw new DeviceLinkingInputError('active linked-device session has no aggregate receipt');
      }
      return session.aggregateReceipt.manifestDigestB64u;
    case 'displaying_qr':
    case 'claimed_by_owner':
    case 'awaiting_target_factor':
    case 'expired_unclaimed':
    case 'expired_claimed':
    case 'cancelled_unclaimed':
    case 'cancelled_claimed_precommit':
      return null;
    default:
      return assertNever(session.state);
  }
}

function isProvisioningSessionState(state: LinkedDeviceSessionState): boolean {
  return (
    state.state === 'awaiting_target_factor' ||
    state.state === 'provisioning' ||
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

function assertTargetReadySourceIdentity(
  targetReady: LinkedDeviceTargetReadyR102InputV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  requestedAtMs: number,
): void {
  const authorization = targetReady.manifest.authorization;
  if (
    targetReady.linkSessionId !== session.linkSessionId ||
    targetReady.linkSessionId !== approval.linkSessionId ||
    targetReady.walletId !== approval.walletId ||
    targetReady.enrollmentId !== approval.enrollmentId ||
    targetReady.deviceId !== approval.deviceId ||
    targetReady.manifest.walletId !== approval.walletId ||
    String(targetReady.manifest.enrollmentId) !== String(approval.enrollmentId) ||
    authorization.kind !== 'linked_device_enrollment' ||
    targetReady.manifest.orderedChildren.length !== approval.orderedKeyBindings.length ||
    targetReady.children.length !== approval.orderedKeyBindings.length ||
    targetReady.manifest.expiresAtMs > approval.expiresAtMs ||
    (session.state.state !== 'committed_completion_required' &&
      targetReady.manifest.expiresAtMs <= requestedAtMs) ||
    session.claimTranscript?.value.deviceId !== targetReady.deviceId
  ) {
    throw new DeviceLinkingInputError('R102 target-ready input does not match approved session');
  }
  if (
    authorization.linkedDeviceEnrollmentId !== approval.enrollmentId ||
    authorization.linkedDevicePermissionDigestB64u !== approval.policyDigestB64u ||
    String(authorization.authorizedOperationId) !== String(approval.operationId)
  ) {
    throw new DeviceLinkingInputError('R102 target-ready authorization differs from approval');
  }
  for (let index = 0; index < targetReady.children.length; index += 1) {
    const job = targetReady.children[index];
    const child = targetReady.manifest.orderedChildren[index];
    const approved = approval.orderedKeyBindings[index];
    if (
      !job ||
      !child ||
      !approved ||
      child.targetLaneId !== approved.targetLaneId ||
      child.targetLaneShareEpoch !== approved.targetLaneShareEpoch ||
      job.target.laneId !== approved.targetLaneId ||
      job.target.laneShareEpoch !== approved.targetLaneShareEpoch ||
      job.expiresAtMs > approval.expiresAtMs ||
      job.expiresAtMs <= requestedAtMs
    ) {
      throw new DeviceLinkingInputError('R102 target-ready child differs from approval');
    }
  }
}

function parseCreateRequest(raw: unknown): DeviceLinkingCreateRequestV1 {
  const record = requireRecord(raw, 'device-linking create request');
  requireExactKeys(record, ['kind', 'payload']);
  if (record.kind !== 'linked_device_session_create_request_v1')
    throw new Error('device-linking create request kind is invalid');
  return {
    kind: 'linked_device_session_create_request_v1',
    payload: parseQrLinkedDeviceSessionPayloadV5(record.payload),
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

function parseWalletSessionRenewalRequest(raw: unknown): WalletSessionRenewalRequestV1 {
  const record = requireRecord(raw, 'linked-device Wallet Session renewal request');
  requireExactKeys(record, ['keyFamily', 'localPresenceAssertion']);
  if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked-device Wallet Session renewal key family is invalid');
  }
  return { keyFamily: record.keyFamily, localPresenceAssertion: record.localPresenceAssertion };
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
  readonly qrPayload: QrLinkedDeviceSessionPayloadV5;
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
    state.state === 'awaiting_target_factor' ||
    state.state === 'provisioning' ||
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
