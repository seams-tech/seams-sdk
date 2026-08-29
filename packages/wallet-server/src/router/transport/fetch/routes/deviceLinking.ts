import type {
  ActiveWalletSessionV1,
  ActivateInstalledAuthorityResultV1 as WireActivateInstalledAuthorityResultV1,
  LinkSessionProjectionV1,
  LinkSessionStateV1,
  LinkedDeviceApprovalV1,
  LinkedDeviceApprovedTargetFactorV1,
  LinkedDeviceEmailOtpChallengeResendRequestV1,
  LinkedDeviceEmailOtpChallengeStartRequestV1,
  LinkedDeviceEmailOtpBaseFactorRequestV1,
  LinkedDeviceEmailOtpBaseFactorResolutionV1,
  LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  LinkedDeviceEmailOtpVerificationGrantV1,
  LinkedDeviceEmailOtpVerificationResultV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetCredentialRegistrationResultV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceOrdinaryMaterialSourceContributionTupleV1,
  LocalAuthorityActivationFinalAckV1,
  LocalAuthorityInstallationReceiptV1,
  QrLinkedDeviceSessionPayloadV5,
  VerifiedLinkInputV1,
} from '@shared/device-linking/contracts';
import { assertNeverLinkSessionStateV1 } from '@shared/device-linking/contracts';
import type { CommittedAuthorityPackagesV1 } from '@shared/device-linking/committedSignerPackages';
import {
  parseLinkedDeviceApprovalDeliveryV1,
  parseLinkedDeviceApprovalV1,
  parseLinkedDeviceEmailOtpBaseFactorRequestV1,
  parseLinkedDeviceEmailOtpChallengeResendRequestV1,
  parseLinkedDeviceEmailOtpChallengeResultV1,
  parseLinkedDeviceEmailOtpChallengeStartRequestV1,
  parseLinkedDeviceEmailOtpChallengeVerifyRequestV1,
  parseLinkedDeviceEmailOtpVerificationResultV1,
  parseActiveWalletSessionV1,
  parseLocalAuthorityActivationFinalAckV1,
  parseLocalAuthorityInstallationReceiptV1,
  parseLinkedDeviceSessionClaimRequestV1,
  parseLinkedDeviceSessionTransportRequestV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceTargetPreparationV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking/parsers';
import {
  parseLinkedDeviceEd25519ExportRootRecipientV1,
  parseLinkedDeviceEd25519ExportRootSubmissionV1,
} from '@shared/device-linking/ed25519ExportRoot';
import type { LinkedDeviceEd25519ExportRootPortV1 } from '../../../../core/deviceLinking/linkedDeviceEd25519ExportRoot';
import {
  parseLinkedDeviceEd25519SourcePreservingReservationV1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  type LinkedDeviceEd25519SourceContributionPreparationV1,
} from '@shared/device-linking/sourceContribution';
import {
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { alphabetizeStringify } from '@shared/utils/digests';
import type {
  ActivateInstalledAuthorityResultV1 as D1ActivateInstalledAuthorityResultV1,
  CommitPendingAuthorityResultV1,
} from '../../../../router/cloudflare/d1/deviceLinking/d1LinkedDeviceAuthorityInstallService';
import {
  computeLinkedDevicePublicKeyDigestV1,
  LINKED_DEVICE_REQUEST_PROOF_HEADER_V1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  parseLinkedDeviceRequestProofV1,
  type LinkedDeviceRequestProofV1,
} from '../../../../core/deviceLinking/requestProof';
import type {
  LinkedDeviceOwnerAuthorizationContextV1,
  LinkedDeviceSessionRecordV1,
  LinkedDeviceSessionServiceResultV1,
  LinkedDeviceSessionServiceV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import { normalizeCorsOrigin } from '../../../../core/SessionService';
import { resolvePublishableKeyApiCredentialAuth } from '../../../auth/routerApiCredentialAuth';
import { extractRouterApiEnvironmentId } from '../../../auth/routerApiKeyAuth';
import { findRouteDefinitionById } from '../../../framework/routeDefinitions';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256Bytes } from '@shared/utils/digests';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import type { WalletAuthMethodId, WalletId } from '@shared/utils/domainIds';

const DEVICE_LINKING_BASE = '/wallet/device-linking/v1/sessions';
const TARGET_PREPARATION_ROUTE_ID = 'linked_device_target_preparation';
const TARGET_CREDENTIAL_ROUTE_ID = 'linked_device_target_credential';
export const DEVICE_LINKING_REQUEST_PROOF_HEADER_V1 = LINKED_DEVICE_REQUEST_PROOF_HEADER_V1;

export type DeviceLinkingAuthDeniedV1 = {
  readonly kind: 'denied';
  readonly code: 'unauthorized' | 'expired' | 'invalid' | 'replayed';
  readonly message: string;
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
  readonly bodyDigestB64u: DigestB64u;
  readonly requestedAtMs: number;
};

export type DeviceLinkingAuthenticatedRequestV1 = {
  readonly kind: 'authorized';
  readonly body: unknown;
  readonly owner: LinkedDeviceOwnerAuthorizationContextV1;
  readonly binding: DeviceLinkingRequestBindingV1;
};

export type DeviceLinkingRequestProofV1 = LinkedDeviceRequestProofV1;

export type DeviceLinkingDeviceAuthenticatedRequestV1 = {
  readonly kind: 'authorized';
  readonly body: unknown;
  readonly proof: DeviceLinkingRequestProofV1;
};

export type DeviceLinkingRouteMutationResultV1 = LinkedDeviceSessionServiceResultV1;

export type DeviceLinkingTargetCredentialProviderV1 = {
  getTargetPreparationV1(
    input: {
      readonly session: LinkedDeviceSessionRecordV1;
      readonly approval: LinkedDeviceApprovalV1;
      readonly requestedAtMs: number;
    } & (
      | { readonly access: 'create_or_replay'; readonly expectedOrigin: string }
      | { readonly access: 'replay_only'; readonly expectedOrigin?: never }
    ),
  ): Promise<LinkedDeviceTargetPreparationV1>;
  registerTargetCredentialV1(input: {
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly expectedOrigin: string;
    readonly requestedAtMs: number;
  }): Promise<
    | {
        readonly outcome: 'applied' | 'replayed';
        readonly keyManifestDigestB64u: DigestB64u;
        readonly targetCredential: LinkedDeviceTargetCredentialRegistrationResultV1;
      }
    | { readonly outcome: 'invalid_input'; readonly message: string }
  >;
  buildVerifiedLinkInputV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<VerifiedLinkInputV1>;
};

export type DeviceLinkingEmailOtpTargetFactorProviderV1 = {
  resolveBaseFactorSelectionV1(input: {
    readonly walletId: WalletId;
    readonly request: LinkedDeviceEmailOtpBaseFactorRequestV1;
  }): Promise<LinkedDeviceEmailOtpBaseFactorResolutionV1>;
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
        readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1 | null;
      }
    | { readonly kind: 'refused'; readonly code: string; readonly message: string }
  >;
};

export type DeviceLinkingInstallationReceiptPortV1 = {
  commitPendingAuthorityV1(input: {
    readonly input: VerifiedLinkInputV1;
    readonly nowMs: number;
    readonly ed25519ExportRootPackage: CommittedAuthorityPackagesV1['ed25519ExportRootPackage'];
  }): Promise<CommitPendingAuthorityResultV1>;
  readCommittedAuthorityPackagesV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<CommittedAuthorityPackagesV1 | null>;
  activateInstalledAuthorityV1(input: {
    readonly receipt: LocalAuthorityInstallationReceiptV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<D1ActivateInstalledAuthorityResultV1>;
  acknowledgeLocalAuthorityActivationV1(input: {
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<void>;
};

/** Owner-authenticated bridge to the Router's private source-preserving lane. */
export type DeviceLinkingEd25519SourcePreservingRouterPortV1 = {
  executeEd25519SourcePreservingV1(input: {
    readonly sourceBinding: LinkedDeviceEd25519SourceContributionPreparationV1['sourceBinding'];
    readonly targetRequest: RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
    readonly participantIds: readonly [number, number];
  }): Promise<unknown>;
};

export type DeviceLinkingRouteServiceV1 = {
  readonly sessionService: Pick<
    LinkedDeviceSessionServiceV1,
    | 'createUnclaimedSessionV1'
    | 'claimSessionV1'
    | 'recordOwnerApprovalV1'
    | 'recordTargetCredentialV1'
    | 'recordSourceContributionV1'
    | 'recordEmailOtpChallengeStateV1'
    | 'failBeforeCommitV1'
    | 'cancelSessionV1'
    | 'getSessionV1'
  > & {
    readonly listSessionsForWalletV1: LinkedDeviceSessionServiceV1['listSessionsForWalletV1'];
  };
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
    readonly bodyDigestB64u: DigestB64u;
    readonly expectedDevicePublicKeyB64u: string;
    readonly expectedDevicePublicKeyDigestB64u: DigestB64u;
    readonly proof: DeviceLinkingRequestProofV1;
    readonly requestedAtMs: number;
  }): Promise<DeviceLinkingDeviceAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1>;
  readonly targetCredential: DeviceLinkingTargetCredentialProviderV1;
  readonly installationReceipt?: DeviceLinkingInstallationReceiptPortV1;
  readonly ed25519ExportRoot?: LinkedDeviceEd25519ExportRootPortV1;
  readonly sourceContributionRouter?: DeviceLinkingEd25519SourcePreservingRouterPortV1;
};

type DeviceLinkingCreateRequestV1 = {
  readonly kind: 'linked_device_session_create_request_v1';
  readonly payload: QrLinkedDeviceSessionPayloadV5;
};

type RouteAction =
  | { readonly kind: 'create' }
  | { readonly kind: 'session'; readonly linkSessionId: string }
  | {
      readonly kind:
        | 'claim'
        | 'approval'
        | 'target-preparation'
        | 'credential'
        | 'source-contribution-preparation'
        | 'source-contribution'
        | 'source-contribution-execute'
        | 'email-otp-challenge'
        | 'email-otp-resend'
        | 'email-otp-verify'
        | 'email-otp-base-factor'
        | 'owner-cancel'
        | 'ed25519-export-root'
        | 'ed25519-export-root-recipient'
        | 'receipt'
        | 'cancel';
      readonly linkSessionId: string;
    };

export async function handleDeviceLinking(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (!ctx.pathname.startsWith(DEVICE_LINKING_BASE)) return null;
  const service = ctx.service.deviceLinking;
  if (!service) return notSupportedResponse();
  const action = parseRoutePath(ctx.pathname);
  if (!action) return null;
  const nowMs = service.nowV1();
  try {
    switch (action.kind) {
      case 'create':
        return await handleCreate(ctx, service, nowMs);
      case 'session':
        return await handleSession(ctx, service, action.linkSessionId, nowMs);
      case 'claim':
        return await handleClaim(ctx, service, action.linkSessionId, nowMs);
      case 'approval':
        return await handleApproval(ctx, service, action.linkSessionId, nowMs);
      case 'target-preparation':
        return await handleTargetPreparation(ctx, service, action.linkSessionId, nowMs);
      case 'credential':
        return await handleCredential(ctx, service, action.linkSessionId, nowMs);
      case 'source-contribution-preparation':
        return await handleSourceContributionPreparation(ctx, service, action.linkSessionId, nowMs);
      case 'source-contribution':
        return await handleSourceContribution(ctx, service, action.linkSessionId, nowMs);
      case 'source-contribution-execute':
        return await handleSourceContributionExecute(ctx, service, action.linkSessionId, nowMs);
      case 'email-otp-challenge':
        return await handleEmailOtpChallenge(ctx, service, action.linkSessionId, nowMs, false);
      case 'email-otp-resend':
        return await handleEmailOtpChallenge(ctx, service, action.linkSessionId, nowMs, true);
      case 'email-otp-verify':
        return await handleEmailOtpVerify(ctx, service, action.linkSessionId, nowMs);
      case 'email-otp-base-factor':
        return await handleEmailOtpBaseFactor(ctx, service, action.linkSessionId, nowMs);
      case 'owner-cancel':
        return await handleOwnerCancel(ctx, service, action.linkSessionId, nowMs);
      case 'ed25519-export-root-recipient':
        return await handleExportRootRecipient(ctx, service, action.linkSessionId, nowMs);
      case 'ed25519-export-root':
        return await handleExportRootPackage(ctx, service, action.linkSessionId, nowMs);
      case 'receipt':
        return await handleReceipt(ctx, service, action.linkSessionId, nowMs);
      case 'cancel':
        return await handleCancel(ctx, service, action.linkSessionId, nowMs);
      default:
        return assertNever(action);
    }
  } catch (error: unknown) {
    if (error instanceof DeviceLinkingInputError) return invalidInputResponse(error.message);
    return json({ ok: false, code: 'internal', message: errorMessage(error) }, { status: 500 });
  }
}

async function handleCreate(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  nowMs: number,
): Promise<Response> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const rawBody = await readJsonBody(ctx.request);
  const body = parseBoundary(() => parseCreateRequest(rawBody));
  const keyDigest = await computeDevicePublicKeyDigestB64u(body.payload.devicePublicKeyB64u);
  const proof = parseBoundary(() => parseRequestProofHeader(ctx.request));
  validateRequestProof(
    proof,
    ctx.method,
    ctx.pathname,
    body.payload.linkSessionId,
    bodyDigestB64u,
    keyDigest,
    nowMs,
  );
  const verified = await service.verifyPublicSessionProofV1({
    payload: body.payload,
    proof,
    method: ctx.method,
    canonicalPath: ctx.pathname,
    bodyDigestB64u,
    devicePublicKeyDigestB64u: keyDigest,
    requestedAtMs: nowMs,
  });
  if (verified.kind === 'denied') return authDeniedResponse(verified);
  return sessionResultResponse(
    await service.sessionService.createUnclaimedSessionV1({ payload: body.payload, nowMs }),
  );
}

async function handleSession(
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
  const authentication = await authenticateOwner(service, ctx, bodyDigestB64u, nowMs);
  if (authentication.kind === 'denied') return authDeniedResponse(authentication);
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const request = parseBoundary(() => parseLinkedDeviceSessionClaimRequestV1(authentication.body));
  if (request.payload.linkSessionId !== parseSessionId(rawLinkSessionId))
    return invalidInputResponse('link session id does not match route');
  validateOwnerRequestBinding(authentication.binding, ctx, bodyDigestB64u, nowMs);
  return claimResultResponse(
    await service.sessionService.claimSessionV1({
      payload: request.payload,
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
    if (
      service.installationReceipt &&
      (authenticated.session.state.state === 'provisioning' ||
        authenticated.session.state.state === 'authority_pending_local_install' ||
        authenticated.session.state.state === 'active')
    ) {
      const committed = await service.installationReceipt.readCommittedAuthorityPackagesV1({
        session: authenticated.session,
        requestedAtMs: nowMs,
      });
      if (!committed) return new Response(null, { status: 204 });
      return json(committed, { status: 200 });
    }
    const approval = authenticated.session.approvalTranscript?.value;
    if (!approval) return invalidStateResponse(authenticated.session);
    return json(
      parseLinkedDeviceApprovalDeliveryV1({ kind: 'linked_device_approval_delivery_v1', approval }),
      { status: 200 },
    );
  }
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const authentication = await authenticateOwner(service, ctx, bodyDigestB64u, nowMs);
  if (authentication.kind === 'denied') return authDeniedResponse(authentication);
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const approval = parseBoundary(() => parseLinkedDeviceApprovalV1(authentication.body));
  const linkSessionId = parseSessionId(rawLinkSessionId);
  if (approval.linkSessionId !== linkSessionId)
    return invalidInputResponse('link session id does not match route');
  validateOwnerRequestBinding(authentication.binding, ctx, bodyDigestB64u, nowMs);
  const targetFactor = approval.targetFactor;
  if (isExistingEmailOtpTargetFactorV1(targetFactor)) {
    const session = await service.sessionService.getSessionV1({ linkSessionId, nowMs });
    if (!session) return notFoundResponse();
    const ownerMismatch = requireOwnerMatchesClaimedWallet(authentication.owner, session);
    if (ownerMismatch) return ownerMismatch;
    if (authentication.owner.walletId !== approval.walletId) {
      return authDeniedResponse({
        kind: 'denied',
        code: 'unauthorized',
        message: 'owner session does not match link wallet',
      });
    }
    if (session.state.state !== 'claimed' || !session.claimTranscript) {
      return invalidStateResponse(session);
    }
    const selectionError = await requireSelectedEmailOtpBaseFactorV1(service, session, {
      walletId: approval.walletId,
      baseWalletAuthMethodId: targetFactor.baseWalletAuthMethodId,
    });
    if (selectionError) return selectionError;
  }
  return approvalResultResponse(
    await service.sessionService.recordOwnerApprovalV1({
      approval,
      nowMs,
      owner: authentication.owner,
    }),
  );
}

function isExistingEmailOtpTargetFactorV1(
  targetFactor: LinkedDeviceApprovedTargetFactorV1,
): targetFactor is Extract<
  LinkedDeviceApprovedTargetFactorV1,
  { readonly baseWalletAuthMethodId: WalletAuthMethodId }
> {
  return (
    targetFactor.kind === 'email_otp' && targetFactor.enrollment.kind === 'existing_enrollment'
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
  const origin = await authenticateTargetPasskeyOriginV1(ctx, TARGET_PREPARATION_ROUTE_ID);
  if (!origin.ok) return origin.response;
  const approval = requireApproval(authenticated.session);
  const rawPreparation = await readTargetPreparation(
    service,
    authenticated.session,
    approval,
    { access: 'create_or_replay', expectedOrigin: origin.expectedOrigin },
    nowMs,
  );
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  return json(preparation, { status: 200 });
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
  const origin = await authenticateTargetPasskeyOriginV1(ctx, TARGET_CREDENTIAL_ROUTE_ID);
  if (!origin.ok) return origin.response;
  const registration = parseBoundary(() =>
    parseLinkedDeviceTargetCredentialRegistrationV1(authenticated.body),
  );
  if (registration.linkSessionId !== authenticated.linkSessionId)
    return invalidInputResponse('link session id does not match route');
  const session = authenticated.session;
  const approval = requireApproval(session);
  const rawPreparation = await readTargetPreparation(
    service,
    session,
    approval,
    { access: 'replay_only' },
    nowMs,
  );
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  const result = await service.targetCredential.registerTargetCredentialV1({
    registration,
    preparation,
    session,
    approval,
    expectedOrigin: origin.expectedOrigin,
    requestedAtMs: nowMs,
  });
  if (result.outcome === 'invalid_input') return invalidInputResponse(result.message);
  let sessionOutcome: 'applied' | 'replayed' = result.outcome;
  let recordedSession = session;
  if (session.state.state === 'awaiting_target_factor') {
    const recorded = await service.sessionService.recordTargetCredentialV1({
      linkSessionId: session.linkSessionId,
      expectedRevision: session.revision,
      sourceContributionPreparation: result.targetCredential.ordinarySignerMaterialPreparations,
      nowMs,
    });
    if (recorded.outcome !== 'applied' && recorded.outcome !== 'replayed') {
      return sessionResultResponse(recorded);
    }
    sessionOutcome = recorded.outcome;
    recordedSession = recorded.record;
  } else if (
    session.state.state !== 'awaiting_source_contribution' &&
    session.state.state !== 'provisioning' &&
    session.state.state !== 'authority_pending_local_install' &&
    session.state.state !== 'active'
  ) {
    return invalidStateResponse(session);
  }
  return targetCredentialResultResponse(recordedSession, sessionOutcome, result.targetCredential);
}

async function handleSourceContributionPreparation(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const linkSessionId = parseSessionId(rawLinkSessionId);
  const owner = await authenticateOwnerForSession(ctx, service, linkSessionId, nowMs);
  if (owner.kind !== 'authorized') return ownerSessionResponse(owner);
  if (ctx.method !== 'GET') return methodNotAllowedResponse();
  const preparation = owner.session.sourceContributionPreparation;
  if (!preparation) return new Response(null, { status: 204 });
  return json(preparation, { status: 200 });
}

async function handleSourceContribution(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const linkSessionId = parseSessionId(rawLinkSessionId);
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const authentication = await authenticateOwner(service, ctx, bodyDigestB64u, nowMs);
  if (authentication.kind === 'denied') return authDeniedResponse(authentication);
  const approval = parseBoundary(() => parseLinkedDeviceApprovalV1(authentication.body));
  if (approval.linkSessionId !== linkSessionId) {
    return invalidInputResponse('link session id does not match route');
  }
  validateOwnerRequestBinding(authentication.binding, ctx, bodyDigestB64u, nowMs);
  const recorded = await service.sessionService.recordSourceContributionV1({
    approval,
    nowMs,
    owner: authentication.owner,
  });
  if (recorded.outcome !== 'applied' && recorded.outcome !== 'replayed') {
    return sessionResultResponse(recorded);
  }
  if (
    recorded.record.state.state !== 'provisioning' &&
    recorded.record.state.state !== 'authority_pending_local_install' &&
    recorded.record.state.state !== 'active'
  ) {
    return sessionResultResponse(recorded);
  }
  if (recorded.record.state.state !== 'provisioning') {
    return sessionProjectionResponse(recorded.record, recorded.outcome);
  }
  const installationReceipt = service.installationReceipt;
  if (!installationReceipt) {
    return invalidInputResponse('verified authority installation is not configured');
  }
  const finalApproval = requireSourceContributionApproval(recorded.record);
  const verifiedLinkInput = await service.targetCredential.buildVerifiedLinkInputV1({
    session: recorded.record,
    approval: finalApproval,
    requestedAtMs: nowMs,
  });
  const exportRootTransfer = await service.ed25519ExportRoot?.readTransferV1(linkSessionId);
  const ed25519ExportRootPackage =
    exportRootTransfer?.state === 'sealed' ? exportRootTransfer.package : null;
  const keyFamilies = verifiedLinkInput.signerManifest.keyFamilies;
  const requiresEd25519ExportRoot = keyFamilies[0] === 'ed25519';
  if (requiresEd25519ExportRoot !== (ed25519ExportRootPackage !== null)) {
    return invalidInputResponse(
      requiresEd25519ExportRoot
        ? 'linked-device Ed25519 export-root package is unavailable'
        : 'linked-device export-root package has no Ed25519 signer',
    );
  }
  const committed = await installationReceipt.commitPendingAuthorityV1({
    input: verifiedLinkInput,
    nowMs,
    ed25519ExportRootPackage,
  });
  if (committed.kind === 'invalid_input') {
    const failed = await service.sessionService.failBeforeCommitV1({
      linkSessionId,
      expectedRevision: recorded.record.revision,
      error: { kind: 'package_preparation_failed', reason: committed.message },
      nowMs,
    });
    return sessionResultResponse(failed);
  }
  if (committed.kind === 'conflict') {
    const failed = await service.sessionService.failBeforeCommitV1({
      linkSessionId,
      expectedRevision: recorded.record.revision,
      error: { kind: 'package_preparation_failed', reason: committed.message },
      nowMs,
    });
    return sessionResultResponse(failed);
  }
  return sessionProjectionResponse(
    committed.session,
    committed.kind === 'replayed' ? 'replayed' : recorded.outcome,
  );
}

async function handleSourceContributionExecute(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const linkSessionId = parseSessionId(rawLinkSessionId);
  const owner = await authenticateOwnerForSession(ctx, service, linkSessionId, nowMs);
  if (owner.kind !== 'authorized') return ownerSessionResponse(owner);
  const router = service.sourceContributionRouter;
  if (!router) return notSupportedResponse('Ed25519 source-preserving linking is not configured');
  const preparation = requireEd25519SourceContributionPreparation(owner.session);
  const targetRequest = parseBoundary(() => {
    const parsed = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(owner.body);
    if (!parsed.ok) throw new Error(parsed.message);
    return parsed.value;
  });
  if (
    alphabetizeStringify(targetRequest.binding) !==
    alphabetizeStringify(preparation.targetAdmission.binding)
  ) {
    throw new DeviceLinkingInputError(
      'source-preserving target request binding does not match the persisted preparation',
    );
  }
  const rawReservation = await router.executeEd25519SourcePreservingV1({
    sourceBinding: preparation.sourceBinding,
    targetRequest,
    participantIds: preparation.participantIds,
  });
  const reservation = parseBoundary(() =>
    parseLinkedDeviceEd25519SourcePreservingReservationV1(rawReservation),
  );
  if (
    alphabetizeStringify(reservation.participantIds) !==
    alphabetizeStringify(preparation.participantIds)
  ) {
    throw new DeviceLinkingInputError(
      'source-preserving reservation participant ids do not match the persisted preparation',
    );
  }
  return json(rawReservation, { status: 200 });
}

async function handleEmailOtpChallenge(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
  resend: boolean,
): Promise<Response> {
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const request = parseBoundary(() => parseEmailOtpChallengeRequest(authenticated.body, resend));
  if (request.linkSessionId !== authenticated.linkSessionId)
    return invalidInputResponse('link session id does not match route');
  const provider = service.emailOtpTargetFactor;
  if (!provider) return notSupportedResponse('Email OTP linking is not configured');
  const session = authenticated.session;
  const approval = requireApproval(session);
  const rawPreparation = await readTargetPreparation(
    service,
    session,
    approval,
    { access: 'replay_only' },
    nowMs,
  );
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  const started = await provider.startChallengeV1({
    session,
    approval,
    preparation,
    resend,
    requestedAtMs: nowMs,
  });
  if (started.kind === 'refused')
    return json({ ok: false, code: started.code, message: started.message }, { status: 403 });
  const workerEphemeralPublicKey65B64u =
    request.kind === 'linked_device_email_otp_challenge_start_request_v1'
      ? request.workerEphemeralPublicKey65B64u
      : requireSentEmailOtpChallenge(session).workerEphemeralPublicKey65B64u;
  const recorded = await service.sessionService.recordEmailOtpChallengeStateV1({
    linkSessionId: session.linkSessionId,
    expectedRevision: session.revision,
    challenge: {
      challengeId: started.challengeId,
      workerEphemeralPublicKey65B64u,
      maskedEmailHint: started.maskedEmailHint,
      expiresAtMs: started.expiresAtMs,
      resendAvailableAtMs: started.resendAvailableAtMs,
    },
    nowMs,
  });
  if (recorded.outcome !== 'applied' && recorded.outcome !== 'replayed')
    return sessionResultResponse(recorded);
  return json(
    parseLinkedDeviceEmailOtpChallengeResultV1({
      kind: 'linked_device_email_otp_challenge_result_v1',
      challengeId: started.challengeId,
      maskedEmailHint: started.maskedEmailHint,
      expiresAtMs: started.expiresAtMs,
      resendAvailableAtMs: started.resendAvailableAtMs,
    }),
    { status: 200 },
  );
}

async function handleEmailOtpBaseFactor(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const linkSessionId = parseSessionId(rawLinkSessionId);
  const authenticated = await authenticateOwnerForSession(ctx, service, linkSessionId, nowMs);
  if (authenticated.kind !== 'authorized') return ownerSessionResponse(authenticated);
  const session = authenticated.session;
  const ownerMismatch = requireOwnerMatchesClaimedWallet(authenticated.owner, session);
  if (ownerMismatch) return ownerMismatch;
  if (
    session.state.state !== 'claimed' ||
    session.qrPayload.targetFactor.kind !== 'email_otp' ||
    !session.claimTranscript
  ) {
    return invalidStateResponse(session);
  }
  const walletId = session.claimTranscript.value.walletId;
  const request = parseBoundary(() =>
    parseLinkedDeviceEmailOtpBaseFactorRequestV1(authenticated.body),
  );
  if (request.expectedRevision !== session.revision) {
    return json(
      {
        ok: false,
        outcome: 'conflict',
        expectedRevision: request.expectedRevision,
        actualRevision: session.revision,
      },
      { status: 409 },
    );
  }
  const provider = service.emailOtpTargetFactor;
  if (!provider) return notSupportedResponse('Email OTP linking is not configured');
  const resolution = await provider.resolveBaseFactorSelectionV1({ walletId, request });
  return json({ revision: session.revision, resolution }, { status: 200 });
}

async function handleOwnerCancel(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const linkSessionId = parseSessionId(rawLinkSessionId);
  const authenticated = await authenticateOwnerForSession(ctx, service, linkSessionId, nowMs);
  if (authenticated.kind !== 'authorized') return ownerSessionResponse(authenticated);
  parseBoundary(() => parseOwnerCancelRequest(authenticated.body));
  const session = authenticated.session;
  const ownerMismatch = requireOwnerMatchesClaimedWallet(authenticated.owner, session);
  if (ownerMismatch) return ownerMismatch;
  if (session.state.state === 'cancelled') {
    return sessionProjectionResponse(session, 'replayed');
  }
  return sessionResultResponse(
    await service.sessionService.cancelSessionV1({
      linkSessionId,
      expectedRevision: session.revision,
      nowMs,
    }),
  );
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
  if (request.linkSessionId !== authenticated.linkSessionId)
    return invalidInputResponse('link session id does not match route');
  const provider = service.emailOtpTargetFactor;
  if (!provider) return notSupportedResponse('Email OTP linking is not configured');
  const session = authenticated.session;
  const approval = requireApproval(session);
  const rawPreparation = await readTargetPreparation(
    service,
    session,
    approval,
    { access: 'replay_only' },
    nowMs,
  );
  const preparation = parseBoundary(() => parseLinkedDeviceTargetPreparationV1(rawPreparation));
  const challenge = requireSentEmailOtpChallenge(session);
  if (challenge.challengeId !== request.challengeId)
    return invalidInputResponse('email OTP challenge does not match this session');
  const verified = await provider.verifyChallengeV1({
    session,
    approval,
    preparation,
    challengeId: request.challengeId,
    otpCode: request.otpCode,
    requestedAtMs: nowMs,
  });
  if (verified.kind === 'refused')
    return json({ ok: false, code: verified.code, message: verified.message }, { status: 403 });
  const response: LinkedDeviceEmailOtpVerificationResultV1 = parseBoundary(() =>
    parseLinkedDeviceEmailOtpVerificationResultV1({
      kind: 'linked_device_email_otp_verification_result_v1',
      verificationGrant: verified.grant,
      factorRelease: verified.factorRelease,
    }),
  );
  return json(response, { status: 200 });
}

async function handleExportRootRecipient(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const port = service.ed25519ExportRoot;
  if (!port)
    return notSupportedResponse('Linked-device Ed25519 export-root relay is not configured');
  const sessionId = parseSessionId(rawLinkSessionId);
  if (ctx.method === 'GET') {
    const owner = await authenticateOwnerForSession(ctx, service, sessionId, nowMs);
    if (owner.kind !== 'authorized') return ownerSessionResponse(owner);
    const transfer = await port.readTransferV1(sessionId);
    return transfer
      ? json(transfer.recipient, { status: 200 })
      : new Response(null, { status: 204 });
  }
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  const recipient = parseBoundary(() =>
    parseLinkedDeviceEd25519ExportRootRecipientV1(authenticated.body),
  );
  if (recipient.linkSessionId !== authenticated.linkSessionId)
    return invalidInputResponse('link session id does not match route');
  return exportRootWriteResponse(await port.registerRecipientV1({ recipient }));
}

async function handleExportRootPackage(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  const port = service.ed25519ExportRoot;
  if (!port)
    return notSupportedResponse('Linked-device Ed25519 export-root relay is not configured');
  const sessionId = parseSessionId(rawLinkSessionId);
  if (ctx.method === 'GET') {
    const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
    if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
    if (authenticated.kind === 'not_found') return notFoundResponse();
    const transfer = await port.readTransferV1(sessionId);
    return transfer?.state === 'sealed'
      ? json(transfer.package, { status: 200 })
      : new Response(null, { status: 204 });
  }
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  const owner = await authenticateOwnerForSession(ctx, service, sessionId, nowMs);
  if (owner.kind !== 'authorized') return ownerSessionResponse(owner);
  const submission = parseBoundary(() =>
    parseLinkedDeviceEd25519ExportRootSubmissionV1(owner.body),
  );
  if (submission.linkSessionId !== sessionId)
    return invalidInputResponse('link session id does not match route');
  return exportRootWriteResponse(
    await port.submitPackageV1({ linkSessionId: sessionId, package: submission.package }),
  );
}

async function handleReceipt(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  rawLinkSessionId: string,
  nowMs: number,
): Promise<Response> {
  if (!service.installationReceipt)
    return notSupportedResponse('Installation receipt is not configured');
  const authenticated = await authenticateDeviceForSession(ctx, service, rawLinkSessionId, nowMs);
  if (authenticated.kind === 'denied') return authDeniedResponse(authenticated);
  if (authenticated.kind === 'not_found') return notFoundResponse();
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  if (isFinalActivationAcknowledgement(authenticated.body)) {
    const acknowledgement = parseBoundary(() =>
      parseLocalAuthorityActivationFinalAckV1(authenticated.body),
    );
    if (acknowledgement.linkSessionId !== authenticated.session.linkSessionId) {
      return invalidInputResponse('activation acknowledgement session does not match this session');
    }
    await service.installationReceipt.acknowledgeLocalAuthorityActivationV1({
      acknowledgement,
      session: authenticated.session,
      requestedAtMs: nowMs,
    });
    return new Response(null, { status: 204 });
  }
  const receipt = parseBoundary(() => parseLocalAuthorityInstallationReceiptV1(authenticated.body));
  if (receipt.deviceId !== authenticated.session.state.deviceId)
    return invalidInputResponse('installation receipt device does not match this session');
  const result = await service.installationReceipt.activateInstalledAuthorityV1({
    receipt,
    session: authenticated.session,
    requestedAtMs: nowMs,
  });
  return installationResultResponse(result);
}

function isFinalActivationAcknowledgement(raw: unknown): boolean {
  return (
    raw !== null &&
    typeof raw === 'object' &&
    !Array.isArray(raw) &&
    'kind' in raw &&
    raw.kind === 'local_authority_activation_final_ack_v1'
  );
}

function installationResultResponse(result: D1ActivateInstalledAuthorityResultV1): Response {
  switch (result.kind) {
    case 'active':
      return json(
        {
          kind: 'active',
          authority: result.authority,
          authMethod: result.authMethod,
          walletSession: activeWalletSessionWireV1(result.walletSession),
          operationCredential: result.operationCredential,
        } satisfies WireActivateInstalledAuthorityResultV1,
        { status: 200 },
      );
    case 'pending_local_install':
      return json(
        {
          kind: 'pending_local_install',
          authorityId: result.authorityId,
          reason: { kind: result.reason },
        } satisfies WireActivateInstalledAuthorityResultV1,
        { status: 202 },
      );
    case 'integrity_error':
      return json(
        {
          kind: 'integrity_error',
          reason: { kind: 'installation_receipt_mismatch', field: 'installedActivationRefs' },
        } satisfies WireActivateInstalledAuthorityResultV1,
        { status: 409 },
      );
  }
}

type D1IssuedWalletSessionV1 = Extract<
  D1ActivateInstalledAuthorityResultV1,
  { readonly kind: 'active' }
>['walletSession'];

function activeWalletSessionWireV1(issued: D1IssuedWalletSessionV1): ActiveWalletSessionV1 {
  const session = issued.session;
  const capabilitySubjects = session.capabilitySubjects.map((subject) => {
    switch (subject.kind) {
      case 'sign':
      case 'export_keys':
        return {
          kind: subject.kind,
          keyFamily: subject.keyFamily,
          materialActivation: subject.materialActivation,
        };
      case 'link_devices':
      case 'revoke_devices':
        return { kind: subject.kind };
      default:
        return assertNever(subject);
    }
  });
  const first = capabilitySubjects[0];
  if (!first) throw new Error('issued Wallet Session has no capability subjects');
  return parseActiveWalletSessionV1({
    kind: 'active_wallet_session_v1',
    walletId: session.walletId,
    authorityId: session.authorityId,
    authMethodId: session.walletAuthMethodId,
    authorizationId: session.authorizationId,
    quotaId: issued.quota.quotaId,
    authorityDigestB64u: session.authorityDigestB64u,
    authorityRevocationEpoch: session.authorityRevocationEpoch,
    capabilitySubjects: [first, ...capabilitySubjects.slice(1)],
    issuedAtMs: session.createdAtMs,
    expiresAtMs: session.expiresAtMs,
  });
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
  if (
    request.kind !== 'linked_device_session_cancel_unclaimed_request_v1' &&
    request.kind !== 'linked_device_session_cancel_claimed_request_v1'
  )
    return invalidInputResponse('cancel request kind is invalid');
  if (request.linkSessionId !== authenticated.linkSessionId)
    return invalidInputResponse('link session id does not match route');
  return sessionResultResponse(
    await service.sessionService.cancelSessionV1({
      linkSessionId: authenticated.linkSessionId,
      expectedRevision: authenticated.session.revision,
      nowMs,
    }),
  );
}

type AuthenticatedOwnerForSession =
  | {
      readonly kind: 'authorized';
      readonly body: unknown;
      readonly owner: LinkedDeviceOwnerAuthorizationContextV1;
      readonly linkSessionId: LinkDeviceSessionId;
      readonly session: LinkedDeviceSessionRecordV1;
    }
  | DeviceLinkingAuthDeniedV1
  | { readonly kind: 'not_found' };

async function authenticateOwnerForSession(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingRouteServiceV1,
  linkSessionId: LinkDeviceSessionId,
  nowMs: number,
): Promise<AuthenticatedOwnerForSession> {
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const authentication = await authenticateOwner(service, ctx, bodyDigestB64u, nowMs);
  if (authentication.kind === 'denied') return authentication;
  const session = await service.sessionService.getSessionV1({ linkSessionId, nowMs });
  if (!session) return { kind: 'not_found' };
  validateOwnerRequestBinding(authentication.binding, ctx, bodyDigestB64u, nowMs);
  return {
    kind: 'authorized',
    body: authentication.body,
    owner: authentication.owner,
    linkSessionId,
    session,
  };
}

async function authenticateOwner(
  service: DeviceLinkingRouteServiceV1,
  ctx: FetchRouterApiContext,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
): Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1> {
  return service.authenticateOwnerRequestV1({
    request: ctx.request,
    method: ctx.method,
    pathname: ctx.pathname,
    bodyDigestB64u,
    requestedAtMs: nowMs,
  });
}

type AuthenticatedDeviceForSession =
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
): Promise<AuthenticatedDeviceForSession> {
  const linkSessionId = parseSessionId(rawLinkSessionId);
  const rawSession = await service.sessionService.getSessionV1(linkSessionId);
  if (!rawSession) return { kind: 'not_found' };
  const bodyDigestB64u = await requestBodyDigest(ctx.request);
  const expectedKey = rawSession.qrPayload.devicePublicKeyB64u;
  const keyDigest = await computeDevicePublicKeyDigestB64u(expectedKey);
  const proof = parseBoundary(() => parseRequestProofHeader(ctx.request));
  validateRequestProof(
    proof,
    ctx.method,
    ctx.pathname,
    linkSessionId,
    bodyDigestB64u,
    keyDigest,
    nowMs,
  );
  const authentication = await service.authenticateDeviceRequestV1({
    request: ctx.request,
    method: ctx.method,
    pathname: ctx.pathname,
    linkSessionId: String(linkSessionId),
    bodyDigestB64u,
    expectedDevicePublicKeyB64u: expectedKey,
    expectedDevicePublicKeyDigestB64u: keyDigest,
    proof,
    requestedAtMs: nowMs,
  });
  if (authentication.kind === 'denied') return authentication;
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

function parseRoutePath(pathname: string): RouteAction | null {
  if (pathname === DEVICE_LINKING_BASE) return { kind: 'create' };
  if (!pathname.startsWith(`${DEVICE_LINKING_BASE}/`)) return null;
  const parts = pathname.slice(DEVICE_LINKING_BASE.length + 1).split('/');
  const linkSessionId = parts[0];
  if (!linkSessionId) return null;
  if (parts.length === 1) return { kind: 'session', linkSessionId };
  if (parts.length === 3 && parts[1] === 'email-otp' && parts[2] === 'challenge')
    return { kind: 'email-otp-challenge', linkSessionId };
  if (
    parts.length === 4 &&
    parts[1] === 'email-otp' &&
    parts[2] === 'challenge' &&
    parts[3] === 'resend'
  )
    return { kind: 'email-otp-resend', linkSessionId };
  if (
    parts.length === 4 &&
    parts[1] === 'email-otp' &&
    parts[2] === 'challenge' &&
    parts[3] === 'verify'
  )
    return { kind: 'email-otp-verify', linkSessionId };
  if (parts.length === 2 && parts[1] === 'email-otp-base-factor')
    return { kind: 'email-otp-base-factor', linkSessionId };
  if (parts.length === 2 && parts[1] === 'owner-cancel')
    return { kind: 'owner-cancel', linkSessionId };
  if (parts.length === 3 && parts[1] === 'source-contribution' && parts[2] === 'execute')
    return { kind: 'source-contribution-execute', linkSessionId };
  if (parts.length !== 2 || !parts[1]) return null;
  switch (parts[1]) {
    case 'claim':
    case 'approval':
    case 'target-preparation':
    case 'credential':
    case 'source-contribution-preparation':
    case 'source-contribution':
    case 'ed25519-export-root':
    case 'ed25519-export-root-recipient':
    case 'receipt':
    case 'cancel':
      return { kind: parts[1], linkSessionId };
    default:
      return null;
  }
}

function requireApproval(session: LinkedDeviceSessionRecordV1): LinkedDeviceApprovalV1 {
  const approval = session.approvalTranscript?.value;
  if (!approval) throw new DeviceLinkingInputError('link session has no owner approval');
  return approval;
}

function requireSourceContributionApproval(
  session: LinkedDeviceSessionRecordV1,
): Extract<
  LinkedDeviceApprovalV1,
  { readonly sourceContribution: LinkedDeviceOrdinaryMaterialSourceContributionTupleV1 }
> {
  const approval = session.sourceContributionTranscript?.value;
  if (!approval?.sourceContribution) {
    throw new DeviceLinkingInputError('link session has no source contribution approval');
  }
  return approval;
}

function requireEd25519SourceContributionPreparation(
  session: LinkedDeviceSessionRecordV1,
): LinkedDeviceEd25519SourceContributionPreparationV1 {
  if (!session.sourceContributionPreparation) {
    throw new DeviceLinkingInputError('link session has no source contribution preparation');
  }
  const preparations = parseBoundary(() =>
    parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1(
      session.sourceContributionPreparation,
    ),
  );
  const ed25519 = preparations.find(
    (preparation): preparation is LinkedDeviceEd25519SourceContributionPreparationV1 =>
      'kind' in preparation,
  );
  if (!ed25519) {
    throw new DeviceLinkingInputError(
      'link session has no Ed25519 source contribution preparation',
    );
  }
  if (
    preparations.filter((preparation) => 'kind' in preparation).length !== 1 ||
    ed25519.linkSessionId !== session.linkSessionId
  ) {
    throw new DeviceLinkingInputError(
      'Ed25519 source contribution preparation does not match the link session',
    );
  }
  return ed25519;
}

function requireSentEmailOtpChallenge(
  session: LinkedDeviceSessionRecordV1,
): Extract<
  NonNullable<LinkedDeviceSessionRecordV1['emailOtpChallenge']>,
  { readonly state: 'sent' }
> {
  const challenge = session.emailOtpChallenge;
  if (!challenge || challenge.state !== 'sent')
    throw new DeviceLinkingInputError('email OTP challenge has not been sent');
  return challenge;
}

function parseEmailOtpChallengeRequest(
  raw: unknown,
  resend: boolean,
): LinkedDeviceEmailOtpChallengeStartRequestV1 | LinkedDeviceEmailOtpChallengeResendRequestV1 {
  return resend
    ? parseLinkedDeviceEmailOtpChallengeResendRequestV1(raw)
    : parseLinkedDeviceEmailOtpChallengeStartRequestV1(raw);
}

function readTargetPreparation(
  service: DeviceLinkingRouteServiceV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
  access:
    | { readonly access: 'create_or_replay'; readonly expectedOrigin: string }
    | { readonly access: 'replay_only' },
  nowMs: number,
): Promise<LinkedDeviceTargetPreparationV1> {
  return service.targetCredential.getTargetPreparationV1({
    session,
    approval,
    ...access,
    requestedAtMs: nowMs,
  });
}

async function authenticateTargetPasskeyOriginV1(
  ctx: FetchRouterApiContext,
  routeId: string,
): Promise<
  | { readonly ok: true; readonly expectedOrigin: string }
  | { readonly ok: false; readonly response: Response }
> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, routeId);
  if (!route) throw new Error(`Missing route definition for ${routeId}`);
  const publishableKeyAuth = ctx.opts.publishableKeyAuth;
  if (!publishableKeyAuth) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'service_not_configured',
          message: 'Publishable-key auth is not configured',
        },
        { status: 501 },
      ),
    };
  }
  const rawOrigin = String(ctx.request.headers.get('origin') || '').trim();
  const expectedOrigin = normalizeCorsOrigin(rawOrigin);
  if (!expectedOrigin || expectedOrigin !== rawOrigin) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'forbidden',
          message: 'Origin header is required and must be a valid exact origin',
        },
        { status: 403 },
      ),
    };
  }
  const headers = Object.fromEntries(ctx.request.headers.entries());
  const auth = await resolvePublishableKeyApiCredentialAuth({
    environmentId: extractRouterApiEnvironmentId(headers),
    headers,
    missingEnvironmentMessage: 'Environment header is required for linked-device Passkey setup',
    missingOriginMessage: 'Origin header is required and must be a valid exact origin',
    missingPublishableKeyMessage: 'Missing publishable key',
    origin: expectedOrigin,
    publishableKeyAuth,
    route,
    routeAuthNotConfiguredMessage: 'Linked-device Passkey route auth is not configured',
  });
  if (!auth.ok) {
    return {
      ok: false,
      response: json(
        { ok: false, code: auth.code, message: auth.message },
        { status: auth.status },
      ),
    };
  }
  return { ok: true, expectedOrigin };
}

function projectLinkSessionStateV1(state: LinkSessionStateV1): LinkSessionStateV1 {
  switch (state.state) {
    case 'displaying_qr':
      return { state: 'displaying_qr' };
    case 'claimed':
    case 'awaiting_target_factor':
    case 'awaiting_source_contribution':
    case 'provisioning':
      return { state: state.state, deviceId: state.deviceId };
    case 'authority_pending_local_install':
      return {
        state: 'authority_pending_local_install',
        deviceId: state.deviceId,
        authorityId: state.authorityId,
        packageSetDigestB64u: state.packageSetDigestB64u,
      };
    case 'active':
      return {
        state: 'active',
        deviceId: state.deviceId,
        authorityId: state.authorityId,
        activatedAtMs: state.activatedAtMs,
      };
    case 'failed_before_commit':
      return { state: 'failed_before_commit', error: state.error };
    case 'cancelled':
      return { state: 'cancelled', cancelledAtMs: state.cancelledAtMs };
    case 'expired':
      return { state: 'expired', expiredAtMs: state.expiredAtMs };
    default:
      return assertNeverLinkSessionStateV1(state);
  }
}

function projectSession(record: LinkedDeviceSessionRecordV1): LinkSessionProjectionV1 {
  return {
    kind: 'linked_device_session_projection_v1',
    linkSessionId: record.linkSessionId,
    qrPayload: record.qrPayload,
    revision: record.revision,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
    state: projectLinkSessionStateV1(record.state),
  };
}

function sessionProjectionResponse(
  record: LinkedDeviceSessionRecordV1,
  outcome: 'applied' | 'replayed',
): Response {
  return json({ ok: true, outcome, session: projectSession(record) }, { status: 200 });
}

export function targetCredentialResultResponse(
  record: LinkedDeviceSessionRecordV1,
  outcome: 'applied' | 'replayed',
  targetCredential: LinkedDeviceTargetCredentialRegistrationResultV1,
): Response {
  return json(
    { ok: true, outcome, targetCredential, session: projectSession(record) },
    { status: 200 },
  );
}

function claimResultResponse(result: LinkedDeviceSessionServiceResultV1): Response {
  if (result.outcome !== 'applied' && result.outcome !== 'replayed')
    return sessionResultResponse(result);
  const claim = result.record.claimTranscript?.value;
  return claim ? json(claim, { status: 200 }) : invalidStateResponse(result.record);
}

function approvalResultResponse(result: LinkedDeviceSessionServiceResultV1): Response {
  if (result.outcome !== 'applied' && result.outcome !== 'replayed')
    return sessionResultResponse(result);
  const record = result.record;
  if (record.state.state === 'active')
    return json(
      { ok: true, outcome: result.outcome, state: record.state, authorityId: record.authorityId },
      { status: 200 },
    );
  if (
    record.state.state === 'awaiting_target_factor' ||
    record.state.state === 'awaiting_source_contribution' ||
    record.state.state === 'provisioning' ||
    record.state.state === 'authority_pending_local_install'
  )
    return result.outcome === 'replayed'
      ? json(
          { outcome: 'replayed', replay: { state: 'pending', session: record.state } },
          { status: 200 },
        )
      : json({ outcome: 'pending', state: record.state }, { status: 200 });
  return invalidStateResponse(record);
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
    case 'integrity_error':
      return json(
        {
          ok: false,
          outcome: result.outcome,
          reason: result.reason,
          session: projectSession(result.record),
        },
        { status: 500 },
      );
    case 'unauthorized':
      return json(
        { ok: false, outcome: result.outcome, code: result.code, message: result.message },
        { status: 401 },
      );
    case 'invalid_input':
      return invalidInputResponse(result.message);
    case 'deleted':
      return json({ ok: true, outcome: result.outcome }, { status: 200 });
    default:
      return assertNever(result);
  }
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

function exportRootWriteResponse(result: {
  readonly outcome: 'applied' | 'replayed' | 'conflict';
  readonly reason?: string;
}): Response {
  return result.outcome === 'conflict'
    ? json(
        { ok: false, code: result.reason ?? 'conflict', message: 'export-root relay conflict' },
        { status: 409 },
      )
    : json({ ok: true, outcome: result.outcome }, { status: 200 });
}

function ownerSessionResponse(
  context: Exclude<AuthenticatedOwnerForSession, { readonly kind: 'authorized' }>,
): Response {
  return context.kind === 'denied' ? authDeniedResponse(context) : notFoundResponse();
}

/**
 * The one owner-to-session binding, shared by every owner route on a claimed
 * session. It runs before any state is disclosed: an authenticated owner of a
 * DIFFERENT wallet must get the same denial for every state, not a projection
 * or an invalid-state body. An unclaimed session has no wallet to bind to yet,
 * so the caller's state checks answer instead.
 */
function requireOwnerMatchesClaimedWallet(
  owner: LinkedDeviceOwnerAuthorizationContextV1,
  session: LinkedDeviceSessionRecordV1,
): Response | null {
  const claimWalletId = session.claimTranscript?.value.walletId;
  if (claimWalletId === undefined) return null;
  if (owner.walletId === claimWalletId) return null;
  return authDeniedResponse({
    kind: 'denied',
    code: 'unauthorized',
    message: 'owner session does not match link wallet',
  });
}

/**
 * Approval-time revalidation of the selected Email OTP base method. The same
 * eligibility question the dedicated base-factor route answers, asked once
 * more with the id the approval names, so the two paths cannot drift.
 */
async function requireSelectedEmailOtpBaseFactorV1(
  service: DeviceLinkingRouteServiceV1,
  session: LinkedDeviceSessionRecordV1,
  input: {
    readonly walletId: LinkedDeviceApprovalV1['walletId'];
    readonly baseWalletAuthMethodId: WalletAuthMethodId;
  },
): Promise<Response | null> {
  const provider = service.emailOtpTargetFactor;
  if (!provider) return notSupportedResponse('Email OTP linking is not configured');
  const selection = await provider.resolveBaseFactorSelectionV1({
    walletId: input.walletId,
    request: {
      kind: 'select',
      expectedRevision: session.revision,
      baseWalletAuthMethodId: input.baseWalletAuthMethodId,
    },
  });
  if (
    selection.kind !== 'selected' ||
    selection.choice.baseWalletAuthMethodId !== input.baseWalletAuthMethodId
  ) {
    return authDeniedResponse({
      kind: 'denied',
      code: 'unauthorized',
      message: 'Email OTP base method is unavailable',
    });
  }
  return null;
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

function notSupportedResponse(message = 'Device linking is not configured'): Response {
  return json({ ok: false, code: 'not_supported', message }, { status: 501 });
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
  return parseLinkedDeviceRequestProofV1(raw);
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
  if (
    proof.method !== method ||
    proof.canonicalPath !== pathname ||
    proof.linkSessionId !== linkSessionId
  )
    throw new DeviceLinkingInputError('request proof does not match method, path, or session');
  if (proof.bodyDigestB64u !== bodyDigestB64u)
    throw new DeviceLinkingInputError('request body digest does not match authenticated bytes');
  if (proof.devicePublicKeyDigestB64u !== devicePublicKeyDigestB64u)
    throw new DeviceLinkingInputError('request proof device identity does not match QR session');
  if (
    proof.expiresAtMs <= nowMs ||
    proof.issuedAtMs > nowMs ||
    proof.expiresAtMs <= proof.issuedAtMs
  )
    throw new DeviceLinkingInputError('request proof is expired');
  if (proof.expiresAtMs - proof.issuedAtMs > LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1)
    throw new DeviceLinkingInputError('request proof lifetime exceeds the maximum');
}

function validateOwnerRequestBinding(
  binding: DeviceLinkingRequestBindingV1,
  ctx: FetchRouterApiContext,
  bodyDigestB64u: DigestB64u,
  nowMs: number,
): void {
  if (
    binding.kind !== 'linked_device_owner_request_binding_v1' ||
    binding.method !== ctx.method ||
    binding.pathname !== ctx.pathname
  )
    throw new DeviceLinkingInputError('owner request binding does not match method or path');
  if (binding.bodyDigestB64u !== bodyDigestB64u || binding.expiresAtMs <= nowMs)
    throw new DeviceLinkingInputError(
      'owner request proof is expired or does not match the request',
    );
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

function parseB64uBytes(raw: unknown, field: string): Uint8Array {
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
  return bytes;
}

async function readJsonBody(request: Request): Promise<unknown> {
  return await readJson(request);
}

function parseBoundary<T>(parse: () => T): T {
  try {
    return parse();
  } catch (error: unknown) {
    throw new DeviceLinkingInputError(errorMessage(error));
  }
}

function requireRecord(raw: unknown, field: string): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error(`${field} must be an object`);
  return raw as Record<string, unknown>;
}

function requireExactKeys(record: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]))
    throw new Error('record contains invalid fields');
}

function parseOwnerCancelRequest(raw: unknown): { readonly expectedRevision: number } {
  const record = requireRecord(raw, 'owner cancel request');
  requireExactKeys(record, ['expectedRevision']);
  if (!Number.isSafeInteger(record.expectedRevision) || Number(record.expectedRevision) < 0) {
    throw new Error('owner cancel expectedRevision is invalid');
  }
  return { expectedRevision: Number(record.expectedRevision) };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'invalid device-linking request');
}

function assertNever(value: never): never {
  throw new Error(`unsupported device-linking value: ${String(value)}`);
}

class DeviceLinkingInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeviceLinkingInputError';
  }
}
