import type {
  LinkedDeviceOwnerAuthorizationRequestV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import { parseLinkedDeviceOwnerAuthorizationRequestV1 } from '@shared/device-linking/parsers';
import type {
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletId } from '@shared/utils/domainIds';
import type { WalletId } from '@shared/utils/domainIds';
import type { ThresholdEd25519AuthorityScope } from '../../../../core/types';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import type { WalletExecutionLaneAuthSource } from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { ExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';
import type { RouterApiAuthorizationSessionService } from '../../../framework/authServicePort';
import type { FetchRouterApiContext } from '../createFetchRouter';
import type { DeviceLinkingAuthDeniedV1, DeviceLinkingOwnerRequestInputV1 } from './deviceLinking';
import { json, readJson } from '../../../framework/http';
import {
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../../auth/commonRouterUtils';

export const LINKED_DEVICE_OWNER_AUTHORIZATION_PATH_V1 =
  '/wallet/device-linking/v1/owner-authorization' as const;

export type DeviceLinkingOwnerAuthorizationAuthenticationV1 = {
  readonly kind: 'link_session_authenticated_request_v1';
  readonly source: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly proofDigestB64u: DigestB64u;
};

export type DeviceLinkingOwnerAuthorizationResponseV1 = {
  readonly authentication: DeviceLinkingOwnerAuthorizationAuthenticationV1;
  readonly walletId: WalletId;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1;
  readonly sourceSignerManifest: ExactAdministeredSignerManifestV1;
  readonly expiresAtMs: number;
};

export type DeviceLinkingOwnerWalletSessionContextV1 =
  | {
      readonly walletId: WalletId;
      readonly walletSessionId: WalletSessionId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly expiresAtMs: number;
      readonly permission: DelegatedWalletAuthorityV1;
      /** The manifest this owner session's key set was registered against. */
      readonly keyManifestDigestB64u: DigestB64u;
      readonly curve: 'ed25519';
      readonly authority: WalletAuthAuthority;
      readonly authorityScope: ThresholdEd25519AuthorityScope;
      readonly walletAuthAuthorityRef?: never;
      readonly authSource?: never;
    }
  | {
      readonly walletId: WalletId;
      readonly walletSessionId: WalletSessionId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly expiresAtMs: number;
      readonly permission: DelegatedWalletAuthorityV1;
      /** The manifest this owner session's key set was registered against. */
      readonly keyManifestDigestB64u: DigestB64u;
      readonly curve: 'ecdsa';
      readonly walletAuthAuthorityRef: WalletAuthAuthorityRef;
      readonly authSource: WalletExecutionLaneAuthSource;
      readonly authority?: never;
      readonly authorityScope?: never;
    };

export type DeviceLinkingOwnerRequestAuthenticationV1 =
  | {
      readonly kind: 'authorized';
      readonly body: unknown;
      readonly binding: {
        readonly kind: 'linked_device_owner_request_binding_v1';
        readonly method: 'GET' | 'POST';
        readonly pathname: string;
        readonly bodyDigestB64u: DigestB64u;
        readonly expiresAtMs: number;
      };
      readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    }
  | DeviceLinkingAuthDeniedV1;

export type DeviceLinkingOwnerAuthorizationRouteServiceV1 = {
  authorizeOwnerForLinkingV1(input: {
    readonly payload: QrLinkedDeviceSessionPayloadV5;
    readonly requestedAtMs: number;
    readonly bodyDigestB64u: DigestB64u;
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
  }): Promise<DeviceLinkingOwnerAuthorizationResponseV1>;
};

/**
 * Request-scoped owner bearer verifier used by claim, approval, and the owner
 * authorization metadata route. The returned binding is valid only until the
 * verified Wallet Session expires and is bound to the exact request bytes.
 */
export function createDeviceLinkingOwnerRequestAuthenticatorV1(input: {
  readonly authorizationSessions: RouterApiAuthorizationSessionService;
  readonly nowV1?: () => number;
}): (
  input: DeviceLinkingOwnerRequestInputV1,
) => Promise<DeviceLinkingOwnerRequestAuthenticationV1> {
  const nowV1 = input.nowV1 ?? Date.now;
  return async (requestInput) => {
    const authenticated = await authenticateDeviceLinkingOwnerWalletSessionRequestV1({
      ...requestInput,
      authorizationSessions: input.authorizationSessions,
      nowV1,
    });
    if (authenticated.kind === 'denied') return authenticated;
    return {
      kind: 'authorized',
      body: authenticated.body,
      binding: authenticated.binding,
      owner: authenticated.owner,
    };
  };
}

export async function authenticateDeviceLinkingOwnerWalletSessionRequestV1(input: {
  readonly request: Request;
  readonly method: string;
  readonly pathname: string;
  readonly bodyDigestB64u: DigestB64u;
  readonly requestedAtMs: number;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly nowV1?: () => number;
}): Promise<DeviceLinkingOwnerRequestAuthenticationV1> {
  if (input.method !== 'GET' && input.method !== 'POST') {
    return {
      kind: 'denied',
      code: 'invalid',
      message: 'Owner request method is invalid',
    };
  }
  const nowV1 = input.nowV1 ?? Date.now;
  const body = await readClonedJson(input.request);
  const headers = Object.fromEntries(input.request.headers.entries());
  const validated = await validateOwnerWalletSessionV1({
    body,
    headers,
    authorizationSessions: input.authorizationSessions,
    nowV1,
  });
  if (validated.kind === 'denied') return validated;
  return {
    kind: 'authorized',
    body,
    binding: {
      kind: 'linked_device_owner_request_binding_v1',
      method: input.method,
      pathname: input.pathname,
      bodyDigestB64u: input.bodyDigestB64u,
      expiresAtMs: validated.owner.expiresAtMs,
    },
    owner: validated.owner,
  };
}

export async function handleDeviceLinkingOwnerAuthorization(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingOwnerAuthorizationRouteServiceV1 | undefined,
): Promise<Response | null> {
  if (ctx.pathname !== LINKED_DEVICE_OWNER_AUTHORIZATION_PATH_V1) return null;
  if (ctx.method !== 'POST') return methodNotAllowedResponse();
  if (!service) {
    return json(
      {
        ok: false,
        code: 'not_supported',
        message: 'Linked-device owner authorization is not configured',
      },
      { status: 501 },
    );
  }
  const nowV1 = Date.now;
  let body: LinkedDeviceOwnerAuthorizationRequestV1;
  let rawBody: unknown;
  let bodyDigestB64u: DigestB64u;
  try {
    bodyDigestB64u = await requestBodyDigest(ctx.request);
    // Keep the original body untouched for the request-scoped verifier.
    rawBody = await readJson(ctx.request.clone());
    body = parseLinkedDeviceOwnerAuthorizationRequestV1(rawBody);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Owner authorization body is invalid',
      },
      { status: 400 },
    );
  }
  const validated = await authenticateDeviceLinkingOwnerWalletSessionRequestV1({
    request: ctx.request,
    method: ctx.method,
    pathname: ctx.pathname,
    bodyDigestB64u,
    requestedAtMs: body.requestedAtMs,
    authorizationSessions: ctx.service.authorizationSessions,
    nowV1,
  });
  if (validated.kind === 'denied') return authDeniedResponse(validated);
  try {
    const response = await service.authorizeOwnerForLinkingV1({
      payload: body.payload,
      requestedAtMs: body.requestedAtMs,
      bodyDigestB64u,
      owner: validated.owner,
    });
    return json(response, { status: 200 });
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'internal',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}

type OwnerValidationResultV1 =
  | {
      readonly kind: 'authorized';
      readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    }
  | {
      readonly kind: 'denied';
      readonly code: 'unauthorized' | 'expired' | 'invalid' | 'replayed';
      readonly message: string;
    };

async function validateOwnerWalletSessionV1(input: {
  readonly body: unknown;
  readonly headers: Record<string, string>;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly nowV1: () => number;
}): Promise<OwnerValidationResultV1> {
  const ed25519 = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: input.body,
    headers: input.headers,
    authorizationSessions: input.authorizationSessions,
    nowMs: input.nowV1,
  });
  if (ed25519.ok) {
    const walletId = parseWalletIdBoundary(ed25519.binding.walletId);
    const walletSessionId = parseWalletSessionIdBoundary(ed25519.binding.walletSessionId);
    const authorizationId = parseWalletSessionAuthorizationIdBoundary(
      ed25519.binding.authorizationId,
    );
    if (!walletId || !walletSessionId || !authorizationId) {
      return denied('invalid', 'Wallet Session identity is invalid');
    }
    return {
      kind: 'authorized',
      owner: {
        walletId,
        walletSessionId,
        authorizationId,
        expiresAtMs: ed25519.walletSessionAuth.expiresAtMs,
        permission: buildFullOwnerDelegatedWalletAuthorityV1(),
        keyManifestDigestB64u: ed25519.binding.keyManifestDigestB64u,
        curve: 'ed25519',
        authority: ed25519.binding.authority,
        authorityScope: ed25519.binding.authorityScope,
      },
    };
  }

  const ecdsa = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: input.body,
    headers: input.headers,
    authorizationSessions: input.authorizationSessions,
    nowMs: input.nowV1,
  });
  if (ecdsa.ok) {
    const walletId = parseWalletIdBoundary(ecdsa.binding.walletId);
    const walletSessionId = parseWalletSessionIdBoundary(ecdsa.binding.walletSessionId);
    const authorizationId = parseWalletSessionAuthorizationIdBoundary(
      ecdsa.binding.authorizationId,
    );
    if (!walletId || !walletSessionId || !authorizationId) {
      return denied('invalid', 'Wallet Session identity is invalid');
    }
    return {
      kind: 'authorized',
      owner: {
        walletId,
        walletSessionId,
        authorizationId,
        expiresAtMs: ecdsa.walletSessionAuth.expiresAtMs,
        permission: buildFullOwnerDelegatedWalletAuthorityV1(),
        keyManifestDigestB64u: ecdsa.binding.keyManifestDigestB64u,
        curve: 'ecdsa',
        walletAuthAuthorityRef: ecdsa.binding.walletAuthAuthorityRef,
        authSource: ecdsa.binding.authSource,
      },
    };
  }
  const code =
    ed25519.code === 'wallet_session_expired' || ecdsa.code === 'wallet_session_expired'
      ? 'expired'
      : ed25519.code === 'wallet_session_invalid' || ecdsa.code === 'wallet_session_invalid'
        ? 'invalid'
        : 'unauthorized';
  return denied(code, 'An active owner Wallet Session is required');
}

async function readClonedJson(request: Request): Promise<unknown> {
  if (request.method === 'GET') return {};
  try {
    return await request.clone().json();
  } catch {
    return {};
  }
}

async function requestBodyDigest(request: Request): Promise<DigestB64u> {
  const bytes = new Uint8Array(await request.clone().arrayBuffer());
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(bytes)));
}

function parseWalletIdBoundary(raw: unknown): WalletId | null {
  const parsed = parseWalletId(raw);
  return parsed.ok ? parsed.value : null;
}

function parseWalletSessionIdBoundary(raw: unknown): WalletSessionId | null {
  const parsed = parseWalletSessionId(raw);
  return parsed.ok ? parsed.value : null;
}

function parseWalletSessionAuthorizationIdBoundary(
  raw: unknown,
): WalletSessionAuthorizationId | null {
  const parsed = parseWalletSessionAuthorizationId(raw);
  return parsed.ok ? parsed.value : null;
}

function denied(
  code: 'unauthorized' | 'expired' | 'invalid' | 'replayed',
  message: string,
): Extract<OwnerValidationResultV1, { readonly kind: 'denied' }> {
  return { kind: 'denied', code, message };
}

function methodNotAllowedResponse(): Response {
  return json({ ok: false, code: 'method_not_allowed' }, { status: 405 });
}

function authDeniedResponse(
  value: Extract<OwnerValidationResultV1, { readonly kind: 'denied' }>,
): Response {
  const status = value.code === 'expired' ? 401 : value.code === 'invalid' ? 403 : 401;
  return json({ ok: false, code: value.code, message: value.message }, { status });
}
