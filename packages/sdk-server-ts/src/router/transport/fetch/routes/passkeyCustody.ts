import type { FetchRouterApiContext } from '../createFetchRouter';
import type { PasskeyCustodyEnvelopeRetrievalWireRequest } from '../../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import {
  findRouteDefinitionById,
  matchesRouteDefinitionRequest,
} from '../../../framework/routeDefinitions';
import { toFetchRouteResponse } from '../../../framework/routeResponses';
import { readJson } from '../../../framework/http';
import { decodeBase64UrlOrBase64 } from '../../../../core/authService/webauthnOidcHelpers';
import { parseRecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import {
  admitWalletRecoveryEmailOtp,
  resolveWalletRecoveryAuthorizationContext,
} from '../../../domains/passkeyCustody/walletRecoveryAuthorization';
import type { AuthorizedOperation } from '../../../../authorization/domain';
import { parsePasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';

/**
 * The transport for custody envelope retrieval.
 *
 * Thin on purpose: it parses a body, hands it to the port, and returns what
 * the port decided. Every gate — assertion verification, credential match,
 * lifecycle, digest — lives below, and the status each failure earns is fixed
 * in one wire mapping. A transport that re-decided any of that would be a
 * second opinion on whether a wallet opens.
 */

const ROUTE_ID = 'passkey_custody_envelope_retrieve';
const RECOVERY_PREPARE_ROUTE_ID = 'wallet_recovery_prepare';
const RECOVERY_FINALIZE_ROUTE_ID = 'wallet_recovery_finalize';
const RECOVERY_ACK_ROUTE_ID = 'wallet_recovery_backup_acknowledge';
const RECOVERY_ROTATE_ROUTE_ID = 'wallet_recovery_codes_rotate';
const RECOVERY_STATUS_ROUTE_ID = 'wallet_recovery_status';

export async function handlePasskeyCustody(ctx: FetchRouterApiContext): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = (await readJson(ctx.request)) as Record<string, unknown> | null;
  const request = parseWireRequest(body, ctx.request.headers.get('origin'));
  if (!request) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'custody retrieval needs a locator, a challenge id, and an assertion',
      },
    });
  }

  const response = await ctx.service.passkeyCustody.retrieveEnvelope(request);
  return toFetchRouteResponse(response);
}

/**
 * Spending a recovery code.
 *
 * The refusal is one shape for every cause — unknown wallet, unknown code,
 * spent code. The domain deliberately makes them indistinguishable so the
 * route cannot be used to count how many of a user's ten codes remain, and
 * this must not helpfully re-separate them on the way out.
 */
export async function handleWalletRecoveryPrepare(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_PREPARE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_PREPARE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = (await readJson(ctx.request)) as Record<string, unknown> | null;
  const walletId = trimmed(body?.walletId);
  const recoveryCode = trimmed(body?.recoveryCode);
  const challengeId = trimmed(body?.challengeId);
  const otpCode = trimmed(body?.otpCode);
  let reservationId;
  try {
    reservationId = parseRecoveryCodeReservationId(body?.reservationId);
  } catch {
    reservationId = null;
  }
  if (!walletId || !recoveryCode || !reservationId || !challengeId || !otpCode) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message:
          'recovery preparation needs a wallet, operation id, Email OTP challenge, and recovery code',
      },
    });
  }

  const authorization = await resolveWalletRecoveryAuthorizationContext({
    headers: Object.fromEntries(ctx.request.headers.entries()),
    session: ctx.opts.session,
    walletId,
    reservationId,
    authorizedOperations: ctx.service.authorizedOperations,
    authorizationSessions: ctx.service.authorizationSessions,
  });
  if (!authorization.ok) return authorizationFailure(authorization);
  if (authorization.context.existing?.lifecycle === 'completed') {
    return authorizedOperationReplay(authorization.context.existing);
  }
  const admitted = await admitWalletRecoveryEmailOtp({
    context: authorization.context,
    emailOtp: ctx.service.emailOtp,
    walletId,
    reservationId,
    challengeId,
    otpCode,
    nowMs: Date.now(),
  });
  if (!admitted.ok) return authorizationFailure(admitted);
  if (admitted.operation.lifecycle === 'completed') {
    return authorizedOperationReplay(admitted.operation);
  }

  let recoveryCodeBytes: Uint8Array;
  try {
    recoveryCodeBytes = decodeRecoveryCode(recoveryCode);
  } catch {
    /* Answered exactly like a wrong code. A distinct "malformed" reply would
       tell an enumerating caller which candidates are even shaped like codes. */
    return toFetchRouteResponse(refusedSpend());
  }

  const result = await ctx.service.passkeyCustody.prepareRecovery({
    walletId,
    recoveryCodeBytes,
    reservationId,
  });

  switch (result.kind) {
    case 'prepared':
      return toFetchRouteResponse({
        status: 200,
        body: {
          ok: true,
          wrap: result.wrap,
          entries: result.entries,
          keyManifest: result.keyManifest,
          reservationId: result.reservationId,
          reservationExpiresAtMs: result.reservationExpiresAtMs,
          storeVersion: result.storeVersion,
        },
      });
    case 'conflict':
      /* 409, and retryable: another attempt committed against the version this
         one read. The code may still be good. */
      return toFetchRouteResponse({
        status: 409,
        body: {
          ok: false,
          code: 'recovery_set_conflict',
          message: 'the recovery set changed during this attempt; try again',
        },
      });
    case 'refused':
      return toFetchRouteResponse(refusedSpend());
    case 'manifest_unavailable':
      return toFetchRouteResponse({
        status: 409,
        body: {
          ok: false,
          code: 'recovery_manifest_unavailable',
          message: result.reason,
        },
      });
  }
}

function refusedSpend() {
  return {
    status: 401,
    body: {
      ok: false,
      code: 'recovery_code_rejected',
      message: 'that recovery code cannot be used',
    },
  };
}

function decodeRecoveryCode(value: string): Uint8Array {
  const normalized = value.replace(/[\s-]/g, '');
  if (!normalized) throw new Error('empty recovery code');
  return decodeBase64UrlOrBase64(normalized, 'recoveryCode');
}

function parseWireRequest(
  body: Record<string, unknown> | null,
  originHeader: string | null,
): PasskeyCustodyEnvelopeRetrievalWireRequest | null {
  if (!body || typeof body !== 'object') return null;

  const challengeId = trimmed(body.challengeId);
  const locator = body.locator;
  const webauthnAuthentication = body.webauthnAuthentication;
  if (!challengeId || !isObject(locator) || !isObject(webauthnAuthentication)) return null;

  /* Shape-checked here, content-checked below. This only establishes that an
     assertion was sent at all — whether it verifies is the retrieval's
     decision, and a transport that judged it would be a second gate. */
  if (
    !trimmed(webauthnAuthentication.id) ||
    !trimmed(webauthnAuthentication.rawId) ||
    !isObject(webauthnAuthentication.response)
  ) {
    return null;
  }

  /* The header, with no body fallback (frozen 2026-08-09). The sibling
     WebAuthn service takes `expected_origin` from its caller because it is
     called by an app server; on a browser-reachable route a value the
     requester supplies is not evidence of anything — it would let a caller
     name the origin its own assertion is checked against.

     A request with no Origin header is refused rather than read from the
     body: browsers set it on cross-origin POSTs, so its absence means the
     caller is not the browser this route exists for. */
  const expectedOrigin = trimmed(originHeader);
  if (!expectedOrigin) return null;

  return {
    challengeId,
    expectedOrigin,
    locator: locator as PasskeyCustodyEnvelopeRetrievalWireRequest['locator'],
    webauthnAuthentication:
      webauthnAuthentication as unknown as PasskeyCustodyEnvelopeRetrievalWireRequest['webauthnAuthentication'],
  };
}

function trimmed(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Installing the credential a recovery enrolled.
 *
 * The envelope arrives sealed, but its complete wire shape is parsed here.
 * The server has no seed and cannot open the ciphertext. Exact key coverage
 * comes from its signer registry and durable activation receipts.
 */
export async function handleWalletRecoveryFinalize(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_FINALIZE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_FINALIZE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  let requestBody: WalletRecoveryFinalizeBody | null;
  try {
    requestBody = parseWalletRecoveryFinalizeBody(await readJson(ctx.request));
  } catch {
    requestBody = null;
  }
  if (!requestBody) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'recovery finalization needs a wallet, operation id, and replacement envelope',
      },
    });
  }
  const { walletId, reservationId, replacementEnvelope } = requestBody;

  const authorization = await resolveWalletRecoveryAuthorizationContext({
    headers: Object.fromEntries(ctx.request.headers.entries()),
    session: ctx.opts.session,
    walletId,
    reservationId,
    authorizedOperations: ctx.service.authorizedOperations,
    authorizationSessions: ctx.service.authorizationSessions,
  });
  if (!authorization.ok) return authorizationFailure(authorization);
  const authorizedOperation = authorization.context.existing;
  if (!authorizedOperation) {
    return toFetchRouteResponse({
      status: 403,
      body: {
        ok: false,
        code: 'recovery_authorization_required',
        message: 'wallet recovery must be prepared with fresh Email OTP authorization',
      },
    });
  }
  if (authorizedOperation.lifecycle === 'completed') {
    return authorizedOperationReplay(authorizedOperation);
  }

  const result = await ctx.service.passkeyCustody.finalizeRecovery({
    walletId,
    reservationId,
    replacementEnvelope,
  });

  switch (result.kind) {
    case 'promoted':
      return await completeWalletRecoveryOperation(ctx, authorizedOperation, {
        status: 200,
        body: {
          ok: true,
          storeVersion: result.storeVersion,
          retiredEnvelopeIds: result.retiredEnvelopeIds,
          /* Surfaced rather than swallowed: the wallet is recovered, but an
             old credential still opens it and someone has to revoke it. */
          ...(result.retireFailures ? { retireFailures: result.retireFailures } : {}),
        },
      });
    case 'refused':
      /* 409: the recovery did not reproduce every key set. Retryable in the
         sense that finishing the outstanding ones makes it valid — unlike a
         rejected envelope, which will not become valid by repeating. */
      return toFetchRouteResponse({
        status: 409,
        body: { ok: false, code: 'promotion_incomplete', message: result.reason },
      });
    case 'conflict':
      return toFetchRouteResponse({
        status: 409,
        body: { ok: false, code: 'recovery_conflict', message: result.reason },
      });
    case 'envelope_rejected':
      return toFetchRouteResponse({
        status: 400,
        body: { ok: false, code: 'envelope_rejected', message: result.reason },
      });
  }
}

type WalletRecoveryFinalizeBody = {
  readonly walletId: WalletId;
  readonly reservationId: ReturnType<typeof parseRecoveryCodeReservationId>;
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
};

function parseWalletRecoveryFinalizeBody(value: unknown): WalletRecoveryFinalizeBody {
  if (!isObject(value)) throw new Error('wallet recovery finalization body must be an object');
  requireExactFinalizeFields(value);
  const walletId = parseWalletId(value.walletId);
  if (!walletId.ok) throw new Error('wallet recovery finalization wallet is invalid');
  return {
    walletId: walletId.value,
    reservationId: parseRecoveryCodeReservationId(value.reservationId),
    replacementEnvelope: parsePasskeyCustodyEnvelopeRecord(
      value.replacementEnvelope,
      'walletRecoveryFinalize.replacementEnvelope',
    ),
  };
}

function requireExactFinalizeFields(value: Record<string, unknown>): void {
  const allowed = new Set(['walletId', 'reservationId', 'replacementEnvelope']);
  for (const field of Object.keys(value)) {
    if (!allowed.has(field)) {
      throw new Error(`wallet recovery finalization.${field} is not allowed`);
    }
  }
  if (!allowedKeysArePresent(value, allowed)) {
    throw new Error('wallet recovery finalization is missing a required field');
  }
}

function allowedKeysArePresent(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): boolean {
  for (const field of allowed) {
    if (!(field in value)) return false;
  }
  return true;
}

function authorizationFailure(input: {
  readonly status: number;
  readonly code: string;
  readonly message: string;
}): Response {
  return toFetchRouteResponse({
    status: input.status,
    body: { ok: false, code: input.code, message: input.message },
  });
}

function authorizedOperationReplay(operation: AuthorizedOperation): Response {
  if (operation.lifecycle !== 'completed') {
    return toFetchRouteResponse({
      status: 409,
      body: {
        ok: false,
        code: 'recovery_in_progress',
        message: 'wallet recovery is still in progress',
      },
    });
  }
  return new Response(operation.response.bodyText, {
    status: operation.response.status,
    headers: { 'content-type': operation.response.contentType },
  });
}

async function completeWalletRecoveryOperation(
  ctx: FetchRouterApiContext,
  operation: AuthorizedOperation,
  result: { readonly status: number; readonly body: Record<string, unknown> },
): Promise<Response> {
  const bodyText = JSON.stringify(result.body);
  await ctx.service.authorizedOperations.completeAuthorizedOperation({
    operation,
    result: 'succeeded',
    response: { status: result.status, contentType: 'application/json', bodyText },
    completedAtMs: Date.now(),
  });
  return new Response(bodyText, {
    status: result.status,
    headers: { 'content-type': 'application/json' },
  });
}

/**
 * Recording that the owner saved their recovery codes.
 *
 * The one thing this must not do is succeed for a wallet with no recovery
 * set. That would write an acknowledgement covering an issuance that never
 * happened, and the user would never be asked to save the codes they
 * eventually get.
 */
export async function handleWalletRecoveryBackupAcknowledge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_ACK_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_ACK_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = (await readJson(ctx.request)) as Record<string, unknown> | null;
  const walletId = trimmed(body?.walletId);
  if (!walletId) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'an acknowledgement needs a wallet' },
    });
  }

  const result = await ctx.service.passkeyCustody.acknowledgeRecoveryBackup({ walletId });
  if (result.kind === 'no_recovery_set') {
    return toFetchRouteResponse({
      status: 404,
      body: {
        ok: false,
        code: 'no_recovery_set',
        message: 'this wallet has no issued recovery codes to acknowledge',
      },
    });
  }
  return toFetchRouteResponse({
    status: 200,
    /* Echoes the issuance it covered, so a client can tell whether its own
       view of "which codes" matches what the server just recorded. */
    body: { ok: true, issuedAtMs: result.issuedAtMs },
  });
}

/**
 * Rotating a wallet's recovery codes.
 *
 * The wraps pass through as opaque records — the server cannot check that
 * they wrap the right KEK, because it has neither. What it does check is the
 * set's shape, and it does so before writing: a set that reaches the store
 * with the wrong number of wraps leaves a wallet holding fewer codes than its
 * owner wrote down, and nothing surfaces that until someone counts.
 */
export async function handleWalletRecoveryRotate(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_ROTATE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_ROTATE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = (await readJson(ctx.request)) as Record<string, unknown> | null;
  const walletId = trimmed(body?.walletId);
  const manifestKekWraps = Array.isArray(body?.manifestKekWraps)
    ? body.manifestKekWraps.filter(isObject)
    : [];
  if (!walletId || manifestKekWraps.length === 0) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'a rotation needs a wallet and its replacement code wraps',
      },
    });
  }

  const result = await ctx.service.passkeyCustody.rotateRecoveryCodes({
    walletId,
    manifestKekWraps: manifestKekWraps as never,
  });

  switch (result.kind) {
    case 'rotated':
      return toFetchRouteResponse({
        status: 200,
        /* The new issuance timestamp, which is what re-arms the backup
           prompt — a client that shows codes without it cannot tell whether
           the user has acknowledged the set in front of them. */
        body: { ok: true, issuedAtMs: result.issuedAtMs, storeVersion: result.storeVersion },
      });
    case 'no_recovery_set':
      return toFetchRouteResponse({
        status: 404,
        body: { ok: false, code: 'no_recovery_set', message: 'this wallet has no codes to rotate' },
      });
    case 'conflict':
      return toFetchRouteResponse({
        status: 409,
        body: {
          ok: false,
          code: 'recovery_set_conflict',
          message: 'the recovery set changed during this rotation; try again',
        },
      });
    case 'rejected':
      return toFetchRouteResponse({
        status: 400,
        body: { ok: false, code: 'rotation_rejected', message: result.reason },
      });
  }
}

/**
 * Reporting recovery status to the wallet's owner.
 *
 * The wallet comes from the path, and the route sits behind credentials —
 * that is what makes counting remaining codes safe here and unsafe on the
 * spend route beside it.
 *
 * Counts only, never identifiers. Which codes remain is not something even
 * the owner's browser needs, and a list would be one leak away from being
 * useful to someone else.
 */
export async function handleWalletRecoveryStatus(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_STATUS_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_STATUS_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const walletId = walletIdFromPath(route.path, ctx.pathname);
  if (!walletId) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'status needs a wallet' },
    });
  }

  const result = await ctx.service.passkeyCustody.readRecoveryStatus({ walletId });
  if (result.kind === 'no_recovery_set') {
    return toFetchRouteResponse({
      status: 404,
      body: { ok: false, code: 'no_recovery_set', message: 'this wallet has no recovery codes' },
    });
  }
  return toFetchRouteResponse({
    status: 200,
    body: {
      ok: true,
      activeCodeCount: result.activeCodeCount,
      totalCodeCount: result.totalCodeCount,
      issuedAtMs: result.issuedAtMs,
      backupOutstanding: result.backupOutstanding,
    },
  });
}

function walletIdFromPath(routePath: string, pathname: string): string {
  const routeSegments = routePath.split('/').filter(Boolean);
  const pathSegments = pathname.split('/').filter(Boolean);
  const index = routeSegments.indexOf(':walletId');
  if (index < 0) return '';
  const segment = pathSegments[index];
  return segment ? decodeURIComponent(segment).trim() : '';
}
