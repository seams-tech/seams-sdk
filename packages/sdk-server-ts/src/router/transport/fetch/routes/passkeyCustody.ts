import type { FetchRouterApiContext } from '../createFetchRouter';
import type { PasskeyCustodyEnvelopeRetrievalWireRequest } from '../../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import {
  findRouteDefinitionById,
  matchesRouteDefinitionRequest,
} from '../../../framework/routeDefinitions';
import { toFetchRouteResponse } from '../../../framework/routeResponses';
import { readJson } from '../../../framework/http';
import { decodeBase64UrlOrBase64 } from '../../../../core/authService/webauthnOidcHelpers';

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
const RECOVERY_SPEND_ROUTE_ID = 'wallet_recovery_code_spend';

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
export async function handleWalletRecoverySpend(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_SPEND_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_SPEND_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = (await readJson(ctx.request)) as Record<string, unknown> | null;
  const walletId = trimmed(body?.walletId);
  const recoveryCode = trimmed(body?.recoveryCode);
  const reservationId = trimmed(body?.reservationId);
  if (!walletId || !recoveryCode || !reservationId) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'a recovery spend needs a wallet, a code, and a reservation id',
      },
    });
  }

  let recoveryCodeBytes: Uint8Array;
  try {
    recoveryCodeBytes = decodeRecoveryCode(recoveryCode);
  } catch {
    /* Answered exactly like a wrong code. A distinct "malformed" reply would
       tell an enumerating caller which candidates are even shaped like codes. */
    return toFetchRouteResponse(refusedSpend());
  }

  const result = await ctx.service.passkeyCustody.spendRecoveryCode({
    walletId,
    recoveryCodeBytes,
    reservationId,
  });

  switch (result.kind) {
    case 'committed':
      return toFetchRouteResponse({
        status: 200,
        body: {
          ok: true,
          wrap: result.wrap,
          entries: result.entries,
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

  /* The Origin header wins over anything in the body. A request that names one
     origin in its headers and another in its payload is not a request worth
     guessing about. */
  const expectedOrigin = trimmed(originHeader) || trimmed(body.expectedOrigin);
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
