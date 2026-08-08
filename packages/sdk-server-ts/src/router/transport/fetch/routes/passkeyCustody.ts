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
const RECOVERY_PROMOTE_ROUTE_ID = 'wallet_recovery_credential_promote';
const RECOVERY_ACK_ROUTE_ID = 'wallet_recovery_backup_acknowledge';
const RECOVERY_ROTATE_ROUTE_ID = 'wallet_recovery_codes_rotate';

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

/**
 * Installing the credential a recovery enrolled.
 *
 * The envelope arrives sealed and is passed through unvalidated as ciphertext
 * — the server has no seed and cannot check the sealing. What it checks is
 * upstream: that the outcomes cover every required key set, and that the
 * envelope names this wallet.
 */
export async function handleWalletRecoveryPromote(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_PROMOTE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_PROMOTE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = (await readJson(ctx.request)) as Record<string, unknown> | null;
  const walletId = trimmed(body?.walletId);
  const replacementEnvelope = isObject(body?.replacementEnvelope) ? body.replacementEnvelope : null;
  const requiredKeySets = stringList(body?.requiredKeySets);
  const outcomes = Array.isArray(body?.outcomes) ? body.outcomes.filter(isObject) : [];
  if (!walletId || !replacementEnvelope || requiredKeySets.length === 0) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'a promotion needs a wallet, a replacement envelope, and its required key sets',
      },
    });
  }

  const result = await ctx.service.passkeyCustody.promoteRecoveredCredential({
    walletId,
    replacementEnvelope: replacementEnvelope as never,
    requiredKeySets,
    outcomes: outcomes as never,
  });

  switch (result.kind) {
    case 'promoted':
      return toFetchRouteResponse({
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
    case 'envelope_rejected':
      return toFetchRouteResponse({
        status: 400,
        body: { ok: false, code: 'envelope_rejected', message: result.reason },
      });
  }
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const entry of value) {
    const text = trimmed(entry);
    if (text) out.push(text);
  }
  return out;
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
