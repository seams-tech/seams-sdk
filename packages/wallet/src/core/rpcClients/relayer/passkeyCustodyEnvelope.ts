import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

/**
 * Fetching a wallet's custody envelope from a device that has none.
 *
 * The server route answers with a distinct status per failure, and this keeps
 * them distinct. Collapsing them into one error is the tempting shape and the
 * wrong one: "this credential no longer opens the wallet" is something the
 * user can act on, "no envelope exists here" means they should register, and a
 * digest mismatch is an incident. A single `throw` makes all three read as
 * "unlock failed", which is how a recoverable state becomes a support ticket.
 *
 * The response is ciphertext. Opening it needs the PRF-derived KEK, which
 * exists only inside the signing worker — nothing here can read what it
 * fetches, and that is why the envelope may cross the network at all.
 */

const PASSKEY_CUSTODY_ENVELOPE_PATH = '/wallets/custody/envelope';

export type PasskeyCustodyEnvelopeFetchResult =
  | {
      readonly kind: 'active';
      /** Opaque here: the sealed record, for the worker to open. */
      readonly envelope: Record<string, unknown>;
      /** The revision a cached copy must match before it is trusted. */
      readonly storeVersion: string;
    }
  /** The credential is not this wallet's, or no longer opens it. */
  | { readonly kind: 'credential_rejected'; readonly code: string; readonly message: string }
  /** This wallet has no envelope for this credential — enrolment, not unlock. */
  | { readonly kind: 'missing'; readonly message: string }
  /** Superseded; the wallet's current credential is the one to use. */
  | { readonly kind: 'retired'; readonly message: string }
  /** The stored record failed its own digest. Never retried, never derived. */
  | { readonly kind: 'corrupt'; readonly message: string }
  | { readonly kind: 'request_rejected'; readonly code: string; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function fetchPasskeyCustodyEnvelope(args: {
  readonly relayUrl: string;
  readonly locator: unknown;
  readonly challengeId: string;
  readonly expectedOrigin: string;
  /** Assertion with extension outputs already stripped in the worker. */
  readonly webauthnAuthentication: unknown;
  readonly fetchImpl?: typeof fetch;
}): Promise<PasskeyCustodyEnvelopeFetchResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${PASSKEY_CUSTODY_ENVELOPE_PATH}`;
  const doFetch = args.fetchImpl || fetch;

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        body: {
          locator: args.locator,
          challengeId: args.challengeId,
          expectedOrigin: args.expectedOrigin,
          webauthnAuthentication: args.webauthnAuthentication,
        },
      }),
    );
  } catch (error: unknown) {
    /* Kept separate from every server refusal. A network failure says nothing
       about whether the credential is valid, and retrying is reasonable —
       which is not true of any of the statuses below. */
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'custody envelope request failed',
    };
  }

  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  const code = typeof body.code === 'string' ? body.code : '';
  const message = typeof body.message === 'string' ? body.message : '';

  if (response.status === 200 && body.ok === true) {
    const envelope = isRecord(body.envelope) ? body.envelope : null;
    const storeVersion = String(body.storeVersion || '').trim();
    if (!envelope || !storeVersion) {
      /* A 200 that cannot be used is treated as corrupt rather than active:
         unlocking against a half-read response would fail later and further
         from the cause. */
      return { kind: 'corrupt', message: 'custody envelope response was incomplete' };
    }
    return { kind: 'active', envelope, storeVersion };
  }

  switch (response.status) {
    case 404:
      return { kind: 'missing', message: message || 'no custody envelope for this credential' };
    case 409:
      return { kind: 'retired', message: message || 'this envelope was superseded' };
    case 401:
    case 403:
      return {
        kind: 'credential_rejected',
        code: code || 'credential_rejected',
        message: message || 'this credential does not open the wallet',
      };
    case 500:
      if (code === 'envelope_digest_mismatch') {
        return { kind: 'corrupt', message: message || 'stored custody envelope failed its digest' };
      }
      return {
        kind: 'transport_failed',
        message: message || `custody envelope request failed (HTTP ${response.status})`,
      };
    default:
      return {
        kind: 'request_rejected',
        code: code || 'invalid_request',
        message: message || `custody envelope request rejected (HTTP ${response.status})`,
      };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Refactor 109C: hands a resealed pre-109C envelope to the server.
 *
 * The unlock that opened an `unbound` envelope has already resealed it under
 * the exact method that authenticated. This is the only thing left to do with
 * that result, and the only thing this call does — no new envelope, no factor
 * change, no seed leaves the worker.
 *
 * Every outcome except a transport failure is terminal for this attempt, and
 * none of them is worth surfacing to the user: the V2 row stands, the wallet
 * still opens, and the next unlock tries again. The caller logs and moves on.
 */
export type WalletCustodyEnvelopeOwnershipUpgradeOutcome =
  | { readonly kind: 'upgraded'; readonly envelopeRevision: number }
  /** The envelope already names this method — an earlier attempt landed. */
  | { readonly kind: 'already_owned' }
  | { readonly kind: 'rejected'; readonly code: string; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

export async function upgradeWalletCustodyEnvelopeOwnership(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly walletSessionToken: string;
  readonly envelope: unknown;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletCustodyEnvelopeOwnershipUpgradeOutcome> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}/wallets/${encodeURIComponent(
    args.walletId,
  )}/custody/envelope/ownership`;
  const doFetch = args.fetchImpl || fetch;

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        body: { envelope: args.envelope },
        headers: buildBearerAuthorizationHeader({
          token: args.walletSessionToken,
          missingMessage: 'custody envelope upgrade needs an active Wallet Session',
        }),
      }),
    );
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'custody envelope upgrade failed',
    };
  }

  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  if (response.status === 200 && body.ok === true) {
    if (body.upgraded !== true) return { kind: 'already_owned' };
    const envelopeRevision = Number(body.envelopeRevision);
    return Number.isSafeInteger(envelopeRevision) && envelopeRevision > 0
      ? { kind: 'upgraded', envelopeRevision }
      : {
          kind: 'rejected',
          code: 'invalid_response',
          message: 'custody envelope upgrade returned no revision',
        };
  }
  return {
    kind: 'rejected',
    code: typeof body.code === 'string' && body.code ? body.code : 'upgrade_rejected',
    message:
      typeof body.message === 'string' && body.message
        ? body.message
        : `custody envelope upgrade rejected (HTTP ${response.status})`,
  };
}
