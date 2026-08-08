import {
  retrievePasskeyCustodyEnvelope,
  type PasskeyCustodyEnvelopeRetrievalRequest,
  type PasskeyCustodyEnvelopeRetrievalResult,
} from './passkeyCustodyEnvelopeRetrieval';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type { WebAuthnAuthenticatorStore } from '../../../core/WebAuthnAuthenticatorStore';
import type { NormalizedLogger } from '../../../core/logger';

/**
 * The route a browser with empty IndexedDB uses to fetch its wallet's custody
 * envelope.
 *
 * Synced cold unlock needs it: the same passkey is available on the new device,
 * but the envelope is server-held and nothing local has it. The retrieval
 * itself was already written and gated; what was missing was any way to reach
 * it over the wire, which is what made cold unlock unimplementable end to end.
 *
 * **The response carries ciphertext and public binding only.** The KEK derives
 * from the PRF result, which never leaves the browser's secure worker — so this
 * route cannot open what it returns, and a compromised server learns no custody
 * secret by answering.
 *
 * Every failure is a distinct status rather than one generic refusal. A client
 * must be able to tell "your credential is no longer active" from "this wallet
 * has no envelope" from "the stored record is corrupt": the first two are
 * things a user can act on, and the third is an incident.
 */

export type PasskeyCustodyEnvelopeRetrievalRouteResponse = {
  readonly status: number;
  readonly body: Record<string, unknown>;
};

export async function handlePasskeyCustodyEnvelopeRetrieval(input: {
  readonly request: PasskeyCustodyEnvelopeRetrievalRequest;
  readonly envelopeStore: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly authenticatorStore: WebAuthnAuthenticatorStore;
  readonly logger: NormalizedLogger;
}): Promise<PasskeyCustodyEnvelopeRetrievalRouteResponse> {
  const result = await retrievePasskeyCustodyEnvelope(input);
  return passkeyCustodyEnvelopeRetrievalRouteResponse(result);
}

/**
 * The wire mapping, exported because it is the part with the decisions.
 *
 * The retrieval it wraps is tested on its own; what belongs here is which
 * status each outcome earns, and that is worth reading and testing without a
 * store, an authenticator, or an assertion.
 */
export function passkeyCustodyEnvelopeRetrievalRouteResponse(
  result: PasskeyCustodyEnvelopeRetrievalResult,
): PasskeyCustodyEnvelopeRetrievalRouteResponse {
  switch (result.kind) {
    case 'active':
      return {
        status: 200,
        body: {
          ok: true,
          envelope: result.envelope,
          /* The exact revision the client must match before trusting any
             cached copy. Without it a browser could open a stale local
             envelope against a rewrapped server one and fail to unlock with a
             correct credential. */
          storeVersion: result.storeVersion,
        },
      };
    case 'prf_disclosed':
      /* 400, not 403: the request is malformed in a way the client must fix,
         and it means a PRF result escaped the worker. Loud on purpose — a
         server that quietly sanitized and served would hide the escape. */
      return refusal(400, 'prf_disclosed', result.message);
    case 'assertion_rejected':
      return refusal(401, result.code, result.message);
    case 'credential_mismatch':
      return refusal(
        403,
        'credential_mismatch',
        'the assertion does not name the credential this envelope is sealed to',
      );
    case 'retired':
      return refusal(
        409,
        'envelope_retired',
        'this envelope was superseded; unlock with the wallet current credential',
      );
    case 'revoked':
      return refusal(403, 'envelope_revoked', 'this credential no longer opens the wallet');
    case 'missing':
      return refusal(404, 'envelope_missing', 'no custody envelope for this wallet and credential');
    case 'digest_mismatch':
      /* 500: the stored record disagrees with itself, which is a server-side
         integrity failure rather than anything the client did. Never falls
         back to derivation — a wallet must not be re-registered because a row
         is corrupt. */
      return refusal(500, 'envelope_digest_mismatch', 'stored custody envelope failed its digest');
  }
}

function refusal(
  status: number,
  code: string,
  message: string,
): PasskeyCustodyEnvelopeRetrievalRouteResponse {
  return { status, body: { ok: false, code, message } };
}
