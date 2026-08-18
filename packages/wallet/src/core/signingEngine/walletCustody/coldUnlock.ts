import { joinCustodyWireFromEnvelopeRecord } from './joinCustodyWire';
import {
  rejoinNearEd25519CustodyV1,
  type RejoinNearEd25519CustodyInput,
} from './registrationCeremony';
import type { PasskeyCustodyEnvelopeFetchResult } from '@/core/rpcClients/relayer/passkeyCustodyEnvelope';

/**
 * Cold unlock: reproducing a wallet's NEAR key set on a device that has
 * nothing local.
 *
 * **This path never reads a local cache, so the envelope-caching question does
 * not gate it.** A new device has no cached envelope by definition — that is
 * what makes it cold — so it fetches, and the only decision left in that area
 * is whether a *warm* unlock may skip the network.
 *
 * The order is forced. The envelope must be fetched before the ceremony can
 * run, because the ceremony joins existing custody by opening it; and the
 * material must be persisted after, because the ceremony is what produces it.
 * Nothing here can be reordered for latency.
 *
 * Each failure keeps the shape the layer below gave it. A revoked credential,
 * a wallet with no envelope, and a corrupt stored record are three different
 * conversations with the user, and the retrieval already distinguishes them —
 * flattening them into "unlock failed" at this seam would discard work that
 * was done deliberately one layer down.
 */

export type ColdUnlockResultV1 =
  | {
      readonly kind: 'unlocked';
      readonly commitPayload: Awaited<
        ReturnType<typeof rejoinNearEd25519CustodyV1>
      >['commitPayload'];
      readonly activationReference: Awaited<
        ReturnType<typeof rejoinNearEd25519CustodyV1>
      >['activationReference'];
    }
  /** The envelope could not be retrieved; the reason is the retrieval's. */
  | { readonly kind: 'envelope_unavailable'; readonly reason: string; readonly code: string }
  /** Retrieved, but not usable — revoked, retired, or self-inconsistent. */
  | { readonly kind: 'envelope_rejected'; readonly reason: string };

export async function coldUnlockNearEd25519CustodyV1(input: {
  /** Fetches the wallet's custody envelope. Already assertion-gated. */
  readonly fetchEnvelope: () => Promise<PasskeyCustodyEnvelopeFetchResult>;
  /** Everything the rejoin needs except the custody wire, which comes from the fetch. */
  readonly rejoin: Omit<RejoinNearEd25519CustodyInput, 'custodyJson'>;
  /**
   * Persists the continuity cache the run produced.
   *
   * Separate from the ceremony so a persistence failure cannot be mistaken
   * for an unlock failure: the wallet *is* unlocked at that point, and the
   * only loss is the next unlock's Router round.
   */
  readonly persistMaterial: (material: {
    readonly b64u: string;
    readonly nonceB64u: string;
    readonly applicationBindingDigestB64u: string;
  }) => Promise<void>;
}): Promise<ColdUnlockResultV1> {
  const fetched = await input.fetchEnvelope();
  if (fetched.kind !== 'active') {
    return envelopeUnavailable(fetched);
  }

  const wire = joinCustodyWireFromEnvelopeRecord(fetched.envelope);
  if (!wire.ok) {
    /* The server serves only active envelopes, so reaching here means the
       record disagrees with itself or with what the projection requires.
       Reported separately from a refusal: nothing the user does differently
       will change it. */
    return { kind: 'envelope_rejected', reason: wire.reason };
  }

  const rejoined = await rejoinNearEd25519CustodyV1({
    ...input.rejoin,
    custodyJson: wire.custodyJson,
  });

  /* Persisted after the ceremony because the ceremony produces it, and
     awaited rather than fired off: a caller that returns before the write
     lands would report a cache that may not exist.

     The rejoin refuses to return without material, so the null branch is
     unreachable through it — handled rather than asserted because the wallet
     is genuinely unlocked at this point and a missing cache costs only the
     next unlock's Router round. Throwing here would turn a successful unlock
     into a failed one. */
  if (rejoined.localMaterial) {
    await input.persistMaterial(rejoined.localMaterial);
  }

  return {
    kind: 'unlocked',
    commitPayload: rejoined.commitPayload,
    activationReference: rejoined.activationReference,
  };
}

function envelopeUnavailable(
  fetched: Exclude<PasskeyCustodyEnvelopeFetchResult, { kind: 'active' }>,
): Extract<ColdUnlockResultV1, { kind: 'envelope_unavailable' }> {
  switch (fetched.kind) {
    case 'credential_rejected':
      return { kind: 'envelope_unavailable', code: fetched.code, reason: fetched.message };
    case 'request_rejected':
      return { kind: 'envelope_unavailable', code: fetched.code, reason: fetched.message };
    case 'missing':
      return { kind: 'envelope_unavailable', code: 'envelope_missing', reason: fetched.message };
    case 'retired':
      return { kind: 'envelope_unavailable', code: 'envelope_retired', reason: fetched.message };
    case 'corrupt':
      return { kind: 'envelope_unavailable', code: 'envelope_corrupt', reason: fetched.message };
    case 'transport_failed':
      return { kind: 'envelope_unavailable', code: 'transport_failed', reason: fetched.message };
  }
}
