import type {
  NearFundingRequest,
  NearTransactionReadiness,
  NonceLease,
} from '../nonce/NonceCoordinator';

/**
 * Funds an unfunded implicit NEAR account in the middle of a signing
 * confirmation, between the user's confirm click and the step-up assertion.
 *
 * Why the confirmation flow needs this: a step-up assertion signs the digest of
 * the prepared operation — nonce and block hash included — so the account must
 * exist and its transaction context must be reservable BEFORE the assertion is
 * collected. The confirmation flow discovers `funding_required` (it owns
 * context fetching) but cannot fund on its own authority; the signing side
 * holds the Wallet Session and registers a funder per request, exactly like the
 * operation step-up builder.
 *
 * Funding returns the reserved context rather than leaving the caller to
 * re-fetch it: this runs while the user waits for the step-up prompt, and the
 * reservation doubles as the retry for an access key the RPC node has not caught
 * up to yet. Warm sessions never use this port — their authorization is not
 * context-bound, so the signing side funds after the confirmation returns.
 */
export type NearImplicitAccountFundingResult = {
  readiness: Extract<NearTransactionReadiness, { kind: 'context_ready' }>;
  /** Full leases, so the caller can release them if the confirmation fails. */
  reservedNonceLeases: NonceLease[];
};

export type NearImplicitAccountFundingPort = {
  fund(input: {
    requestId: string;
    request: NearFundingRequest;
  }): Promise<NearImplicitAccountFundingResult>;
};
