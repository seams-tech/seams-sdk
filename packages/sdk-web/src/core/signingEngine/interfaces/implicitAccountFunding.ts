import type { NearFundingRequest } from '../nonce/nearTransactionReadiness';

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
 * The port only funds. Context reservation stays where it always was — the
 * confirmation flow re-fetches through its ordinary context path and proceeds
 * down the unchanged `context_ready` route. Warm sessions never use this port:
 * their authorization is not context-bound, so the signing side funds after the
 * confirmation returns.
 */
export type NearImplicitAccountFundingPort = {
  fund(input: { requestId: string; request: NearFundingRequest }): Promise<void>;
};
