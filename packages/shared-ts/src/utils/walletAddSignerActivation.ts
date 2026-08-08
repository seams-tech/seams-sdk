/**
 * The canonical wallet add-signer ECDSA activation command — the add-signer
 * counterpart of registration's `wallet_registration_activate_v2` command.
 *
 * The client computes the activation request digest locally over this exact
 * alphabetized JSON and journals both before calling activate; the server
 * recomputes the digest from the same coordinates and rejects a mismatch
 * before claiming the activation. Both sides import this one builder so the
 * encoding cannot drift. Unlike the registration command there is no
 * `idempotencyKey` member: add-signer finalize owns idempotency on its own
 * route, and the activate claim is keyed by these coordinates alone.
 */

import { base64UrlEncode } from './base64';
import { alphabetizeStringify, sha256BytesUtf8 } from './digests';
import {
  parseCanonicalEcdsaServerActivationRequest,
  type CanonicalEcdsaServerActivationRequest,
} from './ecdsaCapabilityActivation';
import type { RouterAbEcdsaVerifiedClientActivationFactsV1 } from './routerAbEcdsaDerivation';

export const WALLET_ADD_SIGNER_ECDSA_ACTIVATE_OPERATION = 'wallet_add_signer_activate_v2';

export type WalletAddSignerEcdsaActivationCommandInput = {
  readonly addSignerCeremonyId: string;
  readonly activationCorrelationId: string;
  readonly publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
};

export function buildCanonicalWalletAddSignerEcdsaActivationRequest(
  input: WalletAddSignerEcdsaActivationCommandInput,
): CanonicalEcdsaServerActivationRequest {
  return parseCanonicalEcdsaServerActivationRequest(
    alphabetizeStringify({
      operation: WALLET_ADD_SIGNER_ECDSA_ACTIVATE_OPERATION,
      addSignerCeremonyId: input.addSignerCeremonyId,
      activationCorrelationId: input.activationCorrelationId,
      publicFacts: input.publicFacts,
    }),
  );
}

export async function computeWalletAddSignerEcdsaActivationRequestDigestB64u(
  input: WalletAddSignerEcdsaActivationCommandInput,
): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(String(buildCanonicalWalletAddSignerEcdsaActivationRequest(input))),
  );
}
