/**
 * Whether a recovery may promote its replacement credential.
 *
 * **All or nothing, across the wallet's whole key set.** A mixed wallet
 * recovers NEAR and EVM-family keys in one operation, and promoting the new
 * credential after only some of them verified would leave a wallet the owner
 * believes is recovered while part of it still answers to a credential they no
 * longer hold — or to none at all. The failure is silent: the promoted
 * credential works, and the gap surfaces the first time the missing key set is
 * used.
 *
 * So promotion is a function of the *set*, and this is the only thing that
 * decides it. Each key set reports its own outcome; anything short of every
 * required one verifying refuses, and names which ones did not.
 *
 * A key set the wallet does not have is not a gap — the manifest is the list of
 * what must be reproduced, and a wallet with one key set recovers when that one
 * verifies.
 */

export type RecoveredKeySetOutcome =
  | { readonly keySet: string; readonly kind: 'verified' }
  | { readonly keySet: string; readonly kind: 'failed'; readonly reason: string };

export type CredentialPromotionAdmission =
  | { readonly kind: 'admitted'; readonly verifiedKeySets: readonly string[] }
  | {
      readonly kind: 'refused';
      readonly reason: string;
      /** The key sets that did not verify, so a caller can report or retry. */
      readonly outstandingKeySets: readonly string[];
    };

export function admitWalletRecoveryCredentialPromotion(input: {
  /** Every key set the wallet's manifest requires, as recorded. */
  readonly requiredKeySets: readonly string[];
  /** What this recovery managed to reproduce. */
  readonly outcomes: readonly RecoveredKeySetOutcome[];
}): CredentialPromotionAdmission {
  const required = normalize(input.requiredKeySets);
  if (required.length === 0) {
    /* A wallet with no required key sets would promote on an empty proof.
       Refused rather than treated as trivially satisfied: an empty manifest
       means the caller did not load one, not that there is nothing to check. */
    return {
      kind: 'refused',
      reason: 'a recovery must name the key sets its manifest requires',
      outstandingKeySets: [],
    };
  }

  const verified = new Set<string>();
  const failed = new Map<string, string>();
  for (const outcome of input.outcomes) {
    const keySet = String(outcome.keySet || '').trim();
    if (!keySet) continue;
    if (outcome.kind === 'verified') {
      verified.add(keySet);
      continue;
    }
    failed.set(keySet, outcome.reason);
  }

  /* A key set that both verified and failed is treated as failed. Two
     conflicting reports mean the caller cannot say which run produced the
     material, and promoting on the optimistic one is exactly the mistake this
     gate exists to prevent. */
  for (const keySet of failed.keys()) verified.delete(keySet);

  const outstanding = required.filter((keySet) => !verified.has(keySet));
  if (outstanding.length > 0) {
    return {
      kind: 'refused',
      reason: `recovery did not reproduce every required key set: ${outstanding.join(', ')}`,
      outstandingKeySets: outstanding,
    };
  }
  return { kind: 'admitted', verifiedKeySets: required };
}

function normalize(values: readonly string[]): readonly string[] {
  const seen = new Set<string>();
  for (const value of values) {
    const keySet = String(value || '').trim();
    if (keySet) seen.add(keySet);
  }
  return [...seen];
}
