/**
 * Refactor 94C. Typed pending state for the passkey warm-session seal.
 *
 * Sealing (`sealed_refresh_v1`) exists so a reloaded page can resume a warm
 * signing session without a fresh Touch ID. It is refresh persistence, not a
 * prerequisite for signing: the in-memory warm session is committed before the
 * seal runs, so same-tab signing never depends on it. Measured on staging, the
 * seal cost ~0.7 s of the blocking registration path while contributing
 * nothing the caller could observe at return time.
 *
 * Registration therefore defers the seal and publishes its outcome here.
 * Anything that would read a sealed record in the same tab awaits the pending
 * attempt instead of racing it. A failed or interrupted seal degrades to the
 * existing re-auth fallback — it must never fault the registered wallet.
 *
 * The attempt closure holds the PRF output in memory exactly as the inline
 * call did; nothing here persists factor material, and this registry stores
 * only status values.
 */

export type EcdsaWarmSessionSealState =
  | { status: 'seal_pending' }
  | { status: 'sealed' }
  | { status: 'seal_failed_reauth_required'; errorCode: 'warm_session_seal_failed' };

type SealEntry = {
  state: EcdsaWarmSessionSealState;
  inFlight: Promise<EcdsaWarmSessionSealState> | null;
};

const entries = new Map<string, SealEntry>();

export function readEcdsaWarmSessionSealState(walletId: string): EcdsaWarmSessionSealState | null {
  return entries.get(walletId)?.state ?? null;
}

/**
 * Runs `attempt` as the wallet's single seal attempt, or joins the one in
 * flight. Never rejects: a thrown attempt settles as
 * `seal_failed_reauth_required`, because the wallet is already durable and a
 * missing seal only means the next reload re-authenticates.
 */
export function runSingleFlightEcdsaWarmSessionSeal(args: {
  walletId: string;
  attempt: () => Promise<void>;
}): Promise<EcdsaWarmSessionSealState> {
  const existing = entries.get(args.walletId);
  if (existing?.inFlight) return existing.inFlight;
  if (existing?.state.status === 'sealed') return Promise.resolve(existing.state);

  const entry: SealEntry = { state: { status: 'seal_pending' }, inFlight: null };
  entries.set(args.walletId, entry);

  const inFlight = args
    .attempt()
    .then<EcdsaWarmSessionSealState>(() => ({ status: 'sealed' }))
    .catch<EcdsaWarmSessionSealState>(() => ({
      status: 'seal_failed_reauth_required',
      errorCode: 'warm_session_seal_failed',
    }))
    .then((state) => {
      entry.state = state;
      entry.inFlight = null;
      return state;
    });
  entry.inFlight = inFlight;
  return inFlight;
}

/**
 * Awaits a pending seal, or returns the settled state immediately. Callers
 * that find `seal_failed_reauth_required` use the existing re-auth path;
 * `null` means no seal was ever scheduled for this wallet in this tab.
 */
export async function awaitEcdsaWarmSessionSeal(
  walletId: string,
): Promise<EcdsaWarmSessionSealState | null> {
  const entry = entries.get(walletId);
  if (!entry) return null;
  return entry.inFlight ?? entry.state;
}

/** Test seam. */
export function resetEcdsaWarmSessionSealRegistryForTests(): void {
  entries.clear();
}
