import type { NearProvisioningState, NearProvisioningWriteV1 } from '@/core/types/seams';
import type { WalletId } from '@shared/utils/registrationIntent';

/**
 * Refactor 94 Phase 6. Page-owned NEAR provisioning state for wallets that
 * registered ECDSA-ready.
 *
 * Registration returns before the Ed25519/NEAR branch settles, so the outcome
 * of that deferred work has nowhere to go on the already-returned
 * `RegistrationResult` — it has crossed the postMessage boundary and must not
 * be mutated. This registry is where the outcome is published instead:
 * subscribers observe it live, and the durable local wallet record carries it
 * across reloads.
 *
 * The in-flight promise doubles as the same-tab single-flight. Concurrent
 * first-NEAR requests join one attempt rather than racing two commits against
 * the same registration ceremony.
 */

export type NearProvisioningListener = (walletId: WalletId, state: NearProvisioningState) => void;

type WalletEntry = {
  state: NearProvisioningState;
  inFlight: Promise<NearProvisioningState> | null;
};

const entries = new Map<string, WalletEntry>();
const listeners = new Set<NearProvisioningListener>();

function notify(walletId: WalletId, state: NearProvisioningState): void {
  for (const listener of listeners) {
    try {
      listener(walletId, state);
    } catch {
      /* A failing subscriber must not stall provisioning or the subscribers
         registered after it. */
    }
  }
}

function entryFor(walletId: WalletId, nowMs: number): WalletEntry {
  const key = String(walletId);
  const existing = entries.get(key);
  if (existing) return existing;
  const created: WalletEntry = {
    state: { status: 'near_pending', updatedAtMs: nowMs },
    inFlight: null,
  };
  entries.set(key, created);
  return created;
}

export function readNearProvisioningState(walletId: WalletId): NearProvisioningState | null {
  return entries.get(String(walletId))?.state ?? null;
}

export async function awaitNearProvisioningInFlight(
  walletId: WalletId,
): Promise<NearProvisioningState | null> {
  const entry = entries.get(String(walletId));
  if (!entry) return null;
  return entry.inFlight ? await entry.inFlight : entry.state;
}

export function publishNearProvisioningState(
  walletId: WalletId,
  state: NearProvisioningState,
): void {
  const entry = entryFor(walletId, state.updatedAtMs);
  entry.state = state;
  notify(walletId, state);
}

export function subscribeToNearProvisioning(listener: NearProvisioningListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Seeds state observed from the durable wallet record on page load.
 *
 * A record still reading `near_pending` or `near_provisioning` describes an
 * attempt that died with the tab that owned it: neither the live factor nor the
 * promise survives a reload. Both converge to a retryable failure rather than
 * leaving the wallet looking busy forever. Recovery is a later authenticated
 * retry, which converges because finalize replay is exact.
 */
export async function reconcileNearProvisioningOnLoad(args: {
  walletId: WalletId;
  persisted: NearProvisioningState | null | undefined;
  nowMs: number;
  /* The durable record is authoritative, so a convergence has to be written
     back before it is published — otherwise the next reload sees the stale
     in-flight status again. */
  persist: (write: NearProvisioningWriteV1) => Promise<void>;
}): Promise<NearProvisioningState> {
  const interrupted =
    args.persisted?.status === 'near_pending' || args.persisted?.status === 'near_provisioning';
  if (!interrupted) {
    const observed = args.persisted ?? { status: 'near_pending' as const, updatedAtMs: args.nowMs };
    publishNearProvisioningState(args.walletId, observed);
    return observed;
  }
  const converged: NearProvisioningState = {
    status: 'near_failed_retryable',
    updatedAtMs: args.nowMs,
    error: 'NEAR provisioning was interrupted before it completed',
    errorCode: 'near_provisioning_interrupted',
  };
  await args.persist({
    walletId: String(args.walletId),
    status: 'near_failed_retryable',
    errorCode: 'near_provisioning_interrupted',
  });
  publishNearProvisioningState(args.walletId, converged);
  return converged;
}

/**
 * Runs `attempt` as the wallet's single provisioning attempt, or joins the one
 * already in flight. The returned promise never rejects: a thrown attempt
 * becomes a published `near_failed_retryable`, because the ECDSA wallet is
 * already durable and must not be faulted by this.
 */
export function runSingleFlightNearProvisioning(args: {
  walletId: WalletId;
  nowMs: () => number;
  attempt: () => Promise<NearProvisioningState>;
}): Promise<NearProvisioningState> {
  const entry = entryFor(args.walletId, args.nowMs());
  if (entry.inFlight) return entry.inFlight;
  if (entry.state.status === 'near_ready') return Promise.resolve(entry.state);

  publishNearProvisioningState(args.walletId, {
    status: 'near_provisioning',
    updatedAtMs: args.nowMs(),
  });

  const inFlight = (async (): Promise<NearProvisioningState> => {
    try {
      return await args.attempt();
    } catch (error: unknown) {
      return {
        status: 'near_failed_retryable',
        updatedAtMs: args.nowMs(),
        error: error instanceof Error ? error.message : String(error),
        errorCode: 'near_provisioning_failed',
      };
    }
  })().then((state) => {
    entry.inFlight = null;
    publishNearProvisioningState(args.walletId, state);
    return state;
  });

  entry.inFlight = inFlight;
  return inFlight;
}

/** Test seam: drops all page-owned state and subscribers. */
export function resetNearProvisioningRegistryForTests(): void {
  entries.clear();
  listeners.clear();
}
