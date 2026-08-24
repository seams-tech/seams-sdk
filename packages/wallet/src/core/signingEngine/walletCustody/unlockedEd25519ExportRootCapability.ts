/**
 * Refactor 103 zero-prompt handoff — the main thread's view of the unlocked
 * Ed25519 Yao Client export-root capability.
 *
 * The wallet custody ceremony worker owns the opened custody-seed handle; this
 * module owns the one public reference to it and the discipline around it:
 * established during successful registration or ordinary unlock (where the
 * owner factor was already being presented), read by the device-linking
 * preflight, and destroyed at every lock and session-cleanup choke point. The
 * reference is volatile by construction — it is never persisted, and after the
 * worker destroys or loses its handle the reference grants nothing.
 *
 * Approving a linked device on an already-unlocked Device 1 seals through this
 * capability without WebAuthn, Touch ID, or an OTP challenge. A missing or
 * expired capability is an unlock requirement, never permission to prompt from
 * the linking flow.
 */
import type {
  UnlockedWalletEd25519ExportRootCapabilityDestroyScopeV1,
  UnlockedWalletEd25519ExportRootCapabilityV1,
} from '../workerManager/workerTypes';
import type { WalletCustodyCeremonyTransportPort } from './ceremonyStepRunner';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { WorkerOperationContext } from '../workerManager/executeWorkerOperation';

let currentCapability: UnlockedWalletEd25519ExportRootCapabilityV1 | null = null;
let currentCapabilityTransport: WalletCustodyCeremonyTransportPort | null = null;
let currentCapabilityExpiryTimer: ReturnType<typeof setTimeout> | null = null;

const MAX_EXPIRY_TIMER_DELAY_MS = 2_147_483_647;

function requestWalletCustodyCeremonyOperation(
  workerContext: WorkerOperationContext,
  operation: Parameters<WalletCustodyCeremonyTransportPort['requestOperation']>[0],
): Promise<unknown> {
  return workerContext.requestWorkerOperation({
    kind: operation.kind,
    request: operation.request as never,
  });
}

export function walletCustodyCeremonyTransportFromWorkerContextV1(
  workerContext: WorkerOperationContext,
): WalletCustodyCeremonyTransportPort {
  return {
    requestOperation: requestWalletCustodyCeremonyOperation.bind(undefined, workerContext),
  };
}

function clearCurrentCapabilityExpiryTimer(): void {
  if (currentCapabilityExpiryTimer === null) return;
  clearTimeout(currentCapabilityExpiryTimer);
  currentCapabilityExpiryTimer = null;
}

function clearCurrentCapabilityReference(): void {
  clearCurrentCapabilityExpiryTimer();
  currentCapability = null;
  currentCapabilityTransport = null;
}

function scheduleCurrentCapabilityExpiry(
  capability: UnlockedWalletEd25519ExportRootCapabilityV1,
  transport: WalletCustodyCeremonyTransportPort,
): void {
  clearCurrentCapabilityExpiryTimer();
  const delayMs = Math.max(0, capability.expiresAtMs - Date.now());
  currentCapabilityExpiryTimer = setTimeout(
    () => {
      currentCapabilityExpiryTimer = null;
      if (currentCapability !== capability || currentCapabilityTransport !== transport) return;
      if (capability.expiresAtMs > Date.now()) {
        scheduleCurrentCapabilityExpiry(capability, transport);
        return;
      }
      void destroyUnlockedWalletEd25519ExportRootCapabilitiesV1(transport, {
        kind: 'capability',
        capabilityHandleId: capability.capabilityHandleId,
      });
    },
    Math.min(delayMs, MAX_EXPIRY_TIMER_DELAY_MS),
  );
}

function isCapabilityReference(
  value: unknown,
): value is UnlockedWalletEd25519ExportRootCapabilityV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    record.kind === 'unlocked_wallet_ed25519_export_root_capability_v1' &&
    typeof record.capabilityHandleId === 'string' &&
    record.capabilityHandleId.length > 0 &&
    typeof record.walletId === 'string' &&
    typeof record.walletAuthMethodId === 'string' &&
    typeof record.walletSessionId === 'string' &&
    typeof record.expiresAtMs === 'number'
  );
}

/**
 * Opens the custody envelope inside the worker with the factor secret already
 * present in the calling operation, and records the returned reference as the
 * current capability. The caller still owns `existingFactorSecret` and zeroes
 * it; the worker zeroes its own copy.
 *
 * Call only after the owner Wallet Session named here is active. Establishing
 * adds no authenticator or OTP interaction.
 */
export async function establishUnlockedWalletEd25519ExportRootCapabilityV1(
  transport: WalletCustodyCeremonyTransportPort,
  input: {
    readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly existingFactorSecret: Uint8Array;
    readonly walletId: string;
    readonly walletAuthMethodId: string;
    readonly walletSessionId: string;
    readonly expiresAtMs: number;
  },
): Promise<UnlockedWalletEd25519ExportRootCapabilityV1> {
  // The worker transfers this buffer, so it gets a copy and we wipe it.
  const workerFactorSecret = input.existingFactorSecret.slice();
  let established: unknown;
  try {
    established = await transport.requestOperation({
      kind: 'walletCustodyCeremony',
      request: {
        type: 'establishUnlockedWalletEd25519ExportRootCapability',
        payload: {
          existingEnvelope: input.existingEnvelope,
          existingFactorSecret: workerFactorSecret.buffer,
          walletId: input.walletId,
          walletAuthMethodId: input.walletAuthMethodId,
          walletSessionId: input.walletSessionId,
          expiresAtMs: input.expiresAtMs,
        },
        transfer: [workerFactorSecret.buffer],
      },
    });
  } finally {
    if (workerFactorSecret.byteLength > 0) workerFactorSecret.fill(0);
  }
  if (!isCapabilityReference(established)) {
    throw new Error('unlocked Ed25519 export-root capability worker returned no reference');
  }
  clearCurrentCapabilityExpiryTimer();
  currentCapability = established;
  currentCapabilityTransport = transport;
  scheduleCurrentCapabilityExpiry(established, transport);
  return established;
}

/**
 * The current capability for this exact wallet, or undefined when the wallet
 * has none — never a prompt, and never a stale or expired reference.
 */
export function readUnlockedWalletEd25519ExportRootCapabilityV1(
  walletId: string,
): UnlockedWalletEd25519ExportRootCapabilityV1 | undefined {
  const capability = currentCapability;
  if (!capability) return undefined;
  if (capability.walletId !== walletId) return undefined;
  if (capability.expiresAtMs <= Date.now()) {
    const transport = currentCapabilityTransport;
    if (transport) {
      void destroyUnlockedWalletEd25519ExportRootCapabilitiesV1(transport, {
        kind: 'capability',
        capabilityHandleId: capability.capabilityHandleId,
      });
    } else {
      clearCurrentCapabilityReference();
    }
    return undefined;
  }
  return capability;
}

/**
 * Drops the local reference without a worker round-trip. This is the
 * worker-reset path: a terminated worker has already lost its handle memory,
 * and holding a reference to it would let the linking preflight pass against a
 * handle that no longer exists.
 */
export function dropUnlockedWalletEd25519ExportRootCapabilityReferenceV1(): void {
  clearCurrentCapabilityReference();
}

/**
 * Destroys worker-held capabilities in the given scope and drops the local
 * reference when it falls inside that scope. Failures to reach the worker are
 * absorbed after dropping the local reference: a torn-down or resetting worker
 * has already lost its handle memory, which is the destruction this call
 * wants.
 */
export async function destroyUnlockedWalletEd25519ExportRootCapabilitiesV1(
  transport: WalletCustodyCeremonyTransportPort,
  scope: UnlockedWalletEd25519ExportRootCapabilityDestroyScopeV1,
): Promise<void> {
  const capability = currentCapability;
  const localMatches =
    capability !== null &&
    (scope.kind === 'all' ||
      (scope.kind === 'capability' && scope.capabilityHandleId === capability.capabilityHandleId) ||
      (scope.kind === 'wallet' && scope.walletId === capability.walletId) ||
      (scope.kind === 'wallet_session' && scope.walletSessionId === capability.walletSessionId));
  if (localMatches) clearCurrentCapabilityReference();
  try {
    await transport.requestOperation({
      kind: 'walletCustodyCeremony',
      request: {
        type: 'destroyUnlockedWalletEd25519ExportRootCapabilities',
        payload: { scope },
      },
    });
  } catch {
    // The worker being unreachable means its handle memory is already gone.
  }
}
