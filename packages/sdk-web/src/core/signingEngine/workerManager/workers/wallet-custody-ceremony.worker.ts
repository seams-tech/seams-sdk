import init, {
  wallet_custody_ceremony_begin_registration_v1,
  type WasmCeremonyManifestEstablishedV1,
  type WasmCeremonyProtocolsPreparedV1,
  type WasmCeremonySeedHeldV1,
} from '../../../../../../../wasm/wallet_custody_ceremony/pkg/wallet_custody_ceremony.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';

/**
 * The wallet custody registration ceremony, driven from a dedicated worker.
 *
 * The ceremony spans two Router/relayer round-trips, and its state must survive
 * them without the seed, the owner roots, or the ECDSA pending blob ever
 * existing as JavaScript values. So the wasm state handle stays here, in the
 * worker, keyed by a ceremony id; the main thread carries only the public
 * protocol messages between rounds and the ciphertext at the end.
 *
 * Each wasm transition consumes its handle. This worker mirrors that: a step
 * takes the stored handle out of the map before advancing, and only a
 * successful transition puts the next one back. A failed step therefore ends
 * the ceremony rather than leaving a half-advanced state a caller could retry
 * into — which is the same rule the Rust typestate enforces, made visible at
 * the message layer.
 */

const wasmUrl = resolveWasmUrl('wallet_custody_ceremony_bg.wasm', 'Wallet Custody Ceremony');
let initPromise: Promise<void> | null = null;

/**
 * Ceremonies in flight. Bounded because each holds custody material: a caller
 * that starts ceremonies without finishing them must fail rather than grow this
 * map, and abandoning one is a bug worth surfacing, not absorbing.
 */
const MAX_CONCURRENT_CEREMONIES = 4;

/**
 * The two steps a ceremony can be *parked* at between messages. There is no
 * `completed` state here on purpose: completing the protocols and establishing
 * the manifest happen in one message, so a completed-but-unestablished handle
 * never sits in the map waiting for a caller.
 */
type CeremonyState =
  | { readonly step: 'prepared'; readonly handle: WasmCeremonyProtocolsPreparedV1 }
  | { readonly step: 'established'; readonly handle: WasmCeremonyManifestEstablishedV1 };

const ceremonies = new Map<string, CeremonyState>();

type BeginRequest = {
  readonly id: string;
  readonly type: 'beginWalletCustodyRegistration';
  readonly payload: {
    readonly ceremonyId: string;
    readonly walletId: string;
    /** `RegistrationProtocolInputsWireV1`. Carries no Ed25519 binding digest. */
    readonly protocolInputsJson: string;
  };
};

type CompleteRequest = {
  readonly id: string;
  readonly type: 'completeWalletCustodyRegistration';
  readonly payload: {
    readonly ceremonyId: string;
    readonly yaoResultJson: string;
    readonly relayerPublicIdentityJson: string;
    readonly identitiesJson: string;
  };
};

type SealRequest = {
  readonly id: string;
  readonly type: 'sealWalletCustodyRegistration';
  readonly payload: {
    readonly ceremonyId: string;
    readonly factorJson: string;
    /** The factor secret: a passkey PRF result, or the Email OTP factor key. */
    readonly factorSecret: ArrayBuffer | Uint8Array;
    readonly recoveryCodesJson: string;
  };
};

type DiscardRequest = {
  readonly id: string;
  readonly type: 'discardWalletCustodyCeremony';
  readonly payload: { readonly ceremonyId: string };
};

type WalletCustodyCeremonyWorkerRequest =
  | BeginRequest
  | CompleteRequest
  | SealRequest
  | DiscardRequest;

function postToMainThread(message: unknown): void {
  (self as unknown as { postMessage: (message: unknown) => void }).postMessage(message);
}

function postSucceeded(id: string, result: unknown): void {
  postToMainThread({ id, ok: true, result });
}

function postFailed(id: string, error: unknown): void {
  postToMainThread({ id, ok: false, error: safeErrorMessage(error) });
}

async function initializeWasm(): Promise<void> {
  if (!initPromise) {
    initPromise = init({ module_or_path: wasmUrl }).then(
      () => undefined,
      (error: unknown) => {
        initPromise = null;
        console.error(
          '[wallet-custody-ceremony-worker]: WASM initialization failed:',
          errorLogSummary(error),
        );
        throw new Error(
          `Wallet custody ceremony WASM initialization failed: ${safeErrorMessage(error)}`,
        );
      },
    );
  }
  return initPromise;
}

function toBytes(value: ArrayBuffer | Uint8Array): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function requireCeremonyId(value: unknown): string {
  const ceremonyId = String(value || '').trim();
  if (!ceremonyId) throw new Error('ceremonyId is required');
  return ceremonyId;
}

/**
 * Removes and returns a ceremony's state at the expected step.
 *
 * Taking rather than reading is what makes a failed transition terminal: if the
 * step below throws, nothing puts the handle back, so the ceremony is gone and
 * the caller must start over from a fresh seed.
 */
function takeCeremony<TStep extends CeremonyState['step']>(
  ceremonyId: string,
  step: TStep,
): Extract<CeremonyState, { step: TStep }> {
  const state = ceremonies.get(ceremonyId);
  if (!state) throw new Error(`No wallet custody ceremony ${ceremonyId} is in flight`);
  ceremonies.delete(ceremonyId);
  if (state.step !== step) {
    // The handle is dropped rather than restored: a caller that stepped out of
    // order has lost track of the ceremony, and resuming it would be guesswork.
    throw new Error(
      `Wallet custody ceremony ${ceremonyId} is at step ${state.step}, not ${String(step)}`,
    );
  }
  return state as Extract<CeremonyState, { step: TStep }>;
}

function beginRegistration(request: BeginRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  if (ceremonies.has(ceremonyId)) {
    throw new Error(`Wallet custody ceremony ${ceremonyId} is already in flight`);
  }
  if (ceremonies.size >= MAX_CONCURRENT_CEREMONIES) {
    throw new Error('Too many wallet custody ceremonies are in flight');
  }

  const seedHeld: WasmCeremonySeedHeldV1 = wallet_custody_ceremony_begin_registration_v1(
    String(request.payload.walletId || ''),
  );
  // `prepare` consumes `seedHeld`; on failure the seed is dropped with it.
  const prepared = seedHeld.prepare(String(request.payload.protocolInputsJson || ''));
  ceremonies.set(ceremonyId, { step: 'prepared', handle: prepared });

  return {
    ceremonyId,
    yaoExecuteRequestJson: prepared.yao_execute_request_json(),
    ecdsaContextBinding32B64u: prepared.ecdsa_context_binding32_b64u(),
    ecdsaClientSharePublicKey33B64u: prepared.ecdsa_client_share_public_key33_b64u(),
  };
}

/**
 * Completes both protocols and establishes the key manifest.
 *
 * These are one message because nothing external happens between them: the
 * manifest is built from what the protocols just returned, and leaving the
 * completed state addressable would only widen the window in which a seed sits
 * in the map.
 */
function completeRegistration(request: CompleteRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  const { handle } = takeCeremony(ceremonyId, 'prepared');
  const completed = handle.complete(
    String(request.payload.yaoResultJson || ''),
    String(request.payload.relayerPublicIdentityJson || ''),
  );
  const established = completed.establish_manifest(String(request.payload.identitiesJson || ''));
  ceremonies.set(ceremonyId, { step: 'established', handle: established });
  return { ceremonyId };
}

function sealRegistration(request: SealRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  const { handle } = takeCeremony(ceremonyId, 'established');
  const factorSecret = toBytes(request.payload.factorSecret);
  try {
    return handle.seal(
      String(request.payload.factorJson || ''),
      factorSecret,
      String(request.payload.recoveryCodesJson || ''),
    );
  } finally {
    // The factor secret was copied into wasm; this view is the worker's own and
    // is cleared whether or not the seal succeeded.
    factorSecret.fill(0);
  }
}

/**
 * Ends a ceremony without completing it. Dropping the handle zeroizes the seed
 * and any in-flight protocol state, so an abandoned registration leaves nothing
 * behind.
 */
function discardCeremony(request: DiscardRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  const existed = ceremonies.delete(ceremonyId);
  return { ceremonyId, discarded: existed };
}

async function handleRequest(request: WalletCustodyCeremonyWorkerRequest): Promise<void> {
  await initializeWasm();
  switch (request.type) {
    case 'beginWalletCustodyRegistration':
      postSucceeded(request.id, beginRegistration(request));
      return;
    case 'completeWalletCustodyRegistration':
      postSucceeded(request.id, completeRegistration(request));
      return;
    case 'sealWalletCustodyRegistration':
      postSucceeded(request.id, sealRegistration(request));
      return;
    case 'discardWalletCustodyCeremony':
      postSucceeded(request.id, discardCeremony(request));
      return;
    default:
      throw new Error(
        `Unsupported wallet custody ceremony operation: ${String(
          (request as { type?: unknown }).type,
        )}`,
      );
  }
}

let messageQueue: Promise<void> = Promise.resolve();

self.onmessage = async (event: MessageEvent<WalletCustodyCeremonyWorkerRequest>): Promise<void> => {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[wallet-custody-ceremony-worker]: Ignoring message without request id');
    return;
  }
  // Serialized: two steps of one ceremony must not interleave, and the map is
  // read-modify-write.
  messageQueue = messageQueue
    .catch(() => undefined)
    .then(async () => {
      try {
        await handleRequest(event.data);
      } catch (error: unknown) {
        postFailed(requestId, error);
      }
    });
  await messageQueue;
};

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[wallet-custody-ceremony-worker]: error:', {
    message: safeErrorMessage(typeof message === 'string' ? message : 'Unknown error'),
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: error ? errorLogSummary(error) : undefined,
  });
};
