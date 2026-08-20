import type {
  Ed25519YaoLaneClientCompletionV1,
  Ed25519YaoLaneJobV1,
  LaneProtocolCommitReceiptV1,
  WasmEd25519YaoLaneClientV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneHolderPackageWireV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import { computeEd25519YaoLaneSessionDigestV1 } from '@shared/signing-lanes/rotationDigests';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type {
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoCeremonyBindingV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  deriveRouterAbEd25519YaoApplicationBindingDigestV1,
  deriveRouterAbEd25519YaoStableContextBindingV1,
} from '@shared/utils/routerAbEd25519Yao';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '../../workerManager/workerTypes';

function parseEdJob(value: unknown): Ed25519YaoLaneJobV1 {
  const parsed = parseRotatableSigningLaneJobV1(value);
  if (parsed.keyFamily !== 'ed25519') {
    throw new Error('Ed25519 Yao lane WASM requires an Ed25519 lane job');
  }
  return parsed;
}

/**
 * Checks every public binding used by the Rust lane client before crossing the
 * worker boundary. The Rust check remains authoritative; this gives callers a
 * precise boundary error when a stale local identity or ceremony response is
 * selected, instead of collapsing it into the WASM binding error.
 */
export async function assertEd25519YaoLaneCeremonyBindingParityV1(input: {
  readonly job: Ed25519YaoLaneJobV1;
  readonly ceremonyBinding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly participantIds: readonly [number, number];
  readonly applicationBindingDigestB64u?: string;
}): Promise<void> {
  const expectedApplicationDigestB64u = base64UrlEncode(
    Uint8Array.from(
      await deriveRouterAbEd25519YaoApplicationBindingDigestV1(input.applicationBinding),
    ),
  );
  if (
    input.applicationBindingDigestB64u !== undefined &&
    input.applicationBindingDigestB64u !== expectedApplicationDigestB64u
  ) {
    throw new Error(
      `Ed25519 Yao lane application binding digest mismatch: expected ${expectedApplicationDigestB64u}, received ${input.applicationBindingDigestB64u}`,
    );
  }

  const expectedStableContextBindingB64u = base64UrlEncode(
    Uint8Array.from(
      await deriveRouterAbEd25519YaoStableContextBindingV1(
        input.applicationBinding,
        input.participantIds,
      ),
    ),
  );
  if (input.job.stableContextBindingB64u !== expectedStableContextBindingB64u) {
    throw new Error(
      `Ed25519 Yao lane job stable context binding mismatch: expected ${expectedStableContextBindingB64u}, received ${input.job.stableContextBindingB64u}`,
    );
  }
  const ceremonyStableContextBindingB64u = base64UrlEncode(
    Uint8Array.from(input.ceremonyBinding.stable_key_context_binding),
  );
  if (ceremonyStableContextBindingB64u !== expectedStableContextBindingB64u) {
    throw new Error(
      `Ed25519 Yao lane ceremony stable context binding mismatch: expected ${expectedStableContextBindingB64u}, received ${ceremonyStableContextBindingB64u}`,
    );
  }

  if (input.ceremonyBinding.operation !== input.job.yaoRequestKind) {
    throw new Error(
      `Ed25519 Yao lane ceremony operation mismatch: expected ${input.job.yaoRequestKind}, received ${input.ceremonyBinding.operation}`,
    );
  }
  const expectedSessionDigestB64u = await computeEd25519YaoLaneSessionDigestV1(input.job);
  const ceremonySessionDigestB64u = base64UrlEncode(
    Uint8Array.from(input.ceremonyBinding.session_id),
  );
  if (ceremonySessionDigestB64u !== expectedSessionDigestB64u) {
    throw new Error(
      `Ed25519 Yao lane ceremony session mismatch: expected ${expectedSessionDigestB64u}, received ${ceremonySessionDigestB64u}`,
    );
  }

  if (
    !sameRouterAbMpcMaterialActivationRef(
      routerAbMpcMaterialActivationRefToWire(input.job.source.materialActivation),
      input.ceremonyBinding.material_activation,
    )
  ) {
    throw new Error('Ed25519 Yao lane ceremony material activation mismatch');
  }

  assertCanonicalRecipientKeyV1(
    input.job.targetHolder.hpkePublicKeyB64u,
    'target holder HPKE public key',
  );
  assertCanonicalRecipientKeyV1(
    input.job.targetSigningWorker.hpkePublicKeyB64u,
    'target SigningWorker HPKE public key',
  );
}

function assertCanonicalRecipientKeyV1(value: string, label: string): void {
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(value);
  } catch {
    throw new Error(`Ed25519 Yao lane ${label} is not valid unpadded base64url`);
  }
  if (decoded.length !== 32 || base64UrlEncode(decoded) !== value) {
    throw new Error(`Ed25519 Yao lane ${label} must be a canonical 32-byte value`);
  }
}

function requestJson(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('Yao lane request JSON is required');
  }
  return value;
}

function responseJson(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('Yao lane response JSON is required');
  }
  return value;
}

function parseCommitReceipt(value: unknown): LaneProtocolCommitReceiptV1 {
  const receipt = parseLaneProtocolCommitReceiptV1(value);
  if (receipt.keyFamily !== 'ed25519') {
    throw new Error('Yao lane protocol receipt has the wrong key family');
  }
  return receipt;
}

export async function prepareEd25519YaoLaneV1(
  wasm: WasmEd25519YaoLaneClientV1,
  input: unknown,
): Promise<{ readonly requestJson: string }> {
  const job = parseEdJob(input);
  const result = await wasm.prepare(job);
  return { requestJson: requestJson(result.requestJson) };
}

export async function completeEd25519YaoLaneV1(
  wasm: WasmEd25519YaoLaneClientV1,
  input: { readonly job: unknown; readonly responseJson: unknown },
): Promise<Ed25519YaoLaneClientCompletionV1> {
  const job = parseEdJob(input.job);
  const completion = await wasm.complete({
    job,
    responseJson: responseJson(input.responseJson),
  });
  return parseEd25519YaoLaneCompletionV1(job, completion);
}

function parseEd25519YaoLaneCompletionV1(
  job: Ed25519YaoLaneJobV1,
  completion: Ed25519YaoLaneClientCompletionV1,
): Ed25519YaoLaneClientCompletionV1 {
  const receipt = parseCommitReceipt(completion.protocolCommitReceipt);
  const holderPackage = parseLaneHolderPackageWireV1(completion.holderPackage);
  if (holderPackage.kind !== 'ed25519_yao_lane_holder_package_set_v1') {
    throw new Error('Yao lane completion returned the wrong holder package family');
  }
  assertReceiptJobIdentity(receipt, job);
  return { protocolCommitReceipt: receipt, holderPackage };
}

function assertReceiptJobIdentity(
  receipt: LaneProtocolCommitReceiptV1,
  job: Ed25519YaoLaneJobV1,
): void {
  if (
    String(receipt.operationId) !== String(job.operationId) ||
    String(receipt.enrollmentId) !== String(job.enrollmentId) ||
    String(receipt.walletId) !== String(job.walletId) ||
    String(receipt.walletKeyId) !== String(job.walletKeyId) ||
    String(receipt.sourceLaneId) !== String(job.source.laneId) ||
    String(receipt.targetLaneId) !== String(job.target.laneId) ||
    String(receipt.targetLaneShareEpoch) !== String(job.target.laneShareEpoch) ||
    String(receipt.targetMaterialActivationId) !== String(job.targetMaterialActivationId)
  ) {
    throw new Error('Yao lane protocol receipt does not match its job');
  }
}

export type Ed25519YaoLaneWasmAdapterV1 = WasmEd25519YaoLaneClientV1;

export function createEd25519YaoLaneWasmAdapterV1(
  wasm: WasmEd25519YaoLaneClientV1,
): Ed25519YaoLaneWasmAdapterV1 {
  return {
    async prepare(input) {
      return await prepareEd25519YaoLaneV1(wasm, input);
    },
    async complete(input) {
      return await completeEd25519YaoLaneV1(wasm, input);
    },
  };
}

export const createEd25519YaoLaneWasmAdapter = createEd25519YaoLaneWasmAdapterV1;

export type Ed25519YaoLaneWorkerSourceV1 = {
  readonly sourceHandle: string;
  discard(): Promise<void>;
};

export async function openEd25519YaoLaneWorkerSourceV1(args: {
  readonly workerCtx: WorkerOperationContext;
  readonly factorSecret: ArrayBuffer;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly applicationBindingDigestB64u: string;
}): Promise<Ed25519YaoLaneWorkerSourceV1> {
  const opened = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'walletCustodyCeremony',
    request: {
      type: 'openEd25519YaoLaneSource',
      payload: {
        kind: 'factor',
        factorSecret: args.factorSecret,
        envelope: args.envelope,
        applicationBindingDigestB64u: args.applicationBindingDigestB64u,
      },
      transfer: [args.factorSecret],
    },
  });
  return new Ed25519YaoLaneWorkerSource(args.workerCtx, opened.sourceHandle);
}

export async function openEd25519YaoLaneWorkerSourceFromUnlockedCapabilityV1(args: {
  readonly workerCtx: WorkerOperationContext;
  readonly capability: UnlockedWalletEd25519ExportRootCapabilityV1;
  readonly applicationBindingDigestB64u: string;
}): Promise<Ed25519YaoLaneWorkerSourceV1> {
  const opened = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'walletCustodyCeremony',
    request: {
      type: 'openEd25519YaoLaneSource',
      payload: {
        kind: 'unlocked_ed25519_export_root_capability',
        capability: args.capability,
        applicationBindingDigestB64u: args.applicationBindingDigestB64u,
      },
    },
  });
  return new Ed25519YaoLaneWorkerSource(args.workerCtx, opened.sourceHandle);
}

class Ed25519YaoLaneWorkerSource implements Ed25519YaoLaneWorkerSourceV1 {
  #discarded = false;

  constructor(
    private readonly workerCtx: WorkerOperationContext,
    readonly sourceHandle: string,
  ) {}

  async discard(): Promise<void> {
    if (this.#discarded) return;
    this.#discarded = true;
    await executeWorkerOperation({
      ctx: this.workerCtx,
      kind: 'walletCustodyCeremony',
      request: {
        type: 'discardEd25519YaoLaneSource',
        payload: { sourceHandle: this.sourceHandle },
      },
    });
  }
}

export type Ed25519YaoLaneDerivationWorkerWasmV1Config = {
  readonly workerCtx: WorkerOperationContext;
  readonly source: Ed25519YaoLaneWorkerSourceV1;
  readonly ceremonyBinding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly participantIds: readonly [number, number];
  readonly deriverAInputPublicKeyB64u: string;
  readonly deriverBInputPublicKeyB64u: string;
};

type Ed25519YaoLaneWorkerClientStateV1 =
  | { readonly state: 'empty' }
  | {
      readonly state: 'prepared';
      readonly job: Ed25519YaoLaneJobV1;
      readonly sessionHandle: string;
    }
  | { readonly state: 'consumed' };

class Ed25519YaoLaneDerivationWorkerWasmV1 implements WasmEd25519YaoLaneClientV1 {
  #state: Ed25519YaoLaneWorkerClientStateV1 = { state: 'empty' };

  constructor(private readonly config: Ed25519YaoLaneDerivationWorkerWasmV1Config) {}

  async prepare(input: Ed25519YaoLaneJobV1): Promise<{ requestJson: string }> {
    if (this.#state.state !== 'empty') {
      throw new Error('Ed25519 Yao lane worker client is already prepared');
    }
    const job = parseEdJob(input);
    const prepared = await executeWorkerOperation({
      ctx: this.config.workerCtx,
      kind: 'walletCustodyCeremony',
      request: {
        type: 'prepareEd25519YaoLane',
        payload: {
          sourceHandle: this.config.source.sourceHandle,
          job,
          ceremonyBinding: this.config.ceremonyBinding,
          applicationBinding: this.config.applicationBinding,
          participantIds: this.config.participantIds,
          deriverAInputPublicKeyB64u: this.config.deriverAInputPublicKeyB64u,
          deriverBInputPublicKeyB64u: this.config.deriverBInputPublicKeyB64u,
        },
      },
    });
    this.#state = { state: 'prepared', job, sessionHandle: prepared.sessionHandle };
    return { requestJson: requestJson(prepared.requestJson) };
  }

  async complete(input: {
    job: Ed25519YaoLaneJobV1;
    responseJson: string;
  }): Promise<Ed25519YaoLaneClientCompletionV1> {
    if (this.#state.state !== 'prepared') {
      throw new Error('Ed25519 Yao lane worker client is not prepared');
    }
    const prepared = this.#state;
    this.#state = { state: 'consumed' };
    const job = parseEdJob(input.job);
    if (alphabetizeStringify(job) !== alphabetizeStringify(prepared.job)) {
      throw new Error('Ed25519 Yao lane completion changed the prepared job');
    }
    const completion = await executeWorkerOperation({
      ctx: this.config.workerCtx,
      kind: 'walletCustodyCeremony',
      request: {
        type: 'completeEd25519YaoLane',
        payload: {
          sessionHandle: prepared.sessionHandle,
          responseJson: responseJson(input.responseJson),
        },
      },
    });
    return parseEd25519YaoLaneCompletionV1(prepared.job, completion);
  }
}

export function createEd25519YaoLaneDerivationWorkerWasmV1(
  config: Ed25519YaoLaneDerivationWorkerWasmV1Config,
): WasmEd25519YaoLaneClientV1 {
  return new Ed25519YaoLaneDerivationWorkerWasmV1(config);
}
