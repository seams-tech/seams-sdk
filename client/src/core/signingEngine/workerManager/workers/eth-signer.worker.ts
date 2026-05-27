import init, {
  add_secp256k1_public_keys_33,
  compute_eip1559_tx_hash,
  decode_cose_p256_public_key,
  derive_secp256k1_keypair_from_prf_second,
  encode_eip1559_signed_tx_from_signature65,
  init_eth_signer,
  map_additive_share_to_threshold_signatures_share_2p,
  secp256k1_private_key_32_to_public_key_33,
  sign_secp256k1_recoverable,
  ThresholdEcdsaPresignSession,
  threshold_ecdsa_compute_signature_share,
  validate_secp256k1_public_key_33,
} from '../../../../../../wasm/eth_signer/pkg/eth_signer.js';
import * as ethSignerWasmModule from '../../../../../../wasm/eth_signer/pkg/eth_signer.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorMessage } from '@shared/utils/errors';
import { WorkerControlMessage, type RpcSignerWorkerProgressEvent } from '../workerTypes';

type EthSignerWorkerRequest =
  | { id: string; type: 'computeEip1559TxHash'; payload: { tx: unknown } }
  | {
      id: string;
      type: 'encodeEip1559SignedTxFromSignature65';
      payload: { tx: unknown; signature65: unknown };
    }
  | {
      id: string;
      type: 'signSecp256k1Recoverable';
      payload: { digest32: unknown; privateKey32: unknown };
    }
  | {
      id: string;
      type: 'secp256k1PrivateKey32ToPublicKey33';
      payload: { privateKey32: unknown };
    }
  | {
      id: string;
      type: 'deriveSecp256k1KeypairFromPrfSecond';
      payload: {
        prfSecond: unknown;
        walletSessionUserId: string;
      };
    }
  | {
      id: string;
      type: 'mapAdditiveShareToThresholdSignaturesShare2p';
      payload: {
        additiveShare32: unknown;
        participantId: number;
      };
    }
  | {
      id: string;
      type: 'validateSecp256k1PublicKey33';
      payload: {
        publicKey33: unknown;
      };
    }
  | {
      id: string;
      type: 'addSecp256k1PublicKeys33';
      payload: {
        left33: unknown;
        right33: unknown;
      };
    }
  | {
      id: string;
      type: 'buildWebauthnP256Signature';
      payload: {
        challenge32: unknown;
        authenticatorData: unknown;
        clientDataJSON: unknown;
        signatureDer: unknown;
        pubKeyX32: unknown;
        pubKeyY32: unknown;
      };
    }
  | {
      id: string;
      type: 'decodeCoseP256PublicKey';
      payload: {
        cosePublicKey: unknown;
      };
    }
  | {
      id: string;
      type: 'thresholdEcdsaPresignSessionInit';
      payload: {
        sessionId: string;
        participantIds: number[];
        clientParticipantId: number;
        threshold: number;
        clientThresholdSigningShare32: unknown;
        groupPublicKey33: unknown;
      };
    }
  | {
      id: string;
      type: 'thresholdEcdsaPresignSessionStep';
      payload: {
        sessionId: string;
        relayerParticipantId: number;
        stage: 'triples' | 'presign';
        incomingMessages: unknown[];
      };
    }
  | {
      id: string;
      type: 'thresholdEcdsaPresignSessionAbort';
      payload: { sessionId: string };
    }
  | {
      id: string;
      type: 'thresholdEcdsaComputeSignatureShare';
      payload: {
        participantIds: number[];
        clientParticipantId: number;
        groupPublicKey33: unknown;
        presignBigR33: unknown;
        presignKShare32: unknown;
        presignSigmaShare32: unknown;
        digest32: unknown;
        entropy32: unknown;
      };
    };

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

function asWorkerErrorPayload(err: unknown): WorkerErrorPayload {
  if (err && typeof err === 'object') {
    const message =
      typeof (err as { message?: unknown }).message === 'string'
        ? String((err as { message?: string }).message).trim()
        : '';
    const code =
      typeof (err as { code?: unknown }).code === 'string'
        ? String((err as { code?: string }).code).trim()
        : '';
    const coreCode =
      typeof (err as { coreCode?: unknown }).coreCode === 'string'
        ? String((err as { coreCode?: string }).coreCode).trim()
        : '';
    return {
      message: message || errorMessage(err),
      ...(code ? { code } : {}),
      ...(coreCode ? { coreCode } : {}),
    };
  }
  return { message: errorMessage(err) };
}

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new Error('expected bytes');
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  const workerSelf = self as unknown as {
    postMessage: (message: unknown, transfer?: Transferable[]) => void;
  };
  if (transfer && transfer.length > 0) {
    workerSelf.postMessage(message, transfer);
    return;
  }
  workerSelf.postMessage(message);
}

function ethSignerOperationLabel(type: string): string {
  switch (type) {
    case 'computeEip1559TxHash':
      return 'EIP-1559 transaction hash';
    case 'encodeEip1559SignedTxFromSignature65':
      return 'signed EIP-1559 transaction';
    case 'signSecp256k1Recoverable':
      return 'recoverable secp256k1 signature';
    case 'secp256k1PrivateKey32ToPublicKey33':
      return 'secp256k1 public key';
    case 'deriveSecp256k1KeypairFromPrfSecond':
      return 'secp256k1 keypair';
    case 'mapAdditiveShareToThresholdSignaturesShare2p':
      return 'threshold ECDSA signing share';
    case 'validateSecp256k1PublicKey33':
      return 'secp256k1 public key validation';
    case 'addSecp256k1PublicKeys33':
      return 'combined secp256k1 public key';
    case 'buildWebauthnP256Signature':
      return 'WebAuthn P-256 signature';
    case 'thresholdEcdsaPresignSessionInit':
      return 'threshold ECDSA presign session';
    case 'thresholdEcdsaPresignSessionStep':
      return 'threshold ECDSA presign step';
    case 'thresholdEcdsaPresignSessionAbort':
      return 'threshold ECDSA presign session abort';
    case 'thresholdEcdsaComputeSignatureShare':
      return 'threshold ECDSA signature share';
    default:
      return type || 'unknown ethSigner operation';
  }
}

function postWorkerOperationProgress(
  id: string,
  type: string,
  status: RpcSignerWorkerProgressEvent['status'],
  message?: string,
): void {
  const label = ethSignerOperationLabel(type);
  const payload: RpcSignerWorkerProgressEvent = {
    phase: `eth_signer.${type}.${status}`,
    status,
    message:
      message ||
      (status === 'running'
        ? `Running ${label}`
        : status === 'succeeded'
          ? `Completed ${label}`
          : `Failed ${label}`),
    data: { worker: 'ethSigner', operation: type },
  };
  postToMainThread({ id, progress: true, payload });
}

function postOperationSucceeded(
  msg: EthSignerWorkerRequest,
  result: unknown,
  transfer?: Transferable[],
): void {
  postWorkerOperationProgress(msg.id, msg.type, 'succeeded');
  postToMainThread({ id: msg.id, ok: true, result }, transfer);
}

type PresignProgressResult = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessages: ArrayBuffer[];
  presignature97?: ArrayBuffer;
};

const thresholdEcdsaPresignSessions = new Map<string, ThresholdEcdsaPresignSession>();
const buildWebauthnP256SignatureWasm = (
  ethSignerWasmModule as unknown as {
    build_webauthn_p256_signature?: (
      challenge32: Uint8Array,
      authenticatorData: Uint8Array,
      clientDataJSON: Uint8Array,
      signatureDer: Uint8Array,
      pubKeyX32: Uint8Array,
      pubKeyY32: Uint8Array,
    ) => Uint8Array;
  }
).build_webauthn_p256_signature;

function normalizePresignStage(stageRaw: unknown): 'triples' | 'triples_done' | 'presign' | 'done' {
  if (stageRaw === 'triples') return 'triples';
  if (stageRaw === 'triples_done') return 'triples_done';
  if (stageRaw === 'presign') return 'presign';
  if (stageRaw === 'done') return 'done';
  return 'triples';
}

function normalizePresignEvent(eventRaw: unknown): 'none' | 'triples_done' | 'presign_done' {
  if (eventRaw === 'triples_done') return 'triples_done';
  if (eventRaw === 'presign_done') return 'presign_done';
  return 'none';
}

function parsePresignPollResult(raw: unknown): {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoing: Uint8Array[];
} {
  const obj = (raw || {}) as { stage?: unknown; event?: unknown; outgoing?: unknown };
  const outgoingRaw = obj.outgoing;
  const outgoing = Array.isArray(outgoingRaw) ? outgoingRaw.map((entry) => toU8(entry)) : [];
  return {
    stage: normalizePresignStage(obj.stage),
    event: normalizePresignEvent(obj.event),
    outgoing,
  };
}

function freePresignSession(sessionId: string): void {
  const existing = thresholdEcdsaPresignSessions.get(sessionId);
  if (!existing) return;
  thresholdEcdsaPresignSessions.delete(sessionId);
  try {
    existing.free();
  } catch {}
}

function pollPresignSession(
  sessionId: string,
  session: ThresholdEcdsaPresignSession,
): PresignProgressResult {
  const parsed = parsePresignPollResult(session.poll());
  const outgoingMessages = parsed.outgoing.map((msg) => msg.slice().buffer);
  if (parsed.event !== 'presign_done') {
    return {
      stage: parsed.stage,
      event: parsed.event,
      outgoingMessages,
    };
  }

  const presignature97 = session.take_presignature_97();
  freePresignSession(sessionId);
  const presignature97Buffer = presignature97.slice().buffer;
  zeroizeBytes(presignature97);
  return {
    stage: 'done',
    event: 'presign_done',
    outgoingMessages,
    presignature97: presignature97Buffer,
  };
}

const wasmUrl = resolveWasmUrl('eth_signer.wasm', 'Eth Signer');
let wasmInitPromise: Promise<void> | null = null;

async function ensureWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Eth Signer',
      wasmUrl,
      initFunction: init as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_eth_signer(),
    });
  })();
  return wasmInitPromise;
}

setTimeout(() => {
  postToMainThread({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  const msg = event.data as EthSignerWorkerRequest;
  if (!msg?.id || !msg?.type) return;

  try {
    postWorkerOperationProgress(msg.id, msg.type, 'running');
    await ensureWasm();
    switch (msg.type) {
      case 'computeEip1559TxHash': {
        const out = compute_eip1559_tx_hash(msg.payload.tx) as Uint8Array;
        const ab = out.slice().buffer;
        postOperationSucceeded(msg, ab, [ab]);
        return;
      }
      case 'encodeEip1559SignedTxFromSignature65': {
        const out = encode_eip1559_signed_tx_from_signature65(
          msg.payload.tx,
          toU8(msg.payload.signature65),
        ) as Uint8Array;
        const ab = out.slice().buffer;
        postOperationSucceeded(msg, ab, [ab]);
        return;
      }
      case 'signSecp256k1Recoverable': {
        const digest32 = toU8(msg.payload.digest32);
        const privateKey32 = toU8(msg.payload.privateKey32);
        try {
          const out = sign_secp256k1_recoverable(digest32, privateKey32) as Uint8Array;
          const ab = out.slice().buffer;
          zeroizeBytes(out);
          postOperationSucceeded(msg, ab, [ab]);
          return;
        } finally {
          zeroizeBytes(digest32);
          zeroizeBytes(privateKey32);
        }
      }
      case 'secp256k1PrivateKey32ToPublicKey33': {
        const privateKey32 = toU8(msg.payload.privateKey32);
        try {
          const out = secp256k1_private_key_32_to_public_key_33(privateKey32) as Uint8Array;
          const ab = out.slice().buffer;
          zeroizeBytes(out);
          postOperationSucceeded(msg, ab, [ab]);
          return;
        } finally {
          zeroizeBytes(privateKey32);
        }
      }
      case 'deriveSecp256k1KeypairFromPrfSecond': {
        const prfSecond = toU8(msg.payload.prfSecond);
        const walletSessionUserId = String(msg.payload.walletSessionUserId || '').trim();
        try {
          // The current WASM export keeps the legacy parameter name; this worker boundary carries wallet-session identity.
          const out = derive_secp256k1_keypair_from_prf_second(
            prfSecond,
            walletSessionUserId,
          ) as Uint8Array;
          if (out.length !== 85) {
            throw new Error(
              `derive_secp256k1_keypair_from_prf_second must return 85 bytes (got ${out.length})`,
            );
          }
          const privateKey32 = out.slice(0, 32).buffer;
          const publicKey33 = out.slice(32, 65).buffer;
          const ethereumAddress20 = out.slice(65, 85).buffer;
          zeroizeBytes(out);
          postOperationSucceeded(
            msg,
            {
              privateKey32,
              publicKey33,
              ethereumAddress20,
            },
            [privateKey32, publicKey33, ethereumAddress20],
          );
          return;
        } finally {
          zeroizeBytes(prfSecond);
        }
      }
      case 'mapAdditiveShareToThresholdSignaturesShare2p': {
        const additiveShare32 = toU8(msg.payload.additiveShare32);
        const participantId = Number(msg.payload.participantId);
        try {
          const out = map_additive_share_to_threshold_signatures_share_2p(
            additiveShare32,
            participantId,
          ) as Uint8Array;
          if (out.length !== 32) {
            throw new Error(
              `map_additive_share_to_threshold_signatures_share_2p must return 32 bytes (got ${out.length})`,
            );
          }
          const ab = out.slice().buffer;
          zeroizeBytes(out);
          postOperationSucceeded(msg, ab, [ab]);
          return;
        } finally {
          zeroizeBytes(additiveShare32);
        }
      }
      case 'validateSecp256k1PublicKey33': {
        const publicKey33 = toU8(msg.payload.publicKey33);
        const out = validate_secp256k1_public_key_33(publicKey33) as Uint8Array;
        if (out.length !== 33) {
          throw new Error(
            `validate_secp256k1_public_key_33 must return 33 bytes (got ${out.length})`,
          );
        }
        const ab = out.slice().buffer;
        postOperationSucceeded(msg, ab, [ab]);
        return;
      }
      case 'addSecp256k1PublicKeys33': {
        const left33 = toU8(msg.payload.left33);
        const right33 = toU8(msg.payload.right33);
        const out = add_secp256k1_public_keys_33(left33, right33) as Uint8Array;
        if (out.length !== 33) {
          throw new Error(`add_secp256k1_public_keys_33 must return 33 bytes (got ${out.length})`);
        }
        const ab = out.slice().buffer;
        postOperationSucceeded(msg, ab, [ab]);
        return;
      }
      case 'buildWebauthnP256Signature': {
        if (typeof buildWebauthnP256SignatureWasm !== 'function') {
          throw new Error('eth_signer wasm export build_webauthn_p256_signature is missing');
        }
        const out = buildWebauthnP256SignatureWasm(
          toU8(msg.payload.challenge32),
          toU8(msg.payload.authenticatorData),
          toU8(msg.payload.clientDataJSON),
          toU8(msg.payload.signatureDer),
          toU8(msg.payload.pubKeyX32),
          toU8(msg.payload.pubKeyY32),
        ) as Uint8Array;
        const ab = out.slice().buffer;
        postOperationSucceeded(msg, ab, [ab]);
        return;
      }
      case 'decodeCoseP256PublicKey': {
        const out = decode_cose_p256_public_key(toU8(msg.payload.cosePublicKey)) as Uint8Array;
        if (out.length !== 64) {
          throw new Error(`decode_cose_p256_public_key must return 64 bytes (got ${out.length})`);
        }
        const ab = out.slice().buffer;
        postOperationSucceeded(msg, ab, [ab]);
        return;
      }
      case 'thresholdEcdsaPresignSessionInit': {
        const sessionId = String(msg.payload.sessionId || '').trim();
        if (!sessionId) throw new Error('Missing sessionId');
        freePresignSession(sessionId);

        const participantIds = Array.isArray(msg.payload.participantIds)
          ? msg.payload.participantIds.map((v) => Number(v))
          : [];
        const clientParticipantId = Number(msg.payload.clientParticipantId);
        const threshold = Number(msg.payload.threshold);
        const clientThresholdSigningShare32 = toU8(msg.payload.clientThresholdSigningShare32);
        const groupPublicKey33 = toU8(msg.payload.groupPublicKey33);
        try {
          const session = new ThresholdEcdsaPresignSession(
            new Uint32Array(participantIds),
            clientParticipantId,
            threshold,
            clientThresholdSigningShare32,
            groupPublicKey33,
          );
          thresholdEcdsaPresignSessions.set(sessionId, session);

          const progress = pollPresignSession(sessionId, session);
          const transferables = [...progress.outgoingMessages];
          if (progress.presignature97) transferables.push(progress.presignature97);
          postOperationSucceeded(msg, progress, transferables);
          return;
        } finally {
          zeroizeBytes(clientThresholdSigningShare32);
        }
      }
      case 'thresholdEcdsaPresignSessionStep': {
        const sessionId = String(msg.payload.sessionId || '').trim();
        if (!sessionId) throw new Error('Missing sessionId');
        const session = thresholdEcdsaPresignSessions.get(sessionId);
        if (!session) throw new Error('Unknown threshold ECDSA presign session');

        const stage = msg.payload.stage;
        if (stage !== 'triples' && stage !== 'presign') {
          throw new Error('Invalid stage (expected "triples" or "presign")');
        }
        const relayerParticipantId = Number(msg.payload.relayerParticipantId);
        if (!Number.isFinite(relayerParticipantId) || relayerParticipantId <= 0) {
          throw new Error('Invalid relayerParticipantId');
        }

        const currentStage = session.stage();
        if (stage === 'presign') {
          if (currentStage === 'triples_done') {
            session.start_presign();
          } else if (currentStage === 'triples') {
            throw new Error('Client presign session is not ready for "presign" stage');
          }
        }

        if (!Array.isArray(msg.payload.incomingMessages)) {
          throw new Error('threshold ECDSA presign step requires incomingMessages');
        }
        const incomingMessages = msg.payload.incomingMessages.map((entry) => toU8(entry));
        for (const incoming of incomingMessages) {
          session.message(relayerParticipantId, incoming);
        }

        const progress = pollPresignSession(sessionId, session);
        const transferables = [...progress.outgoingMessages];
        if (progress.presignature97) transferables.push(progress.presignature97);
        postOperationSucceeded(msg, progress, transferables);
        return;
      }
      case 'thresholdEcdsaPresignSessionAbort': {
        const sessionId = String(msg.payload.sessionId || '').trim();
        if (!sessionId) throw new Error('Missing sessionId');
        freePresignSession(sessionId);
        postOperationSucceeded(msg, { ok: true });
        return;
      }
      case 'thresholdEcdsaComputeSignatureShare': {
        const groupPublicKey33 = toU8(msg.payload.groupPublicKey33);
        const presignBigR33 = toU8(msg.payload.presignBigR33);
        const presignKShare32 = toU8(msg.payload.presignKShare32);
        const presignSigmaShare32 = toU8(msg.payload.presignSigmaShare32);
        const digest32 = toU8(msg.payload.digest32);
        const entropy32 = toU8(msg.payload.entropy32);
        try {
          const out = threshold_ecdsa_compute_signature_share(
            new Uint32Array(
              (Array.isArray(msg.payload.participantIds) ? msg.payload.participantIds : []).map((v) =>
                Number(v),
              ),
            ),
            Number(msg.payload.clientParticipantId),
            groupPublicKey33,
            presignBigR33,
            presignKShare32,
            presignSigmaShare32,
            digest32,
            entropy32,
          ) as Uint8Array;
          const ab = out.slice().buffer;
          zeroizeBytes(out);
          postOperationSucceeded(msg, ab, [ab]);
          return;
        } finally {
          zeroizeBytes(presignKShare32);
          zeroizeBytes(presignSigmaShare32);
          zeroizeBytes(digest32);
          zeroizeBytes(entropy32);
        }
      }
      default: {
        throw new Error(
          `Unsupported ethSigner worker operation type: ${String((msg as { type?: unknown }).type)}`,
        );
      }
    }
  } catch (e) {
    if (
      msg?.type === 'thresholdEcdsaPresignSessionInit' ||
      msg?.type === 'thresholdEcdsaPresignSessionStep'
    ) {
      const sessionId = String(
        (msg as { payload?: { sessionId?: unknown } })?.payload?.sessionId || '',
      ).trim();
      if (sessionId) freePresignSession(sessionId);
    }
    const err = asWorkerErrorPayload(e);
    postWorkerOperationProgress(msg.id, msg.type, 'failed', err.message);
    postToMainThread({
      id: msg.id,
      ok: false,
      error: err.message,
      ...(err.code ? { code: err.code } : {}),
      ...(err.coreCode ? { coreCode: err.coreCode } : {}),
    });
  }
});
