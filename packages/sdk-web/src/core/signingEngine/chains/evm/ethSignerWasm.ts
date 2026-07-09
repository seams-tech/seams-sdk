import type { Eip1559UnsignedTx } from './evmSigning.types';
import { bytesToHex } from './bytes';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';
import { base64UrlDecode } from '@shared/utils/base64';
import type { ThresholdEcdsaPresignAbortResult } from '../../workerManager/workerTypes';

type Eip1559TxWasmJson = {
  chainId: number;
  nonce: string;
  maxPriorityFeePerGas: string;
  maxFeePerGas: string;
  gasLimit: string;
  to?: string | null;
  value: string;
  data?: string;
  accessList?: { address: string; storageKeys: string[] }[];
};

function toDec(v: bigint): string {
  if (v < 0n) throw new Error('[ethSignerWasm] negative bigint not supported');
  return v.toString(10);
}

function toChainIdNumber(v: number | bigint): number {
  if (typeof v === 'bigint') {
    if (v < 0n) throw new Error('[ethSignerWasm] chainId must be a non-negative integer');
    const asNumber = Number(v);
    if (!Number.isSafeInteger(asNumber)) {
      throw new Error('[ethSignerWasm] chainId must be a non-negative safe integer');
    }
    return asNumber;
  }
  if (!Number.isSafeInteger(v) || v < 0) {
    throw new Error('[ethSignerWasm] chainId must be a non-negative safe integer');
  }
  return v;
}

function requireTxNonce(nonce: bigint | undefined): bigint {
  if (typeof nonce === 'bigint') return nonce;
  throw new Error('[ethSignerWasm] missing tx nonce');
}

function toWasmTx(tx: Eip1559UnsignedTx): Eip1559TxWasmJson {
  return {
    chainId: toChainIdNumber(tx.chainId),
    nonce: toDec(requireTxNonce(tx.nonce)),
    maxPriorityFeePerGas: toDec(tx.maxPriorityFeePerGas),
    maxFeePerGas: toDec(tx.maxFeePerGas),
    gasLimit: toDec(tx.gasLimit),
    to: tx.to ?? null,
    value: toDec(tx.value),
    data: tx.data ?? '0x',
    accessList: (tx.accessList ?? []).map((item) => ({
      address: item.address,
      storageKeys: item.storageKeys,
    })),
  };
}

const ETH_SIGNER_WORKER_KIND = 'ethSigner' as const;
const ETH_SIGNER_WORKER_TIMEOUT_MS = 20_000;

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

export async function computeEip1559TxHashWasm(
  tx: Eip1559UnsignedTx,
  workerCtx: WorkerOperationContext,
): Promise<Uint8Array> {
  const ab = await executeWorkerOperation({
    ctx: workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'computeEip1559TxHash',
      payload: { tx: toWasmTx(tx) },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
    },
  });
  return new Uint8Array(ab);
}

export async function encodeEip1559SignedTxFromSignature65Wasm(args: {
  tx: Eip1559UnsignedTx;
  signature65: Uint8Array; // recovered secp256k1 signature (r||s||v)
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const signature65 = args.signature65.slice().buffer;
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'encodeEip1559SignedTxFromSignature65',
      payload: { tx: toWasmTx(args.tx), signature65 },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [signature65],
    },
  });
  return new Uint8Array(ab);
}

export async function signSecp256k1RecoverableWasm(args: {
  digest32: Uint8Array;
  privateKey32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const digestBuf = args.digest32.slice().buffer;
  const pkBuf = args.privateKey32.slice().buffer;
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'signSecp256k1Recoverable',
      payload: { digest32: digestBuf, privateKey32: pkBuf },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [digestBuf, pkBuf],
    },
  });
  return new Uint8Array(ab);
}

export async function verifySecp256k1RecoverableSignatureAgainstPublicKey33Wasm(args: {
  digest32: Uint8Array;
  signature65: Uint8Array;
  publicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.digest32 instanceof Uint8Array) || args.digest32.length !== 32) {
    throw new Error('digest32 must be 32 bytes');
  }
  if (!(args.signature65 instanceof Uint8Array) || args.signature65.length !== 65) {
    throw new Error('signature65 must be 65 bytes');
  }
  if (!(args.publicKey33 instanceof Uint8Array) || args.publicKey33.length !== 33) {
    throw new Error('publicKey33 must be 33 bytes');
  }
  const digest32 = args.digest32.slice().buffer;
  const signature65 = args.signature65.slice().buffer;
  const publicKey33 = args.publicKey33.slice().buffer;
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'verifySecp256k1RecoverableSignatureAgainstPublicKey33',
      payload: { digest32, signature65, publicKey33 },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [digest32, signature65, publicKey33],
    },
  });
  const recoveredPublicKey33 = new Uint8Array(ab);
  if (recoveredPublicKey33.length !== 33) {
    throw new Error(
      `verifySecp256k1RecoverableSignatureAgainstPublicKey33 expected 33-byte output (got ${recoveredPublicKey33.length})`,
    );
  }
  return recoveredPublicKey33;
}

export async function secp256k1PrivateKey32ToPublicKey33Wasm(args: {
  privateKey32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.privateKey32 instanceof Uint8Array) || args.privateKey32.length !== 32) {
    throw new Error('privateKey32 must be 32 bytes');
  }
  const privateKey32 = args.privateKey32.slice().buffer;
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'secp256k1PrivateKey32ToPublicKey33',
      payload: { privateKey32 },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [privateKey32],
    },
  });
  const publicKey33 = new Uint8Array(ab);
  if (publicKey33.length !== 33) {
    throw new Error(
      `secp256k1PrivateKey32ToPublicKey33 expected 33-byte output (got ${publicKey33.length})`,
    );
  }
  return publicKey33;
}

export async function deriveSecp256k1KeypairFromPrfSecondWasm(args: {
  prfSecondB64u: string;
  walletSessionUserId: string;
  workerCtx: WorkerOperationContext;
}): Promise<{ privateKeyHex: string; publicKeyHex: string; ethereumAddress: string }> {
  const prfSecondB64u = String(args.prfSecondB64u || '').trim();
  if (!prfSecondB64u) throw new Error('Missing prfSecondB64u');
  const walletSessionUserId = String(args.walletSessionUserId || '').trim();
  if (!walletSessionUserId) throw new Error('Missing walletSessionUserId');

  const prfSecond = base64UrlDecode(prfSecondB64u);
  if (prfSecond.length === 0) {
    throw new Error('Invalid PRF.second: empty after base64url decode');
  }
  const prfSecondCopy = prfSecond.slice();
  try {
    const raw = await executeWorkerOperation({
      ctx: args.workerCtx,
      kind: ETH_SIGNER_WORKER_KIND,
      request: {
        type: 'deriveSecp256k1KeypairFromPrfSecond',
        payload: {
          prfSecond: prfSecondCopy.buffer,
          walletSessionUserId,
        },
        timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
        transfer: [prfSecondCopy.buffer],
      },
    });

    const privateKey32 = new Uint8Array(raw.privateKey32);
    const publicKey33 = new Uint8Array(raw.publicKey33);
    const ethereumAddress20 = new Uint8Array(raw.ethereumAddress20);

    try {
      if (privateKey32.length !== 32) {
        throw new Error(
          `deriveSecp256k1KeypairFromPrfSecond expected 32-byte private key (got ${privateKey32.length})`,
        );
      }
      if (publicKey33.length !== 33) {
        throw new Error(
          `deriveSecp256k1KeypairFromPrfSecond expected 33-byte public key (got ${publicKey33.length})`,
        );
      }
      if (ethereumAddress20.length !== 20) {
        throw new Error(
          `deriveSecp256k1KeypairFromPrfSecond expected 20-byte ethereum address (got ${ethereumAddress20.length})`,
        );
      }

      return {
        privateKeyHex: bytesToHex(privateKey32),
        publicKeyHex: bytesToHex(publicKey33),
        ethereumAddress: bytesToHex(ethereumAddress20),
      };
    } finally {
      zeroizeBytes(privateKey32);
    }
  } finally {
    zeroizeBytes(prfSecond);
  }
}

export async function mapAdditiveShareToThresholdSignaturesShare2pWasm(args: {
  additiveShare32: Uint8Array;
  participantId: number;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.additiveShare32 instanceof Uint8Array) || args.additiveShare32.length !== 32) {
    throw new Error('additiveShare32 must be 32 bytes');
  }
  const additiveShare32 = args.additiveShare32.slice();
  const participantId = Math.floor(Number(args.participantId));
  if (!Number.isFinite(participantId) || participantId <= 0) {
    throw new Error(`Invalid participantId: ${args.participantId}`);
  }

  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'mapAdditiveShareToThresholdSignaturesShare2p',
      payload: {
        additiveShare32: additiveShare32.buffer,
        participantId,
      },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [additiveShare32.buffer],
    },
  });
  const mapped = new Uint8Array(ab);
  if (mapped.length !== 32) {
    throw new Error(
      `mapAdditiveShareToThresholdSignaturesShare2p expected 32-byte output (got ${mapped.length})`,
    );
  }
  return mapped;
}

export async function validateSecp256k1PublicKey33Wasm(args: {
  publicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.publicKey33 instanceof Uint8Array) || args.publicKey33.length !== 33) {
    throw new Error('publicKey33 must be 33 bytes');
  }
  const publicKey33 = args.publicKey33.slice();
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'validateSecp256k1PublicKey33',
      payload: { publicKey33: publicKey33.buffer },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [publicKey33.buffer],
    },
  });
  const validated = new Uint8Array(ab);
  if (validated.length !== 33) {
    throw new Error(
      `validateSecp256k1PublicKey33 expected 33-byte output (got ${validated.length})`,
    );
  }
  return validated;
}

export async function addSecp256k1PublicKeys33Wasm(args: {
  left33: Uint8Array;
  right33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.left33 instanceof Uint8Array) || args.left33.length !== 33) {
    throw new Error('left33 must be 33 bytes');
  }
  if (!(args.right33 instanceof Uint8Array) || args.right33.length !== 33) {
    throw new Error('right33 must be 33 bytes');
  }
  const left33 = args.left33.slice();
  const right33 = args.right33.slice();
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'addSecp256k1PublicKeys33',
      payload: {
        left33: left33.buffer,
        right33: right33.buffer,
      },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [left33.buffer, right33.buffer],
    },
  });
  const groupPublicKey33 = new Uint8Array(ab);
  if (groupPublicKey33.length !== 33) {
    throw new Error(
      `addSecp256k1PublicKeys33 expected 33-byte output (got ${groupPublicKey33.length})`,
    );
  }
  return groupPublicKey33;
}

export async function buildWebauthnP256SignatureWasm(args: {
  challenge32: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signatureDer: Uint8Array;
  pubKeyX32: Uint8Array;
  pubKeyY32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.challenge32 instanceof Uint8Array) || args.challenge32.length !== 32) {
    throw new Error('challenge32 must be 32 bytes');
  }
  if (!(args.pubKeyX32 instanceof Uint8Array) || args.pubKeyX32.length !== 32) {
    throw new Error('pubKeyX32 must be 32 bytes');
  }
  if (!(args.pubKeyY32 instanceof Uint8Array) || args.pubKeyY32.length !== 32) {
    throw new Error('pubKeyY32 must be 32 bytes');
  }
  if (!(args.authenticatorData instanceof Uint8Array) || !args.authenticatorData.length) {
    throw new Error('authenticatorData must be non-empty');
  }
  if (!(args.clientDataJSON instanceof Uint8Array) || !args.clientDataJSON.length) {
    throw new Error('clientDataJSON must be non-empty');
  }
  if (!(args.signatureDer instanceof Uint8Array) || !args.signatureDer.length) {
    throw new Error('signatureDer must be non-empty');
  }

  const challenge32 = args.challenge32.slice();
  const authenticatorData = args.authenticatorData.slice();
  const clientDataJSON = args.clientDataJSON.slice();
  const signatureDer = args.signatureDer.slice();
  const pubKeyX32 = args.pubKeyX32.slice();
  const pubKeyY32 = args.pubKeyY32.slice();

  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'buildWebauthnP256Signature',
      payload: {
        challenge32: challenge32.buffer,
        authenticatorData: authenticatorData.buffer,
        clientDataJSON: clientDataJSON.buffer,
        signatureDer: signatureDer.buffer,
        pubKeyX32: pubKeyX32.buffer,
        pubKeyY32: pubKeyY32.buffer,
      },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [
        challenge32.buffer,
        authenticatorData.buffer,
        clientDataJSON.buffer,
        signatureDer.buffer,
        pubKeyX32.buffer,
        pubKeyY32.buffer,
      ],
    },
  });
  return new Uint8Array(ab);
}

export async function decodeCoseP256PublicKeyWasm(args: {
  cosePublicKey: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<{ pubKeyX32: Uint8Array; pubKeyY32: Uint8Array }> {
  if (!(args.cosePublicKey instanceof Uint8Array) || args.cosePublicKey.length === 0) {
    throw new Error('cosePublicKey must be non-empty');
  }
  const cosePublicKey = args.cosePublicKey.slice();
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'decodeCoseP256PublicKey',
      payload: { cosePublicKey: cosePublicKey.buffer },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [cosePublicKey.buffer],
    },
  });
  const decoded = new Uint8Array(ab);
  if (decoded.length !== 64) {
    throw new Error(`decodeCoseP256PublicKey expected 64-byte output (got ${decoded.length})`);
  }
  return {
    pubKeyX32: decoded.slice(0, 32),
    pubKeyY32: decoded.slice(32, 64),
  };
}

export type ThresholdEcdsaPresignProgressWasm = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessages: Uint8Array[];
  presignatureHandle?: string;
  presignatureBigR33?: Uint8Array;
};

type ThresholdEcdsaPresignProgressWasmRaw = {
  stage?: unknown;
  event?: unknown;
  outgoingMessages?: unknown[];
  presignatureHandle?: unknown;
  presignatureBigR33?: unknown;
};

function asPresignProgress(
  raw: ThresholdEcdsaPresignProgressWasmRaw,
): ThresholdEcdsaPresignProgressWasm {
  const stage =
    raw.stage === 'triples' ||
    raw.stage === 'triples_done' ||
    raw.stage === 'presign' ||
    raw.stage === 'done'
      ? raw.stage
      : 'triples';

  const event = raw.event === 'triples_done' || raw.event === 'presign_done' ? raw.event : 'none';

  const outgoingMessages = Array.isArray(raw.outgoingMessages)
    ? raw.outgoingMessages.map((entry) => new Uint8Array(entry as ArrayBuffer))
    : [];

  const presignatureHandle = String(raw.presignatureHandle || '').trim();
  const presignatureBigR33 = raw.presignatureBigR33
    ? new Uint8Array(raw.presignatureBigR33 as ArrayBuffer)
    : undefined;

  return {
    stage,
    event,
    outgoingMessages,
    ...(presignatureHandle ? { presignatureHandle } : {}),
    ...(presignatureBigR33 ? { presignatureBigR33 } : {}),
  };
}

export async function thresholdEcdsaPresignSessionInitWasm(args: {
  sessionId: string;
  participantIds: number[];
  clientParticipantId: number;
  threshold: number;
  clientThresholdSigningShare32: Uint8Array;
  groupPublicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  const clientThresholdSigningShare32 = args.clientThresholdSigningShare32.slice();
  const groupPublicKey33 = args.groupPublicKey33.slice();

  const raw = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'thresholdEcdsaPresignSessionInit',
      payload: {
        sessionId: args.sessionId,
        participantIds: [...args.participantIds],
        clientParticipantId: args.clientParticipantId,
        threshold: args.threshold,
        clientThresholdSigningShare32: clientThresholdSigningShare32.buffer,
        groupPublicKey33: groupPublicKey33.buffer,
      },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [clientThresholdSigningShare32.buffer, groupPublicKey33.buffer],
    },
  });

  return asPresignProgress(raw);
}

export async function thresholdEcdsaPresignSessionStepWasm(args: {
  sessionId: string;
  relayerParticipantId: number;
  stage: 'triples' | 'presign';
  incomingMessages: Uint8Array[];
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  const incomingMessages = args.incomingMessages.map((entry) => entry.slice());
  const transfer = incomingMessages.map((entry) => entry.buffer);

  const raw = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'thresholdEcdsaPresignSessionStep',
      payload: {
        sessionId: args.sessionId,
        relayerParticipantId: args.relayerParticipantId,
        stage: args.stage,
        incomingMessages: incomingMessages.map((entry) => entry.buffer),
      },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer,
    },
  });

  return asPresignProgress(raw);
}

export async function thresholdEcdsaPresignSessionAbortWasm(args: {
  sessionId: string;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  const result = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'thresholdEcdsaPresignSessionAbort',
      payload: { sessionId: args.sessionId },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
    },
  });
  assertThresholdEcdsaPresignAbortResult({ result, sessionId: args.sessionId });
}

function assertThresholdEcdsaPresignAbortResult(args: {
  result: ThresholdEcdsaPresignAbortResult;
  sessionId: string;
}): void {
  if (
    args.result.kind !== 'threshold_ecdsa_presign_session_aborted' ||
    args.result.sessionId !== args.sessionId
  ) {
    throw new Error('[ethSignerWasm] invalid threshold ECDSA presign abort result');
  }
}

export async function thresholdEcdsaComputeSignatureShareFromPresignatureHandleWasm(args: {
  materialHandle: string;
  participantIds: number[];
  clientParticipantId: number;
  groupPublicKey33: Uint8Array;
  expectedPresignBigR33: Uint8Array;
  digest32: Uint8Array;
  entropy32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const groupPublicKey33 = args.groupPublicKey33.slice();
  const expectedPresignBigR33 = args.expectedPresignBigR33.slice();
  const digest32 = args.digest32.slice();
  const entropy32 = args.entropy32.slice();

  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'thresholdEcdsaComputeSignatureShareFromPresignatureHandle',
      payload: {
        materialHandle: String(args.materialHandle || '').trim(),
        participantIds: [...args.participantIds],
        clientParticipantId: args.clientParticipantId,
        groupPublicKey33: groupPublicKey33.buffer,
        expectedPresignBigR33: expectedPresignBigR33.buffer,
        digest32: digest32.buffer,
        entropy32: entropy32.buffer,
      },
      timeoutMs: ETH_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [
        groupPublicKey33.buffer,
        expectedPresignBigR33.buffer,
        digest32.buffer,
        entropy32.buffer,
      ],
    },
  });
  return new Uint8Array(ab);
}
