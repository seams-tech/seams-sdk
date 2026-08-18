import type { Eip1559UnsignedTx } from './evmSigning.types';
import { bytesToHex } from './bytes';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';
import { base64UrlDecode } from '@shared/utils/base64';

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
  if (v < 0n) throw new Error('[evmCryptoWasm] negative bigint not supported');
  return v.toString(10);
}

function toChainIdNumber(v: number | bigint): number {
  if (typeof v === 'bigint') {
    if (v < 0n) throw new Error('[evmCryptoWasm] chainId must be a non-negative integer');
    const asNumber = Number(v);
    if (!Number.isSafeInteger(asNumber)) {
      throw new Error('[evmCryptoWasm] chainId must be a non-negative safe integer');
    }
    return asNumber;
  }
  if (!Number.isSafeInteger(v) || v < 0) {
    throw new Error('[evmCryptoWasm] chainId must be a non-negative safe integer');
  }
  return v;
}

function requireTxNonce(nonce: bigint | undefined): bigint {
  if (typeof nonce === 'bigint') return nonce;
  throw new Error('[evmCryptoWasm] missing tx nonce');
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

const EVM_CRYPTO_WORKER_KIND = 'evmCrypto' as const;
const EVM_CRYPTO_WORKER_TIMEOUT_MS = 20_000;

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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'computeEip1559TxHash',
      payload: { tx: toWasmTx(tx) },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'encodeEip1559SignedTxFromSignature65',
      payload: { tx: toWasmTx(args.tx), signature65 },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'signSecp256k1Recoverable',
      payload: { digest32: digestBuf, privateKey32: pkBuf },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'verifySecp256k1RecoverableSignatureAgainstPublicKey33',
      payload: { digest32, signature65, publicKey33 },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'secp256k1PrivateKey32ToPublicKey33',
      payload: { privateKey32 },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
      kind: EVM_CRYPTO_WORKER_KIND,
      request: {
        type: 'deriveSecp256k1KeypairFromPrfSecond',
        payload: {
          prfSecond: prfSecondCopy.buffer,
          walletSessionUserId,
        },
        timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'validateSecp256k1PublicKey33',
      payload: { publicKey33: publicKey33.buffer },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'addSecp256k1PublicKeys33',
      payload: {
        left33: left33.buffer,
        right33: right33.buffer,
      },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
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
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
    kind: EVM_CRYPTO_WORKER_KIND,
    request: {
      type: 'decodeCoseP256PublicKey',
      payload: { cosePublicKey: cosePublicKey.buffer },
      timeoutMs: EVM_CRYPTO_WORKER_TIMEOUT_MS,
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
