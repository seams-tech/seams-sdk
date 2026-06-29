import {
  computeEip1559TxHash,
  encodeEip1559SignedTxFromSignature65,
  secp256k1PrivateKey32ToPublicKey33,
  secp256k1PublicKey33ToEthereumAddress,
  signSecp256k1Recoverable,
  type ServerEip1559UnsignedTx,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from '../core/ThresholdService/ethSignerWasm';

export type WorkerEip1559UnsignedTx = ServerEip1559UnsignedTx;

export async function computeWorkerEip1559TxHash(
  tx: WorkerEip1559UnsignedTx,
): Promise<Uint8Array> {
  return await computeEip1559TxHash(tx);
}

export async function signWorkerSecp256k1Recoverable(input: {
  readonly digest32: Uint8Array;
  readonly privateKey32: Uint8Array;
}): Promise<Uint8Array> {
  return await signSecp256k1Recoverable(input.digest32, input.privateKey32);
}

export async function verifyWorkerSecp256k1RecoverableSignatureAgainstPublicKey33(input: {
  readonly digest32: Uint8Array;
  readonly signature65: Uint8Array;
  readonly publicKey33: Uint8Array;
}): Promise<Uint8Array> {
  return await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
    input.digest32,
    input.signature65,
    input.publicKey33,
  );
}

export async function encodeWorkerEip1559SignedTxFromSignature65(input: {
  readonly tx: WorkerEip1559UnsignedTx;
  readonly signature65: Uint8Array;
}): Promise<Uint8Array> {
  return await encodeEip1559SignedTxFromSignature65(input);
}

export async function workerSecp256k1PrivateKey32ToPublicKey33(
  privateKey32: Uint8Array,
): Promise<Uint8Array> {
  return await secp256k1PrivateKey32ToPublicKey33(privateKey32);
}

export async function workerSecp256k1PublicKey33ToEthereumAddress(
  publicKey33: Uint8Array,
): Promise<`0x${string}`> {
  return parseWorkerEvmAddress(await secp256k1PublicKey33ToEthereumAddress(publicKey33));
}

function parseWorkerEvmAddress(value: string): `0x${string}` {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error('[sponsored-evm] eth_signer returned an invalid sponsor address');
  }
  return value as `0x${string}`;
}
