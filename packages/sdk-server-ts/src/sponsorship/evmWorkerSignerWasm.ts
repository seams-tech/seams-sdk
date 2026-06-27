import initEthSignerWasm, {
  compute_eip1559_tx_hash,
  encode_eip1559_signed_tx_from_signature65,
  init_eth_signer,
  secp256k1_private_key_32_to_public_key_33,
  secp256k1_public_key_33_to_ethereum_address_20,
  sign_secp256k1_recoverable,
  verify_secp256k1_recoverable_signature_against_public_key_33,
} from '../../../../wasm/eth_signer/pkg/eth_signer.js';

export type WorkerEip1559UnsignedTx = {
  chainId: number | bigint;
  nonce: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
  to?: string | null;
  value: bigint;
  data?: string;
  accessList?: Array<{
    address: string;
    storageKeys: string[];
  }>;
};

type WorkerEip1559TxWasmJson = {
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

let workerEthSignerWasmInitPromise: Promise<void> | null = null;
let workerEthSignerWasmReady = false;

export async function ensureWorkerEthSignerWasm(): Promise<void> {
  if (workerEthSignerWasmInitPromise) return workerEthSignerWasmInitPromise;
  workerEthSignerWasmInitPromise = initializeWorkerEthSignerWasm();
  return workerEthSignerWasmInitPromise;
}

async function initializeWorkerEthSignerWasm(): Promise<void> {
  await initEthSignerWasm();
  init_eth_signer();
  workerEthSignerWasmReady = true;
}

function requireWorkerEthSignerReady(): void {
  if (!workerEthSignerWasmReady) {
    throw new Error('[sponsored-evm] Worker eth_signer WASM is not initialized');
  }
}

function checkedBytes(label: string, value: Uint8Array, expectedLength: number): Uint8Array {
  if (value.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes (got ${value.length})`);
  }
  return value;
}

function toDec(value: bigint): string {
  if (value < 0n) throw new Error('[sponsored-evm] negative bigint not supported');
  return value.toString(10);
}

function toChainIdNumber(value: number | bigint): number {
  if (typeof value === 'bigint') return bigintChainIdToNumber(value);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('[sponsored-evm] chainId must be a safe integer');
  }
  return value;
}

function bigintChainIdToNumber(value: bigint): number {
  if (value < 0n) throw new Error('[sponsored-evm] chainId must be non-negative');
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric)) {
    throw new Error('[sponsored-evm] chainId must be a safe integer');
  }
  return numeric;
}

function toWasmEip1559Tx(tx: WorkerEip1559UnsignedTx): WorkerEip1559TxWasmJson {
  return {
    chainId: toChainIdNumber(tx.chainId),
    nonce: toDec(tx.nonce),
    maxPriorityFeePerGas: toDec(tx.maxPriorityFeePerGas),
    maxFeePerGas: toDec(tx.maxFeePerGas),
    gasLimit: toDec(tx.gasLimit),
    to: tx.to ?? null,
    value: toDec(tx.value),
    data: tx.data ?? '0x',
    accessList: (tx.accessList ?? []).map(formatAccessListEntry),
  };
}

function formatAccessListEntry(entry: {
  address: string;
  storageKeys: string[];
}): { address: string; storageKeys: string[] } {
  return {
    address: entry.address,
    storageKeys: [...entry.storageKeys],
  };
}

function address20ToHex(address20: Uint8Array): `0x${string}` {
  return `0x${Array.from(address20)
    .map(hexByte)
    .join('')}` as `0x${string}`;
}

function hexByte(entry: number): string {
  return entry.toString(16).padStart(2, '0');
}

export async function computeWorkerEip1559TxHash(
  tx: WorkerEip1559UnsignedTx,
): Promise<Uint8Array> {
  await ensureWorkerEthSignerWasm();
  requireWorkerEthSignerReady();
  const out = compute_eip1559_tx_hash(toWasmEip1559Tx(tx)) as Uint8Array;
  return checkedBytes('compute_eip1559_tx_hash output', out, 32);
}

export async function signWorkerSecp256k1Recoverable(input: {
  digest32: Uint8Array;
  privateKey32: Uint8Array;
}): Promise<Uint8Array> {
  await ensureWorkerEthSignerWasm();
  requireWorkerEthSignerReady();
  const out = sign_secp256k1_recoverable(input.digest32, input.privateKey32) as Uint8Array;
  return checkedBytes('sign_secp256k1_recoverable output', out, 65);
}

export async function verifyWorkerSecp256k1RecoverableSignatureAgainstPublicKey33(input: {
  digest32: Uint8Array;
  signature65: Uint8Array;
  publicKey33: Uint8Array;
}): Promise<Uint8Array> {
  await ensureWorkerEthSignerWasm();
  requireWorkerEthSignerReady();
  const out = verify_secp256k1_recoverable_signature_against_public_key_33(
    input.digest32,
    input.signature65,
    input.publicKey33,
  ) as Uint8Array;
  return checkedBytes(
    'verify_secp256k1_recoverable_signature_against_public_key_33 output',
    out,
    33,
  );
}

export async function encodeWorkerEip1559SignedTxFromSignature65(input: {
  tx: WorkerEip1559UnsignedTx;
  signature65: Uint8Array;
}): Promise<Uint8Array> {
  await ensureWorkerEthSignerWasm();
  requireWorkerEthSignerReady();
  const out = encode_eip1559_signed_tx_from_signature65(
    toWasmEip1559Tx(input.tx),
    input.signature65,
  ) as Uint8Array;
  return out.slice();
}

export async function workerSecp256k1PrivateKey32ToPublicKey33(
  privateKey32: Uint8Array,
): Promise<Uint8Array> {
  await ensureWorkerEthSignerWasm();
  requireWorkerEthSignerReady();
  const out = secp256k1_private_key_32_to_public_key_33(privateKey32) as Uint8Array;
  return checkedBytes('secp256k1_private_key_32_to_public_key_33 output', out, 33);
}

export async function workerSecp256k1PublicKey33ToEthereumAddress(
  publicKey33: Uint8Array,
): Promise<`0x${string}`> {
  await ensureWorkerEthSignerWasm();
  requireWorkerEthSignerReady();
  const out = secp256k1_public_key_33_to_ethereum_address_20(publicKey33) as Uint8Array;
  const address20 = checkedBytes('secp256k1_public_key_33_to_ethereum_address_20 output', out, 20);
  return address20ToHex(address20);
}
