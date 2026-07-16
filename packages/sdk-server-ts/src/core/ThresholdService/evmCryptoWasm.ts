import initEvmCryptoWasm, {
  add_secp256k1_public_keys_33,
  compute_eip1559_tx_hash,
  encode_eip1559_signed_tx_from_signature65,
  init_evm_crypto,
  secp256k1_private_key_32_to_public_key_33,
  secp256k1_public_key_33_to_ethereum_address_20,
  sha256_bytes,
  sign_secp256k1_recoverable,
  validate_secp256k1_public_key_33,
  verify_secp256k1_recoverable_signature_against_public_key_33,
} from '../../../../../wasm/evm_crypto/pkg/evm_crypto.js';
import type { InitInput } from '../../../../../wasm/evm_crypto/pkg/evm_crypto.js';

const EVM_CRYPTO_WASM_PATH_CANDIDATES = [
  '../../wasm/evm_crypto/pkg/evm_crypto_bg.wasm',
  '../wasm/evm_crypto/pkg/evm_crypto_bg.wasm',
  '../../../../../wasm/evm_crypto/pkg/evm_crypto_bg.wasm',
];

type EvmCryptoWasmModuleImport = {
  readonly default?: WebAssembly.Module;
};

let evmCryptoWasmInitPromise: Promise<void> | null = null;
let evmCryptoWasmReady = false;

function isNodeEnvironment(): boolean {
  const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } })
    .process;
  const isNode = Boolean(processObj?.versions?.node);
  const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
  const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

function getEvmCryptoWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of EVM_CRYPTO_WASM_PATH_CANDIDATES) {
    try {
      if (!baseUrl) throw new Error('import.meta.url is undefined');
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore
    }
  }
  return resolved;
}

async function loadBundledEvmCryptoWasmModule(): Promise<WebAssembly.Module | null> {
  try {
    const imported =
      (await import('../../../../../wasm/evm_crypto/pkg/evm_crypto_bg.wasm')) as EvmCryptoWasmModuleImport;
    return imported.default instanceof WebAssembly.Module ? imported.default : null;
  } catch {
    return null;
  }
}

async function initEvmCryptoFromCompiledModule(module: WebAssembly.Module): Promise<void> {
  await initEvmCryptoWasm({ module_or_path: module as unknown as InitInput });
  init_evm_crypto();
  evmCryptoWasmReady = true;
}

export async function ensureEvmCryptoWasm(): Promise<void> {
  if (evmCryptoWasmInitPromise) return evmCryptoWasmInitPromise;
  evmCryptoWasmInitPromise = (async () => {
    const urls = getEvmCryptoWasmUrls();
    if (isNodeEnvironment()) {
      const { fileURLToPath } = await import('node:url');
      const { readFile } = await import('node:fs/promises');
      for (const url of urls) {
        try {
          const filePath = fileURLToPath(url);
          const bytes = await readFile(filePath);
          const ab = new ArrayBuffer(bytes.byteLength);
          new Uint8Array(ab).set(bytes);
          const module = await WebAssembly.compile(ab);
          await initEvmCryptoFromCompiledModule(module);
          return;
        } catch {
          // try next
        }
      }
      throw new Error(
        `[threshold-ecdsa] Failed to initialize evm_crypto WASM from filesystem candidates: ${urls.map((u) => u.toString()).join(', ')}`,
      );
    }

    let lastErr: unknown = null;
    const bundledModule = await loadBundledEvmCryptoWasmModule();
    if (bundledModule) {
      try {
        await initEvmCryptoFromCompiledModule(bundledModule);
        return;
      } catch (e) {
        lastErr = e;
      }
    }
    for (const url of urls) {
      try {
        await initEvmCryptoWasm({ module_or_path: url as unknown as InitInput });
        init_evm_crypto();
        evmCryptoWasmReady = true;
        return;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr instanceof Error
      ? lastErr
      : new Error(String(lastErr || 'Failed to initialize evm_crypto WASM'));
  })();
  return evmCryptoWasmInitPromise;
}

function requireEvmCryptoReady(): void {
  if (!evmCryptoWasmReady) {
    throw new Error('[threshold-ecdsa] evm_crypto WASM is not initialized');
  }
}

function checkedBytes(label: string, value: Uint8Array, expectedLength: number): Uint8Array {
  if (value.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes (got ${value.length})`);
  }
  return value;
}

export type ServerEip1559UnsignedTx = {
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

function toDec(value: bigint): string {
  if (value < 0n) throw new Error('[threshold-ecdsa] negative bigint not supported');
  return value.toString(10);
}

function toChainIdNumber(value: number | bigint): number {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new Error('[threshold-ecdsa] chainId must be non-negative');
    const numeric = Number(value);
    if (!Number.isSafeInteger(numeric)) {
      throw new Error('[threshold-ecdsa] chainId must be a safe integer');
    }
    return numeric;
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('[threshold-ecdsa] chainId must be a safe integer');
  }
  return value;
}

function toWasmEip1559Tx(tx: ServerEip1559UnsignedTx): Eip1559TxWasmJson {
  return {
    chainId: toChainIdNumber(tx.chainId),
    nonce: toDec(tx.nonce),
    maxPriorityFeePerGas: toDec(tx.maxPriorityFeePerGas),
    maxFeePerGas: toDec(tx.maxFeePerGas),
    gasLimit: toDec(tx.gasLimit),
    to: tx.to ?? null,
    value: toDec(tx.value),
    data: tx.data ?? '0x',
    accessList: (tx.accessList ?? []).map((entry) => ({
      address: entry.address,
      storageKeys: [...entry.storageKeys],
    })),
  };
}

export function sha256BytesSync(input: Uint8Array): Uint8Array {
  requireEvmCryptoReady();
  const out = sha256_bytes(input) as Uint8Array;
  return checkedBytes('sha256_bytes output', out, 32);
}

export async function computeEip1559TxHash(tx: ServerEip1559UnsignedTx): Promise<Uint8Array> {
  await ensureEvmCryptoWasm();
  const out = compute_eip1559_tx_hash(toWasmEip1559Tx(tx)) as Uint8Array;
  return checkedBytes('compute_eip1559_tx_hash output', out, 32);
}

export async function signSecp256k1Recoverable(
  digest32: Uint8Array,
  privateKey32: Uint8Array,
): Promise<Uint8Array> {
  await ensureEvmCryptoWasm();
  const out = sign_secp256k1_recoverable(digest32, privateKey32) as Uint8Array;
  return checkedBytes('sign_secp256k1_recoverable output', out, 65);
}

export async function verifySecp256k1RecoverableSignatureAgainstPublicKey33(
  digest32: Uint8Array,
  signature65: Uint8Array,
  publicKey33: Uint8Array,
): Promise<Uint8Array> {
  await ensureEvmCryptoWasm();
  const out = verify_secp256k1_recoverable_signature_against_public_key_33(
    digest32,
    signature65,
    publicKey33,
  ) as Uint8Array;
  return checkedBytes(
    'verify_secp256k1_recoverable_signature_against_public_key_33 output',
    out,
    33,
  );
}

export async function encodeEip1559SignedTxFromSignature65(input: {
  tx: ServerEip1559UnsignedTx;
  signature65: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEvmCryptoWasm();
  const out = encode_eip1559_signed_tx_from_signature65(
    toWasmEip1559Tx(input.tx),
    input.signature65,
  ) as Uint8Array;
  return out.slice();
}

export async function validateSecp256k1PublicKey33(input: Uint8Array): Promise<Uint8Array> {
  await ensureEvmCryptoWasm();
  const out = validate_secp256k1_public_key_33(input) as Uint8Array;
  return checkedBytes('validate_secp256k1_public_key_33 output', out, 33);
}

export async function addSecp256k1PublicKeys33(input: {
  left33: Uint8Array;
  right33: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEvmCryptoWasm();
  const out = add_secp256k1_public_keys_33(input.left33, input.right33) as Uint8Array;
  return checkedBytes('add_secp256k1_public_keys_33 output', out, 33);
}

export async function secp256k1PrivateKey32ToPublicKey33(
  privateKey32: Uint8Array,
): Promise<Uint8Array> {
  await ensureEvmCryptoWasm();
  const out = secp256k1_private_key_32_to_public_key_33(privateKey32) as Uint8Array;
  return checkedBytes('secp256k1_private_key_32_to_public_key_33 output', out, 33);
}

export async function secp256k1PublicKey33ToEthereumAddress(
  publicKey33: Uint8Array,
): Promise<string> {
  await ensureEvmCryptoWasm();
  const out = secp256k1_public_key_33_to_ethereum_address_20(publicKey33) as Uint8Array;
  const address20 = checkedBytes('secp256k1_public_key_33_to_ethereum_address_20 output', out, 20);
  return `0x${Array.from(address20)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;
}
