import initEthSignerWasm, {
  add_secp256k1_public_keys_33,
  compute_eip1559_tx_hash,
  threshold_ecdsa_hss_role_local_relayer_bootstrap,
  encode_eip1559_signed_tx_from_signature65,
  init_eth_signer,
  map_additive_share_to_threshold_signatures_share_2p,
  secp256k1_private_key_32_to_public_key_33,
  secp256k1_public_key_33_to_ethereum_address_20,
  sha256_bytes,
  sign_secp256k1_recoverable,
  validate_secp256k1_public_key_33,
  verify_secp256k1_recoverable_signature_against_public_key_33,
} from '../../../../wasm/eth_signer/pkg/eth_signer.js';
import type { InitInput } from '../../../../wasm/eth_signer/pkg/eth_signer.js';

const ETH_SIGNER_WASM_PATH_CANDIDATES = [
  // Source-tree execution (server/src/* -> repo/wasm/*)
  '../../../../wasm/eth_signer/pkg/eth_signer_bg.wasm',
  // Built SDK execution (sdk/dist/esm/server/* -> repo/wasm/*)
  '../../../../../../wasm/eth_signer/pkg/eth_signer_bg.wasm',
  // Built SDK workers output (sdk/dist/workers/*)
  '../../../../workers/eth_signer.wasm',
  // Legacy/alternate workers output (sdk/dist/esm/workers/*)
  '../../../workers/eth_signer.wasm',
];

let ethSignerWasmInitPromise: Promise<void> | null = null;
let ethSignerWasmReady = false;

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

function getEthSignerWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of ETH_SIGNER_WASM_PATH_CANDIDATES) {
    try {
      if (!baseUrl) throw new Error('import.meta.url is undefined');
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore
    }
  }
  return resolved;
}

export async function ensureEthSignerWasm(): Promise<void> {
  if (ethSignerWasmInitPromise) return ethSignerWasmInitPromise;
  ethSignerWasmInitPromise = (async () => {
    const urls = getEthSignerWasmUrls();
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
          await initEthSignerWasm({ module_or_path: module as unknown as InitInput });
          init_eth_signer();
          ethSignerWasmReady = true;
          return;
        } catch {
          // try next
        }
      }
      throw new Error(
        `[threshold-ecdsa] Failed to initialize eth_signer WASM from filesystem candidates: ${urls.map((u) => u.toString()).join(', ')}`,
      );
    }

    let lastErr: unknown = null;
    for (const url of urls) {
      try {
        await initEthSignerWasm({ module_or_path: url as unknown as InitInput });
        init_eth_signer();
        ethSignerWasmReady = true;
        return;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr instanceof Error
      ? lastErr
      : new Error(String(lastErr || 'Failed to initialize eth_signer WASM'));
  })();
  return ethSignerWasmInitPromise;
}

function requireEthSignerReady(): void {
  if (!ethSignerWasmReady) {
    throw new Error('[threshold-ecdsa] eth_signer WASM is not initialized');
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
  requireEthSignerReady();
  const out = sha256_bytes(input) as Uint8Array;
  return checkedBytes('sha256_bytes output', out, 32);
}

export async function computeEip1559TxHash(tx: ServerEip1559UnsignedTx): Promise<Uint8Array> {
  await ensureEthSignerWasm();
  const out = compute_eip1559_tx_hash(toWasmEip1559Tx(tx)) as Uint8Array;
  return checkedBytes('compute_eip1559_tx_hash output', out, 32);
}

export async function signSecp256k1Recoverable(
  digest32: Uint8Array,
  privateKey32: Uint8Array,
): Promise<Uint8Array> {
  await ensureEthSignerWasm();
  const out = sign_secp256k1_recoverable(digest32, privateKey32) as Uint8Array;
  return checkedBytes('sign_secp256k1_recoverable output', out, 65);
}

export async function verifySecp256k1RecoverableSignatureAgainstPublicKey33(
  digest32: Uint8Array,
  signature65: Uint8Array,
  publicKey33: Uint8Array,
): Promise<Uint8Array> {
  await ensureEthSignerWasm();
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
  await ensureEthSignerWasm();
  const out = encode_eip1559_signed_tx_from_signature65(
    toWasmEip1559Tx(input.tx),
    input.signature65,
  ) as Uint8Array;
  return out.slice();
}

export async function validateSecp256k1PublicKey33(input: Uint8Array): Promise<Uint8Array> {
  await ensureEthSignerWasm();
  const out = validate_secp256k1_public_key_33(input) as Uint8Array;
  return checkedBytes('validate_secp256k1_public_key_33 output', out, 33);
}

export async function addSecp256k1PublicKeys33(input: {
  left33: Uint8Array;
  right33: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEthSignerWasm();
  const out = add_secp256k1_public_keys_33(input.left33, input.right33) as Uint8Array;
  return checkedBytes('add_secp256k1_public_keys_33 output', out, 33);
}

export async function secp256k1PrivateKey32ToPublicKey33(
  privateKey32: Uint8Array,
): Promise<Uint8Array> {
  await ensureEthSignerWasm();
  const out = secp256k1_private_key_32_to_public_key_33(privateKey32) as Uint8Array;
  return checkedBytes('secp256k1_private_key_32_to_public_key_33 output', out, 33);
}

export async function mapAdditiveShareToThresholdSignaturesShare2p(input: {
  additiveShare32: Uint8Array;
  participantId: number;
}): Promise<Uint8Array> {
  await ensureEthSignerWasm();
  const out = map_additive_share_to_threshold_signatures_share_2p(
    input.additiveShare32,
    input.participantId,
  ) as Uint8Array;
  return checkedBytes('map_additive_share_to_threshold_signatures_share_2p output', out, 32);
}

export async function roleLocalThresholdEcdsaHssRelayerBootstrap(input: {
  walletSessionUserId: string;
  subjectId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
  relayerKeyId: string;
  yRelayer32Le: Uint8Array;
  clientPublicKey33: Uint8Array;
  clientShareRetryCounter: number;
}): Promise<{
  contextBinding32: Uint8Array;
  relayerShare32: Uint8Array;
  relayerPublicKey33: Uint8Array;
  groupPublicKey33: Uint8Array;
  ethereumAddress20: Uint8Array;
  relayerMappedPrivateShare32: Uint8Array;
  relayerShareRetryCounter: number;
  publicTranscriptDigest32: Uint8Array;
}> {
  await ensureEthSignerWasm();
  const raw = threshold_ecdsa_hss_role_local_relayer_bootstrap({
    walletSessionUserId: String(input.walletSessionUserId || '').trim(),
    subjectId: String(input.subjectId || '').trim(),
    ecdsaThresholdKeyId: String(input.ecdsaThresholdKeyId || '').trim(),
    signingRootId: String(input.signingRootId || '').trim(),
    signingRootVersion: String(input.signingRootVersion || '').trim(),
    keyPurpose: String(input.keyPurpose || '').trim(),
    keyVersion: String(input.keyVersion || '').trim(),
    relayerKeyId: String(input.relayerKeyId || '').trim(),
    yRelayer32Le: Array.from(checkedBytes('yRelayer32Le', input.yRelayer32Le, 32)),
    clientPublicKey33: Array.from(checkedBytes('clientPublicKey33', input.clientPublicKey33, 33)),
    clientShareRetryCounter: Number(input.clientShareRetryCounter),
  }) as {
    contextBinding32?: Uint8Array | number[];
    relayerShare32?: Uint8Array | number[];
    relayerPublicKey33?: Uint8Array | number[];
    groupPublicKey33?: Uint8Array | number[];
    ethereumAddress20?: Uint8Array | number[];
    relayerMappedPrivateShare32?: Uint8Array | number[];
    relayerShareRetryCounter?: number;
    publicTranscriptDigest32?: Uint8Array | number[];
  };
  const toBytes = (
    label: string,
    value: Uint8Array | number[] | undefined,
    len: number,
  ): Uint8Array =>
    checkedBytes(label, value instanceof Uint8Array ? value : Uint8Array.from(value || []), len);
  return {
    contextBinding32: toBytes('ecdsa_hss contextBinding32', raw.contextBinding32, 32),
    relayerShare32: toBytes('ecdsa_hss relayerShare32', raw.relayerShare32, 32),
    relayerPublicKey33: toBytes('ecdsa_hss relayerPublicKey33', raw.relayerPublicKey33, 33),
    groupPublicKey33: toBytes('ecdsa_hss groupPublicKey33', raw.groupPublicKey33, 33),
    ethereumAddress20: toBytes('ecdsa_hss ethereumAddress20', raw.ethereumAddress20, 20),
    relayerMappedPrivateShare32: toBytes(
      'ecdsa_hss relayerMappedPrivateShare32',
      raw.relayerMappedPrivateShare32,
      32,
    ),
    relayerShareRetryCounter: Number.isFinite(raw.relayerShareRetryCounter)
      ? Math.floor(Number(raw.relayerShareRetryCounter))
      : 0,
    publicTranscriptDigest32: toBytes(
      'ecdsa_hss publicTranscriptDigest32',
      raw.publicTranscriptDigest32,
      32,
    ),
  };
}

export async function secp256k1PublicKey33ToEthereumAddress(
  publicKey33: Uint8Array,
): Promise<string> {
  await ensureEthSignerWasm();
  const out = secp256k1_public_key_33_to_ethereum_address_20(publicKey33) as Uint8Array;
  const address20 = checkedBytes('secp256k1_public_key_33_to_ethereum_address_20 output', out, 20);
  return `0x${Array.from(address20)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;
}
