import initEthSignerWasm, {
  add_secp256k1_public_keys_33,
  compute_eip1559_tx_hash,
  ecdsa_hss_bootstrap_non_export_sign_full,
  ecdsa_hss_explicit_export,
  threshold_ecdsa_hss_finalize_server_report,
  threshold_ecdsa_hss_open_server_output,
  threshold_ecdsa_hss_prepare_server_ceremony,
  threshold_ecdsa_hss_prepare_server_session,
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
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '../thresholdEcdsaChainTarget';

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

export async function ecdsaHssBootstrapNonExportSign(input: {
  walletSessionUserId: string;
  subjectId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
  yClient32Le: Uint8Array;
  yRelayer32Le: Uint8Array;
}): Promise<{
  groupPublicKey33: Uint8Array;
  ethereumAddress20: Uint8Array;
  clientAdditiveShare32: Uint8Array;
  clientPublicKey33: Uint8Array;
  relayerAdditiveShare32: Uint8Array;
  relayerPublicKey33: Uint8Array;
  clientThresholdPrivateShare32: Uint8Array;
  relayerThresholdPrivateShare32: Uint8Array;
  retryCounter: number;
}> {
  await ensureEthSignerWasm();
  const walletSessionUserId = String(input.walletSessionUserId || '').trim();
  const raw = ecdsa_hss_bootstrap_non_export_sign_full({
    walletSessionUserId,
    subjectId: String(input.subjectId || '').trim(),
    chainTarget: thresholdEcdsaChainTargetKey(input.chainTarget),
    ecdsaThresholdKeyId: String(input.ecdsaThresholdKeyId || '').trim(),
    signingRootId: String(input.signingRootId || '').trim(),
    signingRootVersion: String(input.signingRootVersion || '').trim(),
    keyPurpose: String(input.keyPurpose || '').trim(),
    keyVersion: String(input.keyVersion || '').trim(),
    yClient32Le: Array.from(checkedBytes('yClient32Le', input.yClient32Le, 32)),
    yRelayer32Le: Array.from(checkedBytes('yRelayer32Le', input.yRelayer32Le, 32)),
  }) as {
    groupPublicKey33?: Uint8Array | number[];
    ethereumAddress20?: Uint8Array | number[];
    clientAdditiveShare32?: Uint8Array | number[];
    clientPublicKey33?: Uint8Array | number[];
    relayerAdditiveShare32?: Uint8Array | number[];
    relayerPublicKey33?: Uint8Array | number[];
    clientThresholdPrivateShare32?: Uint8Array | number[];
    relayerThresholdPrivateShare32?: Uint8Array | number[];
    retryCounter?: number;
  };
  const toBytes = (
    label: string,
    value: Uint8Array | number[] | undefined,
    len: number,
  ): Uint8Array =>
    checkedBytes(label, value instanceof Uint8Array ? value : Uint8Array.from(value || []), len);
  return {
    groupPublicKey33: toBytes('ecdsa_hss groupPublicKey33', raw.groupPublicKey33, 33),
    ethereumAddress20: toBytes('ecdsa_hss ethereumAddress20', raw.ethereumAddress20, 20),
    clientAdditiveShare32: toBytes(
      'ecdsa_hss clientAdditiveShare32',
      raw.clientAdditiveShare32,
      32,
    ),
    clientPublicKey33: toBytes('ecdsa_hss clientPublicKey33', raw.clientPublicKey33, 33),
    relayerAdditiveShare32: toBytes(
      'ecdsa_hss relayerAdditiveShare32',
      raw.relayerAdditiveShare32,
      32,
    ),
    relayerPublicKey33: toBytes('ecdsa_hss relayerPublicKey33', raw.relayerPublicKey33, 33),
    clientThresholdPrivateShare32: toBytes(
      'ecdsa_hss clientThresholdPrivateShare32',
      raw.clientThresholdPrivateShare32,
      32,
    ),
    relayerThresholdPrivateShare32: toBytes(
      'ecdsa_hss relayerThresholdPrivateShare32',
      raw.relayerThresholdPrivateShare32,
      32,
    ),
    retryCounter: Number.isFinite(raw.retryCounter) ? Math.floor(Number(raw.retryCounter)) : 0,
  };
}

export async function ecdsaHssExplicitExport(input: {
  walletSessionUserId: string;
  subjectId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
  yClient32Le: Uint8Array;
  yRelayer32Le: Uint8Array;
}): Promise<{
  canonicalX32: Uint8Array;
  canonicalPublicKey33: Uint8Array;
  canonicalEthereumAddress20: Uint8Array;
}> {
  await ensureEthSignerWasm();
  const walletSessionUserId = String(input.walletSessionUserId || '').trim();
  const raw = ecdsa_hss_explicit_export({
    walletSessionUserId,
    subjectId: String(input.subjectId || '').trim(),
    chainTarget: thresholdEcdsaChainTargetKey(input.chainTarget),
    ecdsaThresholdKeyId: String(input.ecdsaThresholdKeyId || '').trim(),
    signingRootId: String(input.signingRootId || '').trim(),
    signingRootVersion: String(input.signingRootVersion || '').trim(),
    keyPurpose: String(input.keyPurpose || '').trim(),
    keyVersion: String(input.keyVersion || '').trim(),
    yClient32Le: Array.from(checkedBytes('yClient32Le', input.yClient32Le, 32)),
    yRelayer32Le: Array.from(checkedBytes('yRelayer32Le', input.yRelayer32Le, 32)),
  }) as {
    canonicalX32?: Uint8Array | number[];
    canonicalPublicKey33?: Uint8Array | number[];
    canonicalEthereumAddress20?: Uint8Array | number[];
  };
  const toBytes = (
    label: string,
    value: Uint8Array | number[] | undefined,
    len: number,
  ): Uint8Array =>
    checkedBytes(label, value instanceof Uint8Array ? value : Uint8Array.from(value || []), len);
  return {
    canonicalX32: toBytes('ecdsa_hss canonicalX32', raw.canonicalX32, 32),
    canonicalPublicKey33: toBytes('ecdsa_hss canonicalPublicKey33', raw.canonicalPublicKey33, 33),
    canonicalEthereumAddress20: toBytes(
      'ecdsa_hss canonicalEthereumAddress20',
      raw.canonicalEthereumAddress20,
      20,
    ),
  };
}

export async function prepareThresholdEcdsaHssServerSession(input: {
  walletSessionUserId: string;
  subjectId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyPurpose: string;
  keyVersion: string;
  operation:
    | 'registration_bootstrap'
    | 'session_bootstrap'
    | 'non_export_sign'
    | 'explicit_key_export';
  yRelayer32Le: Uint8Array;
}): Promise<{
  preparedServerSessionB64u: string;
  serverAssistInitMessageB64u: string;
}> {
  await ensureEthSignerWasm();
  const walletSessionUserId = String(input.walletSessionUserId || '').trim();
  return threshold_ecdsa_hss_prepare_server_session({
    walletSessionUserId,
    subjectId: String(input.subjectId || '').trim(),
    chainTarget: thresholdEcdsaChainTargetKey(input.chainTarget),
    ecdsaThresholdKeyId: String(input.ecdsaThresholdKeyId || '').trim(),
    signingRootId: String(input.signingRootId || '').trim(),
    signingRootVersion: String(input.signingRootVersion || '').trim(),
    keyPurpose: String(input.keyPurpose || '').trim(),
    keyVersion: String(input.keyVersion || '').trim(),
    operation: String(input.operation || '').trim(),
    yRelayer32Le: Array.from(checkedBytes('yRelayer32Le', input.yRelayer32Le, 32)),
  });
}

export async function prepareThresholdEcdsaHssServerCeremony(input: {
  preparedServerSessionB64u: string;
  clientEvalRequestB64u: string;
  serverAssistInitB64u: string;
}): Promise<{
  serverEvalResponseB64u: string;
}> {
  await ensureEthSignerWasm();
  return threshold_ecdsa_hss_prepare_server_ceremony({
    preparedServerSessionB64u: String(input.preparedServerSessionB64u || '').trim(),
    clientEvalRequestB64u: String(input.clientEvalRequestB64u || '').trim(),
    serverAssistInitB64u: String(input.serverAssistInitB64u || '').trim(),
  });
}

export async function finalizeThresholdEcdsaHssServerReport(input: {
  preparedServerSessionB64u: string;
  clientEvalRequestB64u: string;
  clientEvalFinalizeB64u: string;
  serverEvalResponseB64u: string;
}): Promise<{
  serverOutputMessageB64u: string;
}> {
  await ensureEthSignerWasm();
  return threshold_ecdsa_hss_finalize_server_report({
    preparedServerSessionB64u: String(input.preparedServerSessionB64u || '').trim(),
    clientEvalRequestB64u: String(input.clientEvalRequestB64u || '').trim(),
    clientEvalFinalizeB64u: String(input.clientEvalFinalizeB64u || '').trim(),
    serverEvalResponseB64u: String(input.serverEvalResponseB64u || '').trim(),
  });
}

export async function openThresholdEcdsaHssServerOutput(input: {
  preparedServerSessionB64u: string;
  serverOutputMessageB64u: string;
}): Promise<{
  contextBindingB64u: string;
  yClient32LeB64u: string;
}> {
  await ensureEthSignerWasm();
  return threshold_ecdsa_hss_open_server_output({
    preparedServerSessionB64u: String(input.preparedServerSessionB64u || '').trim(),
    serverOutputMessageB64u: String(input.serverOutputMessageB64u || '').trim(),
  });
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
