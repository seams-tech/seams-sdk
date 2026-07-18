import fs from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';

const repoRoot = path.resolve(import.meta.dirname, '../..');

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function requireContains(source, fragment, label) {
  if (!source.includes(fragment)) {
    throw new Error(`${label} is missing required fragment: ${fragment}`);
  }
}

function requireAbsent(source, fragment, label) {
  if (source.includes(fragment)) {
    throw new Error(`${label} contains forbidden fragment: ${fragment}`);
  }
}

function requirePathAbsent(relativePath) {
  if (fs.existsSync(path.join(repoRoot, relativePath))) {
    throw new Error(`deleted ECDSA owner returned: ${relativePath}`);
  }
}

function verifyReviewCorpusDigests() {
  const reviewRecord = read('docs/security/router-ab-ecdsa-phase4-review.md');
  const digestRows = Array.from(reviewRecord.matchAll(/\| `([^`]+)` \| `([0-9a-f]{64})` \|/g));
  if (digestRows.length !== 16) {
    throw new Error(
      `ECDSA review corpus must pin exactly 16 artifacts; found ${digestRows.length}`,
    );
  }

  for (const [, relativePath, expectedDigest] of digestRows) {
    const artifactPath = path.join(repoRoot, relativePath);
    if (!fs.existsSync(artifactPath)) {
      throw new Error(`ECDSA review corpus artifact is missing: ${relativePath}`);
    }
    const actualDigest = createHash('sha256').update(fs.readFileSync(artifactPath)).digest('hex');
    if (actualDigest !== expectedDigest) {
      throw new Error(
        `ECDSA review corpus digest mismatch for ${relativePath}: ${actualDigest} != ${expectedDigest}`,
      );
    }
  }
}

for (const deletedPath of [
  'crates/ecdsa-hss',
  'wasm/eth_signer',
  'wasm/evm_transaction_codec/Cargo.toml',
  'wasm/evm_transaction_codec/src/lib.rs',
  'wasm/webauthn_p256/Cargo.toml',
  'wasm/webauthn_p256/src/lib.rs',
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-hss-client.worker.ts',
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/ecdsaHssPoolFillLiveSession.ts',
  'tests/unit/thresholdEcdsa.doPoolFill.unit.test.ts',
  'packages/sdk-web/dist/workers/ecdsa-hss-client.worker.js',
  'packages/sdk-web/dist/workers/eth-signer.worker.js',
  'packages/sdk-web/dist/workers/eth_signer.wasm',
  'packages/sdk-web/dist/workers/eth_signer_bg.wasm',
]) {
  requirePathAbsent(deletedPath);
}

const derivationWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts',
);
const presignWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-presign-client.worker.ts',
);
const onlineWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-online-client.worker.ts',
);
const emailOtpWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
);
const evmCryptoWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/evm-crypto.worker.ts',
);
const channels = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels.ts',
);
const workerTypes = read('packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts');
const transport = read('packages/sdk-web/src/core/signingEngine/workerManager/workerTransport.ts');
const facade = read(
  'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts',
);
const registrationDts = read(
  'wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.d.ts',
);
const registrationManifest = read('wasm/ecdsa_registration_client/Cargo.toml');
const presignDts = read(
  'wasm/router_ab_ecdsa_presign_client/pkg/router_ab_ecdsa_presign_client.d.ts',
);
const onlineDts = read('wasm/router_ab_ecdsa_online_client/pkg/router_ab_ecdsa_online_client.d.ts');
const presignManifest = read('wasm/router_ab_ecdsa_presign_client/Cargo.toml');
const onlineManifest = read('wasm/router_ab_ecdsa_online_client/Cargo.toml');
const evmCryptoDts = read('wasm/evm_crypto/pkg/evm_crypto.d.ts');
const evmCryptoManifest = read('wasm/evm_crypto/Cargo.toml');
const serverSigningWorkerDts = read(
  'wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.d.ts',
);
const serverSigningWorkerManifest = read('wasm/router_ab_ecdsa_signing_worker/Cargo.toml');
const embeddedSignerLock = read('crates/signer-embedded-linux/Cargo.lock');
const derivationReadme = read('crates/router-ab-ecdsa-derivation/README.md');
const derivationProtocol = read('crates/router-ab-ecdsa-derivation/specs/protocol.md');
const derivationFormalReadme = read(
  'crates/router-ab-ecdsa-derivation/formal-verification/README.md',
);
const serverEcdsaSigningStore = read(
  'packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore.ts',
);
const serverCloudflareStore = read(
  'packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts',
);
const thresholdStoreDurableObject = read(
  'packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts',
);
const thresholdValidation = read('packages/sdk-server-ts/src/core/ThresholdService/validation.ts');
const persistedRecords = read(
  'packages/sdk-server-ts/src/core/ThresholdService/persistedRecords.ts',
);
const normalSigningSource = read(
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/ecdsaDerivationClientSigningMaterialSource.ts',
);
const loginPrefillSource = read(
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource.ts',
);
const builtDerivationWorker = read(
  'packages/sdk-web/dist/workers/ecdsa-derivation-client.worker.js',
);
const builtPresignWorker = read('packages/sdk-web/dist/workers/ecdsa-presign-client.worker.js');
const builtOnlineWorker = read('packages/sdk-web/dist/workers/ecdsa-online-client.worker.js');
const ed25519YaoClientTypes = read(
  'crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.d.ts',
);

function wasmExportNames(relativePath) {
  const bytes = fs.readFileSync(path.join(repoRoot, relativePath));
  return WebAssembly.Module.exports(new WebAssembly.Module(bytes)).map((entry) => entry.name);
}

function requireArtifactTokensAbsent(values, forbiddenTokens, label) {
  const normalizedValues = values.map((value) => value.toLowerCase());
  for (const token of forbiddenTokens) {
    if (normalizedValues.some((value) => value.includes(token))) {
      throw new Error(`${label} contains forbidden token: ${token}`);
    }
  }
}

requireContains(
  derivationWorker,
  'ecdsa_registration_client.js',
  'ECDSA derivation worker',
);
requireContains(
  derivationWorker,
  'router_ab_ecdsa_derivation_client.js',
  'ECDSA derivation worker',
);
requireAbsent(derivationWorker, 'router_ab_ecdsa_presign_client', 'ECDSA derivation worker');
requireAbsent(derivationWorker, 'router_ab_ecdsa_online_client', 'ECDSA derivation worker');
requireAbsent(derivationWorker, 'ClientPresignSession', 'ECDSA derivation worker');
requireAbsent(derivationWorker, 'compute_client_signature_share', 'ECDSA derivation worker');

requireContains(presignWorker, 'router_ab_ecdsa_presign_client.js', 'ECDSA presign worker');
requireAbsent(presignWorker, 'router_ab_ecdsa_derivation_client', 'ECDSA presign worker');
requireAbsent(presignWorker, 'ecdsa_registration_client', 'ECDSA presign worker');
requireAbsent(presignWorker, 'router_ab_ecdsa_online_client', 'ECDSA presign worker');
requireAbsent(presignWorker, 'compute_client_signature_share', 'ECDSA presign worker');

requireContains(onlineWorker, 'router_ab_ecdsa_online_client.js', 'ECDSA online worker');
requireAbsent(onlineWorker, 'router_ab_ecdsa_derivation_client', 'ECDSA online worker');
requireAbsent(onlineWorker, 'ecdsa_registration_client', 'ECDSA online worker');
requireAbsent(onlineWorker, 'router_ab_ecdsa_presign_client', 'ECDSA online worker');
requireAbsent(onlineWorker, 'ClientPresignSession', 'ECDSA online worker');
requireContains(
  onlineWorker,
  'IndexedDbClientPresignMaterialStore',
  'ECDSA online durable material boundary',
);
requireAbsent(onlineWorker, 'MessagePort', 'ECDSA online worker');
requireAbsent(onlineWorker, 'WorkerDeferred', 'ECDSA online worker');

requireContains(
  emailOtpWorker,
  'isAttachEmailOtpToPresignPort',
  'Email OTP direct presign channel',
);
requireContains(channels, 'AttachEmailOtpToPresign', 'ECDSA client worker channel contracts');
requireContains(
  presignWorker,
  "case 'email_otp_worker_session'",
  'ECDSA presign authority dispatch',
);
requireAbsent(workerTypes, 'claimEmailOtpEcdsaSigningShare', 'host-facing worker operation types');
requireAbsent(normalSigningSource, 'additiveShare32', 'normal signing host orchestration');
requireAbsent(loginPrefillSource, 'additiveShare32', 'login prefill host orchestration');

for (const [source, label] of [
  [embeddedSignerLock, 'embedded signer release lockfile'],
  [derivationReadme, 'active ECDSA derivation README'],
  [derivationProtocol, 'active ECDSA derivation protocol'],
  [derivationFormalReadme, 'active ECDSA derivation formal README'],
]) {
  for (const forbidden of ['threshold-signatures', 'Cait-Sith', 'mapped backend shares']) {
    requireAbsent(source, forbidden, label);
  }
}

for (const [source, label] of [
  [serverEcdsaSigningStore, 'server ECDSA signing store'],
  [serverCloudflareStore, 'server Cloudflare threshold store adapter'],
  [thresholdStoreDurableObject, 'threshold store Durable Object'],
  [thresholdValidation, 'threshold persistence validation'],
  [persistedRecords, 'current persisted-record parsers'],
]) {
  for (const forbidden of [
    'RouterAbEcdsaDerivationPresignaturePool',
    'RouterAbEcdsaDerivationServerPresignatureShareRecord',
    'routerAbEcdsaDerivationPresignaturePut',
    'routerAbEcdsaDerivationPresignatureReserve',
    'routerAbEcdsaDerivationPresignatureReserveById',
    'parseRouterAbEcdsaDerivationServerPresignatureShareRecord',
    'parseCurrentRouterAbEcdsaDerivationServerPresignatureRecord',
  ]) {
    requireAbsent(source, forbidden, label);
  }
}

requireContains(evmCryptoWorker, 'evm_crypto.js', 'EVM crypto worker');
requireAbsent(evmCryptoWorker, 'thresholdEcdsa', 'EVM crypto worker');
requireAbsent(evmCryptoWorker, 'Presign', 'EVM crypto worker');
requireAbsent(evmCryptoDts, 'threshold_ecdsa', 'EVM crypto WASM declaration');
requireAbsent(evmCryptoDts, 'Presign', 'EVM crypto WASM declaration');
requireAbsent(evmCryptoDts, 'derivation_relayer', 'EVM crypto WASM declaration');
requireAbsent(evmCryptoManifest, 'threshold-ecdsa', 'EVM crypto dependency graph');
requireAbsent(evmCryptoManifest, 'threshold-signatures', 'EVM crypto dependency graph');
requireContains(
  serverSigningWorkerDts,
  'export class SigningWorkerPresignSession',
  'server signing worker declaration',
);
for (const forbidden of ['participant_ids', 'client_participant_id', 'threshold: number']) {
  requireAbsent(presignDts, forbidden, 'client presign declaration');
}
for (const forbidden of [
  'ThresholdEcdsaPresignSession',
  'participant_ids',
  'participant_id: number',
  'threshold: number',
]) {
  requireAbsent(serverSigningWorkerDts, forbidden, 'server signing worker declaration');
}
requireContains(
  serverSigningWorkerDts,
  'router_ab_ecdsa_derivation_relayer_bootstrap',
  'server signing worker declaration',
);

requireContains(workerTypes, 'ecdsaPresignClient: EcdsaPresignClientOperationMap', 'worker types');
requireContains(workerTypes, 'ecdsaOnlineClient: EcdsaOnlineClientOperationMap', 'worker types');
requireAbsent(workerTypes, 'client_k_share32', 'host-facing worker types');
requireAbsent(workerTypes, 'client_sigma_share32', 'host-facing worker types');

requireContains(transport, 'new MessageChannel()', 'ECDSA worker transport');
requireContains(
  transport,
  'EcdsaClientWorkerControlKind.AttachDerivationToPresign',
  'ECDSA worker transport',
);
requireAbsent(
  transport,
  'EcdsaClientWorkerControlKind.AttachPresignToOnline',
  'ECDSA worker transport',
);
requireAbsent(channels, 'AttachPresignToOnline', 'ECDSA client worker channel contracts');
requireAbsent(presignWorker, 'onlinePort', 'ECDSA presign worker');
requireContains(facade, "kind: 'ecdsaPresignClient'", 'ECDSA client facade');
requireContains(facade, "kind: 'ecdsaOnlineClient'", 'ECDSA client facade');

requireContains(presignDts, 'export class ClientPresignSession', 'presign WASM declaration');
requireContains(
  registrationDts,
  'prepare_ecdsa_client_bootstrap_v1',
  'registration WASM declaration',
);
requireContains(
  registrationDts,
  'finalize_ecdsa_client_bootstrap_v1',
  'registration WASM declaration',
);
requireContains(
  registrationDts,
  'open_ecdsa_role_local_signing_share_v1',
  'registration WASM declaration',
);
for (const forbidden of [
  'build_ecdsa_role_local_export_artifact_v1',
  'RouterAbEcdsaClientCeremonyV1',
  'ClientPresignSession',
  'compute_client_signature_share',
]) {
  requireAbsent(registrationDts, forbidden, 'registration WASM declaration');
}
requireAbsent(presignDts, 'map_client_additive_share_2p', 'presign WASM declaration');
requireAbsent(presignDts, 'compute_client_signature_share', 'presign WASM declaration');
requireAbsent(presignDts, 'prepare_ecdsa_client_bootstrap', 'presign WASM declaration');
requireContains(
  onlineDts,
  'export function compute_client_signature_share',
  'online WASM declaration',
);
requireAbsent(onlineDts, 'ClientPresignSession', 'online WASM declaration');
requireAbsent(onlineDts, 'prepare_ecdsa_client_bootstrap', 'online WASM declaration');
requireAbsent(onlineManifest, 'signer-core', 'online WASM dependency graph');
requireAbsent(onlineManifest, 'threshold-signatures', 'online WASM dependency graph');
requireAbsent(presignManifest, 'signer-core', 'presign WASM dependency graph');
requireAbsent(presignManifest, 'threshold-signatures', 'presign WASM dependency graph');
requireAbsent(registrationManifest, 'threshold-signatures', 'registration WASM dependency graph');
requireAbsent(serverSigningWorkerManifest, 'signer-core', 'SigningWorker WASM dependency graph');
requireAbsent(
  serverSigningWorkerManifest,
  'threshold-signatures',
  'SigningWorker WASM dependency graph',
);
requireAbsent(
  serverSigningWorkerDts,
  'map_signing_worker_additive_share_2p',
  'SigningWorker WASM declaration',
);
requireAbsent(
  serverSigningWorkerDts,
  'relayerMappedPrivateShare32',
  'SigningWorker WASM declaration',
);

requireContains(
  builtDerivationWorker,
  'ecdsa_registration_client',
  'built ECDSA derivation worker',
);
requireContains(
  builtDerivationWorker,
  'router_ab_ecdsa_derivation_client',
  'built ECDSA derivation worker',
);
requireAbsent(
  builtDerivationWorker,
  'router_ab_ecdsa_presign_client',
  'built ECDSA derivation worker',
);
requireAbsent(
  builtDerivationWorker,
  'router_ab_ecdsa_online_client',
  'built ECDSA derivation worker',
);
requireContains(builtPresignWorker, 'router_ab_ecdsa_presign_client', 'built ECDSA presign worker');
requireAbsent(
  builtPresignWorker,
  'router_ab_ecdsa_derivation_client',
  'built ECDSA presign worker',
);
requireAbsent(
  builtPresignWorker,
  'ecdsa_registration_client',
  'built ECDSA presign worker',
);
requireAbsent(builtPresignWorker, 'router_ab_ecdsa_online_client', 'built ECDSA presign worker');
requireContains(builtOnlineWorker, 'router_ab_ecdsa_online_client', 'built ECDSA online worker');
requireAbsent(builtOnlineWorker, 'router_ab_ecdsa_derivation_client', 'built ECDSA online worker');
requireAbsent(
  builtOnlineWorker,
  'ecdsa_registration_client',
  'built ECDSA online worker',
);
requireAbsent(builtOnlineWorker, 'router_ab_ecdsa_presign_client', 'built ECDSA online worker');

requireArtifactTokensAbsent(
  wasmExportNames(
    'wasm/ecdsa_registration_client/pkg/ecdsa_registration_client_bg.wasm',
  ),
  [
    'explicit_export',
    'recovery',
    'activation_refresh',
    'presign',
    'triple',
    'signature_share',
    'signing_worker',
  ],
  'generated ECDSA registration client WASM exports',
);
requireArtifactTokensAbsent(
  wasmExportNames(
    'wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client_bg.wasm',
  ),
  ['presign', 'triple', 'signature_share', 'signing_worker', 'deriver_relayer'],
  'generated ECDSA derivation client WASM exports',
);
requireArtifactTokensAbsent(
  wasmExportNames('wasm/router_ab_ecdsa_presign_client/pkg/router_ab_ecdsa_presign_client_bg.wasm'),
  ['client_bootstrap', 'encrypted_proof', 'explicit_export', 'compute_client_signature_share'],
  'generated ECDSA presign client WASM exports',
);
requireArtifactTokensAbsent(
  wasmExportNames('wasm/router_ab_ecdsa_online_client/pkg/router_ab_ecdsa_online_client_bg.wasm'),
  ['client_bootstrap', 'encrypted_proof', 'explicit_export', 'clientpresignsession'],
  'generated ECDSA online client WASM exports',
);
requireArtifactTokensAbsent(
  [
    ed25519YaoClientTypes,
    ...wasmExportNames(
      'crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client_bg.wasm',
    ),
  ],
  ['garbler', 'evaluator', 'local_protocol', 'clear_oracle', 'circuit_schedule', 'ot_sender'],
  'generated Ed25519 Yao client artifact surface',
);

verifyReviewCorpusDigests();

console.log('ECDSA client worker ownership split checks passed.');
