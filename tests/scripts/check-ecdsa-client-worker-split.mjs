import fs from 'node:fs';
import path from 'node:path';

const repoRoot = path.resolve(import.meta.dirname, '../..');

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function requireContains(source, fragment, label) {
  if (!source.includes(fragment)) throw new Error(`${label} is missing ${fragment}`);
}

function requireAbsent(source, fragment, label) {
  if (source.includes(fragment)) throw new Error(`${label} contains forbidden ${fragment}`);
}

const channels = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels.ts',
);
const presignWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-presign-client.worker.ts',
);
const onlineWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-online-client.worker.ts',
);
const opaqueAuthority = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/opaqueEcdsaPresignAuthority.ts',
);
const derivationWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts',
);
const emailOtpWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
);
const linkedHolderWorker = read(
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/device-linking-key.worker.ts',
);
const roleLocalTypes = read('wasm/router_ab_ecdsa_client/pkg/router_ab_ecdsa_client.d.ts');
const linkedHolderTypes = read(
  'crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.d.ts',
);

for (const [source, label] of [
  [channels, 'ECDSA worker channel contracts'],
  [presignWorker, 'ECDSA presign coordinator worker'],
  [onlineWorker, 'ECDSA online proxy worker'],
  [opaqueAuthority, 'ECDSA opaque presign authority'],
  [derivationWorker, 'ECDSA derivation authority worker'],
  [linkedHolderWorker, 'linked-holder ECDSA authority worker'],
]) {
  requireAbsent(source, 'signingShare32B64u', label);
  requireAbsent(source, 'ecdsa_additive_share32', label);
  requireAbsent(source, 'ecdsa_derivation_additive_share', label);
  requireAbsent(source, 'linked_holder_ecdsa_additive_share', label);
}

requireAbsent(channels, 'additiveShare32', 'ECDSA worker channel contracts');
requireAbsent(emailOtpWorker, 'email_otp_ecdsa_signing_share_result_v1', 'Email OTP worker');
requireAbsent(presignWorker, 'ClientPresignSession', 'ECDSA presign coordinator worker');
requireAbsent(presignWorker, 'ecdsaPresignMaterialStore', 'ECDSA presign coordinator worker');
requireAbsent(onlineWorker, 'ecdsaPresignMaterialStore', 'ECDSA online proxy worker');
requireAbsent(onlineWorker, 'router_ab_ecdsa_online_client', 'ECDSA online proxy worker');
requireAbsent(roleLocalTypes, 'open_ecdsa_role_local_signing_share_v1', 'role-local WASM types');
requireAbsent(linkedHolderTypes, 'ecdsa_additive_share32', 'linked-holder WASM types');

for (const token of ['take_presignature_97', 'kShare32', 'sigmaShare32', 'clientAdditiveShare32']) {
  for (const [source, label] of [
    [channels, 'ECDSA worker channel contracts'],
    [presignWorker, 'ECDSA presign coordinator worker'],
    [onlineWorker, 'ECDSA online proxy worker'],
    [opaqueAuthority, 'ECDSA opaque presign authority'],
    [derivationWorker, 'ECDSA derivation authority worker'],
    [emailOtpWorker, 'Email OTP worker'],
    [linkedHolderWorker, 'linked-holder ECDSA authority worker'],
  ]) {
    requireAbsent(source, token, label);
  }
}

for (const [source, label] of [
  [channels, 'ECDSA worker channel contracts'],
  [presignWorker, 'ECDSA presign coordinator worker'],
  [derivationWorker, 'ECDSA derivation authority worker'],
  [linkedHolderWorker, 'linked-holder ECDSA authority worker'],
]) {
  requireContains(source, 'opaque_ecdsa_presign_session_', label);
}

requireContains(opaqueAuthority, 'class OpaqueEcdsaPresignAuthorityV1', 'opaque authority');
requireContains(opaqueAuthority, 'computeSignatureShare(', 'opaque authority');

requireContains(
  roleLocalTypes,
  'export class EcdsaRoleLocalPresignSessionV1',
  'role-local WASM types',
);
requireContains(linkedHolderTypes, 'create_ecdsa_presign_session', 'linked-holder WASM types');
requireContains(roleLocalTypes, 'presignature_big_r_33', 'role-local WASM types');
requireContains(roleLocalTypes, 'compute_signature_share', 'role-local WASM types');
requireContains(linkedHolderTypes, 'presignature_big_r_33', 'linked-holder WASM types');
requireContains(linkedHolderTypes, 'compute_signature_share', 'linked-holder WASM types');

console.log('ECDSA opaque presign boundary checks passed.');
