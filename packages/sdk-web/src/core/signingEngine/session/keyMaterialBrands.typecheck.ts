import type {
  EcdsaClientAdditiveShareHandle,
  EcdsaClientVerifyingShareB64u,
  EcdsaHssKeyVersion,
  EcdsaKeyHandle,
  EcdsaRelayerKeyId,
  EcdsaThresholdKeyId,
  Ed25519ClientVerifyingShareB64u,
  Ed25519HssKeyVersion,
  Ed25519RelayerKeyId,
  Ed25519SealedWorkerMaterialRef,
  Ed25519WorkerMaterialBindingDigest,
  Ed25519WorkerMaterialHandle,
  Ed25519WorkerMaterialKeyId,
  SigningSessionSealKeyVersion,
  SigningSessionSealShamirPrimeB64u,
} from './keyMaterialBrands';
import {
  formatEcdsaClientAdditiveShareHandleForWire,
  formatEcdsaClientVerifyingShareB64uForWire,
  formatEcdsaHssKeyVersionForWire,
  formatEcdsaKeyHandleForWire,
  formatEcdsaRelayerKeyIdForWire,
  formatEcdsaThresholdKeyIdForWire,
  formatEd25519ClientVerifyingShareB64uForWire,
  formatEd25519HssKeyVersionForWire,
  formatEd25519RelayerKeyIdForWire,
  formatEd25519SealedWorkerMaterialRefForWire,
  formatEd25519WorkerMaterialBindingDigestForWire,
  formatEd25519WorkerMaterialHandleForWire,
  formatEd25519WorkerMaterialKeyIdForWire,
  formatSigningSessionSealKeyVersionForWire,
  formatSigningSessionSealShamirPrimeB64uForWire,
  parseEcdsaClientAdditiveShareHandle,
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaHssKeyVersion,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519HssKeyVersion,
  parseEd25519RelayerKeyId,
  parseEd25519SealedWorkerMaterialRef,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialHandle,
  parseEd25519WorkerMaterialKeyId,
  parseSigningSessionSealKeyVersion,
  parseSigningSessionSealShamirPrimeB64u,
} from './keyMaterialBrands';

const ed25519 = parseEd25519HssKeyVersion('threshold-ed25519-hss-v1');
const ecdsa = parseEcdsaHssKeyVersion('ecdsa-hss-material-test-v1');
const seal = parseSigningSessionSealKeyVersion('signing-session-seal-kek-test-r1');
const materialHandle = parseEd25519WorkerMaterialHandle('ed25519-material-handle');
const sealedMaterialRef = parseEd25519SealedWorkerMaterialRef('sealed-material-ref');
const materialKeyId = parseEd25519WorkerMaterialKeyId('material-key-id');
const materialBindingDigest = parseEd25519WorkerMaterialBindingDigest('material-binding-digest');
const ed25519Verifier = parseEd25519ClientVerifyingShareB64u('ed25519-client-verifier');
const ecdsaVerifier = parseEcdsaClientVerifyingShareB64u('ecdsa-client-verifier');
const ed25519RelayerKeyId = parseEd25519RelayerKeyId('ed25519-relayer-key-id');
const ecdsaRelayerKeyId = parseEcdsaRelayerKeyId('ecdsa-relayer-key-id');
const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId('ecdsa-threshold-key-id');
const ecdsaKeyHandle = parseEcdsaKeyHandle('ecdsa-key-handle');
const ecdsaAdditiveShareHandle =
  parseEcdsaClientAdditiveShareHandle('ecdsa-additive-share-handle');
const shamirPrime = parseSigningSessionSealShamirPrimeB64u('signing-session-shamir-prime');

function acceptsEd25519(value: Ed25519HssKeyVersion) {
  return formatEd25519HssKeyVersionForWire(value);
}

function acceptsEcdsa(value: EcdsaHssKeyVersion) {
  return formatEcdsaHssKeyVersionForWire(value);
}

function acceptsSeal(value: SigningSessionSealKeyVersion) {
  return formatSigningSessionSealKeyVersionForWire(value);
}

function acceptsMaterialHandle(value: Ed25519WorkerMaterialHandle) {
  return formatEd25519WorkerMaterialHandleForWire(value);
}

function acceptsSealedMaterialRef(value: Ed25519SealedWorkerMaterialRef) {
  return formatEd25519SealedWorkerMaterialRefForWire(value);
}

function acceptsMaterialKeyId(value: Ed25519WorkerMaterialKeyId) {
  return formatEd25519WorkerMaterialKeyIdForWire(value);
}

function acceptsMaterialBindingDigest(value: Ed25519WorkerMaterialBindingDigest) {
  return formatEd25519WorkerMaterialBindingDigestForWire(value);
}

function acceptsEd25519Verifier(value: Ed25519ClientVerifyingShareB64u) {
  return formatEd25519ClientVerifyingShareB64uForWire(value);
}

function acceptsEcdsaVerifier(value: EcdsaClientVerifyingShareB64u) {
  return formatEcdsaClientVerifyingShareB64uForWire(value);
}

function acceptsEd25519RelayerKeyId(value: Ed25519RelayerKeyId) {
  return formatEd25519RelayerKeyIdForWire(value);
}

function acceptsEcdsaRelayerKeyId(value: EcdsaRelayerKeyId) {
  return formatEcdsaRelayerKeyIdForWire(value);
}

function acceptsEcdsaThresholdKeyId(value: EcdsaThresholdKeyId) {
  return formatEcdsaThresholdKeyIdForWire(value);
}

function acceptsEcdsaKeyHandle(value: EcdsaKeyHandle) {
  return formatEcdsaKeyHandleForWire(value);
}

function acceptsEcdsaAdditiveShareHandle(value: EcdsaClientAdditiveShareHandle) {
  return formatEcdsaClientAdditiveShareHandleForWire(value);
}

function acceptsShamirPrime(value: SigningSessionSealShamirPrimeB64u) {
  return formatSigningSessionSealShamirPrimeB64uForWire(value);
}

acceptsEd25519(ed25519);
acceptsEcdsa(ecdsa);
acceptsSeal(seal);
acceptsMaterialHandle(materialHandle);
acceptsSealedMaterialRef(sealedMaterialRef);
acceptsMaterialKeyId(materialKeyId);
acceptsMaterialBindingDigest(materialBindingDigest);
acceptsEd25519Verifier(ed25519Verifier);
acceptsEcdsaVerifier(ecdsaVerifier);
acceptsEd25519RelayerKeyId(ed25519RelayerKeyId);
acceptsEcdsaRelayerKeyId(ecdsaRelayerKeyId);
acceptsEcdsaThresholdKeyId(ecdsaThresholdKeyId);
acceptsEcdsaKeyHandle(ecdsaKeyHandle);
acceptsEcdsaAdditiveShareHandle(ecdsaAdditiveShareHandle);
acceptsShamirPrime(shamirPrime);

// @ts-expect-error Ed25519 HSS key versions cannot be used as seal KEK versions.
acceptsSeal(ed25519);

// @ts-expect-error signing-session seal KEK versions cannot be used as Ed25519 HSS versions.
acceptsEd25519(seal);

// @ts-expect-error ECDSA HSS key versions cannot be used as Ed25519 HSS versions.
acceptsEd25519(ecdsa);

// @ts-expect-error raw strings must be parsed at a boundary before core use.
acceptsSeal('signing-session-seal-kek-test-r1');

// @ts-expect-error runtime material handles are not sealed artifact refs.
acceptsSealedMaterialRef(materialHandle);

// @ts-expect-error material binding digests are not material key ids.
acceptsMaterialKeyId(materialBindingDigest);

// @ts-expect-error ECDSA verifying shares are not Ed25519 verifying shares.
acceptsEd25519Verifier(ecdsaVerifier);

// @ts-expect-error ECDSA relayer keys are not Ed25519 relayer keys.
acceptsEd25519RelayerKeyId(ecdsaRelayerKeyId);

// @ts-expect-error ECDSA key handles are not threshold key ids.
acceptsEcdsaThresholdKeyId(ecdsaKeyHandle);

// @ts-expect-error ECDSA additive share handles are not key handles.
acceptsEcdsaKeyHandle(ecdsaAdditiveShareHandle);

// @ts-expect-error raw strings must be parsed at a boundary before core use.
acceptsMaterialHandle('ed25519-material-handle');
