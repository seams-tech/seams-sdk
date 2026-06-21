import type {
  EcdsaClientVerifyingShareB64u,
  EcdsaHssKeyVersion,
  EcdsaKeyHandle,
  EcdsaRelayerKeyId,
  EcdsaThresholdKeyId,
  Ed25519ClientVerifyingShareB64u,
  Ed25519HssKeyVersion,
  Ed25519RelayerKeyId,
  SigningSessionSealKeyVersion,
  SigningSessionSealShamirPrimeB64u,
} from './keyMaterialBrands';
import {
  formatEcdsaClientVerifyingShareB64uForWire,
  formatEcdsaHssKeyVersionForWire,
  formatEcdsaKeyHandleForWire,
  formatEcdsaRelayerKeyIdForWire,
  formatEcdsaThresholdKeyIdForWire,
  formatEd25519ClientVerifyingShareB64uForWire,
  formatEd25519HssKeyVersionForWire,
  formatEd25519RelayerKeyIdForWire,
  formatSigningSessionSealKeyVersionForWire,
  formatSigningSessionSealShamirPrimeB64uForWire,
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaHssKeyVersion,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519HssKeyVersion,
  parseEd25519RelayerKeyId,
  parseSigningSessionSealKeyVersion,
  parseSigningSessionSealShamirPrimeB64u,
} from './keyMaterialBrands';

const ed25519 = parseEd25519HssKeyVersion('threshold-ed25519-hss-v1');
const ecdsa = parseEcdsaHssKeyVersion('ecdsa-hss-material-test-v1');
const seal = parseSigningSessionSealKeyVersion('signing-session-seal-kek-test-r1');
const ed25519Verifier = parseEd25519ClientVerifyingShareB64u('ed25519-client-verifier');
const ecdsaVerifier = parseEcdsaClientVerifyingShareB64u('ecdsa-client-verifier');
const ed25519RelayerKeyId = parseEd25519RelayerKeyId('ed25519-relayer-key-id');
const ecdsaRelayerKeyId = parseEcdsaRelayerKeyId('ecdsa-relayer-key-id');
const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId('ecdsa-threshold-key-id');
const ecdsaKeyHandle = parseEcdsaKeyHandle('ecdsa-key-handle');
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

function acceptsShamirPrime(value: SigningSessionSealShamirPrimeB64u) {
  return formatSigningSessionSealShamirPrimeB64uForWire(value);
}

acceptsEd25519(ed25519);
acceptsEcdsa(ecdsa);
acceptsSeal(seal);
acceptsEd25519Verifier(ed25519Verifier);
acceptsEcdsaVerifier(ecdsaVerifier);
acceptsEd25519RelayerKeyId(ed25519RelayerKeyId);
acceptsEcdsaRelayerKeyId(ecdsaRelayerKeyId);
acceptsEcdsaThresholdKeyId(ecdsaThresholdKeyId);
acceptsEcdsaKeyHandle(ecdsaKeyHandle);
acceptsShamirPrime(shamirPrime);

// @ts-expect-error Ed25519 HSS key versions cannot be used as seal KEK versions.
acceptsSeal(ed25519);

// @ts-expect-error signing-session seal KEK versions cannot be used as Ed25519 HSS versions.
acceptsEd25519(seal);

// @ts-expect-error ECDSA HSS key versions cannot be used as Ed25519 HSS versions.
acceptsEd25519(ecdsa);

// @ts-expect-error raw strings must be parsed at a boundary before core use.
acceptsSeal('signing-session-seal-kek-test-r1');

// @ts-expect-error ECDSA verifying shares are not Ed25519 verifying shares.
acceptsEd25519Verifier(ecdsaVerifier);

// @ts-expect-error ECDSA relayer keys are not Ed25519 relayer keys.
acceptsEd25519RelayerKeyId(ecdsaRelayerKeyId);

// @ts-expect-error ECDSA key handles are not threshold key ids.
acceptsEcdsaThresholdKeyId(ecdsaKeyHandle);

// @ts-expect-error raw strings must be parsed at a boundary before core use.
acceptsEcdsaRelayerKeyId('ecdsa-relayer-key-id');
