import type {
  EcdsaClientVerifyingShareB64u,
  EcdsaHssKeyVersion,
  EcdsaKeyHandle,
  EcdsaRelayerKeyId,
  EcdsaThresholdKeyId,
  Ed25519ClientVerifyingShareB64u,
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
  formatEd25519RelayerKeyIdForWire,
  formatSigningSessionSealKeyVersionForWire,
  formatSigningSessionSealShamirPrimeB64uForWire,
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaHssKeyVersion,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519RelayerKeyId,
  parseSigningSessionSealKeyVersion,
  parseSigningSessionSealShamirPrimeB64u,
} from './keyMaterialBrands';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import {
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';

const ecdsa = parseEcdsaHssKeyVersion('ecdsa-hss-material-test-v1');
const seal = parseSigningSessionSealKeyVersion('signing-session-seal-kek-test-r1');
const ed25519Verifier = parseEd25519ClientVerifyingShareB64u('ed25519-client-verifier');
const ecdsaVerifier = parseEcdsaClientVerifyingShareB64u('ecdsa-client-verifier');
const ed25519RelayerKeyId = parseEd25519RelayerKeyId('ed25519-relayer-key-id');
const ecdsaRelayerKeyId = parseEcdsaRelayerKeyId('ecdsa-relayer-key-id');
const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId('ecdsa-threshold-key-id');
const ecdsaKeyHandle = parseEcdsaKeyHandle('ecdsa-key-handle');
const shamirPrime = parseSigningSessionSealShamirPrimeB64u('signing-session-shamir-prime');
const webAuthnRpIdResult = parseWebAuthnRpId('wallet.example.test');
if (!webAuthnRpIdResult.ok) throw new Error(webAuthnRpIdResult.error.message);
const webAuthnRpId = webAuthnRpIdResult.value;
const nearEd25519SigningKeyId = parseNearEd25519SigningKeyId('ed25519ks_fixture');

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

function acceptsWebAuthnRpId(value: WebAuthnRpId) {
  return value;
}

function acceptsNearEd25519SigningKeyId(value: NearEd25519SigningKeyId) {
  return value;
}

acceptsEcdsa(ecdsa);
acceptsSeal(seal);
acceptsEd25519Verifier(ed25519Verifier);
acceptsEcdsaVerifier(ecdsaVerifier);
acceptsEd25519RelayerKeyId(ed25519RelayerKeyId);
acceptsEcdsaRelayerKeyId(ecdsaRelayerKeyId);
acceptsEcdsaThresholdKeyId(ecdsaThresholdKeyId);
acceptsEcdsaKeyHandle(ecdsaKeyHandle);
acceptsShamirPrime(shamirPrime);
acceptsWebAuthnRpId(webAuthnRpId);
acceptsNearEd25519SigningKeyId(nearEd25519SigningKeyId);

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

// @ts-expect-error NEAR Ed25519 signing-key ids are not WebAuthn RP ids.
acceptsWebAuthnRpId(nearEd25519SigningKeyId);

// @ts-expect-error WebAuthn RP ids are not NEAR Ed25519 signing-key ids.
acceptsNearEd25519SigningKeyId(webAuthnRpId);
