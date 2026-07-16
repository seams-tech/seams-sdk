import type {
  EcdsaClientAdditiveShareHandle,
  EcdsaClientVerifyingShareB64u,
  EcdsaDerivationKeyVersion,
  EcdsaKeyHandle,
  EcdsaRelayerKeyId,
  EcdsaThresholdKeyId,
  Ed25519KeyVersion,
  Ed25519RelayerKeyId,
  SigningSessionSealKeyVersion,
  SigningSessionSealShamirPrimeB64u,
} from './keyMaterialBrands';
import {
  formatEcdsaClientAdditiveShareHandleForWire,
  formatEcdsaClientVerifyingShareB64uForWire,
  formatEcdsaDerivationKeyVersionForWire,
  formatEcdsaKeyHandleForWire,
  formatEcdsaRelayerKeyIdForWire,
  formatEcdsaThresholdKeyIdForWire,
  formatEd25519KeyVersionForWire,
  formatEd25519RelayerKeyIdForWire,
  formatSigningSessionSealKeyVersionForWire,
  formatSigningSessionSealShamirPrimeB64uForWire,
  parseEcdsaClientAdditiveShareHandle,
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaDerivationKeyVersion,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
  parseEd25519KeyVersion,
  parseEd25519RelayerKeyId,
  parseSigningSessionSealKeyVersion,
  parseSigningSessionSealShamirPrimeB64u,
} from './keyMaterialBrands';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import {
  parseNearEd25519SigningKeyId,
  type NearEd25519SigningKeyId,
} from '@shared/utils/registrationIntent';

const ed25519 = parseEd25519KeyVersion('yaos-ab-ed25519-v1');
const ecdsa = parseEcdsaDerivationKeyVersion('ecdsa-derivation-material-test-v1');
const seal = parseSigningSessionSealKeyVersion('signing-session-seal-kek-test-r1');
const ecdsaVerifier = parseEcdsaClientVerifyingShareB64u('ecdsa-client-verifier');
const ed25519RelayerKeyId = parseEd25519RelayerKeyId('ed25519-relayer-key-id');
const ecdsaRelayerKeyId = parseEcdsaRelayerKeyId('ecdsa-relayer-key-id');
const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId('ecdsa-threshold-key-id');
const ecdsaKeyHandle = parseEcdsaKeyHandle('ecdsa-key-handle');
const ecdsaAdditiveShareHandle =
  parseEcdsaClientAdditiveShareHandle('ecdsa-additive-share-handle');
const shamirPrime = parseSigningSessionSealShamirPrimeB64u('signing-session-shamir-prime');
const webAuthnRpIdResult = parseWebAuthnRpId('wallet.example.test');
if (!webAuthnRpIdResult.ok) throw new Error(webAuthnRpIdResult.error.message);
const webAuthnRpId = webAuthnRpIdResult.value;
const nearEd25519SigningKeyId = parseNearEd25519SigningKeyId('ed25519ks_fixture');

function acceptsEd25519(value: Ed25519KeyVersion) {
  return formatEd25519KeyVersionForWire(value);
}

function acceptsEcdsa(value: EcdsaDerivationKeyVersion) {
  return formatEcdsaDerivationKeyVersionForWire(value);
}

function acceptsSeal(value: SigningSessionSealKeyVersion) {
  return formatSigningSessionSealKeyVersionForWire(value);
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

function acceptsWebAuthnRpId(value: WebAuthnRpId) {
  return value;
}

function acceptsNearEd25519SigningKeyId(value: NearEd25519SigningKeyId) {
  return value;
}

acceptsEd25519(ed25519);
acceptsEcdsa(ecdsa);
acceptsSeal(seal);
acceptsEcdsaVerifier(ecdsaVerifier);
acceptsEd25519RelayerKeyId(ed25519RelayerKeyId);
acceptsEcdsaRelayerKeyId(ecdsaRelayerKeyId);
acceptsEcdsaThresholdKeyId(ecdsaThresholdKeyId);
acceptsEcdsaKeyHandle(ecdsaKeyHandle);
acceptsEcdsaAdditiveShareHandle(ecdsaAdditiveShareHandle);
acceptsShamirPrime(shamirPrime);
acceptsWebAuthnRpId(webAuthnRpId);
acceptsNearEd25519SigningKeyId(nearEd25519SigningKeyId);

// @ts-expect-error Ed25519 key versions cannot be used as seal KEK versions.
acceptsSeal(ed25519);

// @ts-expect-error signing-session seal KEK versions cannot be used as Ed25519 versions.
acceptsEd25519(seal);

// @ts-expect-error ECDSA DERIVATION key versions cannot be used as Ed25519 versions.
acceptsEd25519(ecdsa);

// @ts-expect-error raw strings must be parsed at a boundary before core use.
acceptsEd25519('yaos-ab-ed25519-v1');

// @ts-expect-error raw strings must be parsed at a boundary before core use.
acceptsSeal('signing-session-seal-kek-test-r1');

// @ts-expect-error ECDSA relayer keys are not Ed25519 relayer keys.
acceptsEd25519RelayerKeyId(ecdsaRelayerKeyId);

// @ts-expect-error ECDSA key handles are not threshold key ids.
acceptsEcdsaThresholdKeyId(ecdsaKeyHandle);

// @ts-expect-error ECDSA additive share handles are not key handles.
acceptsEcdsaKeyHandle(ecdsaAdditiveShareHandle);

// @ts-expect-error NEAR Ed25519 signing-key ids are not WebAuthn RP ids.
acceptsWebAuthnRpId(nearEd25519SigningKeyId);

// @ts-expect-error WebAuthn RP ids are not NEAR Ed25519 signing-key ids.
acceptsNearEd25519SigningKeyId(webAuthnRpId);
