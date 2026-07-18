import { alphabetizeStringify, sha256Bytes, sha256BytesUtf8 } from '../utils/digests';
import { base64UrlDecode, base64UrlEncode } from '../utils/encoders';
import type { WalletId } from '../utils/domainIds';

const THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID = 'threshold-secp256k1-ecdsa-2p-v1';
const SDK_ECDSA_DERIVATION_APPLICATION_BINDING_DOMAIN_V1 =
  'seams-sdk:ecdsa-derivation:application-binding:v1';

export const ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION =
  'ecdsa-derivation:role-local:first-bootstrap-root-proof:v2' as const;
export const ECDSA_DERIVATION_ROLE_LOCAL_PASSKEY_BOOTSTRAP_AUTH_VERSION =
  'ecdsa-derivation:role-local:passkey-bootstrap-auth:v2' as const;

export type EcdsaClientRootPublicKey33B64u = string & {
  readonly __brand: 'EcdsaClientRootPublicKey33B64u';
};

export type DerivationClientSharePublicKey33B64u = string & {
  readonly __brand: 'DerivationClientSharePublicKey33B64u';
};

export function derivationClientSharePublicKey33B64uFromString(
  value: string,
): DerivationClientSharePublicKey33B64u {
  const normalized = value.trim();
  const bytes = base64UrlDecode(normalized);
  if (bytes.length !== 33 || base64UrlEncode(bytes) !== normalized) {
    throw new Error('derivation client share public key must be canonical base64url for 33 bytes');
  }
  return normalized as DerivationClientSharePublicKey33B64u;
}

export type EcdsaDerivationRelayerPublicKey33B64u = string & {
  readonly __brand: 'EcdsaDerivationRelayerPublicKey33B64u';
};

export type EcdsaThresholdKeyId = string & {
  readonly __brand: 'EcdsaThresholdKeyId';
};

export type SigningRootId = string & {
  readonly __brand: 'SigningRootId';
};

export type SigningRootVersion = string & {
  readonly __brand: 'SigningRootVersion';
};

export type EcdsaDerivationRoleLocalFirstBootstrapRootProof = {
  version: typeof ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION;
  clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  digest32B64u: string;
  signature65B64u: string;
};

export type EcdsaDerivationRoleLocalBootstrapIdentity = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
};

export type EcdsaDerivationRoleLocalPasskeyBootstrapIdentity = Omit<
  EcdsaDerivationRoleLocalBootstrapIdentity,
  'derivationClientSharePublicKey33B64u' | 'clientShareRetryCounter' | 'contextBinding32B64u'
> & {
  rpId: string;
};

export type SdkEcdsaDerivationBindingFacts = {
  walletId: WalletId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
};

function requireSdkBindingFactString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

export function parseSdkEcdsaDerivationThresholdKeyId(value: unknown): EcdsaThresholdKeyId {
  return requireSdkBindingFactString(value, 'ecdsaThresholdKeyId') as EcdsaThresholdKeyId;
}

export function parseSdkEcdsaDerivationSigningRootId(value: unknown): SigningRootId {
  return requireSdkBindingFactString(value, 'signingRootId') as SigningRootId;
}

export function parseSdkEcdsaDerivationSigningRootVersion(value: unknown): SigningRootVersion {
  return requireSdkBindingFactString(value, 'signingRootVersion') as SigningRootVersion;
}

function pushU32(out: number[], value: number): void {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function pushLengthDelimitedField(out: number[], label: string, value: unknown): void {
  const labelBytes = new TextEncoder().encode(label);
  const valueBytes = new TextEncoder().encode(requireSdkBindingFactString(value, label));
  pushU32(out, labelBytes.length);
  out.push(...labelBytes);
  pushU32(out, valueBytes.length);
  out.push(...valueBytes);
}

export function encodeSdkEcdsaDerivationBindingFactsV1(input: SdkEcdsaDerivationBindingFacts): Uint8Array {
  const out: number[] = [];
  const domainBytes = new TextEncoder().encode(SDK_ECDSA_DERIVATION_APPLICATION_BINDING_DOMAIN_V1);
  pushU32(out, domainBytes.length);
  out.push(...domainBytes);
  pushLengthDelimitedField(out, 'walletId', input.walletId);
  pushLengthDelimitedField(out, 'ecdsaThresholdKeyId', input.ecdsaThresholdKeyId);
  pushLengthDelimitedField(out, 'signingRootId', input.signingRootId);
  pushLengthDelimitedField(out, 'signingRootVersion', input.signingRootVersion);
  return new Uint8Array(out);
}

export async function computeSdkEcdsaDerivationApplicationBindingDigest32(
  input: SdkEcdsaDerivationBindingFacts,
): Promise<Uint8Array> {
  return await sha256Bytes(encodeSdkEcdsaDerivationBindingFactsV1(input));
}

export async function computeSdkEcdsaDerivationApplicationBindingDigestB64u(
  input: SdkEcdsaDerivationBindingFacts,
): Promise<string> {
  return base64UrlEncode(await computeSdkEcdsaDerivationApplicationBindingDigest32(input));
}

export async function computeEcdsaDerivationRoleLocalThresholdKeyId(input: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  signingRootId: string;
  signingRootVersion: string;
}): Promise<string> {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'threshold_ecdsa_derivation_key_id_v7',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
  );
  return `ederivation-${base64UrlEncode(digest32)}`;
}

export async function computeEcdsaDerivationRoleLocalRelayerKeyId(input: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
}): Promise<string> {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'threshold_ecdsa_derivation_relayer_key_id_v1',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
    }),
  );
  return `ederivation-relayer-${base64UrlEncode(digest32)}`;
}

export async function computeEcdsaDerivationRoleLocalFirstBootstrapRootProofDigest32(
  input: EcdsaDerivationRoleLocalBootstrapIdentity,
): Promise<Uint8Array> {
  return await sha256BytesUtf8(
    alphabetizeStringify({
      version: ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
      keyScope: input.keyScope,
      relayerKeyId: input.relayerKeyId,
      derivationClientSharePublicKey33B64u: input.derivationClientSharePublicKey33B64u,
      clientShareRetryCounter: input.clientShareRetryCounter,
      contextBinding32B64u: input.contextBinding32B64u,
      requestId: input.requestId,
      sessionId: input.sessionId,
      signingGrantId: input.signingGrantId,
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
      participantIds: input.participantIds,
    }),
  );
}

export async function computeEcdsaDerivationRoleLocalFirstBootstrapRootProofDigest32B64u(
  input: EcdsaDerivationRoleLocalBootstrapIdentity,
): Promise<string> {
  return base64UrlEncode(await computeEcdsaDerivationRoleLocalFirstBootstrapRootProofDigest32(input));
}

export async function computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32(
  input: EcdsaDerivationRoleLocalPasskeyBootstrapIdentity,
): Promise<Uint8Array> {
  return await sha256BytesUtf8(
    alphabetizeStringify({
      version: ECDSA_DERIVATION_ROLE_LOCAL_PASSKEY_BOOTSTRAP_AUTH_VERSION,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      rpId: input.rpId,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
      keyScope: input.keyScope,
      relayerKeyId: input.relayerKeyId,
      requestId: input.requestId,
      sessionId: input.sessionId,
      signingGrantId: input.signingGrantId,
      ttlMs: input.ttlMs,
      remainingUses: input.remainingUses,
      participantIds: input.participantIds,
    }),
  );
}


export async function computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32B64u(
  input: EcdsaDerivationRoleLocalPasskeyBootstrapIdentity,
): Promise<string> {
  return base64UrlEncode(
    await computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32(input),
  );
}
