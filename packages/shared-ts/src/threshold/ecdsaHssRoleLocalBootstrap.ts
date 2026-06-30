import { alphabetizeStringify, sha256Bytes, sha256BytesUtf8 } from '../utils/digests';
import { base64UrlEncode } from '../utils/encoders';
import type { WalletId } from '../utils/domainIds';

const THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID = 'threshold-secp256k1-ecdsa-2p-v1';
const SDK_ECDSA_HSS_APPLICATION_BINDING_DOMAIN_V1 =
  'seams-sdk:ecdsa-hss:application-binding:v1';

export const ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION =
  'ecdsa-hss:role-local:first-bootstrap-root-proof:v2' as const;
export const ECDSA_HSS_ROLE_LOCAL_PASSKEY_BOOTSTRAP_AUTH_VERSION =
  'ecdsa-hss:role-local:passkey-bootstrap-auth:v2' as const;

export type EcdsaClientRootPublicKey33B64u = string & {
  readonly __brand: 'EcdsaClientRootPublicKey33B64u';
};

export type EcdsaHssClientSharePublicKey33B64u = string & {
  readonly __brand: 'EcdsaHssClientSharePublicKey33B64u';
};

export type EcdsaRelayerHssPublicKey33B64u = string & {
  readonly __brand: 'EcdsaRelayerHssPublicKey33B64u';
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

export type EcdsaHssRoleLocalFirstBootstrapRootProof = {
  version: typeof ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION;
  clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  digest32B64u: string;
  signature65B64u: string;
};

export type EcdsaHssRoleLocalBootstrapIdentity = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
};

export type EcdsaHssRoleLocalPasskeyBootstrapIdentity = Omit<
  EcdsaHssRoleLocalBootstrapIdentity,
  'hssClientSharePublicKey33B64u' | 'clientShareRetryCounter' | 'contextBinding32B64u'
> & {
  rpId: string;
};

export type SdkEcdsaHssBindingFacts = {
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

export function parseSdkEcdsaHssThresholdKeyId(value: unknown): EcdsaThresholdKeyId {
  return requireSdkBindingFactString(value, 'ecdsaThresholdKeyId') as EcdsaThresholdKeyId;
}

export function parseSdkEcdsaHssSigningRootId(value: unknown): SigningRootId {
  return requireSdkBindingFactString(value, 'signingRootId') as SigningRootId;
}

export function parseSdkEcdsaHssSigningRootVersion(value: unknown): SigningRootVersion {
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

export function encodeSdkEcdsaHssBindingFactsV1(input: SdkEcdsaHssBindingFacts): Uint8Array {
  const out: number[] = [];
  const domainBytes = new TextEncoder().encode(SDK_ECDSA_HSS_APPLICATION_BINDING_DOMAIN_V1);
  pushU32(out, domainBytes.length);
  out.push(...domainBytes);
  pushLengthDelimitedField(out, 'walletId', input.walletId);
  pushLengthDelimitedField(out, 'ecdsaThresholdKeyId', input.ecdsaThresholdKeyId);
  pushLengthDelimitedField(out, 'signingRootId', input.signingRootId);
  pushLengthDelimitedField(out, 'signingRootVersion', input.signingRootVersion);
  return new Uint8Array(out);
}

export async function computeSdkEcdsaHssApplicationBindingDigest32(
  input: SdkEcdsaHssBindingFacts,
): Promise<Uint8Array> {
  return await sha256Bytes(encodeSdkEcdsaHssBindingFactsV1(input));
}

export async function computeSdkEcdsaHssApplicationBindingDigestB64u(
  input: SdkEcdsaHssBindingFacts,
): Promise<string> {
  return base64UrlEncode(await computeSdkEcdsaHssApplicationBindingDigest32(input));
}

export async function computeEcdsaHssRoleLocalThresholdKeyId(input: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  signingRootId: string;
  signingRootVersion: string;
}): Promise<string> {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'threshold_ecdsa_hss_key_id_v7',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
  );
  return `ehss-${base64UrlEncode(digest32)}`;
}

export async function computeEcdsaHssRoleLocalRelayerKeyId(input: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
}): Promise<string> {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'threshold_ecdsa_hss_relayer_key_id_v1',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
    }),
  );
  return `ehss-relayer-${base64UrlEncode(digest32)}`;
}

export async function computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32(
  input: EcdsaHssRoleLocalBootstrapIdentity,
): Promise<Uint8Array> {
  return await sha256BytesUtf8(
    alphabetizeStringify({
      version: ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
      keyScope: input.keyScope,
      relayerKeyId: input.relayerKeyId,
      hssClientSharePublicKey33B64u: input.hssClientSharePublicKey33B64u,
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

export async function computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32B64u(
  input: EcdsaHssRoleLocalBootstrapIdentity,
): Promise<string> {
  return base64UrlEncode(await computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32(input));
}

export async function computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32(
  input: EcdsaHssRoleLocalPasskeyBootstrapIdentity,
): Promise<Uint8Array> {
  return await sha256BytesUtf8(
    alphabetizeStringify({
      version: ECDSA_HSS_ROLE_LOCAL_PASSKEY_BOOTSTRAP_AUTH_VERSION,
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

export async function computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u(
  input: EcdsaHssRoleLocalPasskeyBootstrapIdentity,
): Promise<string> {
  return base64UrlEncode(
    await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32(input),
  );
}
