import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';
import { base64UrlEncode } from '../utils/encoders';

const THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID = 'threshold-secp256k1-ecdsa-2p-v1';

export const ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION =
  'ecdsa-hss:role-local:first-bootstrap-root-proof:v2' as const;
export const ECDSA_HSS_ROLE_LOCAL_PASSKEY_BOOTSTRAP_AUTH_VERSION =
  'ecdsa-hss:role-local:passkey-bootstrap-auth:v2' as const;

export type EcdsaHssRoleLocalFirstBootstrapRootProof = {
  version: typeof ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION;
  digest32B64u: string;
  signature65B64u: string;
};

export type EcdsaHssRoleLocalBootstrapIdentity = {
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  clientPublicKey33B64u: string;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  walletSigningSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
};

export type EcdsaHssRoleLocalPasskeyBootstrapIdentity = Omit<
  EcdsaHssRoleLocalBootstrapIdentity,
  'clientPublicKey33B64u' | 'clientShareRetryCounter' | 'contextBinding32B64u'
>;

export async function computeEcdsaHssRoleLocalThresholdKeyId(input: {
  walletId: string;
  rpId: string;
  signingRootId: string;
  signingRootVersion: string;
}): Promise<string> {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'threshold_ecdsa_hss_key_id_v7',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      walletId: input.walletId,
      rpId: input.rpId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    }),
  );
  return `ehss-${base64UrlEncode(digest32)}`;
}

export async function computeEcdsaHssRoleLocalRelayerKeyId(input: {
  walletId: string;
  rpId: string;
}): Promise<string> {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'threshold_ecdsa_hss_relayer_key_id_v1',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      walletId: input.walletId,
      rpId: input.rpId,
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
      rpId: input.rpId,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
      keyScope: input.keyScope,
      relayerKeyId: input.relayerKeyId,
      clientPublicKey33B64u: input.clientPublicKey33B64u,
      clientShareRetryCounter: input.clientShareRetryCounter,
      contextBinding32B64u: input.contextBinding32B64u,
      requestId: input.requestId,
      sessionId: input.sessionId,
      walletSigningSessionId: input.walletSigningSessionId,
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
      rpId: input.rpId,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
      keyScope: input.keyScope,
      relayerKeyId: input.relayerKeyId,
      requestId: input.requestId,
      sessionId: input.sessionId,
      walletSigningSessionId: input.walletSigningSessionId,
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
