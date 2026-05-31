import { thresholdEcdsaHssRoleLocalExportShare } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '../../session/identity/emailOtpHssIdentity';
import {
  toRpId,
  type ReadyEcdsaSignerSession,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial } from '@/core/platform/ecdsaRoleLocalRecords';
import { buildThresholdEcdsaHssRoleLocalExportArtifactWasm } from '../../threshold/crypto/hssClientSignerWasm';
import { resolveThresholdEcdsaClientRootShare } from '../../threshold/ecdsa/clientSecretSource';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';

const ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-confirmation:v2';
const ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-authorization:v2';
const ECDSA_HSS_EXPORT_AUTH_TTL_MS = 60_000;
const ECDSA_HSS_KEY_PURPOSE = 'evm-signing';
const ECDSA_HSS_KEY_VERSION = 'v1';
const ECDSA_HSS_SIGNING_ROOT_VERSION_DEFAULT = 'default';

export type EcdsaHssExplicitExportDeps = {
  getSignerWorkerContext: () => WorkerOperationContext;
};

function randomB64u32(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required for threshold ECDSA export');
  }
  return base64UrlEncode(cryptoApi.getRandomValues(new Uint8Array(32)));
}

async function digestB64u(input: unknown): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input)));
}

export async function exportEcdsaHssKeyWithThresholdSession(
  deps: EcdsaHssExplicitExportDeps,
  args: {
    walletSessionUserId: string;
    rpId: string;
    signerSession: ReadyEcdsaSignerSession;
    record: ThresholdEcdsaSessionRecord;
    credential: WebAuthnAuthenticationCredential;
  },
): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  const signerTransport = args.signerSession.transport;
  const signerTransportAuth = signerTransport.auth;
  const thresholdSessionAuthToken =
    signerTransportAuth.kind === 'jwt_threshold_session_auth'
      ? String(signerTransportAuth.thresholdSessionAuthToken || '').trim()
      : '';
  const relayerUrl = String(signerTransport.relayerUrl || '').trim();
  const keyHandle = String(args.signerSession.publicFacts.keyHandle || '').trim();
  const walletId = toWalletId(args.walletSessionUserId);
  const sessionKind =
    signerTransportAuth.kind === 'cookie_threshold_session_auth' ? 'cookie' : 'jwt';
  if (!relayerUrl || !keyHandle || (!thresholdSessionAuthToken && sessionKind !== 'cookie')) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }

  const roleLocalMaterial = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(args.record);
  const clientRoot = await resolveThresholdEcdsaClientRootShare({
    kind: 'provided_webauthn_prf_credential',
    credential: args.credential,
    rpId: args.rpId,
  });
  if (!clientRoot.ok) {
    throw new Error(clientRoot.message);
  }
  const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId(args.record.ecdsaThresholdKeyId);
  const signingRootId = toEcdsaHssSigningRootId(args.record.signingRootId);
  const signingRootVersion = toEcdsaHssSigningRootVersion(
    args.record.signingRootVersion || ECDSA_HSS_SIGNING_ROOT_VERSION_DEFAULT,
  );
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = Math.min(
    issuedAtUnixMs + ECDSA_HSS_EXPORT_AUTH_TTL_MS,
    Number(args.record.expiresAtMs),
  );
  if (!Number.isFinite(expiresAtUnixMs) || expiresAtUnixMs <= issuedAtUnixMs) {
    throw new Error('Threshold ECDSA export session is expired');
  }

  const publicIdentity = {
    hssClientSharePublicKey33B64u:
      roleLocalMaterial.readyRecord.publicFacts.hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u: roleLocalMaterial.readyRecord.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: roleLocalMaterial.readyRecord.publicFacts.groupPublicKey33B64u,
    ethereumAddress: roleLocalMaterial.readyRecord.publicFacts.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId,
    rpId: args.rpId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    clientDeviceId: String(args.signerSession.session.walletSigningSessionId),
    clientSessionId: String(args.signerSession.session.thresholdSessionId),
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u({
    version: ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION,
    operation: 'explicit_key_export',
    keyHandle,
    walletId,
    rpId: args.rpId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    signingRootId,
    signingRootVersion,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: String(args.signerSession.session.walletSigningSessionId),
    clientSessionId: String(args.signerSession.session.thresholdSessionId),
    thresholdSessionId: String(args.signerSession.session.thresholdSessionId),
    walletSigningSessionId: String(args.signerSession.session.walletSigningSessionId),
    thresholdExpiresAtMs: args.record.expiresAtMs,
    participantIds: args.record.participantIds,
  });

  const exportShare = await thresholdEcdsaHssRoleLocalExportShare(relayerUrl, {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId,
    rpId: args.rpId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    authorizationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: String(args.signerSession.session.walletSigningSessionId),
    clientSessionId: String(args.signerSession.session.thresholdSessionId),
    auth:
      sessionKind === 'cookie'
        ? { kind: 'cookie' }
        : { kind: 'threshold_session', jwt: thresholdSessionAuthToken },
    sessionKind,
  });
  if (!exportShare.ok) {
    throw new Error(
      exportShare.error || exportShare.message || 'Threshold explicit export share request failed',
    );
  }

  try {
    return await buildThresholdEcdsaHssRoleLocalExportArtifactWasm({
      context: {
        walletId,
        rpId: toRpId(args.rpId),
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        keyPurpose: ECDSA_HSS_KEY_PURPOSE,
        keyVersion: ECDSA_HSS_KEY_VERSION,
      },
      clientRootShare32: clientRoot.clientRootShare32,
      serverExportShare32B64u: exportShare.value.serverExportShare32B64u,
      contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
      publicIdentity: exportShare.value.publicIdentity,
      clientShareRetryCounter: roleLocalMaterial.clientShareRetryCounter,
      workerCtx: deps.getSignerWorkerContext(),
    });
  } finally {
    clientRoot.clientRootShare32.fill(0);
  }
}
