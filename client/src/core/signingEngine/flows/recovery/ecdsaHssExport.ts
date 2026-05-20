import { thresholdEcdsaHssRoleLocalExportShare } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { walletSubjectIdFromWalletProfile } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toWalletSessionUserId,
} from '../../session/identity/emailOtpHssIdentity';
import type { ReadyEcdsaSignerSession } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { buildThresholdEcdsaHssRoleLocalExportArtifactWasm } from '../../threshold/crypto/hssClientSignerWasm';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';

const ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-confirmation:v1';
const ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-authorization:v1';
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
    clientRootShare32B64u: string;
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
  const walletSessionUserId = toWalletSessionUserId(args.walletSessionUserId);
  const subjectId = walletSubjectIdFromWalletProfile({
    walletId: args.walletSessionUserId,
  });
  const sessionKind =
    signerTransportAuth.kind === 'cookie_threshold_session_auth' ? 'cookie' : 'jwt';
  if (!relayerUrl || !keyHandle || (!thresholdSessionAuthToken && sessionKind !== 'cookie')) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }

  const roleLocalState = args.record.ecdsaHssRoleLocalClientState;
  if (!roleLocalState) {
    throw new Error('Threshold ECDSA export requires role-local HSS client state');
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
    clientPublicKey33B64u: roleLocalState.clientPublicKey33B64u,
    relayerPublicKey33B64u: roleLocalState.relayerPublicKey33B64u,
    groupPublicKey33B64u: roleLocalState.groupPublicKey33B64u,
    ethereumAddress: roleLocalState.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletSessionUserId,
    rpId: args.rpId,
    subjectId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalState.contextBinding32B64u,
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
    walletSessionUserId,
    rpId: args.rpId,
    subjectId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    signingRootId,
    signingRootVersion,
    contextBinding32B64u: roleLocalState.contextBinding32B64u,
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
    walletSessionUserId,
    rpId: args.rpId,
    subjectId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalState.contextBinding32B64u,
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

  return await buildThresholdEcdsaHssRoleLocalExportArtifactWasm({
    context: {
      walletSessionUserId,
      subjectId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      keyPurpose: ECDSA_HSS_KEY_PURPOSE,
      keyVersion: ECDSA_HSS_KEY_VERSION,
    },
    clientRootShare32B64u: args.clientRootShare32B64u,
    serverExportShare32B64u: exportShare.value.serverExportShare32B64u,
    contextBinding32B64u: roleLocalState.contextBinding32B64u,
    publicIdentity: exportShare.value.publicIdentity,
    clientShareRetryCounter: roleLocalState.clientShareRetryCounter,
    workerCtx: deps.getSignerWorkerContext(),
  });
}
