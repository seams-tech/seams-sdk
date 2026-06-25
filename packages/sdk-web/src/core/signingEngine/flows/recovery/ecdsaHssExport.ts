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
  type ReadyEcdsaSignerSession,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial } from '../../session/persistence/ecdsaRoleLocalRecords';
import { buildEcdsaRoleLocalExportArtifactCommandWasm } from '../../threshold/crypto/hssClientSignerWasm';
import {
  parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput,
  toGeneratedBuildEcdsaRoleLocalExportArtifactCommand,
} from '@/core/platform/signerCoreCommandAdapters';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';

const ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-confirmation:v2';
const ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-authorization:v2';
const ECDSA_HSS_EXPORT_AUTH_TTL_MS = 60_000;
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

export async function exportEcdsaHssKeyWithWalletSession(
  deps: EcdsaHssExplicitExportDeps,
  args: {
    walletSessionUserId: string;
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
  const walletSessionJwt = String(
    args.signerSession.routerAbEcdsaHssNormalSigning.credential.walletSessionJwt || '',
  ).trim();
  const relayerUrl = String(signerTransport.relayerUrl || '').trim();
  const keyHandle = String(args.signerSession.publicFacts.keyHandle || '').trim();
  const walletId = toWalletId(args.walletSessionUserId);
  const sessionKind = 'jwt' as const;
  if (!relayerUrl || !keyHandle || !walletSessionJwt) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }

  const roleLocalMaterial = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(args.record);
  const readyRecord = roleLocalMaterial.readyRecord;
  const walletKeyId = String(readyRecord.publicFacts.walletKeyId || '').trim();
  if (!walletKeyId) {
    throw new Error('[SigningEngine][ecdsa-export] ready export material is missing walletKeyId');
  }
  if (readyRecord.authMethod.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] passkey export requires passkey ready material');
  }
  const authorizedCredentialId = String(args.credential.rawId || args.credential.id || '').trim();
  if (authorizedCredentialId && authorizedCredentialId !== readyRecord.authMethod.credentialIdB64u) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export authorization credential mismatch');
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
      readyRecord.publicFacts.hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u: readyRecord.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: readyRecord.publicFacts.groupPublicKey33B64u,
    ethereumAddress: readyRecord.publicFacts.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_HSS_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    clientDeviceId: String(args.signerSession.session.signingGrantId),
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
    walletKeyId,
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
    clientDeviceId: String(args.signerSession.session.signingGrantId),
    clientSessionId: String(args.signerSession.session.thresholdSessionId),
    thresholdSessionId: String(args.signerSession.session.thresholdSessionId),
    signingGrantId: String(args.signerSession.session.signingGrantId),
    thresholdExpiresAtMs: args.record.expiresAtMs,
    participantIds: args.record.participantIds,
  });

  const exportShare = await thresholdEcdsaHssRoleLocalExportShare(relayerUrl, {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId,
    walletKeyId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    authorizationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: String(args.signerSession.session.signingGrantId),
    clientSessionId: String(args.signerSession.session.thresholdSessionId),
    auth: { kind: 'wallet_session', jwt: walletSessionJwt },
  });
  if (!exportShare.ok) {
    throw new Error(
      exportShare.error || exportShare.message || 'Threshold explicit export share request failed',
    );
  }
  if (
    exportShare.value.contextBinding32B64u !== roleLocalMaterial.contextBinding32B64u ||
    exportShare.value.publicIdentity.groupPublicKey33B64u !== publicIdentity.groupPublicKey33B64u ||
    exportShare.value.publicIdentity.ethereumAddress !== publicIdentity.ethereumAddress
  ) {
    throw new Error('[SigningEngine][ecdsa-export] relayer export share identity mismatch');
  }

  const generatedCommand = toGeneratedBuildEcdsaRoleLocalExportArtifactCommand({
    kind: 'build_ecdsa_role_local_export_artifact_v1',
    algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
    stateBlob: readyRecord.stateBlob,
    publicFacts: readyRecord.publicFacts,
    serverExportShare32B64u: exportShare.value.serverExportShare32B64u,
  });
  const generatedOutput = await buildEcdsaRoleLocalExportArtifactCommandWasm({
    command: generatedCommand,
    workerCtx: deps.getSignerWorkerContext(),
  });
  return parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput(generatedOutput);
}
