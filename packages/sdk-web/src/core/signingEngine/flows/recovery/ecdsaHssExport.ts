import { thresholdEcdsaHssRoleLocalExportShare } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { PasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  decodeJwtPayloadRecord,
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '../../session/identity/emailOtpHssIdentity';
import { type ReadyEcdsaSignerSession } from '../../session/identity/evmFamilyEcdsaIdentity';
import { parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial } from '../../session/persistence/ecdsaRoleLocalRecords';
import type { ReadyEcdsaExportLane } from './ecdsaExportMaterial';
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

type EcdsaHssExportPublicIdentity = {
  hssClientSharePublicKey33B64u: string;
  relayerPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
};

type EcdsaHssExportWalletSessionClaims = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  relayerKeyId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  thresholdExpiresAtMs: number;
  participantIds: readonly number[];
};

type EcdsaHssExportAuthorizationDigestInput = {
  version: typeof ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION;
  operation: 'explicit_key_export';
  keyHandle: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssExportPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  thresholdExpiresAtMs: number;
  participantIds: readonly number[];
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

function requiredExportString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine][ecdsa-export] Wallet Session JWT ${field} is invalid`);
  }
  return normalized;
}

function requiredExportNumber(value: unknown, field: string): number {
  const normalized = Math.floor(Number(value));
  if (!Number.isFinite(normalized)) {
    throw new Error(`[SigningEngine][ecdsa-export] Wallet Session JWT ${field} is invalid`);
  }
  return normalized;
}

function requireMatchingExportClaim(args: {
  field: keyof EcdsaHssExportWalletSessionClaims;
  expected: string;
  actual: string;
}): void {
  if (args.expected !== args.actual) {
    throw new Error(
      `[SigningEngine][ecdsa-export] Wallet Session JWT ${args.field} does not match signer session`,
    );
  }
}

export function resolveEcdsaHssExportWalletSessionClaims(args: {
  walletSessionJwt: string;
  signerSession: ReadyEcdsaSignerSession;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  relayerKeyId: string;
}): EcdsaHssExportWalletSessionClaims {
  const payload = decodeJwtPayloadRecord(args.walletSessionJwt);
  if (payload?.kind !== ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND) {
    throw new Error('[SigningEngine][ecdsa-export] Wallet Session JWT kind is invalid');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(payload.participantIds);
  if (!participantIds || participantIds.length < 2) {
    throw new Error('[SigningEngine][ecdsa-export] Wallet Session JWT participantIds are invalid');
  }
  const claims: EcdsaHssExportWalletSessionClaims = {
    walletId: requiredExportString(payload.walletId, 'walletId'),
    evmFamilySigningKeySlotId: requiredExportString(
      payload.evmFamilySigningKeySlotId,
      'evmFamilySigningKeySlotId',
    ),
    keyHandle: requiredExportString(payload.keyHandle, 'keyHandle'),
    relayerKeyId: requiredExportString(payload.relayerKeyId, 'relayerKeyId'),
    thresholdSessionId: requiredExportString(payload.thresholdSessionId, 'thresholdSessionId'),
    signingGrantId: requiredExportString(payload.signingGrantId, 'signingGrantId'),
    thresholdExpiresAtMs: requiredExportNumber(
      payload.thresholdExpiresAtMs,
      'thresholdExpiresAtMs',
    ),
    participantIds,
  };
  requireMatchingExportClaim({
    field: 'walletId',
    expected: args.walletId,
    actual: claims.walletId,
  });
  requireMatchingExportClaim({
    field: 'evmFamilySigningKeySlotId',
    expected: args.evmFamilySigningKeySlotId,
    actual: claims.evmFamilySigningKeySlotId,
  });
  requireMatchingExportClaim({
    field: 'keyHandle',
    expected: args.keyHandle,
    actual: claims.keyHandle,
  });
  requireMatchingExportClaim({
    field: 'relayerKeyId',
    expected: args.relayerKeyId,
    actual: claims.relayerKeyId,
  });
  requireMatchingExportClaim({
    field: 'thresholdSessionId',
    expected: String(args.signerSession.session.thresholdSessionId),
    actual: claims.thresholdSessionId,
  });
  requireMatchingExportClaim({
    field: 'signingGrantId',
    expected: String(args.signerSession.session.signingGrantId),
    actual: claims.signingGrantId,
  });
  return claims;
}

export function buildEcdsaHssExportAuthorizationDigestInput(args: {
  keyHandle: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssExportPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  sessionClaims: EcdsaHssExportWalletSessionClaims;
}): EcdsaHssExportAuthorizationDigestInput {
  return {
    version: ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION,
    operation: 'explicit_key_export',
    keyHandle: args.keyHandle,
    walletId: args.walletId,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    relayerKeyId: args.relayerKeyId,
    signingRootId: args.signingRootId,
    signingRootVersion: args.signingRootVersion,
    contextBinding32B64u: args.contextBinding32B64u,
    publicIdentity: args.publicIdentity,
    exportRequestNonce32B64u: args.exportRequestNonce32B64u,
    confirmationDigest32B64u: args.confirmationDigest32B64u,
    issuedAtUnixMs: args.issuedAtUnixMs,
    expiresAtUnixMs: args.expiresAtUnixMs,
    clientDeviceId: args.sessionClaims.signingGrantId,
    clientSessionId: args.sessionClaims.thresholdSessionId,
    thresholdSessionId: args.sessionClaims.thresholdSessionId,
    signingGrantId: args.sessionClaims.signingGrantId,
    thresholdExpiresAtMs: args.sessionClaims.thresholdExpiresAtMs,
    participantIds: args.sessionClaims.participantIds,
  };
}

export async function exportEcdsaHssKeyWithWalletSession(
  deps: EcdsaHssExplicitExportDeps,
  args: {
    walletSessionUserId: string;
    signerSession: ReadyEcdsaSignerSession;
    committedLane: ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>;
    credential: WebAuthnAuthenticationCredential;
  },
): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  const record = args.committedLane.record;
  const signerTransport = args.signerSession.transport;
  const walletSessionJwt = String(
    args.signerSession.routerAbEcdsaHssNormalSigning.credential.walletSessionJwt || '',
  ).trim();
  const relayerUrl = String(signerTransport.relayerUrl || '').trim();
  const keyHandle = String(args.signerSession.publicFacts.keyHandle || '').trim();
  const walletId = toWalletId(args.walletSessionUserId);
  if (!relayerUrl || !keyHandle || !walletSessionJwt) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }

  const roleLocalMaterial = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(record);
  const readyRecord = roleLocalMaterial.readyRecord;
  const evmFamilySigningKeySlotId = String(record.evmFamilySigningKeySlotId || '').trim();
  if (!evmFamilySigningKeySlotId) {
    throw new Error('[SigningEngine][ecdsa-export] session record is missing evmFamilySigningKeySlotId');
  }
  if (String(readyRecord.publicFacts.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
    throw new Error('[SigningEngine][ecdsa-export] role-local evmFamilySigningKeySlotId mismatch');
  }
  if (readyRecord.authMethod.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] passkey export requires passkey ready material');
  }
  const authorizedCredentialId = String(args.credential.rawId || args.credential.id || '').trim();
  if (authorizedCredentialId && authorizedCredentialId !== readyRecord.authMethod.credentialIdB64u) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export authorization credential mismatch');
  }
  const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId(record.ecdsaThresholdKeyId);
  const signingRootId = toEcdsaHssSigningRootId(record.signingRootId);
  const signingRootVersion = toEcdsaHssSigningRootVersion(
    record.signingRootVersion || ECDSA_HSS_SIGNING_ROOT_VERSION_DEFAULT,
  );
  const sessionClaims = resolveEcdsaHssExportWalletSessionClaims({
    walletSessionJwt,
    signerSession: args.signerSession,
    walletId,
    evmFamilySigningKeySlotId,
    keyHandle,
    relayerKeyId: signerTransport.relayerKeyId,
  });
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = Math.min(
    issuedAtUnixMs + ECDSA_HSS_EXPORT_AUTH_TTL_MS,
    sessionClaims.thresholdExpiresAtMs,
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
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    clientDeviceId: sessionClaims.signingGrantId,
    clientSessionId: sessionClaims.thresholdSessionId,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u(
    buildEcdsaHssExportAuthorizationDigestInput({
      keyHandle,
      walletId,
      evmFamilySigningKeySlotId,
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
      sessionClaims,
    }),
  );

  const exportShare = await thresholdEcdsaHssRoleLocalExportShare(relayerUrl, {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId: signerTransport.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    authorizationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: sessionClaims.signingGrantId,
    clientSessionId: sessionClaims.thresholdSessionId,
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
