import { thresholdEcdsaHssRoleLocalExportShare } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { PasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
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
import type { EcdsaCommittedLaneWalletSessionAuthority } from '../signEvmFamily/ecdsaSelection';

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
  thresholdExpiresAtMs: EcdsaCommittedLaneWalletSessionAuthority['thresholdExpiresAtMs'];
  participantIds: EcdsaCommittedLaneWalletSessionAuthority['participantIds'];
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

export function buildEcdsaHssExportAuthorizationDigestInput(args: {
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssExportPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  walletSessionAuthority: EcdsaCommittedLaneWalletSessionAuthority;
}): EcdsaHssExportAuthorizationDigestInput {
  return {
    version: ECDSA_HSS_EXPORT_AUTHORIZATION_DIGEST_VERSION,
    operation: 'explicit_key_export',
    keyHandle: args.walletSessionAuthority.keyHandle,
    walletId: args.walletSessionAuthority.walletId,
    evmFamilySigningKeySlotId: args.walletSessionAuthority.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    relayerKeyId: args.walletSessionAuthority.relayerKeyId,
    signingRootId: args.signingRootId,
    signingRootVersion: args.signingRootVersion,
    contextBinding32B64u: args.contextBinding32B64u,
    publicIdentity: args.publicIdentity,
    exportRequestNonce32B64u: args.exportRequestNonce32B64u,
    confirmationDigest32B64u: args.confirmationDigest32B64u,
    issuedAtUnixMs: args.issuedAtUnixMs,
    expiresAtUnixMs: args.expiresAtUnixMs,
    clientDeviceId: args.walletSessionAuthority.signingGrantId,
    clientSessionId: args.walletSessionAuthority.thresholdSessionId,
    thresholdSessionId: args.walletSessionAuthority.thresholdSessionId,
    signingGrantId: args.walletSessionAuthority.signingGrantId,
    thresholdExpiresAtMs: args.walletSessionAuthority.thresholdExpiresAtMs,
    participantIds: args.walletSessionAuthority.participantIds,
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
  const walletSessionAuthority = args.committedLane.walletSessionAuthority;
  if (walletSessionAuthority.kind !== 'wallet_session_authority') {
    throw new Error('[SigningEngine][ecdsa-export] export requires Wallet Session JWT authority');
  }
  const signerWalletSessionJwt = String(
    args.signerSession.routerAbEcdsaHssNormalSigning.credential.walletSessionJwt || '',
  ).trim();
  const walletSessionJwt = String(walletSessionAuthority.walletSessionJwt || '').trim();
  const relayerUrl = String(signerTransport.relayerUrl || '').trim();
  const keyHandle = String(args.signerSession.publicFacts.keyHandle || '').trim();
  const walletId = toWalletId(args.walletSessionUserId);
  if (!relayerUrl || !keyHandle || !walletSessionJwt || !signerWalletSessionJwt) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }
  if (walletSessionJwt !== signerWalletSessionJwt) {
    throw new Error('[SigningEngine][ecdsa-export] committed lane Wallet Session JWT mismatch');
  }
  if (
    String(walletSessionAuthority.thresholdSessionId) !==
      String(args.signerSession.session.thresholdSessionId) ||
    String(walletSessionAuthority.signingGrantId) !==
      String(args.signerSession.session.signingGrantId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] committed lane Wallet Session authority does not match signer session',
    );
  }
  if (
    String(walletSessionAuthority.walletId) !== String(walletId) ||
    String(walletSessionAuthority.keyHandle) !== keyHandle ||
    String(walletSessionAuthority.relayerKeyId) !== String(signerTransport.relayerKeyId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] committed lane Wallet Session authority does not match signer transport',
    );
  }

  const roleLocalMaterial = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(record);
  const readyRecord = roleLocalMaterial.readyRecord;
  const evmFamilySigningKeySlotId = String(record.evmFamilySigningKeySlotId || '').trim();
  if (!evmFamilySigningKeySlotId) {
    throw new Error('[SigningEngine][ecdsa-export] session record is missing evmFamilySigningKeySlotId');
  }
  if (String(walletSessionAuthority.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
    throw new Error(
      '[SigningEngine][ecdsa-export] committed lane Wallet Session key slot mismatch',
    );
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
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = Math.min(
    issuedAtUnixMs + ECDSA_HSS_EXPORT_AUTH_TTL_MS,
    walletSessionAuthority.thresholdExpiresAtMs,
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
    walletId: walletSessionAuthority.walletId,
    evmFamilySigningKeySlotId: walletSessionAuthority.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId: walletSessionAuthority.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    clientDeviceId: walletSessionAuthority.signingGrantId,
    clientSessionId: walletSessionAuthority.thresholdSessionId,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u(
    buildEcdsaHssExportAuthorizationDigestInput({
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
      publicIdentity,
      exportRequestNonce32B64u,
      confirmationDigest32B64u,
      issuedAtUnixMs,
      expiresAtUnixMs,
      walletSessionAuthority,
    }),
  );

  const exportShare = await thresholdEcdsaHssRoleLocalExportShare(relayerUrl, {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId: walletSessionAuthority.walletId,
    evmFamilySigningKeySlotId: walletSessionAuthority.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId: walletSessionAuthority.relayerKeyId,
    contextBinding32B64u: roleLocalMaterial.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    authorizationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: walletSessionAuthority.signingGrantId,
    clientSessionId: walletSessionAuthority.thresholdSessionId,
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
