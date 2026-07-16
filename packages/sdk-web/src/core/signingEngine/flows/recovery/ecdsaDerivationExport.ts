import { thresholdEcdsaDerivationRoleLocalExportShare } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { PasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  toEcdsaDerivationSigningRootId,
  toEcdsaDerivationSigningRootVersion,
  toEcdsaDerivationThresholdKeyId,
} from '../../session/identity/emailOtpEcdsaDerivationIdentity';
import { buildEcdsaRoleLocalExportArtifactCommandWasm } from '../../threshold/crypto/ecdsaDerivationClientWasm';
import {
  parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput,
  toGeneratedBuildEcdsaRoleLocalExportArtifactCommand,
} from '@/core/platform/signerCoreCommandAdapters';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  buildEcdsaWalletSessionAuthority,
  type EcdsaWalletSessionAuthority,
} from '../../session/identity/ecdsaWalletSessionAuthority';
import type { ThresholdEcdsaExplicitKeyExportBootstrapResult } from '../../session/passkey/ecdsaSessionProvision';
import type { ReadyEcdsaSignerSession } from '../../session/identity/evmFamilyEcdsaIdentity';
import { parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial } from '../../session/persistence/ecdsaRoleLocalRecords';
import type { ReadyEcdsaExportLane } from './ecdsaExportMaterial';
import type { EcdsaRoleLocalReadyRecord } from '@/core/platform';

const ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-confirmation:v2';
const ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-authorization:v2';
const ECDSA_DERIVATION_EXPORT_AUTH_TTL_MS = 60_000;
const ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT = 'default';

export type EcdsaDerivationExportDeps = {
  getSignerWorkerContext: () => WorkerOperationContext;
};

type ExplicitKeyExportMaterial = ThresholdEcdsaExplicitKeyExportBootstrapResult['material'];

type ResolvedEcdsaDerivationExportMaterial = {
  walletSessionAuthority: EcdsaWalletSessionAuthority;
  relayerUrl: string;
  readyRecord: EcdsaRoleLocalReadyRecord;
  ecdsaThresholdKeyId: ReturnType<typeof toEcdsaDerivationThresholdKeyId>;
  signingRootId: string;
  signingRootVersion: string;
  credential: WebAuthnAuthenticationCredential;
};

type EcdsaDerivationExportPublicIdentity = {
  derivationClientSharePublicKey33B64u: string;
  relayerPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
};

type EcdsaDerivationExportAuthorizationDigestInput = {
  version: typeof ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION;
  operation: 'explicit_key_export';
  keyHandle: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationExportPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  thresholdExpiresAtMs: EcdsaWalletSessionAuthority['thresholdExpiresAtMs'];
  participantIds: EcdsaWalletSessionAuthority['participantIds'];
};

function randomB64u32(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required for threshold ECDSA export');
  }
  return base64UrlEncode(cryptoApi.getRandomValues(new Uint8Array(32)));
}

function participantIdsKey(participantIds: readonly number[]): string {
  return participantIds.map((participantId) => String(participantId)).join(':');
}

function assertExplicitKeyExportMaterialBinding(args: {
  material: ExplicitKeyExportMaterial;
  walletSessionAuthority: EcdsaWalletSessionAuthority;
  walletSessionUserId: string;
}): void {
  const readyRecord = args.material.ecdsaRoleLocalReadyRecord;
  const publicFacts = readyRecord.publicFacts;
  const checks: ReadonlyArray<readonly [field: string, actual: string, expected: string]> = [
    ['walletId', String(publicFacts.walletId), String(args.material.walletId)],
    [
      'evmFamilySigningKeySlotId',
      String(publicFacts.evmFamilySigningKeySlotId),
      String(args.material.evmFamilySigningKeySlotId),
    ],
    ['keyHandle', String(publicFacts.keyHandle), String(args.material.keyHandle)],
    [
      'ecdsaThresholdKeyId',
      String(publicFacts.ecdsaThresholdKeyId),
      String(args.material.ecdsaThresholdKeyId),
    ],
    [
      'participantIds',
      participantIdsKey(publicFacts.participantIds),
      participantIdsKey(args.material.participantIds),
    ],
    [
      'Wallet Session participantIds',
      participantIdsKey(args.walletSessionAuthority.participantIds),
      participantIdsKey(args.material.participantIds),
    ],
    [
      'threshold public key',
      String(publicFacts.groupPublicKey33B64u),
      String(args.material.thresholdEcdsaPublicKeyB64u),
    ],
    [
      'ethereumAddress',
      String(publicFacts.ethereumAddress).toLowerCase(),
      String(args.material.ethereumAddress).toLowerCase(),
    ],
    ['walletSessionUserId', String(args.walletSessionUserId), String(args.material.walletId)],
  ];
  for (const [field, actual, expected] of checks) {
    if (actual === expected) continue;
    throw new Error(`[SigningEngine][ecdsa-export] explicit export ${field} mismatch`);
  }
}

async function digestB64u(input: unknown): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input)));
}

export function buildEcdsaDerivationExportAuthorizationDigestInput(args: {
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationExportPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  walletSessionAuthority: EcdsaWalletSessionAuthority;
}): EcdsaDerivationExportAuthorizationDigestInput {
  return {
    version: ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION,
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

async function executeEcdsaDerivationExport(
  deps: EcdsaDerivationExportDeps,
  material: ResolvedEcdsaDerivationExportMaterial,
): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  const readyRecord = material.readyRecord;
  if (readyRecord.authMethod.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] passkey export requires passkey ready material');
  }
  const authorizedCredentialId = String(
    material.credential.rawId || material.credential.id || '',
  ).trim();
  if (!authorizedCredentialId) {
    throw new Error('[SigningEngine][ecdsa-export] passkey authorization credential is missing');
  }
  if (authorizedCredentialId !== readyRecord.authMethod.credentialIdB64u) {
    throw new Error(
      '[SigningEngine][ecdsa-export] passkey export authorization credential mismatch',
    );
  }
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = Math.min(
    issuedAtUnixMs + ECDSA_DERIVATION_EXPORT_AUTH_TTL_MS,
    material.walletSessionAuthority.thresholdExpiresAtMs,
  );
  if (!Number.isFinite(expiresAtUnixMs) || expiresAtUnixMs <= issuedAtUnixMs) {
    throw new Error('Threshold ECDSA export session is expired');
  }

  const publicIdentity = {
    derivationClientSharePublicKey33B64u:
      readyRecord.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: readyRecord.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: readyRecord.publicFacts.groupPublicKey33B64u,
    ethereumAddress: readyRecord.publicFacts.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId: material.walletSessionAuthority.walletId,
    evmFamilySigningKeySlotId: material.walletSessionAuthority.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: material.ecdsaThresholdKeyId,
    relayerKeyId: material.walletSessionAuthority.relayerKeyId,
    contextBinding32B64u: readyRecord.publicFacts.contextBinding32B64u,
    publicIdentity,
    clientDeviceId: material.walletSessionAuthority.signingGrantId,
    clientSessionId: material.walletSessionAuthority.thresholdSessionId,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u(
    buildEcdsaDerivationExportAuthorizationDigestInput({
      ecdsaThresholdKeyId: material.ecdsaThresholdKeyId,
      signingRootId: material.signingRootId,
      signingRootVersion: material.signingRootVersion,
      contextBinding32B64u: readyRecord.publicFacts.contextBinding32B64u,
      publicIdentity,
      exportRequestNonce32B64u,
      confirmationDigest32B64u,
      issuedAtUnixMs,
      expiresAtUnixMs,
      walletSessionAuthority: material.walletSessionAuthority,
    }),
  );

  const exportShare = await thresholdEcdsaDerivationRoleLocalExportShare(material.relayerUrl, {
    formatVersion: 'ecdsa-derivation-role-local-export',
    walletId: material.walletSessionAuthority.walletId,
    evmFamilySigningKeySlotId: material.walletSessionAuthority.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: material.ecdsaThresholdKeyId,
    relayerKeyId: material.walletSessionAuthority.relayerKeyId,
    contextBinding32B64u: readyRecord.publicFacts.contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    authorizationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId: material.walletSessionAuthority.signingGrantId,
    clientSessionId: material.walletSessionAuthority.thresholdSessionId,
    auth: {
      kind: 'wallet_session',
      jwt: material.walletSessionAuthority.walletSessionJwt,
    },
  });
  if (!exportShare.ok) {
    throw new Error(
      exportShare.error || exportShare.message || 'Threshold explicit export share request failed',
    );
  }
  if (
    exportShare.value.contextBinding32B64u !== readyRecord.publicFacts.contextBinding32B64u ||
    exportShare.value.publicIdentity.groupPublicKey33B64u !== publicIdentity.groupPublicKey33B64u ||
    exportShare.value.publicIdentity.ethereumAddress !== publicIdentity.ethereumAddress
  ) {
    throw new Error('[SigningEngine][ecdsa-export] relayer export share identity mismatch');
  }

  const generatedCommand = toGeneratedBuildEcdsaRoleLocalExportArtifactCommand({
    kind: 'build_ecdsa_role_local_export_artifact_v1',
    algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
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

export async function exportEcdsaDerivationKeyWithExplicitExportSession(
  deps: EcdsaDerivationExportDeps,
  args: {
    walletSessionUserId: string;
    exportProvision: ThresholdEcdsaExplicitKeyExportBootstrapResult;
    credential: WebAuthnAuthenticationCredential;
  },
): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  const material = args.exportProvision.material;
  const walletSessionAuthority = buildEcdsaWalletSessionAuthority({
    walletSessionJwt: material.walletSessionJwt,
    walletId: material.walletId,
    evmFamilySigningKeySlotId: material.evmFamilySigningKeySlotId,
    keyHandle: material.keyHandle,
    thresholdSessionId: material.thresholdSessionId,
    signingGrantId: material.signingGrantId,
  });
  assertExplicitKeyExportMaterialBinding({
    material,
    walletSessionAuthority,
    walletSessionUserId: args.walletSessionUserId,
  });
  const walletSessionJwt = String(walletSessionAuthority.walletSessionJwt || '').trim();
  const relayerUrl = String(material.relayerUrl || '').trim();
  const keyHandle = String(material.keyHandle || '').trim();
  const walletId = toWalletId(args.walletSessionUserId);
  if (!relayerUrl || !keyHandle || !walletSessionJwt) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }
  if (
    String(walletSessionAuthority.thresholdSessionId) !== String(material.thresholdSessionId) ||
    String(walletSessionAuthority.signingGrantId) !== String(material.signingGrantId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] committed lane Wallet Session authority does not match signer session',
    );
  }
  if (
    String(walletSessionAuthority.walletId) !== String(walletId) ||
    String(walletSessionAuthority.keyHandle) !== keyHandle ||
    String(walletSessionAuthority.relayerKeyId) !== String(material.relayerKeyId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] committed lane Wallet Session authority does not match signer transport',
    );
  }

  const readyRecord = material.ecdsaRoleLocalReadyRecord;
  const evmFamilySigningKeySlotId = String(material.evmFamilySigningKeySlotId || '').trim();
  if (!evmFamilySigningKeySlotId) {
    throw new Error(
      '[SigningEngine][ecdsa-export] session record is missing evmFamilySigningKeySlotId',
    );
  }
  if (String(walletSessionAuthority.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
    throw new Error(
      '[SigningEngine][ecdsa-export] committed lane Wallet Session key slot mismatch',
    );
  }
  if (String(readyRecord.publicFacts.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
    throw new Error('[SigningEngine][ecdsa-export] role-local evmFamilySigningKeySlotId mismatch');
  }
  const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId(material.ecdsaThresholdKeyId);
  const signingRootId = toEcdsaDerivationSigningRootId(readyRecord.publicFacts.signingRootId);
  const signingRootVersion = toEcdsaDerivationSigningRootVersion(
    readyRecord.publicFacts.signingRootVersion || ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT,
  );
  return await executeEcdsaDerivationExport(deps, {
    walletSessionAuthority,
    relayerUrl,
    readyRecord,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    credential: args.credential,
  });
}

export async function exportEcdsaDerivationKeyWithWalletSession(
  deps: EcdsaDerivationExportDeps,
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
  if (walletSessionAuthority.kind !== 'ecdsa_wallet_session_authority') {
    throw new Error('[SigningEngine][ecdsa-export] export requires Wallet Session JWT authority');
  }
  const signerWalletSessionJwt = String(
    args.signerSession.routerAbEcdsaDerivationNormalSigning.credential.walletSessionJwt,
  ).trim();
  const walletSessionJwt = String(walletSessionAuthority.walletSessionJwt).trim();
  const relayerUrl = String(signerTransport.relayerUrl).trim();
  const keyHandle = String(args.signerSession.publicFacts.keyHandle).trim();
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
  const evmFamilySigningKeySlotId = String(record.evmFamilySigningKeySlotId).trim();
  if (!evmFamilySigningKeySlotId) {
    throw new Error(
      '[SigningEngine][ecdsa-export] session record is missing evmFamilySigningKeySlotId',
    );
  }
  if (String(walletSessionAuthority.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
    throw new Error(
      '[SigningEngine][ecdsa-export] committed lane Wallet Session key slot mismatch',
    );
  }
  if (String(readyRecord.publicFacts.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
    throw new Error('[SigningEngine][ecdsa-export] role-local evmFamilySigningKeySlotId mismatch');
  }
  const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId(record.ecdsaThresholdKeyId);
  const signingRootId = toEcdsaDerivationSigningRootId(record.signingRootId);
  const signingRootVersion = toEcdsaDerivationSigningRootVersion(
    record.signingRootVersion || ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT,
  );
  return await executeEcdsaDerivationExport(deps, {
    walletSessionAuthority,
    relayerUrl,
    readyRecord,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    credential: args.credential,
  });
}
