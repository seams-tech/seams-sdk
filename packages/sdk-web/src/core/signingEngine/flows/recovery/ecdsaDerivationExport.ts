import { routerAbEcdsaExplicitExport } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { PasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  toEcdsaDerivationSigningRootId,
  toEcdsaDerivationSigningRootVersion,
  toEcdsaDerivationThresholdKeyId,
} from '../../session/identity/emailOtpEcdsaDerivationIdentity';
import {
  closeRouterAbEcdsaPostRegistrationCeremonyWasm,
  createRouterAbEcdsaPostRegistrationCeremonyWasm,
  finalizeRouterAbEcdsaExplicitExportWasm,
} from '../../threshold/crypto/ecdsaDerivationClientWasm';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  buildEcdsaWalletSessionAuthority,
  type EcdsaWalletSessionAuthority,
} from '../../session/identity/ecdsaWalletSessionAuthority';
import type { ThresholdEcdsaExplicitKeyExportBootstrapResult } from '../../session/passkey/ecdsaSessionProvision';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ReadyEcdsaSignerSession } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  requirePersistedEcdsaRoleLocalMaterial,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  persistedEcdsaRoleLocalMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type { EcdsaRoleLocalWorkerHandle } from '../../session/keyMaterialBrands';
import type { ReadyEcdsaExportLane } from './ecdsaExportMaterial';
import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import type { FinalizeRouterAbEcdsaExplicitExportRequestV1 } from '../../workerManager/ecdsaClientWorkerChannels';

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

type EcdsaDerivationExportAuthorization =
  | {
      kind: 'passkey';
      passkeyCredentialIdB64u: string;
      credential: WebAuthnAuthenticationCredential;
    }
  | {
      kind: 'email_otp_verified';
      passkeyCredentialIdB64u?: never;
      credential?: never;
    };

type ResolvedEcdsaDerivationExportMaterial = {
  walletSessionAuthority: EcdsaWalletSessionAuthority;
  relayerUrl: string;
  publicFacts: EcdsaRoleLocalPublicFacts;
  roleLocalMaterial: FinalizeRouterAbEcdsaExplicitExportRequestV1['roleLocalMaterial'];
  ecdsaThresholdKeyId: ReturnType<typeof toEcdsaDerivationThresholdKeyId>;
  signingRootId: string;
  signingRootVersion: string;
  authorization: EcdsaDerivationExportAuthorization;
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
  const publicFacts = args.material.publicFacts;
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

function requireResolvedEcdsaExportMaterial(
  resolution: EcdsaRoleLocalMaterialResolution,
): EcdsaRoleLocalWorkerHandle {
  switch (resolution.kind) {
    case 'live':
    case 'rehydrated':
      return resolution.liveHandle;
    case 'device_link_required':
      throw new Error(
        '[SigningEngine][ecdsa-export] device_link_required: local threshold ECDSA material is unavailable',
      );
    case 'corrupt':
      throw new Error(
        `[SigningEngine][ecdsa-export] local threshold ECDSA material is corrupt (${resolution.reason}): ${resolution.message}`,
      );
    default: {
      const exhaustive: never = resolution;
      throw new Error(`Unsupported ECDSA export material resolution: ${String(exhaustive)}`);
    }
  }
}

async function resolveEcdsaExportMaterial(args: {
  readonly record: ThresholdEcdsaSessionRecord;
  readonly workerCtx: WorkerOperationContext;
}): Promise<EcdsaRoleLocalWorkerHandle> {
  const resolution = await resolveEcdsaRoleLocalMaterial({
    purpose: 'explicit_key_export',
    source: persistedEcdsaRoleLocalMaterialSource(
      requirePersistedEcdsaRoleLocalMaterial(args.record),
    ),
    workerCtx: args.workerCtx,
  });
  return requireResolvedEcdsaExportMaterial(resolution);
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
  switch (material.authorization.kind) {
    case 'passkey': {
      const authorizedCredentialId = String(
        material.authorization.credential.rawId ||
          material.authorization.credential.id ||
          '',
      ).trim();
      if (!authorizedCredentialId) {
        throw new Error('[SigningEngine][ecdsa-export] passkey authorization credential is missing');
      }
      if (authorizedCredentialId !== material.authorization.passkeyCredentialIdB64u) {
        throw new Error(
          '[SigningEngine][ecdsa-export] passkey export authorization credential mismatch',
        );
      }
      break;
    }
    case 'email_otp_verified':
      break;
    default: {
      const exhaustive: never = material.authorization;
      throw new Error(`Unsupported ECDSA export authorization: ${String(exhaustive)}`);
    }
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
    derivationClientSharePublicKey33B64u: material.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: material.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: material.publicFacts.groupPublicKey33B64u,
    ethereumAddress: material.publicFacts.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId: material.walletSessionAuthority.walletId,
    evmFamilySigningKeySlotId: material.walletSessionAuthority.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: material.ecdsaThresholdKeyId,
    relayerKeyId: material.walletSessionAuthority.relayerKeyId,
    contextBinding32B64u: material.publicFacts.contextBinding32B64u,
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
      contextBinding32B64u: material.publicFacts.contextBinding32B64u,
      publicIdentity,
      exportRequestNonce32B64u,
      confirmationDigest32B64u,
      issuedAtUnixMs,
      expiresAtUnixMs,
      walletSessionAuthority: material.walletSessionAuthority,
    }),
  );

  const publicCapability = material.publicFacts.publicCapability;
  const ceremonyId = `ecdsa-export:${exportRequestNonce32B64u}`;
  const created = await createRouterAbEcdsaPostRegistrationCeremonyWasm({
    workerCtx: deps.getSignerWorkerContext(),
    command: {
      kind: 'create_router_ab_ecdsa_explicit_export_ceremony_v1',
      ceremonyId,
      request: {
        context: publicCapability.context,
        lifecycle: {
          lifecycle_id: ceremonyId,
          work_kind: 'key_export',
          primitive_request_kind: 'export',
          root_share_epoch: publicCapability.activation_epoch,
          account_id: String(material.walletSessionAuthority.walletId),
          session_id: material.walletSessionAuthority.thresholdSessionId,
          signer_set_id: publicCapability.signer_set.signer_set_id,
          selected_server_id: publicCapability.signer_set.selected_server.server_id,
        },
        public_identity: publicCapability.public_identity,
        signer_set: publicCapability.signer_set,
        router_id: publicCapability.router_id,
        client_id: publicCapability.client_id,
        export_authorization_digest_b64u: authorizationDigest32B64u,
        export_nonce: exportRequestNonce32B64u,
        expires_at_ms: expiresAtUnixMs,
        deriver_recipient_keys: publicCapability.deriver_recipient_keys,
      },
    },
  });
  if (created.kind !== 'router_ab_ecdsa_explicit_export_ceremony_created_v1') {
    throw new Error('[SigningEngine][ecdsa-export] strict export ceremony kind mismatch');
  }
  try {
    const forwarded = await routerAbEcdsaExplicitExport(material.relayerUrl, {
      request: created.request,
      auth: {
        kind: 'wallet_session',
        jwt: material.walletSessionAuthority.walletSessionJwt,
      },
    });
    if (!forwarded.ok) {
      throw new Error(
        forwarded.error ||
          forwarded.message ||
          forwarded.code ||
          'Strict ECDSA explicit export request failed',
      );
    }
    const finalized = await finalizeRouterAbEcdsaExplicitExportWasm({
      workerCtx: deps.getSignerWorkerContext(),
      command: {
        kind: 'finalize_router_ab_ecdsa_explicit_export_v1',
        ceremonyId,
        clientProofFinalization: {
          kind: 'finalize_encrypted_client_proof_bundles_v1',
          bundles: forwarded.value.response.bundles,
        },
        signingWorkerExport: forwarded.value.signing_worker_export,
        signingGrantId: material.walletSessionAuthority.signingGrantId,
        roleLocalMaterial: material.roleLocalMaterial,
        publicFacts: material.publicFacts,
      },
    });
    return {
      publicKeyHex: finalized.publicKeyHex,
      privateKeyHex: finalized.privateKeyHex,
      ethereumAddress: finalized.ethereumAddress,
    };
  } catch (error: unknown) {
    await closeRouterAbEcdsaPostRegistrationCeremonyWasm({
      workerCtx: deps.getSignerWorkerContext(),
      command: {
        kind: 'close_router_ab_ecdsa_post_registration_ceremony_v1',
        ceremonyId,
      },
    }).catch(() => undefined);
    throw error;
  }
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

  const publicFacts = material.publicFacts;
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
  if (String(publicFacts.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
    throw new Error('[SigningEngine][ecdsa-export] role-local evmFamilySigningKeySlotId mismatch');
  }
  const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId(material.ecdsaThresholdKeyId);
  const signingRootId = toEcdsaDerivationSigningRootId(publicFacts.signingRootId);
  const signingRootVersion = toEcdsaDerivationSigningRootVersion(
    publicFacts.signingRootVersion || ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT,
  );
  return await executeEcdsaDerivationExport(deps, {
    walletSessionAuthority,
    relayerUrl,
    publicFacts,
    roleLocalMaterial: material.roleLocalMaterial,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    authorization: {
      kind: 'passkey',
      passkeyCredentialIdB64u: args.exportProvision.passkeyCredentialIdB64u,
      credential: args.credential,
    },
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

  const authMethod = record.ecdsaRoleLocalAuthMethod;
  if (authMethod.kind !== 'passkey') {
    throw new Error('[SigningEngine][ecdsa-export] passkey export requires passkey ready material');
  }
  const publicFacts = record.ecdsaRoleLocalPublicFacts;
  const exactRoleLocalMaterial = await resolveEcdsaExportMaterial({
    record,
    workerCtx: deps.getSignerWorkerContext(),
  });
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
  if (String(publicFacts.evmFamilySigningKeySlotId) !== evmFamilySigningKeySlotId) {
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
    publicFacts,
    roleLocalMaterial: exactRoleLocalMaterial,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    authorization: {
      kind: 'passkey',
      passkeyCredentialIdB64u: authMethod.credentialIdB64u,
      credential: args.credential,
    },
  });
}

export async function exportEcdsaDerivationKeyWithEmailOtpSession(
  deps: EcdsaDerivationExportDeps,
  args: {
    walletSessionUserId: string;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
  },
): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const backendBinding = keyRef.backendBinding;
  if (!backendBinding || backendBinding.materialKind !== 'role_local_worker_handle') {
    throw new Error(
      '[SigningEngine][ecdsa-export] Email OTP export requires live registered role-local material',
    );
  }
  if (backendBinding.authMethod.kind !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP export material auth mismatch');
  }
  const walletSessionJwt = String(keyRef.walletSessionJwt || args.bootstrap.session.jwt || '').trim();
  const relayerUrl = String(keyRef.relayerUrl || '').trim();
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!walletSessionJwt || !relayerUrl || !keyHandle) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP export session transport is incomplete');
  }
  const walletSessionAuthority = buildEcdsaWalletSessionAuthority({
    walletSessionJwt,
    walletId: args.walletSessionUserId,
    evmFamilySigningKeySlotId: keyRef.evmFamilySigningKeySlotId,
    keyHandle,
    thresholdSessionId: args.bootstrap.session.thresholdSessionId,
    signingGrantId: args.bootstrap.session.signingGrantId,
  });
  const publicFacts = backendBinding.publicFacts;
  if (
    String(publicFacts.walletId) !== String(walletSessionAuthority.walletId) ||
    String(publicFacts.evmFamilySigningKeySlotId) !==
      String(walletSessionAuthority.evmFamilySigningKeySlotId) ||
    String(publicFacts.keyHandle) !== String(walletSessionAuthority.keyHandle)
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP role-local identity mismatch');
  }
  return await executeEcdsaDerivationExport(deps, {
    walletSessionAuthority,
    relayerUrl,
    publicFacts,
    roleLocalMaterial: backendBinding.roleLocalMaterialHandle,
    ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId(keyRef.ecdsaThresholdKeyId),
    signingRootId: toEcdsaDerivationSigningRootId(publicFacts.signingRootId),
    signingRootVersion: toEcdsaDerivationSigningRootVersion(
      publicFacts.signingRootVersion || ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT,
    ),
    authorization: { kind: 'email_otp_verified' },
  });
}
