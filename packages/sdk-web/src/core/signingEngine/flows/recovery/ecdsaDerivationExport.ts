import { routerAbEcdsaExplicitExport } from '@/core/rpcClients/relayer/thresholdEcdsa';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type {
  PasskeyWalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
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
import { SigningSessionIds } from '../../session/operationState/types';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import { parseEcdsaRoleLocalPersistedMaterialRef } from '../../session/keyMaterialBrands';
import type { EcdsaExportOperationAuthorization } from './ecdsaExportMaterial';
import type { ThresholdEcdsaExplicitKeyExportBootstrapResult } from '../../session/passkey/ecdsaSessionProvision';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  ecdsaRoleLocalPersistedMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
  type PersistedEcdsaRoleLocalMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  EcdsaRoleLocalWorkerHandle,
} from '../../session/keyMaterialBrands';
import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import type { FinalizeRouterAbEcdsaExplicitExportRequestV1 } from '../../workerManager/ecdsaClientWorkerChannels';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  WalletSessionFailureError,
  walletSessionFailureFromCode,
} from '../../session/lifecycle/walletSessionFailure';

const ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-confirmation:v3';
const ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-authorization:v3';
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
  walletId: string;
  keyHandle: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  // Opaque bearer for the relayer route; never decoded.
  walletSessionJwtBearer: string;
  // Discriminated operation authority plus the exact material activation this
  // export binds; these replace every legacy session/grant identifier in the
  // digest and wire.
  operationAuthorization: EcdsaExportOperationAuthorization;
  materialActivationId: string;
  authorizationExpiresAtMsCeiling: number | null;
  // Transitional router-ab lifecycle label sourced from the durable record;
  // renamed at the Phase 20 wire cut.
  lifecycleSessionId: string;
  relayerUrl: string;
  publicFacts: EcdsaRoleLocalPublicFacts;
  roleLocalMaterial: FinalizeRouterAbEcdsaExplicitExportRequestV1['roleLocalMaterial'];
  roleLocalMaterialRef: FinalizeRouterAbEcdsaExplicitExportRequestV1['roleLocalMaterialRef'];
  ecdsaThresholdKeyId: ReturnType<typeof toEcdsaDerivationThresholdKeyId>;
  signingRootId: string;
  signingRootVersion: string;
  authorization: EcdsaDerivationExportAuthorization;
};

function exportAuthorizationWire(
  authorization: EcdsaExportOperationAuthorization,
): RouterAbNormalSigningAuthorizationWire {
  return authorization.kind === 'reusable_wallet_session'
    ? { kind: 'reusable_wallet_session', wallet_session_id: authorization.walletSessionId }
    : { kind: 'operation_step_up', grant_id: authorization.grantId };
}

function exportAuthorizationDigestFields(authorization: EcdsaExportOperationAuthorization): {
  authorizationKind: EcdsaExportOperationAuthorization['kind'];
  authorizationId: string;
} {
  return authorization.kind === 'reusable_wallet_session'
    ? { authorizationKind: authorization.kind, authorizationId: authorization.walletSessionId }
    : { authorizationKind: authorization.kind, authorizationId: authorization.grantId };
}

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
  authorizationKind: EcdsaExportOperationAuthorization['kind'];
  authorizationId: string;
  materialActivationId: string;
  participantIds: readonly number[];
};

function randomB64u32(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required for threshold ECDSA export');
  }
  return base64UrlEncode(cryptoApi.getRandomValues(new Uint8Array(32)));
}

function requireActiveEcdsaExportAuthorizationWindow(args: {
  readonly issuedAtUnixMs: number;
  readonly authorizationExpiresAtMsCeiling: number | null;
}): number {
  const expiresAtUnixMs = Math.min(
    args.issuedAtUnixMs + ECDSA_DERIVATION_EXPORT_AUTH_TTL_MS,
    args.authorizationExpiresAtMsCeiling ?? Number.POSITIVE_INFINITY,
  );
  if (Number.isFinite(expiresAtUnixMs) && expiresAtUnixMs > args.issuedAtUnixMs) {
    return expiresAtUnixMs;
  }
  throw new WalletSessionFailureError({
    failure: walletSessionFailureFromCode(WALLET_SESSION_FAILURE_CODES.expired),
    message: 'Wallet Session expired before ECDSA export authorization',
  });
}

function participantIdsKey(participantIds: readonly number[]): string {
  return participantIds.map((participantId) => String(participantId)).join(':');
}

function assertExplicitKeyExportMaterialBinding(args: {
  material: ExplicitKeyExportMaterial;
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
): Extract<EcdsaRoleLocalMaterialResolution, { kind: 'rehydrated' }> {
  switch (resolution.kind) {
    case 'rehydrated':
      return resolution;
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

export async function hydrateEcdsaRoleLocalMaterialForExport(args: {
  readonly persistedMaterial: Pick<
    PersistedEcdsaRoleLocalMaterial,
    'authority' | 'materialActivation' | 'publicFacts'
  >;
  readonly workerCtx: WorkerOperationContext;
}): Promise<Extract<EcdsaRoleLocalMaterialResolution, { kind: 'rehydrated' }>> {
  const resolution = await resolveEcdsaRoleLocalMaterial({
    purpose: 'explicit_key_export',
    source: ecdsaRoleLocalPersistedMaterialSource(args.persistedMaterial),
    workerCtx: args.workerCtx,
  });
  return requireResolvedEcdsaExportMaterial(resolution);
}

export function buildEcdsaDerivationExportAuthorizationDigestInput(args: {
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationExportPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  material: ResolvedEcdsaDerivationExportMaterial;
}): EcdsaDerivationExportAuthorizationDigestInput {
  const authorization = exportAuthorizationDigestFields(args.material.operationAuthorization);
  return {
    version: ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION,
    operation: 'explicit_key_export',
    keyHandle: args.material.keyHandle,
    walletId: args.material.walletId,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    relayerKeyId: args.material.relayerKeyId,
    signingRootId: args.signingRootId,
    signingRootVersion: args.signingRootVersion,
    contextBinding32B64u: args.contextBinding32B64u,
    publicIdentity: args.publicIdentity,
    exportRequestNonce32B64u: args.exportRequestNonce32B64u,
    confirmationDigest32B64u: args.confirmationDigest32B64u,
    issuedAtUnixMs: args.issuedAtUnixMs,
    expiresAtUnixMs: args.expiresAtUnixMs,
    authorizationKind: authorization.authorizationKind,
    authorizationId: authorization.authorizationId,
    materialActivationId: args.material.materialActivationId,
    participantIds: args.material.participantIds,
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
        material.authorization.credential.rawId || material.authorization.credential.id || '',
      ).trim();
      if (!authorizedCredentialId) {
        throw new Error(
          '[SigningEngine][ecdsa-export] passkey authorization credential is missing',
        );
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
  const expiresAtUnixMs = requireActiveEcdsaExportAuthorizationWindow({
    issuedAtUnixMs,
    authorizationExpiresAtMsCeiling: material.authorizationExpiresAtMsCeiling,
  });

  const publicIdentity = {
    derivationClientSharePublicKey33B64u: material.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: material.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: material.publicFacts.groupPublicKey33B64u,
    ethereumAddress: material.publicFacts.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const digestAuthorization = exportAuthorizationDigestFields(material.operationAuthorization);
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId: material.walletId,
    evmFamilySigningKeySlotId: material.publicFacts.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: material.ecdsaThresholdKeyId,
    relayerKeyId: material.relayerKeyId,
    contextBinding32B64u: material.publicFacts.contextBinding32B64u,
    publicIdentity,
    authorizationKind: digestAuthorization.authorizationKind,
    authorizationId: digestAuthorization.authorizationId,
    materialActivationId: material.materialActivationId,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u(
    buildEcdsaDerivationExportAuthorizationDigestInput({
      evmFamilySigningKeySlotId: material.publicFacts.evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId: material.ecdsaThresholdKeyId,
      signingRootId: material.signingRootId,
      signingRootVersion: material.signingRootVersion,
      contextBinding32B64u: material.publicFacts.contextBinding32B64u,
      publicIdentity,
      exportRequestNonce32B64u,
      confirmationDigest32B64u,
      issuedAtUnixMs,
      expiresAtUnixMs,
      material,
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
          account_id: String(material.walletId),
          session_id: SigningSessionIds.thresholdEcdsaSession(material.lifecycleSessionId),
          signer_set_id: publicCapability.signer_set.signer_set_id,
          selected_server_id: publicCapability.signer_set.selected_server.server_id,
        },
        public_identity: publicCapability.public_identity,
        signer_set: publicCapability.signer_set,
        router_id: publicCapability.router_id,
        client_id: publicCapability.client_id,
        authorization: exportAuthorizationWire(material.operationAuthorization),
        material_activation_id: material.materialActivationId,
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
        jwt: material.walletSessionJwtBearer,
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
        authorizationKind: digestAuthorization.authorizationKind,
        authorizationId: digestAuthorization.authorizationId,
        materialActivationId: material.materialActivationId,
        roleLocalMaterial: material.roleLocalMaterial,
        roleLocalMaterialRef: material.roleLocalMaterialRef,
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
  assertExplicitKeyExportMaterialBinding({
    material,
    walletSessionUserId: args.walletSessionUserId,
  });
  const walletSessionJwt = String(material.walletSessionJwt || '').trim();
  const relayerUrl = String(material.relayerUrl || '').trim();
  const keyHandle = String(material.keyHandle || '').trim();
  const walletId = toWalletId(args.walletSessionUserId);
  if (!relayerUrl || !keyHandle || !walletSessionJwt) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }
  if (String(material.walletId) !== String(walletId)) {
    throw new Error(
      '[SigningEngine][ecdsa-export] explicit export session does not match the requested wallet',
    );
  }

  const publicFacts = material.publicFacts;
  const evmFamilySigningKeySlotId = String(material.evmFamilySigningKeySlotId || '').trim();
  if (!evmFamilySigningKeySlotId) {
    throw new Error(
      '[SigningEngine][ecdsa-export] session record is missing evmFamilySigningKeySlotId',
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
    walletId: String(walletId),
    keyHandle,
    relayerKeyId: String(material.relayerKeyId),
    participantIds: material.participantIds.map(Number),
    walletSessionJwtBearer: walletSessionJwt,
    // The explicit export session mints exactly one single-operation grant.
    operationAuthorization: {
      kind: 'operation_step_up',
      grantId: String(material.signingGrantId),
    },
    materialActivationId: String(
      parseEcdsaRoleLocalPersistedMaterialRef(material.roleLocalMaterialRef).materialActivation
        .activationId,
    ),
    authorizationExpiresAtMsCeiling: null,
    lifecycleSessionId: String(material.thresholdSessionId),
    relayerUrl,
    publicFacts,
    roleLocalMaterial: material.roleLocalMaterial,
    roleLocalMaterialRef: material.roleLocalMaterialRef,
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

export async function exportEcdsaDerivationKeyWithEmailOtpSession(
  deps: EcdsaDerivationExportDeps,
  args: {
    walletSessionUserId: string;
    authority: WalletAuthAuthorityRef;
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
  const walletSessionJwt = String(
    keyRef.walletSessionJwt || args.bootstrap.session.jwt || '',
  ).trim();
  const relayerUrl = String(keyRef.relayerUrl || '').trim();
  const keyHandle = String(keyRef.keyHandle || '').trim();
  if (!walletSessionJwt || !relayerUrl || !keyHandle) {
    throw new Error(
      '[SigningEngine][ecdsa-export] Email OTP export session transport is incomplete',
    );
  }
  const publicFacts = backendBinding.publicFacts;
  if (
    String(publicFacts.walletId) !== String(args.walletSessionUserId) ||
    String(publicFacts.keyHandle) !== keyHandle
  ) {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP role-local identity mismatch');
  }
  const exactRoleLocalMaterial = await hydrateEcdsaRoleLocalMaterialForExport({
    persistedMaterial: {
      authority: args.authority,
      materialActivation: backendBinding.roleLocalMaterialRef.materialActivation,
      publicFacts,
    },
    workerCtx: deps.getSignerWorkerContext(),
  });
  return await executeEcdsaDerivationExport(deps, {
    walletId: String(args.walletSessionUserId),
    keyHandle,
    relayerKeyId: String(backendBinding.relayerKeyId),
    participantIds: publicFacts.participantIds.map(Number),
    walletSessionJwtBearer: walletSessionJwt,
    // The Email OTP export session is minted per operation: a single-use grant.
    operationAuthorization: {
      kind: 'operation_step_up',
      grantId: String(args.bootstrap.session.signingGrantId),
    },
    materialActivationId: String(
      backendBinding.roleLocalMaterialRef.materialActivation.activationId,
    ),
    authorizationExpiresAtMsCeiling:
      Math.floor(Number(args.bootstrap.session.expiresAtMs) || 0) || null,
    lifecycleSessionId: String(args.bootstrap.session.thresholdSessionId),
    relayerUrl,
    publicFacts,
    roleLocalMaterial: exactRoleLocalMaterial.liveHandle,
    roleLocalMaterialRef: exactRoleLocalMaterial.materialRef,
    ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId(keyRef.ecdsaThresholdKeyId),
    signingRootId: toEcdsaDerivationSigningRootId(publicFacts.signingRootId),
    signingRootVersion: toEcdsaDerivationSigningRootVersion(
      publicFacts.signingRootVersion || ECDSA_DERIVATION_SIGNING_ROOT_VERSION_DEFAULT,
    ),
    authorization: { kind: 'email_otp_verified' },
  });
}
