import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  closeRouterAbEcdsaPostRegistrationCeremonyWasm,
  createRouterAbEcdsaPostRegistrationCeremonyWasm,
  finalizeRouterAbEcdsaExplicitExportWasm,
} from '../../threshold/crypto/ecdsaDerivationClientWasm';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { SigningSessionIds } from '../../session/operationState/types';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { ThresholdEcdsaExplicitKeyExportBootstrapResult } from '../../session/passkey/ecdsaSessionProvision';
import type {
  EcdsaExplicitExportOperationAuthorization,
} from '../../threshold/ecdsa/activation';
import {
  ecdsaRoleLocalPersistedMaterialSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
  type PersistedEcdsaRoleLocalMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  WalletSessionFailureError,
  walletSessionFailureFromCode,
} from '../../session/lifecycle/walletSessionFailure';
import {
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
  parseRouterAbEcdsaExplicitExportForwardedResponseV1,
  type RouterAbEcdsaDerivationExplicitExportRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';

const ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-confirmation:v5';
const ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-derivation:role-local:product-export-authorization:v5';
const ECDSA_DERIVATION_EXPORT_AUTH_TTL_MS = 60_000;

export type EcdsaDerivationExportDeps = {
  getSignerWorkerContext: () => WorkerOperationContext;
};

type ExplicitKeyExportMaterial = ThresholdEcdsaExplicitKeyExportBootstrapResult['material'];

export type EcdsaDerivationExportAuthorization =
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
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  liveMaterial: Extract<EcdsaRoleLocalMaterialResolution, { kind: 'rehydrated' }>;
  relayerUrl: string;
  operationAuthorization: EcdsaExplicitExportOperationAuthorization;
  factorAuthorization: EcdsaDerivationExportAuthorization;
};

function exportAuthorizationWire(
  authorization: EcdsaExplicitExportOperationAuthorization,
): Extract<RouterAbNormalSigningAuthorizationWire, { readonly kind: 'operation_step_up' }> {
  return { kind: 'operation_step_up' };
}

function exportAuthorizationDigestFields(
  authorization: EcdsaExplicitExportOperationAuthorization,
): {
  authorizationKind: EcdsaExplicitExportOperationAuthorization['kind'];
  authorizationId: string;
} {
  return {
    authorizationKind: authorization.kind,
    authorizationId: authorization.evidenceSetDigest,
  };
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
  authorizationKind: EcdsaExplicitExportOperationAuthorization['kind'];
  authorizationId: string;
  materialActivation: RouterAbMpcMaterialActivationRefWire;
  participantIds: readonly number[];
};

function randomB64u32(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required for threshold ECDSA export');
  }
  return base64UrlEncode(cryptoApi.getRandomValues(new Uint8Array(32)));
}

async function forwardExplicitEcdsaExport(args: {
  readonly relayerUrl: string;
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly requestDigestB64u: string;
}) {
  const relayerUrl = String(args.relayerUrl || '').trim().replace(/\/+$/g, '');
  if (!relayerUrl) throw new Error('[SigningEngine][ecdsa-export] relayer URL is required');
  try {
    const response = await fetch(`${relayerUrl}${ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        request: args.request,
        requestDigestB64u: args.requestDigestB64u,
      }),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      const failure =
        body && typeof body === 'object' && !Array.isArray(body)
          ? (body as Record<string, unknown>)
          : null;
      return {
        ok: false as const,
        code: String(failure?.code || 'http_error'),
        message: String(failure?.message || `HTTP ${response.status}`),
      };
    }
    return {
      ok: true as const,
      value: parseRouterAbEcdsaExplicitExportForwardedResponseV1(body),
    };
  } catch (error: unknown) {
    return {
      ok: false as const,
      error: error instanceof Error ? error.message : String(error),
    };
  }
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

function assertExplicitKeyExportMaterialBinding(args: {
  material: ExplicitKeyExportMaterial;
  walletSessionUserId: string;
}): void {
  if (
    String(args.material.persistedMaterial.publicFacts.walletId) !==
    String(args.walletSessionUserId)
  ) {
    throw new Error('[SigningEngine][ecdsa-export] explicit export wallet mismatch');
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
  const publicFacts = args.material.persistedMaterial.publicFacts;
  return {
    version: ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION,
    operation: 'explicit_key_export',
    keyHandle: publicFacts.keyHandle,
    walletId: String(publicFacts.walletId),
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    relayerKeyId: publicFacts.publicCapability.signer_set.selected_server.server_id,
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
    materialActivation: routerAbMpcMaterialActivationRefToWire(
      args.material.persistedMaterial.materialActivation,
    ),
    participantIds: publicFacts.participantIds,
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
  const publicFacts = material.persistedMaterial.publicFacts;
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    material.persistedMaterial.materialActivation,
  );
  switch (material.factorAuthorization.kind) {
    case 'passkey': {
      const authorizedCredentialId = String(
        material.factorAuthorization.credential.rawId ||
          material.factorAuthorization.credential.id ||
          '',
      ).trim();
      if (!authorizedCredentialId) {
        throw new Error(
          '[SigningEngine][ecdsa-export] passkey authorization credential is missing',
        );
      }
      if (authorizedCredentialId !== material.factorAuthorization.passkeyCredentialIdB64u) {
        throw new Error(
          '[SigningEngine][ecdsa-export] passkey export authorization credential mismatch',
        );
      }
      break;
    }
    case 'email_otp_verified':
      break;
    default: {
      const exhaustive: never = material.factorAuthorization;
      throw new Error(`Unsupported ECDSA export authorization: ${String(exhaustive)}`);
    }
  }
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = requireActiveEcdsaExportAuthorizationWindow({
    issuedAtUnixMs,
    authorizationExpiresAtMsCeiling: material.operationAuthorization.expiresAtMs,
  });

  const publicIdentity = {
    derivationClientSharePublicKey33B64u: publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: publicFacts.groupPublicKey33B64u,
    ethereumAddress: publicFacts.ethereumAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const digestAuthorization = exportAuthorizationDigestFields(material.operationAuthorization);
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId: String(publicFacts.walletId),
    ecdsaThresholdKeyId: publicFacts.ecdsaThresholdKeyId,
    relayerKeyId: publicFacts.publicCapability.signer_set.selected_server.server_id,
    contextBinding32B64u: publicFacts.contextBinding32B64u,
    publicIdentity,
    authorizationKind: digestAuthorization.authorizationKind,
    authorizationId: digestAuthorization.authorizationId,
    materialActivation,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u(
    buildEcdsaDerivationExportAuthorizationDigestInput({
      ecdsaThresholdKeyId: publicFacts.ecdsaThresholdKeyId,
      signingRootId: publicFacts.signingRootId,
      signingRootVersion: publicFacts.signingRootVersion,
      contextBinding32B64u: publicFacts.contextBinding32B64u,
      publicIdentity,
      exportRequestNonce32B64u,
      confirmationDigest32B64u,
      issuedAtUnixMs,
      expiresAtUnixMs,
      material,
    }),
  );

  const publicCapability = publicFacts.publicCapability;
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
          account_id: String(publicFacts.walletId),
          session_id: SigningSessionIds.thresholdEcdsaSession(ceremonyId),
          signer_set_id: publicCapability.signer_set.signer_set_id,
          selected_server_id: publicCapability.signer_set.selected_server.server_id,
        },
        public_identity: publicCapability.public_identity,
        signer_set: publicCapability.signer_set,
        router_id: publicCapability.router_id,
        client_id: publicCapability.client_id,
        authorization: exportAuthorizationWire(material.operationAuthorization),
        authorization_id: material.operationAuthorization.evidenceSetDigest,
        operation: material.operationAuthorization.operation,
        material_activation: materialActivation,
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
    const forwarded = await forwardExplicitEcdsaExport({
      relayerUrl: material.relayerUrl,
      request: created.request,
      requestDigestB64u: created.requestDigestB64u,
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
        materialActivation,
        roleLocalMaterial: material.liveMaterial.liveHandle,
        roleLocalMaterialRef: material.liveMaterial.materialRef,
        publicFacts,
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

export async function exportEcdsaDerivationKey(
  deps: EcdsaDerivationExportDeps,
  args: {
    walletSessionUserId: string;
    exportProvision: ThresholdEcdsaExplicitKeyExportBootstrapResult;
    factorAuthorization: EcdsaDerivationExportAuthorization;
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
  const relayerUrl = String(material.relayerUrl || '').trim();
  if (!relayerUrl) throw new Error('[SigningEngine][ecdsa-export] relayer URL is required');
  const persistedMaterial = material.persistedMaterial;
  const liveMaterial = await hydrateEcdsaRoleLocalMaterialForExport({
    persistedMaterial,
    workerCtx: deps.getSignerWorkerContext(),
  });
  return await executeEcdsaDerivationExport(deps, {
    persistedMaterial,
    liveMaterial,
    relayerUrl,
    operationAuthorization: args.exportProvision.authorization,
    factorAuthorization: args.factorAuthorization,
  });
}
