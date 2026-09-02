import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  closeRouterAbEcdsaPostRegistrationCeremonyWasm,
  createRouterAbEcdsaPostRegistrationCeremonyWasm,
  createEcdsaHolderOrdinaryExportRequestWasm,
  finalizeEcdsaHolderOrdinaryExportWasm,
  finalizeRouterAbEcdsaExplicitExportWasm,
} from '../../threshold/crypto/ecdsaDerivationClientWasm';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  routerAbMpcMaterialActivationRefToWire,
  routerAbMpcMaterialActivationRefFromWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { SigningSessionIds } from '../../session/operationState/types';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { ThresholdEcdsaExplicitKeyExportBootstrapResult } from '../../session/passkey/ecdsaSessionProvision';
import type { EcdsaExplicitExportOperationAuthorization } from '../../threshold/ecdsa/activation';
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
  type RouterAbEcdsaSigningWorkerExportShareBindingV1,
  type RouterAbEcdsaDerivationExplicitExportRequestV1,
  type RouterAbEcdsaOperationStepUpExportTopologyV1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEcdsaExplicitExportRequestFactsV1 } from '../../workerManager/ecdsaClientWorkerChannels';
import type { WalletSessionOperationCredentialV1 } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ActiveWalletAuthorityEcdsaRuntimeV1 } from '../../session/material/activeWalletAuthorityEcdsaRuntime';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';

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

export type ActiveWalletAuthorityEcdsaExportTopology =
  RouterAbEcdsaOperationStepUpExportTopologyV1Wire;

export type ActiveWalletAuthorityEcdsaExportAuthorization =
  EcdsaExplicitExportOperationAuthorization & {
    readonly exportTopology: ActiveWalletAuthorityEcdsaExportTopology;
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

type EcdsaExportForwardAuthorization =
  | { readonly kind: 'legacy_cookie' }
  | { readonly kind: 'wallet_session_bearer'; readonly token: string };

async function forwardEcdsaExportWithAuthorization(args: {
  readonly relayerUrl: string;
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly requestDigestB64u: string;
  readonly authorization: EcdsaExportForwardAuthorization;
}) {
  const relayerUrl = String(args.relayerUrl || '')
    .trim()
    .replace(/\/+$/g, '');
  if (!relayerUrl) throw new Error('[SigningEngine][ecdsa-export] relayer URL is required');
  if (args.authorization.kind === 'wallet_session_bearer') {
    if (!args.authorization.token.trim()) {
      throw new Error(
        '[SigningEngine][ecdsa-export] Wallet Session operation credential is required',
      );
    }
  }
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (args.authorization.kind === 'wallet_session_bearer') {
    headers.Authorization = `Bearer ${args.authorization.token}`;
  }
  try {
    const response = await fetch(`${relayerUrl}${ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH}`, {
      method: 'POST',
      credentials: args.authorization.kind === 'legacy_cookie' ? 'include' : 'omit',
      headers,
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

export async function forwardExplicitEcdsaExport(args: {
  readonly relayerUrl: string;
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly requestDigestB64u: string;
}) {
  return await forwardEcdsaExportWithAuthorization({
    ...args,
    authorization: { kind: 'legacy_cookie' },
  });
}

export async function forwardActiveWalletAuthorityEcdsaExport(args: {
  readonly relayerUrl: string;
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly requestDigestB64u: string;
  readonly operationCredential: WalletSessionOperationCredentialV1;
}) {
  return await forwardEcdsaExportWithAuthorization({
    relayerUrl: args.relayerUrl,
    request: args.request,
    requestDigestB64u: args.requestDigestB64u,
    authorization: {
      kind: 'wallet_session_bearer',
      token: args.operationCredential.token,
    },
  });
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

function assertActiveWalletAuthorityExportOperationBinding(args: {
  readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
  readonly operationAuthorization: ActiveWalletAuthorityEcdsaExportAuthorization;
}): void {
  const scope = args.runtime.normalSigning.scope;
  const operation = args.operationAuthorization.operation;
  const operationMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
    operation.material_activation,
  );
  if (
    operation.operation_kind !== 'evm.export_key' ||
    operation.wallet_id !== String(args.runtime.walletId) ||
    operation.key_handle !== args.runtime.publicFacts.keyHandle ||
    operation.relayer_key_id !== args.runtime.relayerKeyId ||
    operation.participant_ids[0] !== args.runtime.publicFacts.participantIds[0] ||
    operation.participant_ids[1] !== args.runtime.publicFacts.participantIds[1] ||
    operation.signing_worker_id !== scope.signing_worker.server_id ||
    operation.normal_signing_scope.wallet_id !== scope.wallet_id ||
    operation.normal_signing_scope.context.application_binding_digest_b64u !==
      scope.context.application_binding_digest_b64u ||
    operation.normal_signing_scope.public_identity.context_binding_b64u !==
      scope.public_identity.context_binding_b64u ||
    operation.normal_signing_scope.public_identity.threshold_public_key33_b64u !==
      scope.public_identity.threshold_public_key33_b64u ||
    operation.normal_signing_scope.signing_worker.server_id !== scope.signing_worker.server_id ||
    !mpcMaterialActivationRefsEqual(operationMaterialActivation, args.runtime.materialActivation) ||
    !mpcMaterialActivationRefsEqual(
      routerAbMpcMaterialActivationRefFromWire(operation.normal_signing_scope.material_activation),
      args.runtime.materialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] active Wallet Authority operation identity changed',
    );
  }
}

export async function exportActiveWalletAuthorityEcdsaHolderKey(
  deps: EcdsaDerivationExportDeps,
  args: {
    readonly runtime: ActiveWalletAuthorityEcdsaRuntimeV1;
    readonly operationAuthorization: ActiveWalletAuthorityEcdsaExportAuthorization;
    readonly relayerUrl: string;
  },
): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  assertActiveWalletAuthorityExportOperationBinding(args);
  const runtime = args.runtime;
  const scope = runtime.normalSigning.scope;
  if (
    args.operationAuthorization.exportTopology.signer_set.selected_server.server_id !==
    scope.signing_worker.server_id
  ) {
    throw new Error('[SigningEngine][ecdsa-export] active export topology changed');
  }
  const materialActivation = scope.material_activation;
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = requireActiveEcdsaExportAuthorizationWindow({
    issuedAtUnixMs,
    authorizationExpiresAtMsCeiling: args.operationAuthorization.expiresAtMs,
  });
  const publicIdentity = {
    derivationClientSharePublicKey33B64u:
      scope.public_identity.derivation_client_share_public_key33_b64u,
    relayerPublicKey33B64u: scope.public_identity.server_public_key33_b64u,
    groupPublicKey33B64u: scope.public_identity.threshold_public_key33_b64u,
    ethereumAddress: runtime.publicFacts.thresholdOwnerAddress,
  };
  const exportRequestNonce32B64u = randomB64u32();
  const digestAuthorization = exportAuthorizationDigestFields(args.operationAuthorization);
  const confirmationDigest32B64u = await digestB64u({
    version: ECDSA_DERIVATION_EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId: String(runtime.walletId),
    ecdsaThresholdKeyId: scope.ecdsa_threshold_key_id,
    relayerKeyId: runtime.relayerKeyId,
    contextBinding32B64u: scope.public_identity.context_binding_b64u,
    publicIdentity,
    authorizationKind: digestAuthorization.authorizationKind,
    authorizationId: digestAuthorization.authorizationId,
    materialActivation,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  const authorizationDigest32B64u = await digestB64u({
    version: ECDSA_DERIVATION_EXPORT_AUTHORIZATION_DIGEST_VERSION,
    operation: 'explicit_key_export',
    keyHandle: runtime.publicFacts.keyHandle,
    walletId: String(runtime.walletId),
    ecdsaThresholdKeyId: scope.ecdsa_threshold_key_id,
    relayerKeyId: runtime.relayerKeyId,
    signingRootId: scope.signing_root_id,
    signingRootVersion: scope.signing_root_version,
    contextBinding32B64u: scope.public_identity.context_binding_b64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    authorizationKind: digestAuthorization.authorizationKind,
    authorizationId: digestAuthorization.authorizationId,
    materialActivation,
    participantIds: runtime.publicFacts.participantIds,
  });
  const ceremonyId = `ecdsa-export:${exportRequestNonce32B64u}`;
  const request: RouterAbEcdsaExplicitExportRequestFactsV1 = {
    context: scope.context,
    lifecycle: {
      lifecycle_id: ceremonyId,
      work_kind: 'key_export',
      primitive_request_kind: 'export',
      root_share_epoch: scope.activation_epoch,
      account_id: scope.wallet_id,
      session_id: SigningSessionIds.thresholdEcdsaSession(ceremonyId),
      signer_set_id: args.operationAuthorization.exportTopology.signer_set.signer_set_id,
      selected_server_id:
        args.operationAuthorization.exportTopology.signer_set.selected_server.server_id,
    },
    public_identity: scope.public_identity,
    signer_set: args.operationAuthorization.exportTopology.signer_set,
    router_id: args.operationAuthorization.exportTopology.router_id,
    client_id: String(runtime.walletId),
    authorization: exportAuthorizationWire(args.operationAuthorization),
    operation: args.operationAuthorization.operation,
    authorization_id: parseDigestB64u(args.operationAuthorization.evidenceSetDigest),
    material_activation: materialActivation,
    export_authorization_digest_b64u: authorizationDigest32B64u,
    export_nonce: exportRequestNonce32B64u,
    expires_at_ms: expiresAtUnixMs,
    deriver_recipient_keys: args.operationAuthorization.exportTopology.deriver_recipient_keys,
  };
  const created = await createEcdsaHolderOrdinaryExportRequestWasm({
    holderHandleId: runtime.holderRuntime.holderHandleId,
    request,
    workerCtx: deps.getSignerWorkerContext(),
  });
  if (created.kind !== 'ecdsa_holder_ordinary_export_request_created_v1') {
    throw new Error('[SigningEngine][ecdsa-export] active holder export request kind mismatch');
  }
  const forwarded = await forwardActiveWalletAuthorityEcdsaExport({
    relayerUrl: args.relayerUrl,
    request: created.request,
    requestDigestB64u: created.requestDigestB64u,
    operationCredential: runtime.operationCredential,
  });
  if (!forwarded.ok) {
    throw new Error(
      forwarded.error ||
        forwarded.message ||
        forwarded.code ||
        'Active Wallet Authority ECDSA export request failed',
    );
  }
  const expectedBinding: RouterAbEcdsaSigningWorkerExportShareBindingV1 = {
    wallet_id: scope.wallet_id,
    key_handle: runtime.publicFacts.keyHandle,
    ecdsa_threshold_key_id: scope.ecdsa_threshold_key_id,
    signing_root_id: scope.signing_root_id,
    signing_root_version: scope.signing_root_version,
    activation_epoch: scope.activation_epoch,
    signing_worker_id: scope.signing_worker.server_id,
    context_binding_b64u: scope.public_identity.context_binding_b64u,
    threshold_public_key33_b64u: scope.public_identity.threshold_public_key33_b64u,
    export_request_digest_b64u: created.requestDigestB64u,
    export_authorization_digest_b64u: authorizationDigest32B64u,
    export_nonce: exportRequestNonce32B64u,
    authorization_kind: 'verified_step_up',
    authorization_id: args.operationAuthorization.evidenceSetDigest,
    material_activation: materialActivation,
    lifecycle_id: ceremonyId,
    recipient_identity: created.request.client_id,
    recipient_public_key: created.request.client_ephemeral_public_key,
    expires_at_ms: created.request.expires_at_ms,
  };
  const finalized = await finalizeEcdsaHolderOrdinaryExportWasm({
    holderHandleId: runtime.holderRuntime.holderHandleId,
    requestDigestB64u: created.requestDigestB64u,
    expectedBinding,
    forwardedResponse: forwarded.value,
    workerCtx: deps.getSignerWorkerContext(),
  });
  return {
    publicKeyHex: finalized.publicKeyHex,
    privateKeyHex: finalized.privateKeyHex,
    ethereumAddress: finalized.ethereumAddress,
  };
}
