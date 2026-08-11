import {
  buildLinkedDeviceExecutionEnvelopeV1,
  type LinkedDeviceExecutionEnvelopeV1,
} from '@shared/signing-lanes/execution';
import type { LinkedDeviceLocalPresenceAssertionV1 } from '@shared/device-linking';
import {
  parseAuthorizedOperationId,
  type AuthorizedOperationId,
} from '@shared/authorization/capabilityKinds';
import { base64UrlEncode, base64UrlDecode } from '@shared/utils/base64';
import { base58Encode } from '@shared/utils/base58';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildMpcMaterialActivationRef,
  mpcMaterialActivationRefsEqual,
  parseMpcSigningWorkerRef,
  type MpcSigningWorkerRef,
} from '@shared/utils/domainIds';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { AuthenticatorPort } from '@/core/platform';
import type { LaneSealedHolderMaterialRepositoryV1 } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type { LinkedDeviceWalletSessionTokenReadResultV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import type {
  ActiveLinkedDeviceExecutionBundleV1,
  ActiveLinkedDeviceExecutionChildV1,
} from '@/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import type {
  DeviceLinkingHolderSigningMaterialPortV1,
  DeviceLinkingEd25519SigningShareV1,
} from '@/core/signingEngine/session/lanes/linkedDevicePorts';
import { authorizeAndOpenLinkedDeviceHolderV1 } from '@/core/signingEngine/session/lanes/linkedDeviceLocalPresence';
import {
  buildRouterAbEd25519Nep413PrepareRequestV2,
  buildRouterAbEd25519NormalSigningFinalizeRequestV2,
  finalizeRouterAbNormalSigningV2,
  prepareRouterAbNormalSigningV2,
  routerAbCanonicalWireBytesToB64u,
  type RouterAbEd25519NormalSigningCredential,
  type RouterAbNormalSigningFinalizeRequestV2Wire,
  type RouterAbNormalSigningPrepareRequestV2Wire,
  type RouterAbNormalSigningPrepareResponseV1Wire,
  type RouterAbNormalSigningResponseV1Wire,
  type RouterAbNormalSigningScopeV2Wire,
  type RouterAbEd25519NormalSigningAdmissionMaterialV2Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  requireRouterAbNormalSigningPrepareMatchesRequest,
  requireRouterAbNormalSigningResponseMatchesRequest,
} from '@/core/rpcClients/relayer/routerAbNormalSigningValidation';
import { parseSigningOperationFingerprintDigest } from '@/core/signingEngine/session/planning/operationFingerprint';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';

export type LinkedDeviceEd25519Nep413RequestV1 = {
  readonly requestId: string;
  readonly operationId: SigningOperationId;
  readonly operationFingerprint: SigningOperationFingerprint;
  readonly expiresAtMs: number;
  readonly displayDigestB64u: DigestB64u;
  readonly nearAccountId: string;
  readonly nearNetworkId: 'testnet' | 'mainnet';
  readonly message: string;
  readonly recipient: string;
  readonly nonce: string;
  readonly callbackUrl?: string;
  readonly expectedSigningDigestB64u: DigestB64u;
};

export type LinkedDeviceEd25519NormalSigningPrepareRequestV1 =
  RouterAbNormalSigningPrepareRequestV2Wire & {
    readonly linkedDeviceExecution: LinkedDeviceExecutionEnvelopeV1;
    readonly localPresenceAssertion: LinkedDeviceLocalPresenceAssertionV1;
  };

export type LinkedDeviceEd25519NormalSigningFinalizeRequestV1 =
  RouterAbNormalSigningFinalizeRequestV2Wire & {
    readonly linkedDeviceExecution: LinkedDeviceExecutionEnvelopeV1;
    readonly localPresenceAssertion: LinkedDeviceLocalPresenceAssertionV1;
  };

export type LinkedDeviceEd25519NormalSigningTransportV1 = {
  prepare(input: {
    readonly relayServerUrl: string;
    readonly credential: RouterAbEd25519NormalSigningCredential;
    readonly request: LinkedDeviceEd25519NormalSigningPrepareRequestV1;
  }): Promise<RouterAbNormalSigningPrepareResponseV1Wire>;
  finalize(input: {
    readonly relayServerUrl: string;
    readonly credential: RouterAbEd25519NormalSigningCredential;
    readonly request: LinkedDeviceEd25519NormalSigningFinalizeRequestV1;
  }): Promise<RouterAbNormalSigningResponseV1Wire>;
};

export type LinkedDeviceEd25519NormalSigningInputV1 = {
  readonly relayServerUrl: string;
  readonly authenticator: AuthenticatorPort;
  readonly holderRepository: LaneSealedHolderMaterialRepositoryV1;
  readonly holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ed25519' }>;
  readonly walletSession: Extract<
    LinkedDeviceWalletSessionTokenReadResultV1,
    { readonly kind: 'found' }
  >;
  readonly issuedAtMs: number;
  readonly request: LinkedDeviceEd25519Nep413RequestV1;
  readonly transport?: LinkedDeviceEd25519NormalSigningTransportV1;
};

export type LinkedDeviceEd25519NormalSigningResultV1 = {
  readonly kind: 'linked_device_ed25519_normal_signing_result_v1';
  readonly operationId: SigningOperationId;
  readonly signatureB64u: string;
  readonly signerPublicKey: string;
};

const defaultTransport: LinkedDeviceEd25519NormalSigningTransportV1 = {
  prepare: prepareRouterAbNormalSigningV2,
  finalize: finalizeRouterAbNormalSigningV2,
};

function requireNonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} is required`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireRequestId(value: unknown): string {
  const requestId = requireNonEmpty(value, 'linked-device requestId');
  if (/[^\x20-\x7e]/.test(requestId) || /\s/.test(requestId)) {
    throw new Error('linked-device requestId must not contain whitespace');
  }
  return requestId;
}

function requireAuthorizedOperationId(requestId: string): AuthorizedOperationId {
  const parsed = parseAuthorizedOperationId(`linked-ed25519-authorized-operation:${requestId}`);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function digestB64uFromWire(value: { readonly bytes: readonly number[] }): DigestB64u {
  return parseDigestB64u(base64UrlEncode(Uint8Array.from(value.bytes)));
}

function targetSigningWorkerRef(
  child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ed25519' }>,
): MpcSigningWorkerRef {
  const parsed = parseMpcSigningWorkerRef(child.job.targetSigningWorker.participantId);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function assertEd25519ChildIsActive(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
  child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ed25519' }>,
): void {
  if (
    child.kind !== 'active_linked_device_ed25519_execution_v1' ||
    child.keyFamily !== 'ed25519' ||
    child.walletKey.keyFamily !== 'ed25519' ||
    child.walletKey.walletId !== bundle.walletId ||
    child.walletKey.walletKeyId !== child.walletKeyId ||
    child.job.walletId !== bundle.walletId ||
    String(child.job.enrollmentId) !== String(bundle.enrollmentId) ||
    child.lane.laneKind !== 'linked_device' ||
    !mpcMaterialActivationRefsEqual(
      child.materialActivation,
      buildMpcMaterialActivationRef({
        activationId: child.job.targetMaterialActivationId,
        capability: child.job.source.materialActivation.capability,
        materialOwner: child.job.source.materialActivation.materialOwner,
        keyBinding: child.job.source.materialActivation.keyBinding,
        lifecycleBinding: child.job.source.materialActivation.lifecycleBinding,
        signingWorker: targetSigningWorkerRef(child),
      }),
    )
  ) {
    throw new Error('linked-device Ed25519 execution child is not active for this bundle');
  }
  const activeChild = bundle.orderedExecutions.find(
    (candidate) =>
      candidate.kind === 'active_linked_device_ed25519_execution_v1' &&
      candidate.walletKeyId === child.walletKeyId &&
      candidate.operationId === child.operationId &&
      candidate.laneId === child.laneId &&
      candidate.laneShareEpoch === child.laneShareEpoch &&
      mpcMaterialActivationRefsEqual(candidate.materialActivation, child.materialActivation),
  );
  if (!activeChild) {
    throw new Error('linked-device Ed25519 execution child is not part of the active bundle');
  }
}

function assertWalletSessionMatchesChild(
  walletSession: Extract<LinkedDeviceWalletSessionTokenReadResultV1, { readonly kind: 'found' }>,
  bundle: ActiveLinkedDeviceExecutionBundleV1,
  child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ed25519' }>,
): void {
  const { delivery, token } = walletSession;
  const tokenIsDelivered = delivery.orderedTokens.some(
    (candidate) => alphabetizeStringify(candidate) === alphabetizeStringify(token),
  );
  if (
    delivery.tenantId !== bundle.tenantId ||
    delivery.walletId !== bundle.walletId ||
    delivery.enrollmentId !== bundle.enrollmentId ||
    delivery.deviceId !== bundle.deviceId ||
    delivery.authorizationId !== bundle.authorizationId ||
    delivery.walletSessionId !== bundle.walletSessionId ||
    delivery.quotaId !== bundle.quotaId ||
    delivery.keyManifestDigestB64u !== bundle.keyManifestDigestB64u ||
    alphabetizeStringify(delivery.permission) !== alphabetizeStringify(bundle.permission) ||
    delivery.revocationEpoch !== bundle.revocationEpoch ||
    delivery.issuedAtMs !== bundle.issuedAtMs ||
    delivery.expiresAtMs !== bundle.expiresAtMs ||
    !tokenIsDelivered ||
    token.keyFamily !== 'ed25519' ||
    token.walletKeyId !== child.walletKeyId ||
    !requireNonEmpty(token.walletSessionJwt, 'linked-device Wallet Session JWT')
  ) {
    throw new Error('linked-device Wallet Session token does not match the Ed25519 child');
  }
}

function buildScope(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ed25519' }>;
  readonly requestId: string;
}): RouterAbNormalSigningScopeV2Wire {
  return {
    request_id: input.requestId,
    account_id: String(input.bundle.walletId),
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: String(input.bundle.walletSessionId),
    },
    material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: String(input.child.materialActivation.activationId),
      capability: String(input.child.materialActivation.capability),
      material_owner: String(input.child.materialActivation.materialOwner),
      key_binding: String(input.child.materialActivation.keyBinding),
      lifecycle_binding: String(input.child.materialActivation.lifecycleBinding),
      signing_worker: String(input.child.materialActivation.signingWorker),
    },
    signing_worker_id: String(input.child.materialActivation.signingWorker),
  };
}

async function buildPrepare(input: {
  readonly scope: RouterAbNormalSigningScopeV2Wire;
  readonly request: LinkedDeviceEd25519Nep413RequestV1;
}): Promise<{
  readonly request: RouterAbNormalSigningPrepareRequestV2Wire;
  readonly admissionMaterial: RouterAbEd25519NormalSigningAdmissionMaterialV2Wire;
}> {
  return await buildRouterAbEd25519Nep413PrepareRequestV2({
    scope: input.scope,
    expiresAtMs: input.request.expiresAtMs,
    operationId: input.request.operationId,
    operationFingerprint: input.request.operationFingerprint,
    displayDigestB64u: input.request.displayDigestB64u,
    nearAccountId: input.request.nearAccountId,
    nearNetworkId: input.request.nearNetworkId,
    message: input.request.message,
    recipient: input.request.recipient,
    nonce: input.request.nonce,
    ...(input.request.callbackUrl === undefined ? {} : { callbackUrl: input.request.callbackUrl }),
    expectedSigningDigestB64u: input.request.expectedSigningDigestB64u,
  });
}

function buildEnvelope(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
  child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ed25519' }>,
): LinkedDeviceExecutionEnvelopeV1 {
  return buildLinkedDeviceExecutionEnvelopeV1({
    enrollmentId: bundle.enrollmentId,
    deviceId: bundle.deviceId,
    walletKeyId: child.walletKeyId,
    laneId: child.laneId,
    laneShareEpoch: child.laneShareEpoch,
    materialActivation: child.materialActivation,
  });
}

function signerPublicKey(
  child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ed25519' }>,
): string {
  return ensureEd25519Prefix(
    `ed25519:${base58Encode(base64UrlDecode(child.walletKey.registeredPublicKeyB64u))}`,
  );
}

async function createHolderShare(input: {
  readonly holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  readonly handle: Extract<
    Awaited<
      ReturnType<DeviceLinkingHolderSigningMaterialPortV1['openPersistedHolderSigningMaterialV1']>
    >,
    { readonly keyFamily: 'ed25519' }
  >;
  readonly admissionMaterial: RouterAbEd25519NormalSigningAdmissionMaterialV2Wire;
  readonly prepareResponse: RouterAbNormalSigningPrepareResponseV1Wire;
}): Promise<DeviceLinkingEd25519SigningShareV1> {
  return await input.holderMaterial.createEd25519HolderSigningShareV1({
    handle: input.handle,
    admittedDigestB64u: digestB64uFromWire(input.admissionMaterial.admittedSigningDigest),
    signingWorkerCommitments: input.prepareResponse.server_commitments,
    signingWorkerVerifyingShareB64u: input.prepareResponse.server_verifying_share_b64u,
  });
}

export async function executeLinkedDeviceEd25519NormalSigningV1(
  input: LinkedDeviceEd25519NormalSigningInputV1,
): Promise<LinkedDeviceEd25519NormalSigningResultV1> {
  const requestId = requireRequestId(input.request.requestId);
  parseSigningOperationFingerprintDigest(input.request.operationFingerprint);
  assertEd25519ChildIsActive(input.bundle, input.child);
  assertWalletSessionMatchesChild(input.walletSession, input.bundle, input.child);
  const authorizedOperationId = requireAuthorizedOperationId(requestId);
  const scope = buildScope({ bundle: input.bundle, child: input.child, requestId });
  const envelope = buildEnvelope(input.bundle, input.child);
  const prepare = await buildPrepare({ scope, request: input.request });
  const intentDigestB64u = digestB64uFromWire(prepare.admissionMaterial.intentDigest);
  const transport = input.transport ?? defaultTransport;
  const credential: RouterAbEd25519NormalSigningCredential = {
    kind: 'wallet_session_jwt',
    walletSessionJwt: input.walletSession.token.walletSessionJwt,
  };
  const presenceAndHolder = await authorizeAndOpenLinkedDeviceHolderV1({
    authenticator: input.authenticator,
    holderRepository: input.holderRepository,
    holderMaterial: input.holderMaterial,
    bundle: input.bundle,
    child: input.child,
    authorizedOperationId,
    intentDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.request.expiresAtMs,
    authorizeBeforeOpen: async (localPresenceAssertion) =>
      await transport.prepare({
        relayServerUrl: input.relayServerUrl,
        credential,
        request: {
          ...prepare.request,
          linkedDeviceExecution: envelope,
          localPresenceAssertion,
        },
      }),
  });
  try {
    const prepareRequest: LinkedDeviceEd25519NormalSigningPrepareRequestV1 = {
      ...prepare.request,
      linkedDeviceExecution: envelope,
      localPresenceAssertion: presenceAndHolder.localPresenceAssertion,
    };
    const prepareResponse = presenceAndHolder.authorizationResult;
    requireRouterAbNormalSigningPrepareMatchesRequest({
      request: prepareRequest,
      signingPayloadDigest: prepare.admissionMaterial.signingPayloadDigest,
      response: prepareResponse,
    });
    if (presenceAndHolder.holderMaterial.keyFamily !== 'ed25519') {
      throw new Error('linked-device holder material changed its active curve');
    }
    const clientShare = await createHolderShare({
      holderMaterial: input.holderMaterial,
      handle: presenceAndHolder.holderMaterial,
      admissionMaterial: prepare.admissionMaterial,
      prepareResponse,
    });
    const finalizeRequest = buildRouterAbEd25519NormalSigningFinalizeRequestV2({
      scope: prepare.request.scope,
      expiresAtMs: prepare.request.expires_at_ms,
      prepareResponse,
      admissionMaterial: prepare.admissionMaterial,
      clientCommitments: clientShare.clientCommitments,
      clientVerifyingShareB64u: clientShare.clientVerifyingShareB64u,
      clientSignatureShareB64u: clientShare.clientSignatureShareB64u,
    });
    const linkedFinalizeRequest: LinkedDeviceEd25519NormalSigningFinalizeRequestV1 = {
      ...finalizeRequest,
      linkedDeviceExecution: envelope,
      localPresenceAssertion: presenceAndHolder.localPresenceAssertion,
    };
    const signingResponse = await transport.finalize({
      relayServerUrl: input.relayServerUrl,
      credential,
      request: linkedFinalizeRequest,
    });
    requireRouterAbNormalSigningResponseMatchesRequest({
      request: prepareRequest,
      signingPayloadDigest: prepare.admissionMaterial.signingPayloadDigest,
      response: signingResponse,
    });
    return {
      kind: 'linked_device_ed25519_normal_signing_result_v1',
      operationId: input.request.operationId,
      signatureB64u: routerAbCanonicalWireBytesToB64u(
        signingResponse.signature,
        'linked-device Ed25519 normal-signing signature',
      ),
      signerPublicKey: signerPublicKey(input.child),
    };
  } finally {
    await input.holderMaterial.discardHolderSigningMaterialV1({
      handle: presenceAndHolder.holderMaterial,
    });
  }
}
