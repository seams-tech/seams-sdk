import {
  buildLinkedDeviceEcdsaNormalSigningScopeV1,
  parseLinkedDeviceEcdsaNormalSigningScopeV1,
  type LinkedDeviceEcdsaNormalSigningScopeV1,
} from '@shared/signing-lanes/linkedEcdsaScope';
import {
  buildLinkedDeviceExecutionEnvelopeV1,
  type LinkedDeviceExecutionEnvelopeV1,
} from '@shared/signing-lanes/execution';
import type { LinkedDeviceLocalPresenceAssertionV1 } from '@shared/device-linking';
import {
  parseAuthorizedOperationId,
  type AuthorizedOperationId,
} from '@shared/authorization/capabilityKinds';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseRootShareEpoch } from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseSecp256k1CompressedPublicKeyB64u } from '@shared/passkey-custody/primitives';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
  type RouterAbNormalSigningAuthorizationWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { routerAbEcdsaRerandomizationClientCommitmentV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEcdsaOperationStepUpWebAuthnCredentialV1Wire } from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildPasskeyWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { ActiveLinkedDeviceEcdsaExportMaterial } from '../../recovery/ecdsaExportMaterial';
import type { AuthenticatorPort } from '@/core/platform';
import type { LinkedDeviceWalletSessionTokenReadResultV1 } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import type {
  ActiveLinkedDeviceExecutionBundleV1,
  ActiveLinkedDeviceExecutionChildV1,
} from '@/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { RouterAbEd25519NormalSigningCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  DeviceLinkingHolderSigningMaterialPortV1,
  DeviceLinkingHolderSigningMaterialHandleV1,
} from '@/core/signingEngine/session/lanes/linkedDevicePorts';
import { collectLinkedDeviceLocalPresenceV1 } from '@/core/signingEngine/session/lanes/linkedDeviceLocalPresence';
import { LinkedDeviceEcdsaSigningMaterialSourceV1 } from '../signers/linkedDeviceEcdsaSigningMaterialSource';
import { verifySecp256k1RecoverableSignatureAgainstPublicKey33Wasm } from '@/core/signingEngine/chains/evm/evmCryptoWasm';

const LINKED_ECDSA_PRESIGN_INIT_PATH = '/router-ab/ecdsa-derivation/linked-device/presign/init';
const LINKED_ECDSA_PRESIGN_STEP_PATH = '/router-ab/ecdsa-derivation/linked-device/presign/step';
const LINKED_ECDSA_FINALIZE_PATH = '/router-ab/ecdsa-derivation/sign';
const LINKED_ECDSA_EXPORT_SHARE_PATH = '/router-ab/ecdsa-derivation/linked-device/export/share';
const MAX_PRESIGN_STEPS = 64;

type LinkedMaterialActivationScopeWire = {
  readonly kind: 'mpc_material_activation_ref';
  readonly activationId: string;
  readonly capability: string;
  readonly materialOwner: string;
  readonly keyBinding: string;
  readonly lifecycleBinding: string;
  readonly signingWorker: string;
};

export type LinkedDeviceEcdsaScopeWireV1 = Omit<
  LinkedDeviceEcdsaNormalSigningScopeV1,
  'materialActivation'
> & {
  readonly materialActivation: LinkedMaterialActivationScopeWire;
};

type LinkedDeviceEcdsaOperationDigestsWireV1 = {
  readonly lane_digest_b64u: string;
  readonly intent_digest_b64u: string;
  readonly display_digest_b64u: string;
};

export type LinkedDeviceEcdsaFreshExportProofV1 =
  | {
      readonly kind: 'passkey';
      readonly authority: PasskeyWalletAuthAuthority;
      readonly webauthn_authentication: RouterAbEcdsaOperationStepUpWebAuthnCredentialV1Wire;
    }
  | {
      readonly kind: 'email_otp';
      readonly provider_user_id: string;
      readonly challenge_id: string;
      readonly otp_code: string;
    };

export type LinkedDeviceEcdsaFreshExportAuthorizationV1 = (input: {
  readonly challengeB64u: string;
}) => Promise<LinkedDeviceEcdsaFreshExportProofV1>;

export type LinkedDeviceEcdsaPrepareRequestWireV1 = {
  readonly scope: LinkedDeviceEcdsaScopeWireV1;
  readonly request_id: string;
  readonly operation_id: string;
  readonly operation_digests: LinkedDeviceEcdsaOperationDigestsWireV1;
  readonly authorization: Extract<
    RouterAbNormalSigningAuthorizationWire,
    { readonly kind: 'reusable_wallet_session' }
  >;
  readonly material_activation: RouterAbMpcMaterialActivationRefWire;
  readonly client_presignature_id: string;
  readonly expires_at_ms: number;
  readonly signing_digest_b64u: string;
  readonly client_rerandomization_commitment32_b64u: string;
};

export type LinkedDeviceEcdsaFinalizeRequestWireV1 = Omit<
  LinkedDeviceEcdsaPrepareRequestWireV1,
  'client_presignature_id' | 'client_rerandomization_commitment32_b64u'
> & {
  readonly server_presignature_id: string;
  readonly client_signature_share32_b64u: string;
  readonly client_rerandomization_contribution32_b64u: string;
};

type LinkedDeviceEcdsaInitialBoundaryV1 = {
  readonly linkedDeviceExecution: LinkedDeviceExecutionEnvelopeV1;
  readonly localPresenceAssertion?: LinkedDeviceLocalPresenceAssertionV1;
};

type LinkedDeviceEcdsaContinuationBoundaryV1 = {
  readonly linkedDeviceExecution: LinkedDeviceExecutionEnvelopeV1;
};

type LinkedDeviceEcdsaPresignInitBodyV1 = LinkedDeviceEcdsaPrepareRequestWireV1 &
  LinkedDeviceEcdsaInitialBoundaryV1 & {
    readonly lane_operation_id: string;
    readonly presign_session_id?: string;
  };

type LinkedDeviceEcdsaPresignStepBodyV1 = LinkedDeviceEcdsaPrepareRequestWireV1 &
  LinkedDeviceEcdsaContinuationBoundaryV1 & {
    readonly lane_operation_id: string;
    readonly presign_session_id: string;
    readonly requested_stage: 'triples' | 'presign';
    readonly outgoing_messages_b64u: readonly string[];
  };

type LinkedDeviceEcdsaPresignProgressV1 =
  | {
      readonly kind: 'continue';
      readonly presignSessionId: string;
      readonly stage: 'triples' | 'triples_done' | 'presign';
      readonly event: 'none' | 'triples_done';
      readonly outgoingMessagesB64u: readonly string[];
    }
  | {
      readonly kind: 'complete';
      readonly presignSessionId: string;
      readonly stage: 'done';
      readonly event: 'presign_done';
      readonly outgoingMessagesB64u: readonly string[];
      readonly serverPresignatureId: string;
      readonly serverBigR33B64u: string;
      readonly signingWorkerRerandomizationContribution32B64u: string;
    };

type LinkedDeviceEcdsaPresignInitProgressV1 = Extract<
  LinkedDeviceEcdsaPresignProgressV1,
  { readonly kind: 'continue' }
> & {
  readonly materialExpiresAtMs: number;
};

type LinkedDeviceEcdsaSigningResponseV1 = {
  readonly scope: LinkedDeviceEcdsaScopeWireV1;
  readonly request_id: string;
  readonly request_digest: { readonly bytes: readonly number[] };
  readonly signing_digest: { readonly bytes: readonly number[] };
  readonly signature_scheme: 'ecdsa_secp256k1_recoverable_v1';
  readonly signature65_b64u: string;
};

export class LinkedDeviceEcdsaHttpError extends Error {
  readonly kind = 'linked_device_ecdsa_http_error_v1' as const;
  readonly status: number;
  readonly code: string;

  constructor(input: { readonly status: number; readonly code: string; readonly message: string }) {
    super(input.message);
    this.name = 'LinkedDeviceEcdsaHttpError';
    this.status = input.status;
    this.code = input.code;
  }
}

export type LinkedDeviceEcdsaNormalSigningTransportV1 = {
  readonly presignInit: (input: {
    readonly relayServerUrl: string;
    readonly credential: RouterAbEd25519NormalSigningCredential;
    readonly request: LinkedDeviceEcdsaPresignInitBodyV1;
  }) => Promise<LinkedDeviceEcdsaPresignInitProgressV1>;
  readonly presignStep: (input: {
    readonly relayServerUrl: string;
    readonly credential: RouterAbEd25519NormalSigningCredential;
    readonly request: LinkedDeviceEcdsaPresignStepBodyV1;
  }) => Promise<LinkedDeviceEcdsaPresignProgressV1>;
  readonly finalize: (input: {
    readonly relayServerUrl: string;
    readonly credential: RouterAbEd25519NormalSigningCredential;
    readonly request: LinkedDeviceEcdsaFinalizeRequestWireV1 &
      LinkedDeviceEcdsaContinuationBoundaryV1;
  }) => Promise<LinkedDeviceEcdsaSigningResponseV1>;
};

export type LinkedDeviceEcdsaNormalSigningRequestV1 = {
  readonly requestId: string;
  readonly operationId: string;
  readonly operationDigests: OperationDigestSet;
  readonly signingDigest32: Uint8Array;
  readonly expiresAtMs: number;
};

export type LinkedDeviceEcdsaNormalSigningInputV1 = {
  readonly relayServerUrl: string;
  readonly authenticator: AuthenticatorPort;
  readonly holderHandle: Extract<
    DeviceLinkingHolderSigningMaterialHandleV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
  readonly workerCtx: WorkerOperationContext;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: Extract<
    ActiveLinkedDeviceExecutionChildV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
  readonly walletSession: Extract<
    LinkedDeviceWalletSessionTokenReadResultV1,
    { readonly kind: 'found' }
  >;
  readonly issuedAtMs: number;
  readonly request: LinkedDeviceEcdsaNormalSigningRequestV1;
  readonly transport?: LinkedDeviceEcdsaNormalSigningTransportV1;
};

export type LinkedDeviceEcdsaNormalSigningResultV1 = {
  readonly kind: 'linked_device_ecdsa_normal_signing_result_v1';
  readonly operationId: string;
  readonly signature65: Uint8Array;
  readonly signature65B64u: string;
};

function requireText(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function isLinkedDeviceStepUpRequired(error: unknown): boolean {
  return (
    error instanceof LinkedDeviceEcdsaHttpError &&
    error.status === 409 &&
    error.code === 'linked_device_step_up_required'
  );
}

function requireRequestId(value: unknown): string {
  const requestId = requireText(value, 'linked ECDSA requestId');
  if (!/^[\x20-\x7e]+$/.test(requestId) || /\s/.test(requestId)) {
    throw new Error('linked ECDSA requestId must be printable without whitespace');
  }
  return requestId;
}

function requireAuthorizedOperationId(requestId: string): AuthorizedOperationId {
  const parsed = parseAuthorizedOperationId(`linked-ecdsa-authorized-operation:${requestId}`);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function materialActivationScopeWire(
  materialActivation: LinkedDeviceEcdsaNormalSigningScopeV1['materialActivation'],
): LinkedMaterialActivationScopeWire {
  return {
    kind: 'mpc_material_activation_ref',
    activationId: String(materialActivation.activationId),
    capability: String(materialActivation.capability),
    materialOwner: String(materialActivation.materialOwner),
    keyBinding: String(materialActivation.keyBinding),
    lifecycleBinding: String(materialActivation.lifecycleBinding),
    signingWorker: String(materialActivation.signingWorker),
  };
}

function scopeToWire(scope: LinkedDeviceEcdsaNormalSigningScopeV1): LinkedDeviceEcdsaScopeWireV1 {
  return { ...scope, materialActivation: materialActivationScopeWire(scope.materialActivation) };
}

async function linkedEcdsaExportDigest(value: unknown) {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

const LINKED_ECDSA_EXPORT_STEP_UP_CHALLENGE_DOMAIN_V1 =
  'seams:linked-device:ecdsa-export-step-up:v1';

async function linkedEcdsaExportStepUpChallenge(input: {
  readonly scope: LinkedDeviceEcdsaNormalSigningScopeV1;
  readonly requestId: string;
  readonly operationId: string;
  readonly digests: OperationDigestSet;
  readonly recipientIdentity: string;
  readonly recipientPublicKey: string;
  readonly expiresAtMs: number;
}): Promise<DigestB64u> {
  return await linkedEcdsaExportDigest({
    domain: LINKED_ECDSA_EXPORT_STEP_UP_CHALLENGE_DOMAIN_V1,
    requestId: input.requestId,
    operationId: input.operationId,
    walletId: String(input.scope.walletId),
    laneId: String(input.scope.laneId),
    laneShareEpoch: String(input.scope.laneShareEpoch),
    publicIdentityDigestB64u: String(input.scope.publicIdentityDigestB64u),
    operationDigests: operationDigestsToWire(input.digests),
    recipientIdentity: input.recipientIdentity,
    recipientPublicKey: input.recipientPublicKey,
    expiresAtMs: input.expiresAtMs,
  });
}

export async function exportActiveLinkedDeviceEcdsaArtifactV1(input: {
  readonly relayServerUrl: string;
  readonly material: ActiveLinkedDeviceEcdsaExportMaterial;
  readonly flowId: string;
  readonly authorize: LinkedDeviceEcdsaFreshExportAuthorizationV1;
}): Promise<{
  readonly publicKeyHex: string;
  readonly privateKeyHex: string;
  readonly ethereumAddress: string;
}> {
  const requestId = secureRandomId('linked-ecdsa-export', 24, 'linked ECDSA export request');
  const operationId = `${input.flowId}:${requestId}`;
  const scope = input.material.laneScope;
  if (String(input.material.walletSession.delivery.enrollmentId) !== String(scope.enrollmentId)) {
    throw new Error('linked ECDSA export Wallet Session enrollment does not match its lane');
  }
  const expiresAtMs = Math.min(input.material.walletSession.delivery.expiresAtMs, Date.now() + 60_000);
  const recipient = await input.material.holderMaterial.prepareEcdsaExportRecipientV1({
    handle: input.material.holderHandle,
    operationId,
  });
  const laneDigest = await linkedEcdsaExportDigest({
    walletId: scope.walletId,
    enrollmentId: input.material.walletSession.delivery.enrollmentId,
    laneId: scope.laneId,
    laneShareEpoch: scope.laneShareEpoch,
    materialActivation: scope.materialActivation,
  });
  const intentDigest = await linkedEcdsaExportDigest({
    operation: 'evm.export_key',
    requestId,
    operationId,
    walletId: scope.walletId,
    laneId: scope.laneId,
  });
  const displayDigest = await linkedEcdsaExportDigest({
    operation: 'Export Private Key',
    publicKey: scope.thresholdPublicKey33B64u,
    address: scope.evmAddress,
  });
  const recipientIdentity = recipient.recipientIdentity;
  const recipientPublicKey = recipient.recipientPublicKeyB64u;
  const freshStepUpProof = await input.authorize({
    challengeB64u: await linkedEcdsaExportStepUpChallenge({
      scope,
      requestId,
      operationId,
      digests: { laneDigest, intentDigest, displayDigest },
      recipientIdentity,
      recipientPublicKey,
      expiresAtMs,
    }),
  });
  const envelope = buildLinkedDeviceExecutionEnvelopeV1({
    enrollmentId: input.material.walletSession.delivery.enrollmentId,
    deviceId: input.material.walletSession.delivery.deviceId,
    walletKeyId: scope.walletKeyId,
    laneId: scope.laneId,
    laneShareEpoch: scope.laneShareEpoch,
    materialActivation: scope.materialActivation,
  });
  const payload = await postLinkedJson(
    input.relayServerUrl,
    LINKED_ECDSA_EXPORT_SHARE_PATH,
    {
      kind: 'wallet_session_jwt',
      walletSessionJwt: input.material.walletSession.token.walletSessionJwt,
    },
    {
      scope: scopeToWire(scope),
      linkedDeviceExecution: envelope,
      request_id: requestId,
      operation_id: operationId,
      operation_digests: operationDigestsToWire({ laneDigest, intentDigest, displayDigest }),
      material_activation: routerAbMpcMaterialActivationRefToWire(scope.materialActivation),
      recipient_identity: recipientIdentity,
      recipient_public_key: recipientPublicKey,
      expires_at_ms: expiresAtMs,
      fresh_step_up_proof: freshStepUpProof,
    },
  );
  const response = requireResponseOk(payload, 'linked ECDSA export response');
  const signingWorkerExport = parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1(
    response.signing_worker_export,
  );
  if (alphabetizeStringify(response.binding) !== alphabetizeStringify(signingWorkerExport.binding)) {
    throw new Error('linked ECDSA export response binding does not match its share envelope');
  }
  return await input.material.holderMaterial.finalizeEcdsaExportV1({
    handle: input.material.holderHandle,
    recipientHandleId: recipient.recipientHandleId,
    signingWorkerExport,
    expectedBinding: signingWorkerExport.binding,
    expectedPublicFacts: {
      walletId: String(scope.walletId),
      walletKeyId: String(scope.walletKeyId),
      enrollmentId: String(scope.enrollmentId),
      operationId: String(scope.operationId),
      laneId: String(scope.laneId),
      laneShareEpoch: String(scope.laneShareEpoch),
      targetMaterialActivationId: String(scope.targetMaterialActivationId),
      ecdsaThresholdKeyId: String(scope.targetCapability.ecdsaThresholdKeyId),
      thresholdPublicKey33B64u: String(scope.thresholdPublicKey33B64u),
      evmAddress: String(scope.evmAddress),
      targetHolderPublicCommitment33B64u: String(scope.targetHolderPublicCommitmentB64u),
      targetServerPublicCommitment33B64u: String(scope.targetServerPublicCommitmentB64u),
      publicIdentityDigestB64u: String(scope.publicIdentityDigestB64u),
    },
  });
}

export function buildLinkedDeviceEcdsaScopeV1(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: Extract<
    ActiveLinkedDeviceExecutionChildV1,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >;
}): LinkedDeviceEcdsaNormalSigningScopeV1 {
  const { bundle, child } = input;
  if (
    child.kind !== 'active_linked_device_ecdsa_execution_v1' ||
    child.job.keyFamily !== 'ecdsa_secp256k1' ||
    child.lane.laneKind !== 'linked_device' ||
    child.lane.lifecycle.state !== 'active' ||
    child.job.walletId !== bundle.walletId ||
    String(child.job.enrollmentId) !== String(bundle.enrollmentId) ||
    child.job.target.laneId !== child.laneId ||
    child.job.target.laneShareEpoch !== child.laneShareEpoch ||
    child.job.targetMaterialActivationId !== child.materialActivation.activationId
  ) {
    throw new Error('linked ECDSA execution child is not active for this bundle');
  }
  const receipt = child.protocolCommitReceipt;
  return buildLinkedDeviceEcdsaNormalSigningScopeV1({
    walletId: child.job.walletId,
    walletKeyId: child.job.walletKeyId,
    enrollmentId: child.job.enrollmentId,
    operationId: child.job.operationId,
    laneId: child.job.target.laneId,
    laneShareEpoch: child.job.target.laneShareEpoch,
    revocationEpoch: child.lane.lifecycle.revocationEpoch,
    targetMaterialActivationId: child.job.targetMaterialActivationId,
    materialActivation: child.materialActivation,
    targetCapability: child.job.targetCapability,
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      child.job.thresholdPublicKey33B64u,
    ),
    evmAddress: child.job.evmAddress,
    publicIdentityDigestB64u: parseDigestB64u(receipt.publicIdentityDigestB64u),
    targetHolderPublicCommitmentB64u: parseSecp256k1CompressedPublicKeyB64u(
      receipt.targetHolderPublicCommitmentB64u,
    ),
    targetServerPublicCommitmentB64u: parseSecp256k1CompressedPublicKeyB64u(
      receipt.targetServerPublicCommitmentB64u,
    ),
    holderParticipantId: child.job.targetHolder.participantId,
    signingWorkerParticipantId: child.job.targetSigningWorker.participantId,
    holderParticipantBindingDigestB64u: child.job.targetHolder.participantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u:
      child.job.targetSigningWorker.participantBindingDigestB64u,
    holderRecipientKeyDigestB64u: child.job.targetHolder.hpkePublicKeyDigestB64u,
    serverRecipientKeyDigestB64u: child.job.targetSigningWorker.hpkePublicKeyDigestB64u,
    signingWorkerRecipientKeyId: child.job.targetSigningWorker.recipientKeyId,
    signingWorkerHpkePublicKeyB64u: child.job.targetSigningWorker.hpkePublicKeyB64u,
    transcriptHashB64u: parseDigestB64u(receipt.transcriptHashB64u),
    protocolCommitReceiptDigestB64u: child.protocolCommitReceiptDigestB64u,
  });
}

export function buildLinkedDeviceEcdsaExecutionEnvelopeV1(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
  child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ecdsa_secp256k1' }>,
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

function operationDigestsToWire(
  digests: OperationDigestSet,
): LinkedDeviceEcdsaOperationDigestsWireV1 {
  return {
    lane_digest_b64u: digests.laneDigest,
    intent_digest_b64u: digests.intentDigest,
    display_digest_b64u: digests.displayDigest,
  };
}

function stripLocalPresenceAssertion(
  request: LinkedDeviceEcdsaPresignInitBodyV1,
): LinkedDeviceEcdsaPresignStepBodyV1 {
  const { localPresenceAssertion: _localPresenceAssertion, ...continuation } = request;
  return {
    ...continuation,
    presign_session_id: request.presign_session_id ?? '',
    requested_stage: 'triples',
    outgoing_messages_b64u: [],
  };
}

function requireFixedBytes(value: unknown, length: number, label: string): Uint8Array {
  if (!Array.isArray(value) || value.length !== length) {
    throw new Error(`${label} must contain exactly ${length} bytes`);
  }
  const bytes = value.map((entry) => {
    if (!Number.isInteger(entry) || Number(entry) < 0 || Number(entry) > 255) {
      throw new Error(`${label} contains an invalid byte`);
    }
    return Number(entry);
  });
  return Uint8Array.from(bytes);
}

function requireB64uBytes(value: unknown, length: number, label: string): Uint8Array {
  const decoded = base64UrlDecode(requireText(value, label));
  if (decoded.length !== length) throw new Error(`${label} must decode to ${length} bytes`);
  return decoded;
}

function requireExpiry(value: unknown, label: string): number {
  const expiry = Number(value);
  if (!Number.isSafeInteger(expiry) || expiry <= Date.now()) {
    throw new Error(`${label} is invalid or expired`);
  }
  return expiry;
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireResponseOk(value: unknown, label: string): Record<string, unknown> {
  const record = requireRecord(value, label);
  if (record.ok !== true) {
    throw new Error(requireText(record.message ?? `${label} failed`, `${label}.message`));
  }
  return record;
}

function parseScopeWire(value: unknown, label: string): LinkedDeviceEcdsaScopeWireV1 {
  return scopeToWire(parseLinkedDeviceEcdsaNormalSigningScopeV1(value, label));
}

function parseMessages(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry) => requireText(entry, `${label}[]`));
}

function parsePresignInitProgress(value: unknown): LinkedDeviceEcdsaPresignInitProgressV1 {
  const record = requireResponseOk(value, 'linked ECDSA presign init response');
  const stage = requireText(record.stage, 'stage');
  if (stage !== 'triples' && stage !== 'triples_done' && stage !== 'presign') {
    throw new Error('linked ECDSA presign init response stage is invalid');
  }
  return {
    kind: 'continue',
    presignSessionId: requireText(record.presign_session_id, 'presign_session_id'),
    stage,
    event: 'none',
    outgoingMessagesB64u: parseMessages(record.outgoing_messages_b64u, 'outgoing_messages_b64u'),
    materialExpiresAtMs: requireExpiry(record.material_expires_at_ms, 'material_expires_at_ms'),
  };
}

function parsePresignProgress(value: unknown): LinkedDeviceEcdsaPresignProgressV1 {
  const record = requireResponseOk(value, 'linked ECDSA presign response');
  const presignSessionId = requireText(record.presign_session_id, 'presign_session_id');
  const stage = requireText(record.stage, 'stage');
  const event = requireText(record.event, 'event');
  const outgoingMessagesB64u = parseMessages(
    record.outgoing_messages_b64u,
    'outgoing_messages_b64u',
  );
  if (event === 'presign_done') {
    if (stage !== 'done') throw new Error('completed presign response must use done stage');
    return {
      kind: 'complete',
      presignSessionId,
      stage: 'done',
      event: 'presign_done',
      outgoingMessagesB64u,
      serverPresignatureId: requireText(record.server_presignature_id, 'server_presignature_id'),
      serverBigR33B64u: requireText(record.server_big_r33_b64u, 'server_big_r33_b64u'),
      signingWorkerRerandomizationContribution32B64u: requireText(
        record.signing_worker_rerandomization_contribution32_b64u,
        'signing_worker_rerandomization_contribution32_b64u',
      ),
    };
  }
  if (
    (stage !== 'triples' && stage !== 'triples_done' && stage !== 'presign') ||
    (event !== 'none' && event !== 'triples_done')
  ) {
    throw new Error('linked ECDSA presign response stage/event is invalid');
  }
  return {
    kind: 'continue',
    presignSessionId,
    stage,
    event,
    outgoingMessagesB64u,
  };
}

function parseSigningResponse(value: unknown): LinkedDeviceEcdsaSigningResponseV1 {
  const record = requireRecord(value, 'linked ECDSA signing response');
  const signatureScheme = requireText(record.signature_scheme, 'response.signature_scheme');
  if (signatureScheme !== 'ecdsa_secp256k1_recoverable_v1') {
    throw new Error('response.signature_scheme is invalid');
  }
  return {
    scope: parseScopeWire(record.scope, 'response.scope'),
    request_id: requireText(record.request_id, 'response.request_id'),
    request_digest: {
      bytes: Array.from(
        requireFixedBytes(
          requireRecord(record.request_digest, 'response.request_digest').bytes,
          32,
          'response.request_digest.bytes',
        ),
      ),
    },
    signing_digest: {
      bytes: Array.from(
        requireFixedBytes(
          requireRecord(record.signing_digest, 'response.signing_digest').bytes,
          32,
          'response.signing_digest.bytes',
        ),
      ),
    },
    signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
    signature65_b64u: requireText(record.signature65_b64u, 'response.signature65_b64u'),
  };
}

function authorizationFromWalletSession(
  walletSessionId: string,
): Extract<RouterAbNormalSigningAuthorizationWire, { readonly kind: 'reusable_wallet_session' }> {
  return { kind: 'reusable_wallet_session', wallet_session_id: walletSessionId };
}

function buildPoolIdentity(
  scope: LinkedDeviceEcdsaNormalSigningScopeV1,
  child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: 'ecdsa_secp256k1' }>,
  requestId: string,
) {
  const activationEpoch = parseRootShareEpoch(String(child.laneShareEpoch));
  if (!activationEpoch.ok) throw new Error(activationEpoch.error.message);
  return {
    poolKey: `linked-device-ecdsa:${String(child.job.enrollmentId)}:${String(child.laneId)}:${requestId}`,
    materialActivationId: String(scope.materialActivation.activationId),
    capability: String(scope.materialActivation.capability),
    keyBinding: String(scope.materialActivation.keyBinding),
    walletId: String(scope.walletId),
    signingScopeB64u: base64UrlEncode(new TextEncoder().encode(JSON.stringify(scope))),
    pairRole: 'client' as const,
    keyEpoch: String(child.laneShareEpoch),
    activationEpoch: activationEpoch.value,
    protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
  };
}

function resolveExchangeStage(input: {
  readonly clientStage: 'triples' | 'triples_done' | 'presign' | 'done';
  readonly serverStage: 'triples' | 'triples_done' | 'presign' | 'done';
}): 'triples' | 'presign' {
  if (input.clientStage === 'triples' || input.serverStage === 'triples') return 'triples';
  return 'presign';
}

function zeroize(value: Uint8Array | null): void {
  if (value && value.byteLength > 0) value.fill(0);
}

async function presignatureIdFromBigR(bigR33: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bigR33));
  return `presig-${base64UrlEncode(digest)}`;
}

function sameScope(
  left: LinkedDeviceEcdsaScopeWireV1,
  right: LinkedDeviceEcdsaScopeWireV1,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function assertPresignCompletionMatches(
  request: LinkedDeviceEcdsaPrepareRequestWireV1,
  presignSessionId: string,
  response: LinkedDeviceEcdsaPresignProgressV1,
): void {
  if (
    response.kind !== 'complete' ||
    response.presignSessionId !== presignSessionId ||
    response.serverPresignatureId !== request.client_presignature_id
  ) {
    throw new Error('linked ECDSA presign completion does not match request');
  }
  requireB64uBytes(response.serverBigR33B64u, 33, 'server_big_r33_b64u');
  requireB64uBytes(
    response.signingWorkerRerandomizationContribution32B64u,
    32,
    'signing_worker_rerandomization_contribution32_b64u',
  );
}

function assertPresignInitMatches(
  request: LinkedDeviceEcdsaPresignInitBodyV1,
  response: LinkedDeviceEcdsaPresignInitProgressV1,
  expiresAtMs: number,
): void {
  if (
    response.presignSessionId !== requireText(request.presign_session_id, 'presign_session_id') ||
    response.materialExpiresAtMs > expiresAtMs
  ) {
    throw new Error('linked ECDSA presign init does not match request lifetime');
  }
}

function assertSigningResponseMatches(
  request: LinkedDeviceEcdsaFinalizeRequestWireV1,
  response: LinkedDeviceEcdsaSigningResponseV1,
): void {
  if (
    response.request_id !== request.request_id ||
    !sameScope(response.scope, request.scope) ||
    base64UrlEncode(Uint8Array.from(response.signing_digest.bytes)) !== request.signing_digest_b64u
  ) {
    throw new Error('linked ECDSA signing response does not match request');
  }
  requireB64uBytes(response.signature65_b64u, 65, 'signature65_b64u');
}

async function postLinkedJson(
  relayServerUrl: string,
  path: string,
  credential: RouterAbEd25519NormalSigningCredential,
  body: unknown,
): Promise<unknown> {
  const baseUrl = requireText(relayServerUrl, 'relayServerUrl').replace(/\/+$/g, '');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (credential.kind === 'wallet_session_jwt') {
    headers.Authorization = `Bearer ${requireText(credential.walletSessionJwt, 'walletSessionJwt')}`;
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    credentials: 'omit',
    headers,
    body: JSON.stringify(body),
  });
  const payload: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const record =
      payload && typeof payload === 'object' && !Array.isArray(payload)
        ? (payload as Record<string, unknown>)
        : undefined;
    const code = typeof record?.code === 'string' ? record.code : 'linked_request_failed';
    const message =
      typeof record?.message === 'string'
        ? record.message
        : `linked ECDSA request failed (${response.status})`;
    throw new LinkedDeviceEcdsaHttpError({
      status: response.status,
      code,
      message: `${code}: ${message}`,
    });
  }
  return payload;
}

const defaultTransport: LinkedDeviceEcdsaNormalSigningTransportV1 = {
  presignInit: async ({ relayServerUrl, credential, request }) =>
    parsePresignInitProgress(
      await postLinkedJson(relayServerUrl, LINKED_ECDSA_PRESIGN_INIT_PATH, credential, request),
    ),
  presignStep: async ({ relayServerUrl, credential, request }) =>
    parsePresignProgress(
      await postLinkedJson(relayServerUrl, LINKED_ECDSA_PRESIGN_STEP_PATH, credential, request),
    ),
  finalize: async ({ relayServerUrl, credential, request }) =>
    parseSigningResponse(
      await postLinkedJson(relayServerUrl, LINKED_ECDSA_FINALIZE_PATH, credential, request),
    ),
};

export function buildLinkedDeviceEcdsaPresignInitRequestV1(input: {
  readonly scope: LinkedDeviceEcdsaScopeWireV1;
  readonly requestId: string;
  readonly operationId: string;
  readonly operationDigests: OperationDigestSet;
  readonly authorization: Extract<
    RouterAbNormalSigningAuthorizationWire,
    { readonly kind: 'reusable_wallet_session' }
  >;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly clientPresignatureId: string;
  readonly expiresAtMs: number;
  readonly signingDigest32: Uint8Array;
  readonly clientRerandomizationCommitment32: Uint8Array;
  readonly linkedDeviceExecution: LinkedDeviceExecutionEnvelopeV1;
  readonly localPresenceAssertion?: LinkedDeviceLocalPresenceAssertionV1;
  readonly presignSessionId?: string;
}): LinkedDeviceEcdsaPresignInitBodyV1 {
  return {
    scope: input.scope,
    request_id: input.requestId,
    lane_operation_id: input.scope.operationId,
    operation_id: input.operationId,
    operation_digests: operationDigestsToWire(input.operationDigests),
    authorization: input.authorization,
    material_activation: input.materialActivation,
    client_presignature_id: input.clientPresignatureId,
    expires_at_ms: input.expiresAtMs,
    signing_digest_b64u: base64UrlEncode(input.signingDigest32),
    client_rerandomization_commitment32_b64u: base64UrlEncode(
      input.clientRerandomizationCommitment32,
    ),
    linkedDeviceExecution: input.linkedDeviceExecution,
    ...(input.localPresenceAssertion
      ? { localPresenceAssertion: input.localPresenceAssertion }
      : {}),
    ...(input.presignSessionId ? { presign_session_id: input.presignSessionId } : {}),
  };
}

export async function executeLinkedDeviceEcdsaNormalSigningV1(
  input: LinkedDeviceEcdsaNormalSigningInputV1,
): Promise<LinkedDeviceEcdsaNormalSigningResultV1> {
  const requestId = requireRequestId(input.request.requestId);
  const operationId = requireText(input.request.operationId, 'linked ECDSA operationId');
  const expiresAtMs = requireExpiry(input.request.expiresAtMs, 'linked ECDSA request expiry');
  if (expiresAtMs > input.bundle.expiresAtMs || input.issuedAtMs >= expiresAtMs) {
    throw new Error('linked ECDSA request lifetime is outside the Wallet Session');
  }
  if (input.request.signingDigest32.length !== 32) {
    throw new Error('linked ECDSA signing digest must contain exactly 32 bytes');
  }
  const signingDigestB64u = base64UrlEncode(input.request.signingDigest32);
  if (input.request.operationDigests.intentDigest !== signingDigestB64u) {
    throw new Error('linked ECDSA intent digest must match signing digest');
  }
  if (
    input.walletSession.delivery.walletId !== input.bundle.walletId ||
    input.walletSession.delivery.enrollmentId !== input.bundle.enrollmentId ||
    input.walletSession.delivery.deviceId !== input.bundle.deviceId ||
    input.walletSession.delivery.walletSessionId !== input.bundle.walletSessionId ||
    input.walletSession.token.walletKeyId !== input.child.walletKeyId ||
    input.walletSession.token.keyFamily !== 'ecdsa_secp256k1' ||
    input.walletSession.token.revocationEpoch !== input.child.lane.lifecycle.revocationEpoch
  ) {
    throw new Error('linked ECDSA Wallet Session token does not match execution bundle');
  }

  const scope = buildLinkedDeviceEcdsaScopeV1({ bundle: input.bundle, child: input.child });
  const scopeWire = scopeToWire(scope);
  const envelope = buildLinkedDeviceEcdsaExecutionEnvelopeV1(input.bundle, input.child);
  const authorizedOperationId = requireAuthorizedOperationId(requestId);
  const contribution32 = globalThis.crypto?.getRandomValues
    ? globalThis.crypto.getRandomValues(new Uint8Array(32))
    : (() => {
        throw new Error('WebCrypto getRandomValues is required for linked ECDSA signing');
      })();
  const commitment32 = await routerAbEcdsaRerandomizationClientCommitmentV1(contribution32);
  const clientPresignatureId = secureRandomId(
    'linked-ecdsa-presignature',
    32,
    'linked ECDSA client presignature id',
  );
  const presignSessionId = secureRandomId(
    'linked-ecdsa-presign-session',
    32,
    'linked ECDSA presign session id',
  );
  const authorization = authorizationFromWalletSession(String(input.bundle.walletSessionId));
  const materialActivation = routerAbMpcMaterialActivationRefToWire(input.child.materialActivation);
  const credential: RouterAbEd25519NormalSigningCredential = {
    kind: 'wallet_session_jwt',
    walletSessionJwt: input.walletSession.token.walletSessionJwt,
  };
  const transport = input.transport ?? defaultTransport;
  let coreRequest = buildLinkedDeviceEcdsaPresignInitRequestV1({
    scope: scopeWire,
    requestId,
    operationId,
    operationDigests: input.request.operationDigests,
    authorization,
    materialActivation,
    clientPresignatureId,
    expiresAtMs,
    signingDigest32: input.request.signingDigest32,
    clientRerandomizationCommitment32: commitment32,
    linkedDeviceExecution: envelope,
    presignSessionId,
  });
  let initialProgress: LinkedDeviceEcdsaPresignInitProgressV1;
  try {
    initialProgress = await transport.presignInit({
      relayServerUrl: input.relayServerUrl,
      credential,
      request: coreRequest,
    });
  } catch (error) {
    if (!isLinkedDeviceStepUpRequired(error)) throw error;
    const localPresenceAssertion = await collectLinkedDeviceLocalPresenceV1({
      authenticator: input.authenticator,
      bundle: input.bundle,
      child: input.child,
      authorizedOperationId,
      intentDigestB64u: input.request.operationDigests.intentDigest,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs,
    });
    coreRequest = buildLinkedDeviceEcdsaPresignInitRequestV1({
      scope: scopeWire,
      requestId,
      operationId,
      operationDigests: input.request.operationDigests,
      authorization,
      materialActivation,
      clientPresignatureId,
      expiresAtMs,
      signingDigest32: input.request.signingDigest32,
      clientRerandomizationCommitment32: commitment32,
      linkedDeviceExecution: envelope,
      localPresenceAssertion,
      presignSessionId,
    });
    initialProgress = await transport.presignInit({
      relayServerUrl: input.relayServerUrl,
      credential,
      request: coreRequest,
    });
  }
  assertPresignInitMatches(coreRequest, initialProgress, expiresAtMs);
  const source = new LinkedDeviceEcdsaSigningMaterialSourceV1({
    handle: input.holderHandle,
  });
  const continuationCoreRequest = stripLocalPresenceAssertion(coreRequest);
  const poolIdentity = buildPoolIdentity(scope, input.child, requestId);
  let sessionId: string | null = null;
  let localHandle: string | null = null;
  let localBigR33: Uint8Array | null = null;
  let serverProgress: LinkedDeviceEcdsaPresignProgressV1 = initialProgress;
  let serverPresignatureId: string | null = null;
  let serverBigR33B64u: string | null = null;
  let serverRerandomization32: Uint8Array | null = null;
  let reservationId: string | null = null;
  let committed = false;
  try {
    sessionId = serverProgress.presignSessionId;
    const localInit = await source.initClientPresignSession({
      sessionId,
      groupPublicKey33: base64UrlDecode(String(input.child.job.thresholdPublicKey33B64u)),
      materialExpiresAtMs: Math.min(expiresAtMs, input.bundle.expiresAtMs),
      poolIdentity,
      workerCtx: input.workerCtx,
    });
    let clientStage = localInit.stage;
    let serverStage = serverProgress.stage;
    let pendingClientOutgoing = [...localInit.outgoingMessages];
    let pendingServerOutgoing = serverProgress.outgoingMessagesB64u.map(base64UrlDecode);
    if (localInit.presignatureHandle && localInit.presignatureBigR33) {
      localHandle = localInit.presignatureHandle;
      localBigR33 = localInit.presignatureBigR33;
    }
    for (let step = 0; step < MAX_PRESIGN_STEPS; step += 1) {
      if (pendingServerOutgoing.length > 0 && !localHandle) {
        const localStep = await source.stepClientPresignSession({
          sessionId,
          stage: resolveExchangeStage({ clientStage, serverStage }),
          incomingMessages: pendingServerOutgoing,
          workerCtx: input.workerCtx,
        });
        clientStage = localStep.stage;
        pendingServerOutgoing = [];
        pendingClientOutgoing.push(...localStep.outgoingMessages);
        if (localStep.presignatureHandle && localStep.presignatureBigR33) {
          localHandle = localStep.presignatureHandle;
          localBigR33 = localStep.presignatureBigR33;
        }
      }
      if (serverProgress.kind !== 'complete') {
        serverProgress = await transport.presignStep({
          relayServerUrl: input.relayServerUrl,
          credential,
          request: {
            ...continuationCoreRequest,
            presign_session_id: sessionId,
            requested_stage: resolveExchangeStage({ clientStage, serverStage }),
            outgoing_messages_b64u: pendingClientOutgoing.map(base64UrlEncode),
          },
        });
        pendingClientOutgoing = [];
        pendingServerOutgoing = serverProgress.outgoingMessagesB64u.map(base64UrlDecode);
        if (serverProgress.kind === 'complete') {
          serverPresignatureId = serverProgress.serverPresignatureId;
          serverBigR33B64u = serverProgress.serverBigR33B64u;
          serverRerandomization32 = requireB64uBytes(
            serverProgress.signingWorkerRerandomizationContribution32B64u,
            32,
            'signing worker rerandomization contribution',
          );
        } else {
          serverStage = serverProgress.stage;
        }
      }
      if (localHandle && localBigR33 && serverProgress.kind === 'complete') break;
      if (!pendingServerOutgoing.length && !pendingClientOutgoing.length && !localHandle) {
        const localStep = await source.stepClientPresignSession({
          sessionId,
          stage: resolveExchangeStage({ clientStage, serverStage }),
          incomingMessages: [],
          workerCtx: input.workerCtx,
        });
        clientStage = localStep.stage;
        pendingClientOutgoing.push(...localStep.outgoingMessages);
        if (localStep.presignatureHandle && localStep.presignatureBigR33) {
          localHandle = localStep.presignatureHandle;
          localBigR33 = localStep.presignatureBigR33;
        }
      }
    }
    if (
      !localHandle ||
      !localBigR33 ||
      !serverPresignatureId ||
      !serverBigR33B64u ||
      !serverRerandomization32
    ) {
      throw new Error('linked ECDSA presign session did not complete');
    }
    if (base64UrlEncode(localBigR33) !== serverBigR33B64u) {
      throw new Error('linked ECDSA client/server presignature mismatch');
    }
    assertPresignCompletionMatches(coreRequest, sessionId, serverProgress);
    const localPresignatureId = await presignatureIdFromBigR(localBigR33);
    await source.admitClientPresignature({
      materialHandle: localHandle,
      expectedPresignatureId: localPresignatureId,
      poolIdentity,
      workerCtx: input.workerCtx,
    });
    reservationId = secureRandomId('linked-ecdsa-reservation', 32, 'linked ECDSA reservation id');
    await source.reserveClientPresignature({
      materialHandle: localHandle,
      poolIdentity,
      requestBinding: requestId,
      reservationId,
      leaseExpiresAtMs: expiresAtMs,
      workerCtx: input.workerCtx,
    });
    await source.commitClientPresignature({
      materialHandle: localHandle,
      poolIdentity,
      requestBinding: requestId,
      reservationId,
      workerCtx: input.workerCtx,
    });
    committed = true;
    const clientSignatureShare32 = await source.computeSignatureShareFromPresignatureHandle({
      materialHandle: localHandle,
      poolIdentity,
      requestBinding: requestId,
      reservationId,
      groupPublicKey33: base64UrlDecode(String(input.child.job.thresholdPublicKey33B64u)),
      expectedPresignBigR33: localBigR33,
      digest32: input.request.signingDigest32,
      clientRerandomizationContribution32: contribution32,
      signingWorkerRerandomizationContribution32: serverRerandomization32,
      workerCtx: input.workerCtx,
    });
    if (clientSignatureShare32.length !== 32) {
      throw new Error('linked ECDSA client signature share must contain exactly 32 bytes');
    }
    const finalizeRequest: LinkedDeviceEcdsaFinalizeRequestWireV1 &
      LinkedDeviceEcdsaContinuationBoundaryV1 = {
      scope: scopeWire,
      request_id: requestId,
      operation_id: operationId,
      operation_digests: operationDigestsToWire(input.request.operationDigests),
      authorization,
      material_activation: materialActivation,
      expires_at_ms: expiresAtMs,
      signing_digest_b64u: signingDigestB64u,
      server_presignature_id: serverPresignatureId,
      client_signature_share32_b64u: base64UrlEncode(clientSignatureShare32),
      client_rerandomization_contribution32_b64u: base64UrlEncode(contribution32),
      linkedDeviceExecution: envelope,
    };
    const signingResponse = await transport.finalize({
      relayServerUrl: input.relayServerUrl,
      credential,
      request: finalizeRequest,
    });
    assertSigningResponseMatches(finalizeRequest, signingResponse);
    const signature65 = requireB64uBytes(signingResponse.signature65_b64u, 65, 'signature65_b64u');
    await verifySecp256k1RecoverableSignatureAgainstPublicKey33Wasm({
      digest32: input.request.signingDigest32,
      signature65,
      publicKey33: base64UrlDecode(String(input.child.job.thresholdPublicKey33B64u)),
      workerCtx: input.workerCtx,
    });
    return {
      kind: 'linked_device_ecdsa_normal_signing_result_v1',
      operationId,
      signature65,
      signature65B64u: signingResponse.signature65_b64u,
    };
  } finally {
    zeroize(contribution32);
    zeroize(commitment32);
    zeroize(serverRerandomization32);
    zeroize(localBigR33);
    if (sessionId && !committed) {
      await source
        .abortClientPresignSession({ sessionId, workerCtx: input.workerCtx })
        .catch(() => {});
    }
    await source.cleanupAfterSign();
  }
}
