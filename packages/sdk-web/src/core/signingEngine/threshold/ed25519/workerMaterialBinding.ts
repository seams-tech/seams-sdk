import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import type {
  ThresholdEd25519WorkerMaterialBinding,
  ThresholdEd25519WorkerMaterialSessionBinding,
} from '@/core/types/signer-worker';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  formatEd25519HssKeyVersionForWire,
  parseEd25519HssKeyVersion,
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519RelayerKeyId,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialHandle,
  type Ed25519ClientVerifyingShareB64u,
  type Ed25519HssKeyVersion,
  type Ed25519RelayerKeyId,
  type Ed25519SealedWorkerMaterialRef,
  type Ed25519WorkerMaterialBindingDigest,
  type Ed25519WorkerMaterialHandle,
  type Ed25519WorkerMaterialKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';

export type {
  Ed25519ClientVerifyingShareB64u,
  Ed25519RelayerKeyId,
  Ed25519SealedWorkerMaterialRef,
  Ed25519WorkerMaterialBindingDigest,
  Ed25519WorkerMaterialHandle,
  Ed25519WorkerMaterialKeyId,
};

export type RouterAbEd25519WorkerMaterialBindingInput = {
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: Ed25519RelayerKeyId;
  ed25519HssKeyVersion: Ed25519HssKeyVersion;
  participantIds: number[];
  clientVerifyingShareB64u: Ed25519ClientVerifyingShareB64u;
  createdAtMs: number;
};

export type RouterAbEd25519WorkerMaterialSessionBindingInput = {
  materialBindingDigest: Ed25519WorkerMaterialBindingDigest;
  nearAccountId: string;
  signerSlot: number;
  thresholdSessionId: string;
  signingGrantId: string;
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerKeyId: Ed25519RelayerKeyId;
  ed25519HssKeyVersion: Ed25519HssKeyVersion;
  participantIds: number[];
  signingWorkerId: string;
  expiresAtMs: number;
};

export type RouterAbEd25519SigningMaterialRef = {
  kind: 'router_ab_ed25519_worker_material_ref_v1';
  materialHandle: Ed25519WorkerMaterialHandle;
  bindingDigest: Ed25519WorkerMaterialBindingDigest;
  clientVerifierB64u: Ed25519ClientVerifyingShareB64u;
};

export function buildRouterAbEd25519SigningMaterialRef(input: {
  materialHandle: string;
  bindingDigest: string;
  clientVerifyingShareB64u: string;
}): RouterAbEd25519SigningMaterialRef {
  const materialHandle = String(input.materialHandle || '').trim();
  const bindingDigest = String(input.bindingDigest || '').trim();
  const clientVerifierB64u = String(input.clientVerifyingShareB64u || '').trim();
  if (!materialHandle || !bindingDigest || !clientVerifierB64u) {
    throw new Error('Router A/B Ed25519 signing material ref is missing binding input');
  }
  return {
    kind: 'router_ab_ed25519_worker_material_ref_v1',
    materialHandle: parseEd25519WorkerMaterialHandle(materialHandle),
    bindingDigest: parseEd25519WorkerMaterialBindingDigest(bindingDigest),
    clientVerifierB64u: parseEd25519ClientVerifyingShareB64u(clientVerifierB64u),
  };
}

async function digestCanonicalJsonB64u(input: unknown): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(alphabetizeStringify(input)),
  );
}

function requireMaterialBindingString(value: unknown, fieldName: string): string {
  const parsed = String(value || '').trim();
  if (!parsed) {
    throw new Error(`Router A/B Ed25519 worker material binding missing ${fieldName}`);
  }
  return parsed;
}

function requireMaterialBindingPositiveInteger(value: unknown, fieldName: string): number {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`Router A/B Ed25519 worker material binding invalid ${fieldName}`);
  }
  return parsed;
}

function requireMaterialBindingParticipantIds(values: readonly number[]): number[] {
  const participantIds = values.map((value) => Math.floor(Number(value)));
  if (
    participantIds.length === 0 ||
    participantIds.some((value) => !Number.isSafeInteger(value) || value < 1)
  ) {
    throw new Error('Router A/B Ed25519 worker material binding invalid participantIds');
  }
  return participantIds;
}

function buildEd25519WorkerMaterialKeyIdentity(input: {
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: Ed25519RelayerKeyId;
  ed25519HssKeyVersion: Ed25519HssKeyVersion;
}): Record<string, unknown> {
  const keyVersion = formatEd25519HssKeyVersionForWire(input.ed25519HssKeyVersion);
  return {
    kind: 'ed25519_worker_material_key_identity_v1',
    nearAccountId: input.nearAccountId,
    signerSlot: input.signerSlot,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    relayerKeyId: input.relayerKeyId,
    keyVersion,
    materialFormatVersion: 'ed25519_worker_material_v1',
  };
}

export async function buildRouterAbEd25519WorkerMaterialBinding(input: RouterAbEd25519WorkerMaterialBindingInput): Promise<{
  materialBinding: ThresholdEd25519WorkerMaterialBinding;
  materialBindingDigest: Ed25519WorkerMaterialBindingDigest;
}> {
  const nearAccountId = requireMaterialBindingString(input.nearAccountId, 'nearAccountId');
  const signerSlot = requireMaterialBindingPositiveInteger(input.signerSlot, 'signerSlot');
  const signingRootId = requireMaterialBindingString(input.signingRootId, 'signingRootId');
  const signingRootVersion = requireMaterialBindingString(
    input.signingRootVersion,
    'signingRootVersion',
  );
  const relayerKeyId = parseEd25519RelayerKeyId(
    requireMaterialBindingString(input.relayerKeyId, 'relayerKeyId'),
  );
  const ed25519HssKeyVersion = parseEd25519HssKeyVersion(input.ed25519HssKeyVersion);
  const keyVersion = formatEd25519HssKeyVersionForWire(ed25519HssKeyVersion);
  const clientVerifyingShareB64u = parseEd25519ClientVerifyingShareB64u(
    requireMaterialBindingString(input.clientVerifyingShareB64u, 'clientVerifyingShareB64u'),
  );
  const participantIds = requireMaterialBindingParticipantIds(input.participantIds);
  const createdAtMs = requireMaterialBindingPositiveInteger(input.createdAtMs, 'createdAtMs');
  const materialKeyId = await digestCanonicalJsonB64u(
    buildEd25519WorkerMaterialKeyIdentity({
      nearAccountId,
      signerSlot,
      signingRootId,
      signingRootVersion,
      relayerKeyId,
      ed25519HssKeyVersion,
    }),
  );
  const materialBinding: ThresholdEd25519WorkerMaterialBinding = {
    kind: 'ed25519_worker_material_binding_v1',
    curve: 'ed25519',
    protocol: 'router_ab_normal_signing',
    nearAccountId,
    signerSlot,
    signingRootId,
    signingRootVersion,
    relayerKeyId,
    keyVersion,
    participantIds,
    clientVerifyingShareB64u,
    materialFormatVersion: 'ed25519_worker_material_v1',
    materialKeyId,
    createdAtMs,
  };
  return {
    materialBinding,
    materialBindingDigest: parseEd25519WorkerMaterialBindingDigest(
      await digestCanonicalJsonB64u(materialBinding),
    ),
  };
}

export function buildRouterAbEd25519WorkerMaterialSessionBinding(
  input: RouterAbEd25519WorkerMaterialSessionBindingInput,
): ThresholdEd25519WorkerMaterialSessionBinding {
  return {
    kind: 'ed25519_worker_material_session_binding_v1',
    materialBindingDigest: requireMaterialBindingString(
      input.materialBindingDigest,
      'materialBindingDigest',
    ),
    nearAccountId: requireMaterialBindingString(input.nearAccountId, 'nearAccountId'),
    signerSlot: requireMaterialBindingPositiveInteger(input.signerSlot, 'signerSlot'),
    thresholdSessionId: requireMaterialBindingString(
      input.thresholdSessionId,
      'thresholdSessionId',
    ),
    signingGrantId: requireMaterialBindingString(input.signingGrantId, 'signingGrantId'),
    signingRootId: requireMaterialBindingString(input.signingRootId, 'signingRootId'),
    signingRootVersion: requireMaterialBindingString(
      input.signingRootVersion,
      'signingRootVersion',
    ),
    runtimePolicyScope: input.runtimePolicyScope,
    relayerKeyId: parseEd25519RelayerKeyId(
      requireMaterialBindingString(input.relayerKeyId, 'relayerKeyId'),
    ),
    keyVersion: formatEd25519HssKeyVersionForWire(
      parseEd25519HssKeyVersion(input.ed25519HssKeyVersion),
    ),
    participantIds: requireMaterialBindingParticipantIds(input.participantIds),
    signingWorkerId: requireMaterialBindingString(input.signingWorkerId, 'signingWorkerId'),
    expiresAtMs: requireMaterialBindingPositiveInteger(input.expiresAtMs, 'expiresAtMs'),
  };
}

export async function digestRouterAbEd25519WorkerMaterialSessionBinding(
  input: ThresholdEd25519WorkerMaterialSessionBinding,
): Promise<string> {
  return digestCanonicalJsonB64u(input);
}
