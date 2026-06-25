import { validateThresholdEd25519WorkerMaterialNearSignerWasm } from '@/core/signingEngine/chains/near/nearSignerWasm';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import type {
  ThresholdEd25519WorkerMaterialBinding,
  ThresholdEd25519WorkerMaterialSessionBinding,
  ThresholdEd25519ValidateWorkerMaterialResult,
  ThresholdEd25519WorkerMaterialResult,
} from '@/core/types/signer-worker';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519RelayerKeyId,
  parseEd25519WorkerMaterialBindingDigest,
  parseEd25519WorkerMaterialHandle,
  type Ed25519ClientVerifyingShareB64u,
  type Ed25519WorkerMaterialBindingDigest,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildRouterAbEd25519WorkerMaterialBinding,
  buildRouterAbEd25519WorkerMaterialSessionBinding,
  buildRouterAbEd25519SigningMaterialRef,
  type Ed25519WorkerMaterialHandle,
  type RouterAbEd25519SigningMaterialRef,
} from './workerMaterialBinding';

export type { Ed25519WorkerMaterialHandle } from './workerMaterialBinding';

export type RouterAbEd25519RuntimeValidatedMaterial = {
  kind: 'router_ab_ed25519_runtime_validated_material_v1';
  materialRef: RouterAbEd25519SigningMaterialRef;
  materialBinding: ThresholdEd25519WorkerMaterialBinding;
  sessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  xClientBaseB64u?: never;
};

export function ed25519RuntimeMaterialHandle(
  material: RouterAbEd25519RuntimeValidatedMaterial,
): Ed25519WorkerMaterialHandle {
  return material.materialRef.materialHandle;
}

export function ed25519RuntimeMaterialBindingDigest(
  material: RouterAbEd25519RuntimeValidatedMaterial,
): Ed25519WorkerMaterialBindingDigest {
  return material.materialRef.bindingDigest;
}

export function ed25519RuntimeMaterialClientVerifierB64u(
  material: RouterAbEd25519RuntimeValidatedMaterial,
): Ed25519ClientVerifyingShareB64u {
  return material.materialRef.clientVerifierB64u;
}

export async function requireThresholdEd25519WorkerMaterialHandle(args: {
  ctx: WorkerOperationContext;
  thresholdSessionId: string;
  signingGrantId: string;
  existingMaterialHandle: Ed25519WorkerMaterialHandle;
  existingMaterialBindingDigest: Ed25519WorkerMaterialBindingDigest;
  existingMaterialClientVerifierB64u: Ed25519ClientVerifyingShareB64u;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  relayerKeyId: string;
  nearAccountId: string;
  participantIds: number[];
  signingWorkerId: string;
  materialCreatedAtMs?: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
}): Promise<RouterAbEd25519RuntimeValidatedMaterial> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const signingRootId = String(args.signingRootId || '').trim();
  const signingRootVersion = String(args.signingRootVersion || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayerKeyId = parseEd25519RelayerKeyId(args.relayerKeyId);
  const signingWorkerId = String(args.signingWorkerId || '').trim();
  const keyMaterial = args.thresholdKeyMaterial;
  const materialCreatedAtMs = Math.floor(
    Number(args.materialCreatedAtMs ?? keyMaterial.timestamp),
  );
  const existingMaterialHandle = parseEd25519WorkerMaterialHandle(args.existingMaterialHandle);
  const existingMaterialBindingDigest = parseEd25519WorkerMaterialBindingDigest(
    args.existingMaterialBindingDigest,
  );
  const existingMaterialClientVerifierB64u = parseEd25519ClientVerifyingShareB64u(
    args.existingMaterialClientVerifierB64u,
  );
  if (
    String(keyMaterial.nearAccountId) !== nearAccountId ||
    keyMaterial.relayerKeyId !== relayerKeyId
  ) {
    throw new Error('Router A/B Ed25519 signing material threshold key identity mismatch');
  }
  if (!thresholdSessionId || !signingGrantId || !signingRootId || !signingRootVersion) {
    throw new Error('Router A/B Ed25519 signing material is missing session or signing-root scope');
  }
  if (!nearAccountId || !relayerKeyId || !signingWorkerId) {
    throw new Error('Router A/B Ed25519 signing material is missing account or worker scope');
  }
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('Router A/B Ed25519 signing material is expired');
  }
  if (
    !existingMaterialHandle ||
    !existingMaterialBindingDigest ||
    !existingMaterialClientVerifierB64u
  ) {
    throw new Error('Router A/B Ed25519 signing material handle is missing');
  }

  const material = await buildRouterAbEd25519WorkerMaterialBinding({
    nearAccountId,
    signerSlot: keyMaterial.signerSlot,
    signingRootId,
    signingRootVersion,
    relayerKeyId,
    participantIds: args.participantIds,
    clientVerifyingShareB64u: existingMaterialClientVerifierB64u,
    createdAtMs: materialCreatedAtMs,
  });
  if (material.materialBindingDigest !== existingMaterialBindingDigest) {
    throw new Error('Router A/B Ed25519 signing material binding digest mismatch');
  }
  const sessionBinding = buildRouterAbEd25519WorkerMaterialSessionBinding({
    materialBindingDigest: material.materialBindingDigest,
    nearAccountId,
    signerSlot: keyMaterial.signerSlot,
    thresholdSessionId,
    signingGrantId,
    signingRootId,
    signingRootVersion,
    runtimePolicyScope: args.runtimePolicyScope,
    relayerKeyId,
    participantIds: args.participantIds,
    signingWorkerId,
    expiresAtMs,
  });
  const workerMaterialResult = await validateThresholdEd25519WorkerMaterialNearSignerWasm({
    workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
    materialHandle: existingMaterialHandle,
    expectedMaterialBinding: material.materialBinding,
  });
  const workerMaterial = requireValidatedThresholdEd25519WorkerMaterial(workerMaterialResult);
  if (
    workerMaterial.materialHandle !== existingMaterialHandle ||
    workerMaterial.bindingDigest !== existingMaterialBindingDigest ||
    workerMaterial.clientVerifyingShareB64u !== existingMaterialClientVerifierB64u
  ) {
    throw new Error('Router A/B Ed25519 signing material handle binding mismatch');
  }
  const signingMaterialRef = buildRouterAbEd25519SigningMaterialRef({
    materialHandle: workerMaterial.materialHandle,
    bindingDigest: workerMaterial.bindingDigest,
    clientVerifyingShareB64u: workerMaterial.clientVerifyingShareB64u,
  });
  return {
    kind: 'router_ab_ed25519_runtime_validated_material_v1',
    materialRef: signingMaterialRef,
    materialBinding: material.materialBinding,
    sessionBinding,
  };
}

function requireValidatedThresholdEd25519WorkerMaterial(
  result: ThresholdEd25519ValidateWorkerMaterialResult,
): ThresholdEd25519WorkerMaterialResult {
  if ('ok' in result) {
    throw new Error(
      `Router A/B Ed25519 signing material validation failed: ${result.code}: ${result.message}`,
    );
  }
  return result;
}
