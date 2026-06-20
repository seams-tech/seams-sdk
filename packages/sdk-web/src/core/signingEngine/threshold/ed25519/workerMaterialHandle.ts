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
  buildRouterAbEd25519WorkerMaterialBinding,
  buildRouterAbEd25519WorkerMaterialSessionBinding,
  buildRouterAbEd25519SigningMaterialRef,
  type Ed25519WorkerMaterialHandle,
} from './hssMaterialBinding';

export type { Ed25519WorkerMaterialHandle } from './hssMaterialBinding';

export type RouterAbEd25519SigningMaterialReady = {
  kind: 'router_ab_ed25519_signing_material_ready_v1';
  materialHandle: Ed25519WorkerMaterialHandle;
  bindingDigest: string;
  thresholdSessionId: string;
  signingGrantId: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  nearAccountId: string;
  relayerKeyId: string;
  participantIds: number[];
  signingWorkerId: string;
  clientVerifyingShareB64u: string;
  materialBinding: ThresholdEd25519WorkerMaterialBinding;
  sessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  xClientBaseB64u?: never;
};

export async function requireThresholdEd25519WorkerMaterialHandle(args: {
  ctx: WorkerOperationContext;
  thresholdSessionId: string;
  signingGrantId: string;
  existingMaterialHandle: string;
  existingMaterialBindingDigest: string;
  existingMaterialClientVerifierB64u: string;
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
}): Promise<RouterAbEd25519SigningMaterialReady> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const signingRootId = String(args.signingRootId || '').trim();
  const signingRootVersion = String(args.signingRootVersion || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const signingWorkerId = String(args.signingWorkerId || '').trim();
  const keyMaterial = args.thresholdKeyMaterial;
  const materialCreatedAtMs = Math.floor(
    Number(args.materialCreatedAtMs ?? keyMaterial.timestamp),
  );
  const existingMaterialHandle = String(args.existingMaterialHandle || '').trim();
  const existingMaterialBindingDigest = String(args.existingMaterialBindingDigest || '').trim();
  const existingMaterialClientVerifierB64u = String(
    args.existingMaterialClientVerifierB64u || '',
  ).trim();
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
    keyVersion: keyMaterial.keyVersion,
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
    keyVersion: keyMaterial.keyVersion,
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
    kind: 'router_ab_ed25519_signing_material_ready_v1',
    materialHandle: signingMaterialRef.materialHandle,
    bindingDigest: signingMaterialRef.bindingDigest,
    thresholdSessionId,
    signingGrantId,
    signingRootId,
    signingRootVersion,
    expiresAtMs,
    nearAccountId,
    relayerKeyId,
    participantIds: args.participantIds.map((id) => Number(id)),
    signingWorkerId,
    clientVerifyingShareB64u: signingMaterialRef.clientVerifierB64u,
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
