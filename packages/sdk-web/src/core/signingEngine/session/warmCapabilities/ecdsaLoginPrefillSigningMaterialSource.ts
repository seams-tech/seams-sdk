import {
  requirePersistedEcdsaRoleLocalMaterial,
  type ThresholdEcdsaSessionRecord,
} from '../persistence/records';
import {
  thresholdEcdsaRoleLocalAdmitPresignatureWasm,
  thresholdEcdsaRoleLocalDestroyPresignatureWasm,
  thresholdEcdsaRoleLocalReservePresignatureWasm,
  thresholdEcdsaRoleLocalCommitPresignatureWasm,
  thresholdEcdsaRoleLocalListAvailablePresignaturesWasm,
  thresholdEcdsaRoleLocalRetirePresignaturePoolWasm,
  thresholdEcdsaEmailOtpPresignSessionInitWasm,
  thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionAbortWasm,
  thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionStepWasm,
} from '../../threshold/crypto/ecdsaDerivationClientWasm';
import type { RouterAbEcdsaDerivationClientSigningMaterialSource } from '../../routerAb/ecdsaDerivation/presignaturePool';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from '../routerAbSigningWalletSession';
import type { EcdsaRoleLocalWorkerHandle } from '../keyMaterialBrands';
import {
  ecdsaRoleLocalPersistedMaterialRefSource,
  resolveEcdsaRoleLocalMaterial,
  type EcdsaRoleLocalMaterialResolution,
} from '../material/ecdsaRoleLocalMaterialResolver';

function isEmailOtpWorkerRecord(record: ThresholdEcdsaSessionRecord): boolean {
  return record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session';
}

function requireEmailOtpWorkerSessionId(record: ThresholdEcdsaSessionRecord): string {
  const handle = record.clientAdditiveShareHandle;
  if (handle?.kind !== 'email_otp_worker_session') {
    throw new Error('ECDSA login prefill requires an Email OTP worker session authority');
  }
  const sessionId = String(handle.sessionId || '').trim();
  if (!sessionId) throw new Error('ECDSA login prefill Email OTP worker session id is required');
  return sessionId;
}

function requireResolvedLoginPrefillMaterial(
  resolution: EcdsaRoleLocalMaterialResolution,
): EcdsaRoleLocalWorkerHandle {
  switch (resolution.kind) {
    case 'live':
    case 'rehydrated':
      return resolution.liveHandle;
    case 'device_link_required':
      throw new Error('ECDSA login prefill requires local role-local material');
    case 'corrupt':
      throw new Error(
        `ECDSA login prefill role-local material is corrupt (${resolution.reason}): ${resolution.message}`,
      );
    default: {
      const exhaustive: never = resolution;
      throw new Error(`Unsupported ECDSA login prefill material state: ${String(exhaustive)}`);
    }
  }
}

export function createEcdsaLoginPrefillClientSigningMaterialSource(
  record: ThresholdEcdsaSessionRecord,
): RouterAbEcdsaDerivationClientSigningMaterialSource {
  const materialOwner = isEmailOtpWorkerRecord(record) ? 'email_otp_worker' : 'role_local_worker';
  return {
    kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
    initClientPresignSession: async (input) => {
      if (materialOwner === 'role_local_worker') {
        const persistedMaterial = requirePersistedEcdsaRoleLocalMaterial(record);
        const resolution = await resolveEcdsaRoleLocalMaterial({
          purpose: 'wallet_unlock',
          source: ecdsaRoleLocalPersistedMaterialRefSource(persistedMaterial.materialRef),
          workerCtx: input.workerCtx,
        });
        const liveHandle = requireResolvedLoginPrefillMaterial(resolution);
        if (!markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) {
          throw new Error('ECDSA login prefill could not validate runtime role-local material');
        }
        const initialized = await thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm({
          materialHandle: liveHandle.materialHandle,
          material: {
            kind: 'persisted',
            materialRef: persistedMaterial.materialRef,
          },
          ...input,
        });
        return initialized;
      }
      const initialized = await thresholdEcdsaEmailOtpPresignSessionInitWasm({
        emailOtpSessionId: requireEmailOtpWorkerSessionId(record),
        ...input,
      });
      return initialized.progress;
    },
    stepClientPresignSession: thresholdEcdsaRoleLocalPresignSessionStepWasm,
    abortClientPresignSession: thresholdEcdsaRoleLocalPresignSessionAbortWasm,
    admitClientPresignature: thresholdEcdsaRoleLocalAdmitPresignatureWasm,
    destroyClientPresignature: thresholdEcdsaRoleLocalDestroyPresignatureWasm,
    reserveClientPresignature: thresholdEcdsaRoleLocalReservePresignatureWasm,
    commitClientPresignature: thresholdEcdsaRoleLocalCommitPresignatureWasm,
    listAvailableClientPresignatures: thresholdEcdsaRoleLocalListAvailablePresignaturesWasm,
    retireClientPresignaturePool: thresholdEcdsaRoleLocalRetirePresignaturePoolWasm,
    computeSignatureShareFromPresignatureHandle:
      thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
  };
}
