import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import { readThresholdEcdsaSessionRecordRoleLocalReadyRecord } from '../persistence/ecdsaRoleLocalRecords';
import {
  storeEcdsaRoleLocalSigningMaterialWasm,
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
import { buildEcdsaRoleLocalSigningMaterialHandle } from '../identity/ecdsaDerivationSigningMaterialHandle';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from '../routerAbSigningWalletSession';
import { routerAbEcdsaDerivationActiveStateSessionId } from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
} from '../keyMaterialBrands';

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

function buildRoleLocalWorkerShareHandleFromRecord(record: ThresholdEcdsaSessionRecord) {
  const routerAbState = record.routerAbEcdsaDerivationNormalSigning;
  if (!routerAbState) {
    throw new Error(
      'ECDSA login prefill requires Router A/B ECDSA derivation normal-signing state',
    );
  }
  return buildEcdsaRoleLocalSigningMaterialHandle({
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
    keyHandle: parseEcdsaKeyHandle(record.keyHandle),
    routerAbStateSessionId: routerAbEcdsaDerivationActiveStateSessionId(routerAbState),
    chainTarget: record.chainTarget,
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(record.clientVerifyingShareB64u),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(record.ecdsaThresholdKeyId),
    participantIds: record.participantIds,
    relayerKeyId: parseEcdsaRelayerKeyId(record.relayerKeyId),
  });
}

export function createEcdsaLoginPrefillClientSigningMaterialSource(
  record: ThresholdEcdsaSessionRecord,
): RouterAbEcdsaDerivationClientSigningMaterialSource {
  const materialOwner = isEmailOtpWorkerRecord(record) ? 'email_otp_worker' : 'role_local_worker';
  return {
    kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
    initClientPresignSession: async (input) => {
      if (materialOwner === 'role_local_worker') {
        const readyRecord = readThresholdEcdsaSessionRecordRoleLocalReadyRecord(record);
        const handle = buildRoleLocalWorkerShareHandleFromRecord(record);
        await storeEcdsaRoleLocalSigningMaterialWasm({
          materialHandle: handle.materialHandle,
          bindingDigest: handle.bindingDigest,
          stateBlob: readyRecord.stateBlob,
          workerCtx: input.workerCtx,
        });
        if (!markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) {
          throw new Error('ECDSA login prefill could not validate runtime role-local material');
        }
        return await thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm({
          materialHandle: handle.materialHandle,
          durableMaterialRef: handle.durableMaterialRef,
          expectedBindingDigest: handle.bindingDigest,
          ...input,
        });
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
