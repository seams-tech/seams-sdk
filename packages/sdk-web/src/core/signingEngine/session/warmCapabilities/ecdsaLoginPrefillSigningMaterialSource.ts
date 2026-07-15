import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import { parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord } from '../persistence/ecdsaRoleLocalRecords';
import { claimEmailOtpEcdsaSigningShare32 } from '../emailOtp/workerRequests';
import {
  storeEcdsaRoleLocalSigningMaterialWasm,
  thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionAbortWasm,
  thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm,
  thresholdEcdsaRoleLocalPresignSessionStepWasm,
} from '../../threshold/crypto/ecdsaClientSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { RouterAbEcdsaHssClientSigningMaterialSource } from '../../routerAb/ecdsaHss/presignaturePool';
import {
  abortRouterAbEcdsaHssClientPresignSession,
  computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle,
  initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare,
  stepRouterAbEcdsaHssClientPresignSession,
} from '../../routerAb/ecdsaHss/clientSigningMaterialBoundary';
import { buildEcdsaRoleLocalSigningMaterialHandle } from '../identity/ecdsaHssSigningMaterialHandle';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from '../routerAbSigningWalletSession';
import { routerAbEcdsaHssActiveStateSessionId } from '@shared/utils/routerAbEcdsaHss';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaThresholdKeyId,
} from '../keyMaterialBrands';

function isEmailOtpWorkerRecord(record: ThresholdEcdsaSessionRecord): boolean {
  return record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session';
}

async function resolveEcdsaLoginPrefillAdditiveShare32(args: {
  record: ThresholdEcdsaSessionRecord;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const additiveShareHandle = args.record.clientAdditiveShareHandle;
  const emailOtpWorkerShareSessionId =
    additiveShareHandle?.kind === 'email_otp_worker_session'
      ? String(additiveShareHandle.sessionId || '').trim()
      : '';
  if (emailOtpWorkerShareSessionId) {
    return await claimEmailOtpEcdsaSigningShare32({
      workerCtx: args.workerCtx,
      sessionId: emailOtpWorkerShareSessionId,
    });
  }
  throw new Error('ECDSA login prefill raw-share opening is only supported for Email OTP worker sessions');
}

function buildRoleLocalWorkerShareHandleFromRecord(record: ThresholdEcdsaSessionRecord) {
  const routerAbState = record.routerAbEcdsaHssNormalSigning;
  if (!routerAbState) {
    throw new Error('ECDSA login prefill requires Router A/B ECDSA-HSS normal-signing state');
  }
  return buildEcdsaRoleLocalSigningMaterialHandle({
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
    keyHandle: parseEcdsaKeyHandle(record.keyHandle),
    routerAbStateSessionId: routerAbEcdsaHssActiveStateSessionId(routerAbState),
    chainTarget: record.chainTarget,
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(record.clientVerifyingShareB64u),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(record.ecdsaThresholdKeyId),
    participantIds: record.participantIds,
    relayerKeyId: parseEcdsaRelayerKeyId(record.relayerKeyId),
  });
}

export function createEcdsaLoginPrefillClientSigningMaterialSource(
  record: ThresholdEcdsaSessionRecord,
): RouterAbEcdsaHssClientSigningMaterialSource {
  const materialOwner = isEmailOtpWorkerRecord(record) ? 'email_otp_worker' : 'role_local_worker';
  return {
    kind: 'router_ab_ecdsa_hss_client_signing_material_source_v1',
    initClientPresignSession: async (input) => {
      if (materialOwner === 'role_local_worker') {
        const readyRecord = parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
        const handle = buildRoleLocalWorkerShareHandleFromRecord(record);
        await storeEcdsaRoleLocalSigningMaterialWasm({
          materialHandle: handle.materialHandle,
          bindingDigest: handle.bindingDigest,
          stateBlob: readyRecord.stateBlob,
          workerCtx: input.workerCtx,
        });
        if (!markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)) {
          throw new Error('ECDSA login prefill could not validate runtime role-local material');
        }
        return await thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm({
          materialHandle: handle.materialHandle,
          expectedBindingDigest: handle.bindingDigest,
          ...input,
        });
      }
      return await initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare({
        clientSigningShare32: await resolveEcdsaLoginPrefillAdditiveShare32({
          record,
          workerCtx: input.workerCtx,
        }),
        ...input,
      });
    },
    stepClientPresignSession: async (input) =>
      materialOwner === 'role_local_worker'
        ? await thresholdEcdsaRoleLocalPresignSessionStepWasm(input)
        : await stepRouterAbEcdsaHssClientPresignSession(input),
    abortClientPresignSession: async (input) =>
      materialOwner === 'role_local_worker'
        ? await thresholdEcdsaRoleLocalPresignSessionAbortWasm(input)
        : await abortRouterAbEcdsaHssClientPresignSession(input),
    computeSignatureShareFromPresignatureHandle: async (input) =>
      materialOwner === 'role_local_worker'
        ? await thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm(input)
        : await computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle(input),
  };
}
