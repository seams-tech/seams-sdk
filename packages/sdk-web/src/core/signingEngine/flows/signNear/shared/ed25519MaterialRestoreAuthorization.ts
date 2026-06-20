import { prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorizationNearSignerWasm } from '@/core/signingEngine/chains/near/nearSignerWasm';
import { prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential } from '@/core/signingEngine/session/passkey/prfClaim';
import { classifyRouterAbEd25519PersistedSigningRecord } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/types';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  NearEd25519EmailOtpMaterialRestoreAuthorization,
  NearEd25519EmailOtpRecoveryCodeUnsealAuthorization,
  NearEd25519StepUpAuthorization,
} from '@/core/signingEngine/interfaces/near';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type {
  ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest,
  ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult,
} from '@/core/types/signer-worker';
import type { RouterAbEd25519WorkerMaterialRestoreAuthorization } from './ed25519SigningMaterialReadiness';

const MATERIAL_UNSEAL_AUTHORIZATION_TTL_MS = 5 * 60 * 1000;

function unavailableRestoreAuthorization(): RouterAbEd25519WorkerMaterialRestoreAuthorization {
  return { kind: 'unseal_authorization_unavailable' };
}

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function positiveInteger(value: unknown): number {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function unsealAuthorizationExpiresAtMs(record: ThresholdEd25519SessionRecord): number {
  const sessionExpiresAtMs = positiveInteger(record.expiresAtMs);
  const shortLivedExpiresAtMs = Date.now() + MATERIAL_UNSEAL_AUTHORIZATION_TTL_MS;
  return sessionExpiresAtMs
    ? Math.min(sessionExpiresAtMs, shortLivedExpiresAtMs)
    : shortLivedExpiresAtMs;
}

function requireEmailOtpRecoveryCodeUnsealAuthorization(
  authorization: NearEd25519EmailOtpRecoveryCodeUnsealAuthorization,
): NearEd25519EmailOtpRecoveryCodeUnsealAuthorization {
  if (
    authorization.kind !== 'recovery_code_material_authorization_handle_v1' ||
    authorization.purpose !== 'unseal'
  ) {
    throw new Error(
      '[SigningEngine][near] Email OTP Ed25519 restore requires a recovery-code unseal authorization',
    );
  }
  return authorization;
}

function restoreAvailableRecordForThresholdSession(args: {
  signingSessionCoordinator: WarmSessionCapabilityReader;
  thresholdSessionId: string;
}): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = nonEmptyString(args.thresholdSessionId);
  if (!thresholdSessionId) return null;
  const record =
    args.signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(thresholdSessionId);
  const state = classifyRouterAbEd25519PersistedSigningRecord(record);
  return state.kind === 'restore_available' ? state.record : null;
}

async function preparePasskeyRestoreAuthorization(args: {
  ctx: WorkerOperationContext;
  record: ThresholdEd25519SessionRecord;
  credential: WebAuthnAuthenticationCredential;
}): Promise<RouterAbEd25519WorkerMaterialRestoreAuthorization> {
  const materialBindingDigest = nonEmptyString(args.record.ed25519WorkerMaterialBindingDigest);
  const rpId = nonEmptyString(args.record.rpId);
  if (!materialBindingDigest || !rpId) return unavailableRestoreAuthorization();
  const prepared = await prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential({
    authorizationPort: {
      prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorization:
        preparePasskeyWorkerMaterialUnsealAuthorizationWithContext.bind(null, args.ctx),
    },
    materialBindingDigest,
    rpId,
    credential: args.credential,
    expiresAtMs: unsealAuthorizationExpiresAtMs(args.record),
  });
  return {
    kind: 'unseal_authorization_available',
    unsealAuthorization: prepared.unsealAuthorization,
  };
}

function resolveEmailOtpRestoreAuthorization(
  authorization: NearEd25519EmailOtpMaterialRestoreAuthorization,
): RouterAbEd25519WorkerMaterialRestoreAuthorization {
  switch (authorization.kind) {
    case 'ed25519_email_otp_material_unseal_authorization_available':
      return {
        kind: 'unseal_authorization_available',
        unsealAuthorization: requireEmailOtpRecoveryCodeUnsealAuthorization(
          authorization.unsealAuthorization,
        ),
      };
    case 'ed25519_email_otp_material_unseal_authorization_unavailable':
      return unavailableRestoreAuthorization();
    default: {
      const exhaustive: never = authorization;
      return exhaustive;
    }
  }
}

export async function resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForPasskeyCredential(args: {
  ctx: WorkerOperationContext;
  record: ThresholdEd25519SessionRecord;
  credential: WebAuthnAuthenticationCredential;
}): Promise<RouterAbEd25519WorkerMaterialRestoreAuthorization> {
  return await preparePasskeyRestoreAuthorization({
    ctx: args.ctx,
    record: args.record,
    credential: args.credential,
  });
}

function preparePasskeyWorkerMaterialUnsealAuthorizationWithContext(
  workerCtx: WorkerOperationContext,
  args: {
    request: ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest;
  },
): Promise<ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult> {
  return prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorizationNearSignerWasm({
    request: args.request,
    workerCtx,
  });
}

export async function resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp(args: {
  ctx: WorkerOperationContext;
  signingSessionCoordinator: WarmSessionCapabilityReader;
  thresholdSessionId: string;
  stepUpAuthorization: NearEd25519StepUpAuthorization;
}): Promise<RouterAbEd25519WorkerMaterialRestoreAuthorization> {
  const record = restoreAvailableRecordForThresholdSession({
    signingSessionCoordinator: args.signingSessionCoordinator,
    thresholdSessionId: args.thresholdSessionId,
  });
  if (!record) return unavailableRestoreAuthorization();

  switch (args.stepUpAuthorization.kind) {
    case 'passkey':
      return await preparePasskeyRestoreAuthorization({
        ctx: args.ctx,
        record,
        credential: args.stepUpAuthorization.credential,
      });
    case 'email_otp':
      return resolveEmailOtpRestoreAuthorization(
        args.stepUpAuthorization.ed25519MaterialRestoreAuthorization,
      );
    case 'warm_session':
      return unavailableRestoreAuthorization();
    default: {
      const exhaustive: never = args.stepUpAuthorization;
      return exhaustive;
    }
  }
}
