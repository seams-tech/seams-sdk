import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { buildNearEd25519WarmSessionStepUpAuthorization } from '../stepUpAuthorization';
import type { Ed25519MaterialRestoreOperation } from '../../../session/warmCapabilities/ed25519MaterialRestore';
import {
  requireOrRestoreRouterAbEd25519WalletSessionState,
  type RouterAbEd25519ReadySigningMaterialState,
} from '../../../session/warmCapabilities/ed25519SigningMaterialReadiness';
import { resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp } from './ed25519MaterialRestoreAuthorization';

export type NearEd25519PreConfirmMaterialGate =
  | {
      kind: 'warm_session';
      signingAuthPlan: Extract<SigningAuthPlan, { kind: typeof SigningAuthPlanKind.WarmSession }>;
    }
  | {
      kind: 'confirmed_auth';
      signingAuthPlan: Exclude<
        SigningAuthPlan,
        { kind: typeof SigningAuthPlanKind.WarmSession }
      >;
    };

function assertNeverNearEd25519PreConfirmMaterial(value: never): never {
  throw new Error(
    `[SigningEngine][near] unexpected pre-confirm Ed25519 material state: ${String(value)}`,
  );
}

export function preConfirmMaterialGateFromSigningAuthPlan(
  signingAuthPlan: SigningAuthPlan,
): NearEd25519PreConfirmMaterialGate {
  switch (signingAuthPlan.kind) {
    case SigningAuthPlanKind.WarmSession:
      return {
        kind: 'warm_session',
        signingAuthPlan,
      };
    case SigningAuthPlanKind.PasskeyReauth:
    case SigningAuthPlanKind.EmailOtpReauth:
      return {
        kind: 'confirmed_auth',
        signingAuthPlan,
      };
    default:
      return assertNeverNearEd25519PreConfirmMaterial(signingAuthPlan);
  }
}

export async function restoreWarmSessionEd25519MaterialBeforeUserConfirmation(args: {
  ctx: WorkerOperationContext;
  signingSessionCoordinator: WarmSessionCapabilityReader;
  thresholdSessionId: string;
  operation: Ed25519MaterialRestoreOperation;
  nearAccountId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  gate: NearEd25519PreConfirmMaterialGate;
}): Promise<RouterAbEd25519ReadySigningMaterialState | null> {
  switch (args.gate.kind) {
    case 'confirmed_auth':
      return null;
    case 'warm_session':
      break;
    default:
      return assertNeverNearEd25519PreConfirmMaterial(args.gate);
  }

  const stepUpAuthorization = buildNearEd25519WarmSessionStepUpAuthorization(
    args.gate.signingAuthPlan,
  );
  return await requireOrRestoreRouterAbEd25519WalletSessionState({
    ctx: args.ctx,
    signingSessionCoordinator: args.signingSessionCoordinator,
    thresholdSessionId: args.thresholdSessionId,
    operation: args.operation,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    restoreAuthorization: await resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp({
      ctx: args.ctx,
      signingSessionCoordinator: args.signingSessionCoordinator,
      thresholdSessionId: args.thresholdSessionId,
      stepUpAuthorization,
    }),
  });
}

export function selectPreparedEd25519ReadyMaterialState(args: {
  thresholdSessionId: string;
  refreshed: RouterAbEd25519ReadySigningMaterialState | null;
  preConfirmed: RouterAbEd25519ReadySigningMaterialState | null;
}): RouterAbEd25519ReadySigningMaterialState | null {
  const thresholdSessionId = args.thresholdSessionId;
  if (args.refreshed?.walletSessionState.thresholdSessionId === thresholdSessionId) {
    return args.refreshed;
  }
  if (args.preConfirmed?.walletSessionState.thresholdSessionId === thresholdSessionId) {
    return args.preConfirmed;
  }
  return null;
}
