import {
  isWarmSessionSigningAuthPlan,
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { classifyRouterAbEd25519PersistedSigningRecord } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type { WarmSessionCapabilityReader } from '@/core/signingEngine/session/warmCapabilities/types';
import type { NearPasskeyEd25519ReconnectHook } from '@/core/signingEngine/interfaces/near';

function hasMaterialHandle(record: { ed25519WorkerMaterialHandle?: string } | null): boolean {
  return Boolean(String(record?.ed25519WorkerMaterialHandle || '').trim());
}

export function signingAuthPlanForEd25519MaterialReadiness(args: {
  signingSessionCoordinator: WarmSessionCapabilityReader;
  sessionId: string;
  signingAuthPlan: SigningAuthPlan;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
}): SigningAuthPlan {
  if (!isWarmSessionSigningAuthPlan(args.signingAuthPlan) || !args.passkeyEd25519Reconnect) {
    return args.signingAuthPlan;
  }
  const record = args.signingSessionCoordinator.resolveEd25519RecordByThresholdSessionId(
    args.sessionId,
  );
  const state = classifyRouterAbEd25519PersistedSigningRecord(record);
  switch (state.kind) {
    case 'runtime_validated':
    case 'material_hint_unvalidated':
    case 'non_signing':
    case 'invalid':
      return args.signingAuthPlan;
    case 'restore_available':
      return hasMaterialHandle(state.record)
        ? args.signingAuthPlan
        : {
            kind: SigningAuthPlanKind.PasskeyReauth,
            method: 'passkey',
          };
    case 'auth_ready_material_pending':
      return {
        kind: SigningAuthPlanKind.PasskeyReauth,
        method: 'passkey',
      };
    default: {
      const exhaustive: never = state;
      return exhaustive;
    }
  }
}
