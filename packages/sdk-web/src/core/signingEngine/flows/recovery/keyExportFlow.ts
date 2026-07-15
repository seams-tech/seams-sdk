import {
  createKeyExportFlowEvent,
  KeyExportEventPhase,
  type CreateKeyExportFlowEventInput,
  type KeyExportFlowEvent,
} from '@/core/types/sdkSentEvents';
import { errorMessage, isUserCancellationError } from '@shared/utils/errors';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  thresholdEcdsaChainTargetKey,
  type NearAccountRef,
  type ThresholdEcdsaChainTarget,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '../../session/identity/exactSigningLaneIdentity';

export type KeyExportEventCallback = (event: KeyExportFlowEvent) => void;

export type SigningEngineKeyExportUiOptions = {
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
  onEvent?: KeyExportEventCallback;
};

export type SigningEngineExportKeypairWithUIInput =
  | {
      kind: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      walletSession: WalletSessionRef;
      laneIdentity: ExactEcdsaSigningLaneIdentity;
      nearAccount?: never;
      options: SigningEngineKeyExportUiOptions;
    }
  | {
      kind: 'ed25519';
      nearAccount: NearAccountRef;
      walletSession: WalletSessionRef;
      laneIdentity: ExactEd25519SigningLaneIdentity;
      chainTarget?: never;
      options: SigningEngineKeyExportUiOptions;
    };

export type SigningEngineResolveExactKeyExportLaneInput =
  | {
      kind: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      walletSession: WalletSessionRef;
      nearAccount?: never;
    }
  | {
      kind: 'ed25519';
      nearAccount: NearAccountRef;
      walletSession: WalletSessionRef;
      chainTarget?: never;
    };

export type SigningEngineResolveExactKeyExportLaneResult =
  | {
      kind: 'ecdsa';
      laneIdentity: ExactEcdsaSigningLaneIdentity;
    }
  | {
      kind: 'ed25519';
      laneIdentity: ExactEd25519SigningLaneIdentity;
    };

type KeyExportFlowContext = {
  subject: string;
  chain: 'near' | ThresholdEcdsaChainTarget['kind'];
  data:
    | { curve: 'ed25519'; chain: 'near'; nearAccount: NearAccountRef }
    | {
        curve: 'ecdsa';
        chain: ThresholdEcdsaChainTarget['kind'];
        chainTarget: ThresholdEcdsaChainTarget;
      };
};

function keyExportFlowContext(input: SigningEngineExportKeypairWithUIInput): KeyExportFlowContext {
  switch (input.kind) {
    case 'ecdsa':
      return {
        subject: `${String(input.walletSession.walletId)}:${thresholdEcdsaChainTargetKey(input.chainTarget)}`,
        chain: input.chainTarget.kind,
        data: {
          curve: 'ecdsa',
          chain: input.chainTarget.kind,
          chainTarget: input.chainTarget,
        },
      };
    case 'ed25519':
      return {
        subject: `${String(input.walletSession.walletId)}:near:${String(input.nearAccount.accountId)}`,
        chain: 'near',
        data: { curve: 'ed25519', chain: 'near', nearAccount: input.nearAccount },
      };
  }
}

export function emitKeyExportEvent(
  onEvent: KeyExportEventCallback | undefined,
  input: CreateKeyExportFlowEventInput,
): void {
  if (!onEvent) return;
  try {
    onEvent(createKeyExportFlowEvent(input));
  } catch {}
}

export function createExportUiRequestId(prefix: string): string {
  return secureRandomId(prefix, 32, 'key export UI request IDs');
}

export function createKeyExportFlowId(subjectId: string, chain: string): string {
  return `key-export:${subjectId}:${chain}:${createExportUiRequestId('flow')}`;
}

export async function runKeyExportWithFlowEvents<TResult>(
  input: SigningEngineExportKeypairWithUIInput,
  execute: (args: SigningEngineExportKeypairWithUIInput & { flowId: string }) => Promise<TResult>,
): Promise<TResult> {
  const context = keyExportFlowContext(input);
  const flowId = createKeyExportFlowId(context.subject, context.chain);
  const accountId = input.walletSession.walletId;
  const eventData = context.data;

  emitKeyExportEvent(input.options.onEvent, {
    phase: KeyExportEventPhase.STEP_01_STARTED,
    status: 'running',
    flowId,
    accountId: String(accountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: eventData,
  });

  try {
    return await execute({ ...input, flowId });
  } catch (error: unknown) {
    const cancelled = isUserCancellationError(error);
    emitKeyExportEvent(input.options.onEvent, {
      phase: cancelled ? KeyExportEventPhase.CANCELLED : KeyExportEventPhase.FAILED,
      status: cancelled ? 'cancelled' : 'failed',
      flowId,
      accountId: String(accountId),
      interaction: { kind: 'none', overlay: 'hide' },
      error: {
        message: errorMessage(error) || (cancelled ? 'Key export cancelled' : 'Key export failed'),
      },
      data: eventData,
    });
    throw error;
  }
}
