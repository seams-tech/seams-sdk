import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  createKeyExportFlowEvent,
  KeyExportEventPhase,
  type CreateKeyExportFlowEventInput,
  type KeyExportFlowEvent,
} from '@/core/types/sdkSentEvents';
import { errorMessage, isUserCancellationError } from '@shared/utils/errors';
import {
  thresholdEcdsaChainTargetKey,
  type NearAccountRef,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { getPrfResultsFromCredential } from '../../walletAuth/webauthn/credentials/credentialExtensions';

export type KeyExportEventCallback = (event: KeyExportFlowEvent) => void;

export type SigningEngineExportKeypairWithUIInput =
  | {
      kind: 'near';
      nearAccount: NearAccountRef;
      options: {
        chain: 'near';
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
        onEvent?: KeyExportEventCallback;
      };
    }
  | {
      kind: 'ecdsa';
      subjectId: WalletSubjectId;
      chainTarget: ThresholdEcdsaChainTarget;
      walletSessionUserId: string;
      options: {
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
        onEvent?: KeyExportEventCallback;
      };
    };

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
  const randomPart =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${randomPart}`;
}

export function createKeyExportFlowId(nearAccountId: AccountId | string, chain: string): string {
  return `key-export:${String(nearAccountId)}:${chain}:${createExportUiRequestId('flow')}`;
}

export function requirePrfFirstForPrivateKeyExport(args: {
  credential: unknown;
  errorContext: string;
}): string {
  const prfFirstB64u = String(getPrfResultsFromCredential(args.credential).first || '').trim();
  if (!prfFirstB64u) {
    throw new Error(`Missing PRF.first output for ${args.errorContext}`);
  }
  return prfFirstB64u;
}

export async function runKeyExportWithFlowEvents<TResult>(
  input: SigningEngineExportKeypairWithUIInput,
  execute: (args: SigningEngineExportKeypairWithUIInput & { flowId: string }) => Promise<TResult>,
): Promise<TResult> {
  const flowSubject =
    input.kind === 'near'
      ? input.nearAccount.accountId
      : `${String(input.subjectId)}:${thresholdEcdsaChainTargetKey(input.chainTarget)}`;
  const flowChain = input.kind === 'near' ? 'near' : input.chainTarget.kind;
  const flowId = createKeyExportFlowId(flowSubject, flowChain);
  const accountId =
    input.kind === 'near' ? input.nearAccount.accountId : toAccountId(input.walletSessionUserId);
  const eventData =
    input.kind === 'near'
      ? { chain: 'near' as const }
      : {
          chain: input.chainTarget.kind,
          chainTarget: input.chainTarget,
          subjectId: input.subjectId,
        };

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
