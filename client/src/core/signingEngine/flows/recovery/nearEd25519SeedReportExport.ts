import type { AccountId } from '@/core/types/accountIds';
import { KeyExportEventPhase } from '@/core/types/sdkSentEvents';
import type { ThemeName } from '@/core/types/seams';
import { errorMessage, isUserCancellationError } from '@shared/utils/errors';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { buildThresholdEd25519SeedExportArtifactFromHssReport } from '../../threshold/ed25519/hssLifecycle';
import {
  createKeyExportFlowId,
  emitKeyExportEvent,
  type KeyExportEventCallback,
} from './keyExportFlow';
import { showNearEd25519ExportViewer } from './keyExportConfirmation';

export type NearEd25519SeedReportExportDeps = {
  touchConfirm: Pick<UiConfirmRuntimeBridgePort, 'requestUserConfirmation'>;
  theme?: ThemeName;
  getSignerWorkerContext: () => WorkerOperationContext;
};

export async function exportThresholdEd25519SeedFromHssReport(
  deps: NearEd25519SeedReportExportDeps,
  args: {
    nearAccountId: AccountId;
    preparedSession: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReport
    >[0]['preparedSession'];
    finalizedReport: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReport
    >[0]['finalizedReport'];
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    };
  },
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
  const flowId = createKeyExportFlowId(args.nearAccountId, 'near');
  emitKeyExportEvent(args.options.onEvent, {
    phase: KeyExportEventPhase.STEP_01_STARTED,
    status: 'running',
    flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
  emitKeyExportEvent(args.options.onEvent, {
    phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED,
    status: 'running',
    flowId,
    accountId: String(args.nearAccountId),
    interaction: { kind: 'none', overlay: 'none' },
    data: { chain: 'near', curve: 'ed25519' },
  });
  try {
    const artifactResult = await buildThresholdEd25519SeedExportArtifactFromHssReport({
      preparedSession: args.preparedSession,
      finalizedReport: args.finalizedReport,
      expectedPublicKey: args.expectedPublicKey,
      workerCtx: deps.getSignerWorkerContext(),
    });
    if (!artifactResult.ok) {
      throw new Error(
        artifactResult.message || 'Failed to build single-key HSS Ed25519 seed export artifact',
      );
    }
    emitKeyExportEvent(args.options.onEvent, {
      phase: KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED,
      status: 'succeeded',
      flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'none' },
      data: { chain: 'near', curve: 'ed25519' },
    });
    await showNearEd25519ExportViewer(
      { touchConfirm: deps.touchConfirm, theme: deps.theme },
      {
        nearAccountId: args.nearAccountId,
        expectedPublicKey: artifactResult.artifact.publicKey,
        privateKey: artifactResult.artifact.privateKey,
        variant: args.options.variant,
        theme: args.options.theme,
        flowId,
        onEvent: args.options.onEvent,
      },
    );
    return {
      accountId: String(args.nearAccountId),
      exportedSchemes: ['ed25519'],
    };
  } catch (error: unknown) {
    const cancelled = isUserCancellationError(error);
    emitKeyExportEvent(args.options.onEvent, {
      phase: cancelled ? KeyExportEventPhase.CANCELLED : KeyExportEventPhase.FAILED,
      status: cancelled ? 'cancelled' : 'failed',
      flowId,
      accountId: String(args.nearAccountId),
      interaction: { kind: 'none', overlay: 'hide' },
      error: {
        message: errorMessage(error) || (cancelled ? 'Key export cancelled' : 'Key export failed'),
      },
      data: { chain: 'near', curve: 'ed25519' },
    });
    throw error;
  }
}
