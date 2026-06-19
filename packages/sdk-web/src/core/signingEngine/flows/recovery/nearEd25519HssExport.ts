import type { AccountId } from '@/core/types/accountIds';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  type ThresholdEd25519HssFinalizedReportEnvelope,
  type ThresholdEd25519HssPreparedSessionEnvelope,
} from '../../threshold/crypto/hssClientSignerWasm';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '../../threshold/ed25519/hssClientBase';
import { runThresholdEd25519HssCeremonyWithSession } from '../../threshold/ed25519/hssLifecycle';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';

export type NearEd25519SingleKeyHssExportDeps = {
  getSignerWorkerContext: () => WorkerOperationContext;
};

export async function runNearEd25519SingleKeyHssExport(
  deps: NearEd25519SingleKeyHssExportDeps,
  args: {
    signingRootId: string;
    nearAccountId: AccountId;
    keyVersion: string;
    participantIds: number[];
    thresholdSessionId: string;
    walletSessionJwt: string;
    relayerUrl: string;
    relayerKeyId: string;
    prfFirstB64u: string;
  },
): Promise<{
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
}> {
  const workerCtx = deps.getSignerWorkerContext();
  const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: `${args.thresholdSessionId}:hss-export-client-inputs`,
    signingRootId: args.signingRootId,
    nearAccountId: args.nearAccountId,
    keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
    keyVersion: args.keyVersion,
    participantIds: args.participantIds,
    derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    prfFirstB64u: args.prfFirstB64u,
    workerCtx,
  });

  const completed = await runThresholdEd25519HssCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    relayerKeyId: args.relayerKeyId,
    operation: 'explicit_key_export',
    context: {
      signingRootId: args.signingRootId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: args.keyVersion,
      participantIds: args.participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    },
    clientInputs,
    outputProjection: {
      kind: 'client-masked-projection',
      clientRecoverableSecretB64u: args.prfFirstB64u,
    },
    workerCtx,
  });
  if (!completed.ok) {
    throw new Error(
      completed.message || 'Failed to finalize single-key HSS Ed25519 export ceremony',
    );
  }

  return {
    preparedSession: completed.preparedSession,
    finalizedReport: completed.finalizedReport,
  };
}
