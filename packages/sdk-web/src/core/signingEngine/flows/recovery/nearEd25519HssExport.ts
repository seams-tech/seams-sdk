import type { AccountId } from '@/core/types/accountIds';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  type ThresholdEd25519HssFinalizedReportEnvelope,
  type ThresholdEd25519HssPreparedSessionEnvelope,
} from '../../threshold/crypto/hssClientSignerWasm';
import { runThresholdEd25519HssCeremonyWithSession } from '../../threshold/ed25519/hssLifecycle';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  computeSdkEd25519HssApplicationBindingDigestB64u,
  type SdkEd25519HssBindingFacts,
} from '@shared/threshold/ed25519HssBinding';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';

export type NearEd25519SingleKeyHssExportDeps = {
  getSignerWorkerContext: () => WorkerOperationContext;
};

export async function runNearEd25519SingleKeyHssExport(
  deps: NearEd25519SingleKeyHssExportDeps,
  args: {
    signingRootId: string;
    signingRootVersion: string;
    nearEd25519SigningKeyId: NearEd25519SigningKeyId;
    nearAccountId: AccountId;
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
  const hssBindingFacts: SdkEd25519HssBindingFacts = {
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    signingRootId: parseSdkEcdsaHssSigningRootId(args.signingRootId),
    signingRootVersion: parseSdkEcdsaHssSigningRootVersion(args.signingRootVersion),
  };
  const applicationBindingDigestB64u =
    await computeSdkEd25519HssApplicationBindingDigestB64u(hssBindingFacts);
  const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: `${args.thresholdSessionId}:hss-export-client-inputs`,
    applicationBindingDigestB64u,
    participantIds: args.participantIds,
    prfFirstB64u: args.prfFirstB64u,
    workerCtx,
  });

  const completed = await runThresholdEd25519HssCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    relayerKeyId: args.relayerKeyId,
    operation: 'explicit_key_export',
    context: {
      applicationBindingDigestB64u: clientInputs.applicationBindingDigestB64u,
      participantIds: clientInputs.participantIds,
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
