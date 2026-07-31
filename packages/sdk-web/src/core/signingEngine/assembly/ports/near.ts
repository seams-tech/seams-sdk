import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { createWarmSessionStatusReader } from '../../session/warmCapabilities/statusReader';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import { readPersistedEd25519SessionRecordForSigning } from '../../session/availability/persistedAvailableSigningLanes';

export function createNearSigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  nearRpcUrl: string;
  signingSessionCoordinator: SigningSessionCoordinator;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): NearSigningApiDeps {
  const { createArgs, nearRpcUrl, signingSessionCoordinator, getEmailOtpWarmSessionStatus } = args;
  return {
    nearRpcUrl,
    readPersistedEd25519SessionRecordForSigning,
    prepareNearEd25519YaoMaterialBoundary:
      createArgs.prepareNearEd25519YaoMaterialBoundary,
    createSigningSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => createArgs.signerWorkerManager.getContext(),
    readAvailableSigningLanesForSigning: (snapshotArgs) =>
      createArgs.readAvailableSigningLanesForSigning(snapshotArgs),
    ...(createArgs.requestEmailOtpEd25519SigningChallenge
      ? {
          requestEmailOtpEd25519SigningChallenge: (challengeArgs) =>
            createArgs.requestEmailOtpEd25519SigningChallenge!(challengeArgs),
        }
      : {}),
    signingSessionCoordinator,
    getWarmThresholdEd25519SessionStatusForSession: ({ nearAccountId, thresholdSessionId }) =>
      createWarmSessionStatusReader({
        touchConfirm: createArgs.passkeyMpcSession,
        getEmailOtpWarmSessionStatus,
      }).getEd25519SigningSessionStatusForSession({ nearAccountId, thresholdSessionId }),
    withThresholdEd25519CommitQueue: (queueArgs) =>
      createArgs.withThresholdEd25519CommitQueue(queueArgs),
  };
}
