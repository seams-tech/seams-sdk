import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createNearSigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  nearRpcUrl: string;
  signingSessionCoordinator: SigningSessionCoordinator;
}): NearSigningApiDeps {
  const { createArgs, nearRpcUrl, signingSessionCoordinator } = args;
  return {
    nearRpcUrl,
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
    withThresholdEd25519CommitQueue: (queueArgs) =>
      createArgs.withThresholdEd25519CommitQueue(queueArgs),
  };
}
