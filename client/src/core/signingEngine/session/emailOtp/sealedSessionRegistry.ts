import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildCurrentSealedSessionRecord,
  type BuildCurrentSealedSessionRecordInput,
  type readExactSealedSession,
  type writeExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  attachEd25519SessionToEmailOtpSigningSessionSealBestEffort,
} from './companionSessions';
import type { EmailOtpEcdsaPublicationPorts } from './ecdsaPublication';

export class EmailOtpSealedSessionRegistry {
  constructor(
    private readonly ports: {
      configs: SeamsConfigsReadonly;
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      commitEvmFamilyThresholdEcdsaSessions: (args: {
        walletId: AccountId;
        primaryChain: ThresholdEcdsaChainTarget;
        bootstrap: ThresholdEcdsaSessionBootstrapResult;
        source: 'email_otp';
        emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      }) => Promise<{
        bootstrap: ThresholdEcdsaSessionBootstrapResult;
        warmCapability: WarmSessionEcdsaCapabilityState;
      }>;
      writeExactSealedSession: typeof writeExactSealedSession;
      readExactSealedSession: typeof readExactSealedSession;
      getThresholdEcdsaSessionRecordByThresholdSessionId: (
        thresholdSessionId: string,
      ) => ThresholdEcdsaSessionRecord | null;
      getThresholdEd25519SessionRecordByThresholdSessionId: (
        thresholdSessionId: string,
      ) => ThresholdEd25519SessionRecord | null;
      clearEcdsaRestoreCaches: () => void;
    },
  ) {}

  async registerSigningSession(
    record: BuildCurrentSealedSessionRecordInput,
  ): Promise<void> {
    const currentRecord = buildCurrentSealedSessionRecord(record);
    if (!currentRecord) {
      throw new Error('[SigningSessionSealedStore] invalid sealed session record write input');
    }
    await this.ports.writeExactSealedSession(currentRecord);
    this.ports.clearEcdsaRestoreCaches();
  }

  async attachEd25519SessionToEmailOtpSigningSessionSealBestEffort(args: {
    ecdsaThresholdSessionId: string;
    ed25519ThresholdSessionId: string;
  }): Promise<void> {
    await attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({
      sessionPersistenceMode: this.ports.configs.signing.sessionPersistenceMode,
      ecdsaThresholdSessionId: args.ecdsaThresholdSessionId,
      ed25519ThresholdSessionId: args.ed25519ThresholdSessionId,
      readExactSealedSession: (thresholdSessionId, filter) =>
        this.ports.readExactSealedSession(thresholdSessionId, filter),
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        this.ports.getThresholdEd25519SessionRecordByThresholdSessionId,
      registerSigningSession: (record) => this.registerSigningSession(record),
    });
  }

  ecdsaPublicationPorts(): EmailOtpEcdsaPublicationPorts {
    return {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      commitEvmFamilyThresholdEcdsaSessions:
        this.ports.commitEvmFamilyThresholdEcdsaSessions,
      registerSigningSession: (record) => this.registerSigningSession(record),
      readExactSealedSession: this.ports.readExactSealedSession,
    };
  }
}
